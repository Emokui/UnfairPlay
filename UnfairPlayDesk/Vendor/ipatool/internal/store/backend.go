// Package store provides the portable, framework-backed App Store request engine.
package store

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/majd/ipatool/v2/internal/store/emulator"
	apphttp "github.com/majd/ipatool/v2/pkg/http"
)

type Backend struct {
	jar           http.CookieJar
	macAddress    func() (string, error)
	mu            sync.Mutex
	bag           map[string]any
	bagRaw        []byte
	bagGUID       string
	bagURL        string
	transport     *http.Transport
	authTransport *http.Transport
}

type executor struct {
	backend   *Backend
	operation string
}

func New(jar http.CookieJar, macAddress func() (string, error)) *Backend {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.ResponseHeaderTimeout = 30 * time.Second
	transport.IdleConnTimeout = 90 * time.Second
	authTransport := transport.Clone()
	authTransport.DisableKeepAlives = true

	return &Backend{jar: jar, macAddress: macAddress, transport: transport, authTransport: authTransport}
}

// Client shares session cookies and bag data while isolating each guest VM.
func (b *Backend) Client(operation string) apphttp.Executor {
	return &executor{backend: b, operation: operation}
}

func (e *executor) Send(request apphttp.Request, body []byte) (*http.Response, error) {
	ctx := request.Context
	if ctx == nil {
		ctx = context.Background()
	}

	if e.operation == "bag-direct" || e.operation == "catalog" {
		direct, err := http.NewRequestWithContext(ctx, request.Method, request.URL, bytes.NewReader(body))
		if err != nil {
			return nil, fmt.Errorf("create Store request: %w", err)
		}

		for key, value := range request.Headers {
			direct.Header.Set(key, value)
		}

		if direct.Header.Get("User-Agent") == "" {
			direct.Header.Set("User-Agent", apphttp.DefaultUserAgent)
		}

		if e.operation == "catalog" {
			client := &http.Client{Transport: e.backend.transport, Timeout: request.Timeout}
			if request.NoRedirects {
				client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
			}
			return client.Do(direct)
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		guid := direct.URL.Query().Get("guid")
		if guid != "" {
			if raw := e.backend.cachedBagBytes(guid, direct.URL.String()); len(raw) != 0 {
				return &http.Response{
					StatusCode:    http.StatusOK,
					Header:        make(http.Header),
					Body:          io.NopCloser(bytes.NewReader(raw)),
					ContentLength: int64(len(raw)),
					Request:       direct,
				}, nil
			}
		}
		response, err := e.backend.requestTransport(emulator.Request{Operation: e.operation, Timeout: request.Timeout})(direct)
		if err != nil || response.StatusCode != http.StatusOK {
			return response, err
		}
		return e.backend.rememberBag(guid, direct.URL.String(), response)
	}

	// Bound framework preparation too; the network keeps its own I/O limit.
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	input := emulator.Request{URL: request.URL, Method: request.Method, Operation: e.operation, Format: string(request.ResponseFormat), Timeout: request.Timeout, Body: body, Headers: make(http.Header), NoRedirects: request.NoRedirects, Raw: request.ResponseFormat == apphttp.ResponseFormatRaw}
	for key, value := range request.Headers {
		input.Headers.Set(key, value)
	}

	if payload, ok := request.Payload.(*apphttp.XMLPayload); ok {
		input.Parameters = payload.Content
		if input.Parameters == nil {
			input.Parameters = map[string]any{}
		}
	}

	if request.ActionSigner != nil {
		input.Sign = request.ActionSigner.Sign
	}

	return e.backend.execute(ctx, input)
}

func (e *executor) Do(request *http.Request) (*http.Response, error) {
	if request == nil {
		return nil, errors.New("store request is nil")
	}

	if e.operation == "transfer" {
		return e.backend.transfer(request)
	}
	if e.operation == "sap" {
		return e.backend.requestTransport(emulator.Request{Operation: e.operation, Timeout: apphttp.DefaultAuthenticationTimeout})(request)
	}

	var body []byte

	var err error
	if request.Body != nil {
		body, err = io.ReadAll(io.LimitReader(request.Body, (1<<20)+1))
		_ = request.Body.Close()

		if err != nil {
			return nil, fmt.Errorf("read Store request: %w", err)
		}

		if len(body) > 1<<20 {
			return nil, errors.New("store request body exceeds limit")
		}
	}

	return e.backend.execute(request.Context(), emulator.Request{URL: request.URL.String(), Method: request.Method, Headers: request.Header.Clone(), Body: body, Operation: e.operation, Stream: e.operation == "transfer"})
}

func (b *Backend) hardware(parameters map[string]any) ([]byte, error) {
	if value, ok := parameters["guid"].(string); ok {
		data, err := hex.DecodeString(value)
		if err != nil || len(data) != 6 {
			return nil, errors.New("invalid Store hardware identity")
		}

		return data, nil
	}

	if b.macAddress == nil {
		return nil, errors.New("store machine identity is not configured")
	}

	value, err := b.macAddress()
	if err != nil {
		return nil, fmt.Errorf("get Store machine identity: %w", err)
	}

	data, err := net.ParseMAC(value)
	if err != nil || len(data) != 6 {
		return nil, errors.New("invalid Store machine address")
	}

	return data, nil
}

func (b *Backend) execute(ctx context.Context, input emulator.Request) (*http.Response, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("store request: %w", err)
	}

	hardware, err := b.hardware(input.Parameters)
	if err != nil {
		return nil, fmt.Errorf("store request: %w", err)
	}

	input.HardwareID = hardware
	if input.Headers == nil {
		input.Headers = make(http.Header)
	}

	if input.Headers.Get("User-Agent") == "" {
		input.Headers.Set("User-Agent", apphttp.DefaultUserAgent)

		if input.Operation == "purchase" {
			input.Headers.Set("User-Agent", "Configurator/2.18 (Macintosh; OS X 15.3.2; 24D81) AppleWebKit/0620.2.4.11.6")
		}
	}

	if input.Operation == "purchase" {
		guid := strings.ToUpper(hex.EncodeToString(hardware))
		input.Bag = b.cachedBag(guid)
		if input.Bag == nil {
			input.Bag, err = b.fetchPurchaseBag(ctx, guid, input.Headers.Get("User-Agent"))
			if err != nil {
				return nil, fmt.Errorf("load purchase bag: %w", err)
			}
		}
	}

	guest, err := emulator.OpenPinned(ctx)
	if err != nil {
		return nil, fmt.Errorf("open Store framework: %w", err)
	}

	defer guest.Close()

	input.Transport = b.requestTransport(input)

	response, err := guest.Execute(input)
	if err != nil {
		return nil, fmt.Errorf("store request: %w", err)
	}

	if input.Stream {
		return response, nil
	}

	if strings.EqualFold(response.Header.Get("Content-Encoding"), "gzip") {
		reader, e := gzip.NewReader(response.Body)
		if e != nil {
			_ = response.Body.Close()

			return nil, errors.New("invalid compressed Store response")
		}

		data, e := io.ReadAll(io.LimitReader(reader, (32<<20)+1))
		_ = reader.Close()
		_ = response.Body.Close()

		if e != nil {
			return nil, fmt.Errorf("read compressed Store response: %w", e)
		}

		if len(data) > 32<<20 {
			return nil, errors.New("store response exceeds size limit")
		}

		response.Body = io.NopCloser(bytes.NewReader(data))
		response.Header.Del("Content-Encoding")
		response.Header.Del("Content-Length")
		response.ContentLength = int64(len(data))
	}

	return response, nil
}

func (b *Backend) cachedBag(guid string) map[string]any {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.bagGUID != strings.ToUpper(guid) {
		return nil
	}
	return b.bag
}

func (b *Backend) cachedBagBytes(guid, requestURL string) []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.bagGUID != strings.ToUpper(guid) || b.bagURL != requestURL || len(b.bagRaw) == 0 {
		return nil
	}
	return b.bagRaw
}

func (b *Backend) rememberBag(guid, requestURL string, response *http.Response) (*http.Response, error) {
	const maxBagSize = 32 << 20
	data, err := io.ReadAll(io.LimitReader(response.Body, maxBagSize+1))
	_ = response.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("read Store bag response: %w", err)
	}
	if len(data) > maxBagSize {
		return nil, errors.New("Store bag response exceeds size limit")
	}
	response.Body = io.NopCloser(bytes.NewReader(data))

	var values map[string]any
	if err := apphttp.DecodePropertyList(data, &values); err == nil && len(values) > 0 && guid != "" {
		b.mu.Lock()
		b.bag, b.bagRaw, b.bagGUID, b.bagURL = values, data, strings.ToUpper(guid), requestURL
		b.mu.Unlock()
	}
	return response, nil
}

func (b *Backend) fetchPurchaseBag(ctx context.Context, guid, userAgent string) (map[string]any, error) {
	response, err := b.Client("bag-direct").Send(apphttp.Request{
		Context: ctx,
		URL:     "https://init.itunes.apple.com/bag.xml?ix=6&guid=" + url.QueryEscape(guid),
		Method:  http.MethodGet,
		Timeout: apphttp.DefaultAuthenticationTimeout,
		Headers: map[string]string{"Accept": "application/xml", "User-Agent": userAgent},
	}, nil)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Store bag returned HTTP %d", response.StatusCode)
	}
	if bag := b.cachedBag(guid); bag != nil {
		return bag, nil
	}
	return nil, errors.New("invalid Store bag")
}

// ClearBag drops the in-memory bag cache when credentials are revoked.
func (b *Backend) ClearBag() {
	if b == nil {
		return
	}
	b.mu.Lock()
	b.bag, b.bagRaw, b.bagGUID, b.bagURL = nil, nil, "", ""
	b.mu.Unlock()
}

// CloseIdleConnections releases pooled sockets without interrupting active streams.
func (b *Backend) CloseIdleConnections() {
	b.transport.CloseIdleConnections()
	b.authTransport.CloseIdleConnections()
}

// Each request owns its timeout; compatible requests share only the connection pool.
// Login keeps its existing fresh-connection policy, including framework redirects.
func (b *Backend) requestTransport(input emulator.Request) func(*http.Request) (*http.Response, error) {
	timeout := input.Timeout
	if timeout == 0 && input.Operation == "api" {
		timeout = 30 * time.Second
	}

	transport := b.transport

	if input.Operation == "authenticate" {
		transport = b.authTransport
	}

	client := &http.Client{Transport: transport, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	return func(request *http.Request) (*http.Response, error) {
		if b.jar != nil && request.Header.Get("Cookie") == "" {
			for _, cookie := range b.jar.Cookies(request.URL) {
				request.AddCookie(cookie)
			}
		}

		response, err := client.Do(request)
		if err == nil && b.jar != nil {
			b.jar.SetCookies(request.URL, response.Cookies())
		}

		if err != nil {
			return nil, fmt.Errorf("store HTTP transport: %w", err)
		}

		return response, nil
	}
}
