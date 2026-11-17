package store

import (
	"context"
	"errors"
	apphttp "github.com/majd/ipatool/v2/pkg/http"
	"io"
	"net/http"
	"time"
)

// Signed CDN URLs and artwork need HTTP, not an Apple framework VM.
func (b *Backend) transfer(request *http.Request) (*http.Response, error) {
	ctx, cancel := context.WithCancelCause(request.Context())
	request = request.Clone(ctx)
	if request.Header.Get("User-Agent") == "" {
		request.Header.Set("User-Agent", apphttp.DefaultUserAgent)
	}
	client := &http.Client{Transport: b.transport, CheckRedirect: func(next *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return errors.New("too many download redirects")
		}
		if next.URL.Scheme != "https" && via[0].URL.Scheme == "https" {
			return errors.New("download redirect requires HTTPS")
		}
		for _, key := range []string{"Authorization", "Cookie", "X-Token", "X-Dsid", "Icloud-Dsid"} {
			next.Header.Del(key)
		}
		return nil
	}}
	response, err := client.Do(request)
	if err != nil {
		cancel(err)
		return nil, err
	}
	timer := time.AfterFunc(45*time.Second, func() { cancel(apphttp.ErrTransferIdleTimeout) })
	response.Body = &idleTransferBody{ReadCloser: response.Body, ctx: ctx, cancel: cancel, timer: timer}
	return response, nil
}

type idleTransferBody struct {
	io.ReadCloser
	ctx    context.Context
	cancel context.CancelCauseFunc
	timer  *time.Timer
}

func (b *idleTransferBody) Read(data []byte) (int, error) {
	n, err := b.ReadCloser.Read(data)
	if n > 0 {
		b.timer.Reset(45 * time.Second)
	}
	if err != nil {
		b.timer.Stop()
		if cause := context.Cause(b.ctx); cause != nil {
			return n, cause
		}
	}
	return n, err
}
func (b *idleTransferBody) Close() error {
	b.timer.Stop()
	err := b.ReadCloser.Close()
	b.cancel(context.Canceled)
	return err
}
