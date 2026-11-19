package store

import (
	"context"
	apphttp "github.com/majd/ipatool/v2/pkg/http"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/majd/ipatool/v2/internal/store/emulator"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestStoreBackend(t *testing.T) { RegisterFailHandler(Fail); RunSpecs(t, "Store Backend") }

var _ = Describe("Store connection reuse", func() {
	var backend *Backend
	var server *httptest.Server
	BeforeEach(func() {
		jar, err := cookiejar.New(nil)
		Expect(err).NotTo(HaveOccurred())
		backend = New(jar, nil)
		server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Connection", r.RemoteAddr)
			w.Header().Set("X-Received-Cookie", r.Header.Get("Cookie"))
			switch r.URL.Path {
			case "/bag":
				_, _ = io.WriteString(w, `<?xml version="1.0"?><plist version="1.0"><dict><key>urlBag</key><dict><key>buyProduct</key><string>fixture</string></dict></dict></plist>`)
				return
			case "/cookie":
				http.SetCookie(w, &http.Cookie{Name: "session", Value: "fixture", Path: "/"})
			case "/redirect":
				w.Header().Set("Location", "/target")
				w.WriteHeader(http.StatusFound)
			case "/slow-body":
				w.WriteHeader(http.StatusOK)
				w.(http.Flusher).Flush()
				<-r.Context().Done()
				return
			case "/slow":
				<-r.Context().Done()

				return
			case "/stream":
				w.WriteHeader(http.StatusOK)
				w.(http.Flusher).Flush()
				<-r.Context().Done()

				return
			}
			_, _ = io.WriteString(w, "fixture response")
		}))
	})
	AfterEach(func() {
		backend.CloseIdleConnections()
		server.Close()
	})
	get := func(operation, path string) *http.Response {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL+path, nil)
		Expect(err).NotTo(HaveOccurred())
		response, err := backend.requestTransport(emulator.Request{Operation: operation})(req)
		Expect(err).NotTo(HaveOccurred())
		_, err = io.Copy(io.Discard, response.Body)
		Expect(err).NotTo(HaveOccurred())
		Expect(response.Body.Close()).To(Succeed())

		return response
	}
	It("reuses a consumed connection across API and download clients", func() {
		first := get("request", "/cookie")
		second := get("transfer", "/")
		Expect(second.Header.Get("X-Connection")).To(Equal(first.Header.Get("X-Connection")))
		Expect(second.Header.Get("X-Received-Cookie")).To(Equal("session=fixture"))
		third := get("bag", "/")
		Expect(third.Header.Get("X-Connection")).To(Equal(first.Header.Get("X-Connection")))
	})
	It("keeps authentication attempts separate without closing the API pool", func() {
		api := get("request", "/")
		first := get("authenticate", "/")
		second := get("authenticate", "/")
		Expect(first.Header.Get("X-Connection")).NotTo(Equal(api.Header.Get("X-Connection")))
		Expect(second.Header.Get("X-Connection")).NotTo(Equal(first.Header.Get("X-Connection")))
		Expect(get("request", "/").Header.Get("X-Connection")).To(Equal(api.Header.Get("X-Connection")))
	})
	It("reuses the HTTP pool for direct bag and SAP calls but omits account cookies for the catalog", func() {
		original := get("request", "/cookie")
		bag := apphttp.NewClient[[]byte](apphttp.Args{Executor: backend.Client("bag-direct")})
		reply, err := bag.Send(apphttp.Request{Method: http.MethodGet, URL: server.URL, ResponseFormat: apphttp.ResponseFormatRaw})
		Expect(err).NotTo(HaveOccurred())
		Expect(reply.Headers["X-Connection"]).To(Equal(original.Header.Get("X-Connection")))

		req, err := http.NewRequest(http.MethodGet, server.URL, nil)
		Expect(err).NotTo(HaveOccurred())
		sap, err := backend.Client("sap").Do(req)
		Expect(err).NotTo(HaveOccurred())
		_, err = io.Copy(io.Discard, sap.Body)
		Expect(err).NotTo(HaveOccurred())
		Expect(sap.Body.Close()).To(Succeed())
		Expect(sap.Header.Get("X-Connection")).To(Equal(original.Header.Get("X-Connection")))

		catalog := apphttp.NewClient[[]byte](apphttp.Args{Executor: backend.Client("catalog")})
		reply, err = catalog.Send(apphttp.Request{Method: http.MethodGet, URL: server.URL + "/redirect", ResponseFormat: apphttp.ResponseFormatRaw})
		Expect(err).NotTo(HaveOccurred())
		Expect(reply.StatusCode).To(Equal(http.StatusOK))
		Expect(reply.Headers["X-Received-Cookie"]).To(BeEmpty())
	})

	It("retains a direct bag for its hardware GUID while preserving the response", func() {
		requests := 0
		bagServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requests++
			_, _ = io.WriteString(w, `<?xml version="1.0"?><plist version="1.0"><dict><key>urlBag</key><dict><key>buyProduct</key><string>fixture</string></dict></dict></plist>`)
		}))
		defer bagServer.Close()

		bag := apphttp.NewClient[[]byte](apphttp.Args{Executor: backend.Client("bag-direct")})
		response, err := bag.Send(apphttp.Request{Method: http.MethodGet, URL: bagServer.URL + "/bag?guid=001122aabbcc", ResponseFormat: apphttp.ResponseFormatRaw})
		Expect(err).NotTo(HaveOccurred())
		Expect(string(response.Data)).To(ContainSubstring("buyProduct"))
		Expect(requests).To(Equal(1))

		reused, err := bag.Send(apphttp.Request{Method: http.MethodGet, URL: bagServer.URL + "/bag?guid=001122aabbcc", ResponseFormat: apphttp.ResponseFormatRaw})
		Expect(err).NotTo(HaveOccurred())
		Expect(reused.Data).To(Equal(response.Data))
		Expect(requests).To(Equal(1))

		Expect(backend.cachedBag("001122AABBCC")).To(HaveKey("urlBag"))
		Expect(backend.cachedBag("221122AABBCC")).To(BeNil())

		_, err = bag.Send(apphttp.Request{Method: http.MethodGet, URL: bagServer.URL + "/bag?guid=221122aabbcc", ResponseFormat: apphttp.ResponseFormatRaw})
		Expect(err).NotTo(HaveOccurred())
		Expect(requests).To(Equal(2))

		backend.ClearBag()
		Expect(backend.cachedBag("221122AABBCC")).To(BeNil())
		_, err = bag.Send(apphttp.Request{Method: http.MethodGet, URL: bagServer.URL + "/bag?guid=221122aabbcc", ResponseFormat: apphttp.ResponseFormatRaw})
		Expect(err).NotTo(HaveOccurred())
		Expect(requests).To(Equal(3))
	})

	It("returns redirects to the framework", func() {
		Expect(get("request", "/redirect").StatusCode).To(Equal(http.StatusFound))
	})
	It("preserves explicit cookie headers", func() {
		get("request", "/cookie")
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
		Expect(err).NotTo(HaveOccurred())
		req.Header.Set("Cookie", "explicit=value")
		response, err := backend.requestTransport(emulator.Request{})(req)
		Expect(err).NotTo(HaveOccurred())
		defer response.Body.Close()
		Expect(response.Header.Get("X-Received-Cookie")).To(Equal("explicit=value"))
	})
	It("applies timeouts per request without poisoning subsequent requests", func() {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL+"/slow", nil)
		Expect(err).NotTo(HaveOccurred())
		_, err = backend.requestTransport(emulator.Request{Timeout: 20 * time.Millisecond})(req)
		Expect(err).To(MatchError(ContainSubstring("deadline exceeded")))
		Expect(get("request", "/").StatusCode).To(Equal(http.StatusOK))
	})
	It("times out a bag body after headers have arrived", func() {
		client := apphttp.NewClient[[]byte](apphttp.Args{Timeout: 20 * time.Millisecond, Executor: backend.Client("bag-direct")})
		started := time.Now()
		_, err := client.Send(apphttp.Request{Method: http.MethodGet, URL: server.URL + "/slow-body", ResponseFormat: apphttp.ResponseFormatRaw})
		Expect(err).To(MatchError(ContainSubstring("deadline exceeded")))
		Expect(time.Since(started)).To(BeNumerically("<", time.Second))
	})
	It("cancels an active stream without closing an unrelated pooled connection", func() {
		api := get("request", "/")
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/stream", nil)
		Expect(err).NotTo(HaveOccurred())
		response, err := backend.requestTransport(emulator.Request{Operation: "transfer"})(req)
		Expect(err).NotTo(HaveOccurred())
		defer response.Body.Close()
		other := get("request", "/")
		Expect(other.Header.Get("X-Connection")).NotTo(Equal(api.Header.Get("X-Connection")))
		cancel()
		_, err = io.ReadAll(response.Body)
		Expect(err).To(MatchError(context.Canceled))
		Expect(response.Body.Close()).To(Succeed())
		Expect(get("request", "/").Header.Get("X-Connection")).To(Equal(other.Header.Get("X-Connection")))
	})
})
