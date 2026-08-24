package cmd

import (
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"

	"github.com/apernet/hysteria/core/v2/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

type closerFunc func() error

func (f closerFunc) Close() error { return f() }

type countingListener struct {
	net.Listener
	accepts atomic.Int64
}

func (l *countingListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err == nil {
		l.accepts.Add(1)
	}
	return conn, err
}

type observedProxyRequest struct {
	Host            string
	Path            string
	RawQuery        string
	XForwardedFor   string
	XForwardedHost  string
	XForwardedProto string
}

func startUnixHTTPServer(tb testing.TB, handler http.Handler) (string, *countingListener) {
	tb.Helper()
	if runtime.GOOS == "windows" {
		tb.Skip("Unix domain sockets are not supported by this test on Windows")
	}
	dir, err := os.MkdirTemp("/tmp", "hysteria-masq-uds-")
	require.NoError(tb, err)
	tb.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			tb.Errorf("remove Unix socket test directory: %v", err)
		}
	})
	socketPath := filepath.Join(dir, "upstream.sock")
	listener, err := net.Listen("unix", socketPath)
	require.NoError(tb, err)
	counting := &countingListener{Listener: listener}
	upstreamServer := &http.Server{Handler: handler}
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- upstreamServer.Serve(counting)
	}()
	tb.Cleanup(func() {
		if err := upstreamServer.Close(); err != nil {
			tb.Errorf("close Unix socket HTTP server: %v", err)
		}
		if err := <-serveErr; err != nil && err != http.ErrServerClosed {
			tb.Errorf("serve Unix socket HTTP server: %v", err)
		}
	})
	return socketPath, counting
}

func TestMasqueradeProxyUnixURLStyles(t *testing.T) {
	observed := make(chan observedProxyRequest, 3)
	socketPath, _ := startUnixHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observed <- observedProxyRequest{
			Host:            r.Host,
			Path:            r.URL.Path,
			RawQuery:        r.URL.RawQuery,
			XForwardedFor:   r.Header.Get("X-Forwarded-For"),
			XForwardedHost:  r.Header.Get("X-Forwarded-Host"),
			XForwardedProto: r.Header.Get("X-Forwarded-Proto"),
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("proxied"))
	}))

	tests := []struct {
		name        string
		url         string
		rewriteHost bool
		wantHost    string
	}{
		{name: "absolute path", url: socketPath, wantHost: "front.example"},
		{name: "single slash Unix URL", url: "unix:" + socketPath, wantHost: "front.example"},
		{name: "triple slash Unix URL", url: "unix://" + socketPath, rewriteHost: true, wantHost: "localhost"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler, err := newMasqueradeProxyHandler(serverConfigMasqueradeProxy{
				URL:         test.url,
				RewriteHost: test.rewriteHost,
				XForwarded:  true,
			})
			require.NoError(t, err)

			req := httptest.NewRequest(http.MethodGet, "https://front.example/assets/app.js?v=7", nil)
			req.Host = "front.example"
			req.RemoteAddr = "198.51.100.7:43210"
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, req)

			response := recorder.Result()
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			require.NoError(t, err)
			assert.Equal(t, http.StatusCreated, response.StatusCode)
			assert.Equal(t, "proxied", string(body))

			got := <-observed
			assert.Equal(t, test.wantHost, got.Host)
			assert.Equal(t, "/assets/app.js", got.Path)
			assert.Equal(t, "v=7", got.RawQuery)
			assert.Equal(t, "198.51.100.7", got.XForwardedFor)
			assert.Equal(t, "front.example", got.XForwardedHost)
			assert.Equal(t, "https", got.XForwardedProto)
		})
	}
}

func TestMasqueradeProxyUnixReusesConnections(t *testing.T) {
	socketPath, listener := startUnixHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	handler, err := newMasqueradeProxyHandler(serverConfigMasqueradeProxy{URL: socketPath})
	require.NoError(t, err)

	for range 20 {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "https://front.example/", nil))
		assert.Equal(t, http.StatusOK, recorder.Code)
	}
	assert.Equal(t, int64(1), listener.accepts.Load())
}

func TestMasqueradeProxyUnixConnectionErrorReturnsBadGateway(t *testing.T) {
	previousLogger := logger
	logger = zap.NewNop()
	t.Cleanup(func() { logger = previousLogger })

	handler, err := newMasqueradeProxyHandler(serverConfigMasqueradeProxy{URL: "/tmp/hysteria-missing-anubis.sock"})
	require.NoError(t, err)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "https://front.example/", nil))
	assert.Equal(t, http.StatusBadGateway, recorder.Code)
}

func TestMasqueradeProxyURLValidation(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr string
	}{
		{name: "empty", wantErr: "empty proxy url"},
		{name: "relative path", url: "run/anubis.sock", wantErr: `unsupported protocol scheme ""`},
		{name: "unknown scheme", url: "ftp://127.0.0.1", wantErr: `unsupported protocol scheme "ftp"`},
		{name: "Unix host", url: "unix://run/anubis.sock", wantErr: "invalid unix socket URL: host must be empty"},
		{name: "Unix userinfo", url: "unix://user@/run/anubis.sock", wantErr: "invalid unix socket URL: userinfo is not supported"},
		{name: "Unix query", url: "unix:///run/anubis.sock?mode=1", wantErr: "invalid unix socket URL: query and fragment are not supported"},
		{name: "Unix fragment", url: "unix:///run/anubis.sock#fragment", wantErr: "invalid unix socket URL: query and fragment are not supported"},
		{name: "Unix opaque relative path", url: "unix:run/anubis.sock", wantErr: "invalid unix socket URL: path must be absolute"},
		{name: "empty Unix path", url: "unix://", wantErr: "empty unix socket path"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := &serverConfig{Masquerade: serverConfigMasquerade{
				Type:  "proxy",
				Proxy: serverConfigMasqueradeProxy{URL: test.url},
			}}
			err := config.fillMasqHandler(&server.Config{})
			require.Error(t, err)
			assert.EqualError(t, err, "invalid config: masquerade.proxy.url: "+test.wantErr)
		})
	}
}

func TestMasqueradeProxyKeepsExistingMalformedHTTPBehavior(t *testing.T) {
	config := &serverConfig{Masquerade: serverConfigMasquerade{
		Type:  "proxy",
		Proxy: serverConfigMasqueradeProxy{URL: "http:/127.0.0.1:8923"},
	}}
	assert.NoError(t, config.fillMasqHandler(&server.Config{}))
}

func TestMasqueradeProxyHTTPRegression(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "front.example", r.Host)
		assert.Equal(t, "/health", r.URL.Path)
		_, _ = w.Write([]byte("healthy"))
	}))
	defer upstream.Close()

	handler, err := newMasqueradeProxyHandler(serverConfigMasqueradeProxy{URL: upstream.URL})
	require.NoError(t, err)
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://front.example/health", nil)
	req.Host = "front.example"
	handler.ServeHTTP(recorder, req)
	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Equal(t, "healthy", recorder.Body.String())
}

func TestOrderedClosersPreserveShutdownOrderAndErrors(t *testing.T) {
	t.Parallel()
	var order []string
	firstErr := errors.New("listener shutdown failed")
	secondErr := errors.New("transport cleanup failed")
	closers := orderedClosers{
		closerFunc(func() error {
			order = append(order, "listeners")
			return firstErr
		}),
		closerFunc(func() error {
			order = append(order, "transport")
			return secondErr
		}),
		closerFunc(func() error {
			order = append(order, "packet runtime")
			return nil
		}),
	}

	err := closers.Close()

	assert.Equal(t, []string{"listeners", "transport", "packet runtime"}, order)
	assert.ErrorIs(t, err, firstErr)
	assert.ErrorIs(t, err, secondErr)
}
