package masq

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseProxyTarget(t *testing.T) {
	t.Parallel()
	absPath := filepath.Join(string(filepath.Separator), "run", "backend.sock")
	tests := []struct {
		name       string
		rawURL     string
		wantTarget string
		wantSocket string
		wantError  string
	}{
		{name: "HTTP", rawURL: "http://127.0.0.1:8080/base", wantTarget: "http://127.0.0.1:8080/base"},
		{name: "HTTPS", rawURL: "https://example.com", wantTarget: "https://example.com"},
		{name: "absolute path", rawURL: absPath, wantTarget: "http://localhost", wantSocket: absPath},
		{name: "Unix URL", rawURL: "unix:///run/backend.sock", wantTarget: "http://localhost", wantSocket: "/run/backend.sock"},
		{name: "Unix single slash", rawURL: "unix:/run/backend.sock", wantTarget: "http://localhost", wantSocket: "/run/backend.sock"},
		{name: "empty", wantError: "empty proxy url"},
		{name: "relative path", rawURL: "backend.sock", wantError: "unsupported protocol scheme"},
		{name: "Unix host", rawURL: "unix://run/backend.sock", wantError: "host must be empty"},
		{name: "Unix query", rawURL: "unix:///run/backend.sock?mode=1", wantError: "query and fragment are not supported"},
		{name: "Unix relative", rawURL: "unix:backend.sock", wantError: "path must be absolute"},
		{name: "unsupported", rawURL: "ftp://example.com", wantError: "unsupported protocol scheme"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target, socketPath, err := parseProxyTarget(tt.rawURL)
			if tt.wantError != "" {
				require.ErrorContains(t, err, tt.wantError)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantTarget, target.String())
			assert.Equal(t, tt.wantSocket, socketPath)
		})
	}
}

func TestProxyHandlerHTTP(t *testing.T) {
	t.Parallel()
	type receivedRequest struct {
		path       string
		rawQuery   string
		host       string
		xForwarded string
	}
	received := make(chan receivedRequest, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- receivedRequest{
			path:       r.URL.Path,
			rawQuery:   r.URL.RawQuery,
			host:       r.Host,
			xForwarded: r.Header.Get("X-Forwarded-For"),
		}
		w.Header().Set("Alt-Svc", `h3=":9443"`)
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, "upstream")
	}))
	defer upstream.Close()

	proxy, err := NewProxyHandler(ProxyOptions{
		URL:         upstream.URL,
		RewriteHost: false,
		XForwarded:  true,
	})
	require.NoError(t, err)
	defer proxy.CloseIdleConnections()
	frontend := httptest.NewServer(proxy)
	defer frontend.Close()

	req, err := http.NewRequest(http.MethodGet, frontend.URL+"/events?channel=one", nil)
	require.NoError(t, err)
	req.Host = "public.example"
	resp, err := frontend.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.Equal(t, http.StatusCreated, resp.StatusCode)
	assert.Equal(t, "upstream", string(body))
	assert.Empty(t, resp.Header.Get("Alt-Svc"))
	r := <-received
	assert.Equal(t, "/events", r.path)
	assert.Equal(t, "channel=one", r.rawQuery)
	assert.Equal(t, "public.example", r.host)
	assert.NotEmpty(t, r.xForwarded)
}

func TestProxyHandlerSSEStreamsThroughAltSvcWriter(t *testing.T) {
	for _, http2 := range []bool{false, true} {
		name := "HTTP1"
		if http2 {
			name = "HTTP2"
		}
		t.Run(name, func(t *testing.T) {
			testProxyHandlerSSEStreamsThroughAltSvcWriter(t, http2)
		})
	}
}

func testProxyHandlerSSEStreamsThroughAltSvcWriter(t *testing.T, http2 bool) {
	firstWritten := make(chan struct{})
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
		w.Header().Set("Alt-Svc", `h3=":9443"`)
		_, _ = io.WriteString(w, "data: first\n\n")
		w.(http.Flusher).Flush()
		close(firstWritten)
		<-release
		_, _ = io.WriteString(w, "data: second\n\n")
		w.(http.Flusher).Flush()
	}))
	defer upstream.Close()

	proxy, err := NewProxyHandler(ProxyOptions{URL: upstream.URL})
	require.NoError(t, err)
	defer proxy.CloseIdleConnections()
	frontend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxy.ServeHTTP(newAltSvcHijackResponseWriter(w, 8443), r)
	}))
	frontend.EnableHTTP2 = http2
	if http2 {
		frontend.StartTLS()
	} else {
		frontend.Start()
	}
	defer frontend.Close()
	defer close(release)

	resp, err := frontend.Client().Get(frontend.URL)
	require.NoError(t, err)
	defer resp.Body.Close()
	select {
	case <-firstWritten:
	case <-time.After(time.Second):
		t.Fatal("upstream did not write the first SSE event")
	}
	lineResult := make(chan string, 1)
	go func() {
		line, _ := bufio.NewReader(resp.Body).ReadString('\n')
		lineResult <- line
	}()
	select {
	case line := <-lineResult:
		assert.Equal(t, "data: first\n", line)
	case <-time.After(500 * time.Millisecond):
		t.Fatal("first SSE event was buffered instead of being flushed")
	}
	if http2 {
		assert.Equal(t, 2, resp.ProtoMajor)
	} else {
		assert.Equal(t, 1, resp.ProtoMajor)
	}
	assert.Equal(t, `h3=":8443"; ma=2592000`, resp.Header.Get("Alt-Svc"))
}

func TestProxyHandlerClientCancellationReachesUpstream(t *testing.T) {
	started := make(chan struct{})
	cancelled := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		close(started)
		<-r.Context().Done()
		close(cancelled)
	}))
	defer upstream.Close()

	proxy, err := NewProxyHandler(ProxyOptions{URL: upstream.URL})
	require.NoError(t, err)
	defer proxy.CloseIdleConnections()
	frontend := httptest.NewServer(proxy)
	defer frontend.Close()

	ctx, cancel := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, frontend.URL, nil)
	require.NoError(t, err)
	resp, err := frontend.Client().Do(req)
	require.NoError(t, err)
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("upstream request did not start")
	}
	cancel()
	_ = resp.Body.Close()
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("client cancellation did not cancel the upstream request")
	}
}

func TestProxyHandlerUnixSocket(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix sockets are not available on Windows")
	}
	socketPath := filepath.Join(t.TempDir(), "backend.sock")
	listener, err := net.Listen("unix", socketPath)
	require.NoError(t, err)
	counting := &countingListener{Listener: listener}
	received := make(chan string, 5)
	upstream := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- fmt.Sprintf("%s?%s host=%s forwarded=%s", r.URL.Path, r.URL.RawQuery, r.Host, r.Header.Get("X-Forwarded-For"))
		_, _ = io.WriteString(w, "unix upstream")
	})}
	go func() { _ = upstream.Serve(counting) }()
	t.Cleanup(func() {
		_ = upstream.Shutdown(context.Background())
		_ = listener.Close()
	})

	proxy, err := NewProxyHandler(ProxyOptions{
		URL:         "unix://" + socketPath,
		RewriteHost: true,
		XForwarded:  true,
	})
	require.NoError(t, err)
	defer proxy.CloseIdleConnections()
	assert.Nil(t, proxy.transport.Proxy)
	assert.NotNil(t, proxy.transport.DialContext)
	assert.Equal(t, 100, proxy.transport.MaxIdleConns)
	assert.Equal(t, proxyMaxIdleConnsPerHost, proxy.transport.MaxIdleConnsPerHost)
	assert.False(t, proxy.transport.ForceAttemptHTTP2)
	frontend := httptest.NewServer(proxy)
	defer frontend.Close()

	for range 5 {
		resp, err := frontend.Client().Get(frontend.URL + "/health?full=true")
		require.NoError(t, err)
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		require.NoError(t, err)
		assert.Equal(t, "unix upstream", string(body))
		requestDescription := <-received
		assert.True(t, strings.HasPrefix(requestDescription, "/health?full=true host=localhost forwarded="))
		assert.False(t, strings.HasSuffix(requestDescription, "forwarded="))
	}
	assert.Equal(t, int32(1), counting.accepts.Load(), "upstream keep-alive connection should be reused")
}

func TestProxyHandlerUnixSocketConnectError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix sockets are not available on Windows")
	}
	socketPath := filepath.Join(t.TempDir(), "not-created.sock")
	proxyErrors := make(chan error, 1)
	proxy, err := NewProxyHandler(ProxyOptions{
		URL: "unix://" + socketPath,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			proxyErrors <- err
			w.WriteHeader(http.StatusBadGateway)
		},
	})
	require.NoError(t, err, "the socket need not exist while configuration is loaded")
	defer proxy.CloseIdleConnections()

	recorder := httptest.NewRecorder()
	proxy.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "http://public.example/", nil))

	assert.Equal(t, http.StatusBadGateway, recorder.Code)
	select {
	case err := <-proxyErrors:
		assert.ErrorContains(t, err, socketPath)
	case <-time.After(time.Second):
		t.Fatal("proxy connection error was not reported")
	}
}

type countingListener struct {
	net.Listener
	accepts atomic.Int32
}

func (l *countingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.accepts.Add(1)
	}
	return c, err
}
