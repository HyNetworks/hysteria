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

func TestProxyHandlerFlushIntervalStreamsKnownLengthResponse(t *testing.T) {
	firstWritten := make(chan struct{})
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "12")
		_, _ = io.WriteString(w, "first\n")
		w.(http.Flusher).Flush()
		close(firstWritten)
		<-release
		_, _ = io.WriteString(w, "second")
	}))
	defer upstream.Close()

	proxy, err := NewProxyHandler(ProxyOptions{URL: upstream.URL, FlushInterval: -time.Millisecond})
	require.NoError(t, err)
	defer proxy.CloseIdleConnections()
	frontend := httptest.NewServer(proxy)
	defer frontend.Close()
	defer close(release)

	resp, err := frontend.Client().Get(frontend.URL)
	require.NoError(t, err)
	defer resp.Body.Close()
	select {
	case <-firstWritten:
	case <-time.After(time.Second):
		t.Fatal("upstream did not write the first response chunk")
	}
	firstChunk := make(chan string, 1)
	go func() {
		buf := make([]byte, len("first\n"))
		_, _ = io.ReadFull(resp.Body, buf)
		firstChunk <- string(buf)
	}()
	select {
	case chunk := <-firstChunk:
		assert.Equal(t, "first\n", chunk)
	case <-time.After(500 * time.Millisecond):
		t.Fatal("configured flush interval did not flush a known-length response")
	}
}

func TestProxyHandlerStreamsRequestBody(t *testing.T) {
	firstRead := make(chan string, 1)
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 5)
		_, err := io.ReadFull(r.Body, buf)
		if err != nil {
			firstRead <- "read error: " + err.Error()
			return
		}
		firstRead <- string(buf)
		<-release
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_, _ = io.WriteString(w, string(buf)+string(body))
	}))
	defer upstream.Close()

	proxy, err := NewProxyHandler(ProxyOptions{URL: upstream.URL})
	require.NoError(t, err)
	defer proxy.CloseIdleConnections()
	frontend := httptest.NewServer(proxy)
	defer frontend.Close()

	reader, writer := io.Pipe()
	req, err := http.NewRequest(http.MethodPost, frontend.URL, reader)
	require.NoError(t, err)
	req.ContentLength = 10
	response := make(chan struct {
		body string
		err  error
	}, 1)
	go func() {
		resp, err := frontend.Client().Do(req)
		if err != nil {
			response <- struct {
				body string
				err  error
			}{err: err}
			return
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		response <- struct {
			body string
			err  error
		}{body: string(body), err: err}
	}()
	_, err = writer.Write([]byte("first"))
	require.NoError(t, err)
	select {
	case chunk := <-firstRead:
		assert.Equal(t, "first", chunk, "upstream should receive data before the request body completes")
	case <-time.After(time.Second):
		t.Fatal("request body was buffered instead of streamed")
	}
	close(release)
	_, err = writer.Write([]byte("last!"))
	require.NoError(t, err)
	require.NoError(t, writer.Close())
	result := <-response
	require.NoError(t, result.err)
	assert.Equal(t, "firstlast!", result.body)
}

func TestProxyHandlerPreservesTrailers(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Trailer", "X-Checksum")
		_, _ = io.WriteString(w, "payload")
		w.Header().Set("X-Checksum", "complete")
	}))
	defer upstream.Close()
	proxy, err := NewProxyHandler(ProxyOptions{URL: upstream.URL})
	require.NoError(t, err)
	defer proxy.CloseIdleConnections()
	frontend := httptest.NewServer(proxy)
	defer frontend.Close()

	resp, err := frontend.Client().Get(frontend.URL)
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	require.NoError(t, err)
	assert.Equal(t, "payload", string(body))
	assert.Equal(t, "complete", resp.Trailer.Get("X-Checksum"))
}

func TestProxyHandlerPreservesHEADAndRangeSemantics(t *testing.T) {
	const content = "0123456789"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeContent(w, r, "asset.txt", time.Unix(1, 0), strings.NewReader(content))
	}))
	defer upstream.Close()
	proxy, err := NewProxyHandler(ProxyOptions{URL: upstream.URL})
	require.NoError(t, err)
	defer proxy.CloseIdleConnections()
	frontend := httptest.NewServer(proxy)
	defer frontend.Close()

	headReq, err := http.NewRequest(http.MethodHead, frontend.URL+"/asset.txt", nil)
	require.NoError(t, err)
	headResp, err := frontend.Client().Do(headReq)
	require.NoError(t, err)
	headBody, err := io.ReadAll(headResp.Body)
	_ = headResp.Body.Close()
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, headResp.StatusCode)
	assert.Empty(t, headBody)
	assert.Equal(t, int64(len(content)), headResp.ContentLength)

	rangeReq, err := http.NewRequest(http.MethodGet, frontend.URL+"/asset.txt", nil)
	require.NoError(t, err)
	rangeReq.Header.Set("Range", "bytes=2-5")
	rangeResp, err := frontend.Client().Do(rangeReq)
	require.NoError(t, err)
	rangeBody, err := io.ReadAll(rangeResp.Body)
	_ = rangeResp.Body.Close()
	require.NoError(t, err)
	assert.Equal(t, http.StatusPartialContent, rangeResp.StatusCode)
	assert.Equal(t, "2345", string(rangeBody))
	assert.Equal(t, "bytes 2-5/10", rangeResp.Header.Get("Content-Range"))
}

func TestProxyHandlerWebSocketUpgradeThroughAltSvcWriter(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
		_ = rw.Flush()
		buf := make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err == nil {
			_, _ = conn.Write(buf)
		}
	}))
	defer upstream.Close()
	proxy, err := NewProxyHandler(ProxyOptions{URL: upstream.URL})
	require.NoError(t, err)
	defer proxy.CloseIdleConnections()
	frontend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxy.ServeHTTP(newAltSvcHijackResponseWriter(w, 8443), r)
	}))
	defer frontend.Close()

	conn, err := net.Dial("tcp", frontend.Listener.Addr().String())
	require.NoError(t, err)
	defer conn.Close()
	_, err = fmt.Fprintf(conn, "GET /socket HTTP/1.1\r\nHost: public.example\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n")
	require.NoError(t, err)
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
	require.NoError(t, err)
	assert.Equal(t, http.StatusSwitchingProtocols, resp.StatusCode)
	_, err = conn.Write([]byte("ping"))
	require.NoError(t, err)
	echo := make([]byte, 4)
	_, err = io.ReadFull(reader, echo)
	require.NoError(t, err)
	assert.Equal(t, "ping", string(echo))
}

func TestProxyHandlerBackendDisconnectReturnsBadGateway(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			_ = conn.Close()
		}
	}()
	proxyErrors := make(chan error, 1)
	proxy, err := NewProxyHandler(ProxyOptions{
		URL: "http://" + listener.Addr().String(),
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			proxyErrors <- err
			w.WriteHeader(http.StatusBadGateway)
		},
	})
	require.NoError(t, err)
	defer proxy.CloseIdleConnections()
	recorder := httptest.NewRecorder()
	proxy.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "http://public.example/", nil))

	assert.Equal(t, http.StatusBadGateway, recorder.Code)
	select {
	case err := <-proxyErrors:
		assert.Error(t, err)
	case <-time.After(time.Second):
		t.Fatal("backend disconnect was not reported")
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
