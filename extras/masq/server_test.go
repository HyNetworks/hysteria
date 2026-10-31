package masq

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAltSvcResponseWriterImplicitStatusAndFlush(t *testing.T) {
	t.Parallel()
	underlying := &recordingResponseWriter{header: make(http.Header)}
	w := newAltSvcHijackResponseWriter(underlying, 8443)

	flusher, ok := w.(http.Flusher)
	require.True(t, ok)
	_, err := w.Write([]byte("first"))
	require.NoError(t, err)
	flusher.Flush()

	assert.Equal(t, []int{http.StatusOK}, underlying.statuses)
	assert.Equal(t, `h3=":8443"; ma=2592000`, underlying.headersAtWrite[0].Get("Alt-Svc"))
	assert.Equal(t, "first", underlying.body.String())
	assert.Equal(t, 1, underlying.flushes)
	assert.Same(t, underlying, w.(interface{ Unwrap() http.ResponseWriter }).Unwrap())
}

func TestAltSvcResponseWriterInformationalThenFinal(t *testing.T) {
	t.Parallel()
	underlying := &recordingResponseWriter{header: make(http.Header)}
	w := newAltSvcHijackResponseWriter(underlying, 7443)

	w.Header().Set("Alt-Svc", "upstream")
	w.WriteHeader(http.StatusEarlyHints)
	w.Header().Set("Alt-Svc", "changed")
	w.WriteHeader(http.StatusNoContent)

	assert.Equal(t, []int{http.StatusEarlyHints, http.StatusNoContent}, underlying.statuses)
	assert.Equal(t, `h3=":7443"; ma=2592000`, underlying.headersAtWrite[0].Get("Alt-Svc"))
	assert.Equal(t, `h3=":7443"; ma=2592000`, underlying.headersAtWrite[1].Get("Alt-Svc"))
}

func TestAltSvcResponseWriterPreservesHijacker(t *testing.T) {
	t.Parallel()
	underlying := &hijackingResponseWriter{recordingResponseWriter: recordingResponseWriter{header: make(http.Header)}}
	w := newAltSvcHijackResponseWriter(underlying, 443)
	_, ok := w.(http.Hijacker)
	assert.True(t, ok)
}

func TestRedirectHost(t *testing.T) {
	t.Parallel()
	tests := []struct {
		host string
		port int
		want string
	}{
		{host: "example.com:80", port: 443, want: "example.com"},
		{host: "example.com:80", port: 8443, want: "example.com:8443"},
		{host: "example.com", port: 8443, want: "example.com:8443"},
		{host: "[2001:db8::1]:80", port: 443, want: "[2001:db8::1]"},
		{host: "[2001:db8::1]", port: 8443, want: "[2001:db8::1]:8443"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, redirectHost(tt.host, tt.port))
	}
}

func TestMasqTCPServerShutdownWaitsForRequestsAndClosesAllListeners(t *testing.T) {
	requestStarted := make(chan struct{})
	releaseRequest := make(chan struct{})
	s := &MasqTCPServer{}

	blockingListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	idleListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	serveErrors := make(chan error, 2)
	go func() {
		serveErrors <- s.serve(&http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			close(requestStarted)
			<-releaseRequest
			_, _ = io.WriteString(w, "finished")
		})}, blockingListener, false)
	}()
	go func() {
		serveErrors <- s.serve(&http.Server{Handler: http.NotFoundHandler()}, idleListener, false)
	}()

	responseDone := make(chan error, 1)
	go func() {
		resp, err := http.Get("http://" + blockingListener.Addr().String())
		if err != nil {
			responseDone <- err
			return
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err == nil && string(body) != "finished" {
			err = errors.New("unexpected response body")
		}
		responseDone <- err
	}()
	select {
	case <-requestStarted:
	case <-time.After(time.Second):
		t.Fatal("request did not reach the masquerade server")
	}

	shutdownDone := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		shutdownDone <- s.Shutdown(ctx)
	}()
	require.Eventually(t, func() bool {
		conn, err := net.DialTimeout("tcp", idleListener.Addr().String(), 20*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return false
		}
		return true
	}, time.Second, 10*time.Millisecond, "shutdown must close every listener promptly")
	select {
	case err := <-shutdownDone:
		t.Fatalf("shutdown returned before the in-flight request completed: %v", err)
	default:
	}

	close(releaseRequest)
	require.NoError(t, <-responseDone)
	require.NoError(t, <-shutdownDone)
	for range 2 {
		assert.ErrorIs(t, <-serveErrors, http.ErrServerClosed)
	}
}

func TestMasqTCPServerCannotRestartAfterShutdown(t *testing.T) {
	t.Parallel()
	s := &MasqTCPServer{}
	require.NoError(t, s.Shutdown(context.Background()))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	err = s.serve(&http.Server{Handler: http.NotFoundHandler()}, listener, false)

	assert.ErrorIs(t, err, http.ErrServerClosed)
	_, err = net.DialTimeout("tcp", listener.Addr().String(), 20*time.Millisecond)
	assert.Error(t, err, "a rejected listener must be closed")
}

type recordingResponseWriter struct {
	header         http.Header
	statuses       []int
	headersAtWrite []http.Header
	body           bytes.Buffer
	flushes        int
}

func (w *recordingResponseWriter) Header() http.Header { return w.header }

func (w *recordingResponseWriter) WriteHeader(statusCode int) {
	w.statuses = append(w.statuses, statusCode)
	w.headersAtWrite = append(w.headersAtWrite, w.header.Clone())
}

func (w *recordingResponseWriter) Write(p []byte) (int, error) { return w.body.Write(p) }

func (w *recordingResponseWriter) Flush() { w.flushes++ }

type hijackingResponseWriter struct {
	recordingResponseWriter
}

func (w *hijackingResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return nil, nil, nil
}
