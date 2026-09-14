package masq

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/apernet/hysteria/extras/v2/correctnet"
)

const masqTCPServerShutdownTimeout = 10 * time.Second

// MasqTCPServer covers the TCP parts of a standard web server (TCP based HTTP/HTTPS).
// We provide this as an option for masquerading, as some may consider a server
// "suspicious" if it only serves the QUIC protocol and not standard HTTP/HTTPS.
type MasqTCPServer struct {
	QUICPort   int
	HTTPSPort  int
	Handler    http.Handler
	TLSConfig  *tls.Config
	ForceHTTPS bool // Always 301 redirect from HTTP to HTTPS

	mutex        sync.Mutex
	servers      map[*http.Server]struct{}
	shuttingDown bool
}

func (s *MasqTCPServer) ListenAndServeHTTP(addr string) error {
	listener, err := correctnet.Listen("tcp", addr)
	if err != nil {
		return err
	}
	server := &http.Server{
		Addr:              addr,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if s.ForceHTTPS {
				http.Redirect(w, r, "https://"+redirectHost(r.Host, s.HTTPSPort)+r.RequestURI, http.StatusMovedPermanently)
				return
			}
			s.Handler.ServeHTTP(newAltSvcHijackResponseWriter(w, s.QUICPort), r)
		}),
	}
	return s.serve(server, listener, false)
}

func (s *MasqTCPServer) ListenAndServeHTTPS(addr string) error {
	server := &http.Server{
		Addr:              addr,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			s.Handler.ServeHTTP(newAltSvcHijackResponseWriter(w, s.QUICPort), r)
		}),
		TLSConfig: s.TLSConfig,
	}
	listener, err := correctnet.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return s.serve(server, listener, true)
}

func (s *MasqTCPServer) serve(server *http.Server, listener net.Listener, tlsEnabled bool) error {
	s.mutex.Lock()
	if s.shuttingDown {
		s.mutex.Unlock()
		_ = listener.Close()
		return http.ErrServerClosed
	}
	if s.servers == nil {
		s.servers = make(map[*http.Server]struct{})
	}
	s.servers[server] = struct{}{}
	s.mutex.Unlock()

	defer func() {
		s.mutex.Lock()
		delete(s.servers, server)
		s.mutex.Unlock()
	}()
	if tlsEnabled {
		return server.ServeTLS(listener, "", "")
	}
	return server.Serve(listener)
}

// Shutdown gracefully stops all active HTTP and HTTPS listeners. Once called,
// this MasqTCPServer cannot be started again.
func (s *MasqTCPServer) Shutdown(ctx context.Context) error {
	s.mutex.Lock()
	s.shuttingDown = true
	servers := make([]*http.Server, 0, len(s.servers))
	for server := range s.servers {
		servers = append(servers, server)
	}
	s.mutex.Unlock()

	errChan := make(chan error, len(servers))
	for _, server := range servers {
		go func() {
			errChan <- server.Shutdown(ctx)
		}()
	}
	var err error
	for range servers {
		err = errors.Join(err, <-errChan)
	}
	return err
}

// Close implements io.Closer for integration with the main server lifecycle.
// It gives in-flight HTTP requests a bounded grace period, then force-closes
// remaining connections if the grace period expires.
func (s *MasqTCPServer) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), masqTCPServerShutdownTimeout)
	defer cancel()
	if err := s.Shutdown(ctx); err != nil {
		return errors.Join(err, s.closeActiveServers())
	}
	return nil
}

func (s *MasqTCPServer) closeActiveServers() error {
	s.mutex.Lock()
	servers := make([]*http.Server, 0, len(s.servers))
	for server := range s.servers {
		servers = append(servers, server)
	}
	s.mutex.Unlock()

	var err error
	for _, server := range servers {
		err = errors.Join(err, server.Close())
	}
	return err
}

var _ http.ResponseWriter = (*altSvcHijackResponseWriter)(nil)

// altSvcHijackResponseWriter makes sure that the Alt-Svc's port
// is always set with our own value, no matter what the handler sets.
type altSvcHijackResponseWriter struct {
	Port int
	http.ResponseWriter
	wroteHeader bool
}

func (w *altSvcHijackResponseWriter) WriteHeader(statusCode int) {
	if w.wroteHeader {
		return
	}
	w.Header().Set("Alt-Svc", fmt.Sprintf(`h3=":%d"; ma=2592000`, w.Port))
	w.ResponseWriter.WriteHeader(statusCode)
	// Informational responses don't commit the final response headers.
	if statusCode < 100 || statusCode >= 200 || statusCode == http.StatusSwitchingProtocols {
		w.wroteHeader = true
	}
}

func (w *altSvcHijackResponseWriter) Write(p []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(p)
}

// Unwrap allows http.ResponseController to preserve optional interfaces and
// operations implemented by the underlying HTTP/1.1 or HTTP/2 writer.
func (w *altSvcHijackResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func (w *altSvcHijackResponseWriter) Flush() {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	_ = http.NewResponseController(w.ResponseWriter).Flush()
}

var _ http.Hijacker = (*altSvcHijackResponseWriterHijacker)(nil)

// altSvcHijackResponseWriterHijacker is a wrapper around altSvcHijackResponseWriter
// that also implements http.Hijacker. This is needed for WebSocket support.
type altSvcHijackResponseWriterHijacker struct {
	altSvcHijackResponseWriter
}

func (w *altSvcHijackResponseWriterHijacker) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return w.ResponseWriter.(http.Hijacker).Hijack()
}

func newAltSvcHijackResponseWriter(w http.ResponseWriter, port int) http.ResponseWriter {
	if _, ok := w.(http.Hijacker); ok {
		return &altSvcHijackResponseWriterHijacker{
			altSvcHijackResponseWriter: altSvcHijackResponseWriter{
				Port:           port,
				ResponseWriter: w,
			},
		}
	}
	return &altSvcHijackResponseWriter{
		Port:           port,
		ResponseWriter: w,
	}
}

func redirectHost(host string, port int) string {
	hostname := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		hostname = h
	} else if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		hostname = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	}
	if port == 0 || port == 443 {
		if strings.Contains(hostname, ":") {
			return "[" + hostname + "]"
		}
		return hostname
	}
	return net.JoinHostPort(hostname, strconv.Itoa(port))
}
