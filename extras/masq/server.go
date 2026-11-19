package masq

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/apernet/hysteria/extras/v2/correctnet"
)

// MasqTCPServer covers the TCP parts of a standard web server (TCP based HTTP/HTTPS).
// We provide this as an option for masquerading, as some may consider a server
// "suspicious" if it only serves the QUIC protocol and not standard HTTP/HTTPS.
type MasqTCPServer struct {
	QUICPort   int
	HTTPSPort  int
	Handler    http.Handler
	TLSConfig  *tls.Config
	ForceHTTPS bool // Always 301 redirect from HTTP to HTTPS
}

func (s *MasqTCPServer) ListenAndServeHTTP(addr string) error {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.ForceHTTPS {
			if s.HTTPSPort == 0 || s.HTTPSPort == 443 {
				// Omit port if it's the default
				http.Redirect(w, r, "https://"+r.Host+r.RequestURI, http.StatusMovedPermanently)
			} else {
				http.Redirect(w, r, fmt.Sprintf("https://%s:%d%s", r.Host, s.HTTPSPort, r.RequestURI), http.StatusMovedPermanently)
			}
			return
		}
		s.Handler.ServeHTTP(newAltSvcHijackResponseWriter(w, s.QUICPort), r)
	})
	return correctnet.HTTPListenAndServe(addr, h2c.NewHandler(handler, &http2.Server{}))
}

func (s *MasqTCPServer) ListenAndServeHTTPS(addr string) error {
	server := &http.Server{
		Addr: addr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			s.Handler.ServeHTTP(newAltSvcHijackResponseWriter(w, s.QUICPort), r)
		}),
		TLSConfig: s.TLSConfig,
	}
	listener, err := correctnet.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer listener.Close()
	return server.ServeTLS(listener, "", "")
}

var _ http.ResponseWriter = (*altSvcHijackResponseWriter)(nil)

// altSvcHijackResponseWriter makes sure that the Alt-Svc's port
// is always set with our own value, no matter what the handler sets.
type altSvcHijackResponseWriter struct {
	Port int
	http.ResponseWriter
}

func (w *altSvcHijackResponseWriter) WriteHeader(statusCode int) {
	w.Header().Set("Alt-Svc", fmt.Sprintf(`h3=":%d"; ma=2592000`, w.Port))
	w.ResponseWriter.WriteHeader(statusCode)
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
