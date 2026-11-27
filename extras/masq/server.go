package masq

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/apernet/hysteria/extras/v2/correctnet"
)

const (
	masqHTTPReadHeaderTimeout = 10 * time.Second
	masqHTTPReadTimeout       = 60 * time.Second
	masqHTTPIdleTimeout       = 120 * time.Second
	masqHTTPMaxHeaderBytes    = 32 << 10
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

func newMasqHTTPServer(addr string, handler http.Handler, tlsConfig *tls.Config) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: masqHTTPReadHeaderTimeout,
		ReadTimeout:       masqHTTPReadTimeout,
		IdleTimeout:       masqHTTPIdleTimeout,
		MaxHeaderBytes:    masqHTTPMaxHeaderBytes,
	}
}

func redirectHost(hostport string) (string, bool) {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	} else if strings.HasPrefix(hostport, "[") && strings.HasSuffix(hostport, "]") {
		host = hostport[1 : len(hostport)-1]
	}
	if host == "" || len(host) > 255 {
		return "", false
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			return ip4.String(), true
		}
		return "[" + ip.String() + "]", true
	}
	for _, r := range host {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.' || r == '-' || r == '_' || r >= 0x80:
		default:
			return "", false
		}
	}
	return host, true
}

func (s *MasqTCPServer) ListenAndServeHTTP(addr string) error {
	server := newMasqHTTPServer(addr, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.ForceHTTPS {
			host, ok := redirectHost(r.Host)
			if !ok {
				http.Error(w, "invalid host", http.StatusBadRequest)
				return
			}
			if s.HTTPSPort == 0 || s.HTTPSPort == 443 {
				// Omit port if it's the default
				http.Redirect(w, r, "https://"+host+r.RequestURI, http.StatusMovedPermanently)
			} else {
				http.Redirect(w, r, fmt.Sprintf("https://%s:%d%s", host, s.HTTPSPort, r.RequestURI), http.StatusMovedPermanently)
			}
			return
		}
		s.Handler.ServeHTTP(newAltSvcHijackResponseWriter(w, s.QUICPort), r)
	}), nil)
	listener, err := correctnet.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer listener.Close()
	return server.Serve(listener)
}

func (s *MasqTCPServer) ListenAndServeHTTPS(addr string) error {
	server := newMasqHTTPServer(addr, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.Handler.ServeHTTP(newAltSvcHijackResponseWriter(w, s.QUICPort), r)
	}), s.TLSConfig)
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
	http.ResponseWriter
	Port        int
	wroteHeader bool
}

func (w *altSvcHijackResponseWriter) setAltSvc() {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	if w.Port <= 0 {
		return
	}
	w.Header().Set("Alt-Svc", fmt.Sprintf(`h3=":%d"; ma=2592000`, w.Port))
}

func (w *altSvcHijackResponseWriter) WriteHeader(statusCode int) {
	w.setAltSvc()
	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *altSvcHijackResponseWriter) Write(b []byte) (int, error) {
	w.setAltSvc()
	return w.ResponseWriter.Write(b)
}

func (w *altSvcHijackResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
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