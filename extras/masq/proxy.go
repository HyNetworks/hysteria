package masq

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path/filepath"
	"sync"
	"time"
)

const (
	proxyMaxIdleConnsPerHost = 32
	proxyBufferSize          = 32 * 1024
)

// ProxyOptions configures a single-upstream HTTP reverse proxy.
type ProxyOptions struct {
	URL          string
	RewriteHost  bool
	XForwarded   bool
	Insecure     bool
	ErrorHandler func(http.ResponseWriter, *http.Request, error)
}

// ProxyHandler forwards HTTP requests to a single HTTP, HTTPS, or Unix socket
// upstream. It is safe for concurrent use.
type ProxyHandler struct {
	proxy     *httputil.ReverseProxy
	transport *http.Transport
}

// NewProxyHandler builds a reusable single-upstream reverse proxy.
// Absolute filesystem paths and unix:/// URLs are treated as HTTP-over-UDS.
func NewProxyHandler(options ProxyOptions) (*ProxyHandler, error) {
	target, socketPath, err := parseProxyTarget(options.URL)
	if err != nil {
		return nil, err
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxIdleConnsPerHost = proxyMaxIdleConnsPerHost
	if socketPath != "" {
		transport.Proxy = nil
		dialer := &net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}
		transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", socketPath)
		}
		transport.ForceAttemptHTTP2 = false
	}
	if options.Insecure && target.Scheme == "https" {
		if transport.TLSClientConfig == nil {
			transport.TLSClientConfig = &tls.Config{}
		} else {
			transport.TLSClientConfig = transport.TLSClientConfig.Clone()
		}
		transport.TLSClientConfig.InsecureSkipVerify = true
	}

	p := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(target)
			if !options.RewriteHost {
				r.Out.Host = r.In.Host
			}
			if options.XForwarded {
				r.SetXForwarded()
			}
		},
		Transport: transport,
		BufferPool: &proxyBufferPool{pool: sync.Pool{
			New: func() any { return make([]byte, proxyBufferSize) },
		}},
		ModifyResponse: func(r *http.Response) error {
			// The public listener owns Alt-Svc. Advertising an upstream endpoint
			// would either be wrong or leak details about the decoy backend.
			r.Header.Del("Alt-Svc")
			return nil
		},
		ErrorHandler: options.ErrorHandler,
	}
	return &ProxyHandler{proxy: p, transport: transport}, nil
}

func (h *ProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.proxy.ServeHTTP(w, r)
}

// CloseIdleConnections closes cached upstream connections.
func (h *ProxyHandler) CloseIdleConnections() {
	h.transport.CloseIdleConnections()
}

func parseProxyTarget(rawURL string) (*url.URL, string, error) {
	if rawURL == "" {
		return nil, "", errors.New("empty proxy url")
	}
	if filepath.IsAbs(rawURL) {
		return &url.URL{Scheme: "http", Host: "localhost"}, rawURL, nil
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, "", err
	}
	switch u.Scheme {
	case "http", "https":
		return u, "", nil
	case "unix":
		if u.Opaque != "" {
			return nil, "", errors.New("invalid unix socket URL: path must be absolute")
		}
		if u.User != nil {
			return nil, "", errors.New("invalid unix socket URL: userinfo is not supported")
		}
		if u.Host != "" {
			return nil, "", errors.New("invalid unix socket URL: host must be empty")
		}
		if u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
			return nil, "", errors.New("invalid unix socket URL: query and fragment are not supported")
		}
		if u.Path == "" {
			return nil, "", errors.New("empty unix socket path")
		}
		if !filepath.IsAbs(u.Path) {
			return nil, "", errors.New("invalid unix socket URL: path must be absolute")
		}
		return &url.URL{Scheme: "http", Host: "localhost"}, u.Path, nil
	default:
		return nil, "", errors.New("unsupported protocol scheme \"" + u.Scheme + "\"")
	}
}

type proxyBufferPool struct {
	pool sync.Pool
}

func (p *proxyBufferPool) Get() []byte {
	return p.pool.Get().([]byte)
}

func (p *proxyBufferPool) Put(b []byte) {
	if cap(b) < proxyBufferSize {
		return
	}
	p.pool.Put(b[:proxyBufferSize])
}
