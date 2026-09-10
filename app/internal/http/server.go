package http

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/apernet/hysteria/core/v2/client"
)

const (
	httpResponseHeaderTimeout = 10 * time.Second
)

// Server is an HTTP server using a Hysteria client as outbound.
type Server struct {
	HyClient    client.Client
	AuthFunc    func(username, password string) bool // nil = no authentication
	AuthRealm   string
	EventLogger EventLogger

	httpClient *http.Client
}

type EventLogger interface {
	ConnectRequest(addr net.Addr, reqAddr string)
	ConnectError(addr net.Addr, reqAddr string, err error)
	HTTPRequest(addr net.Addr, reqURL string)
	HTTPError(addr net.Addr, reqURL string, err error)
}

func (s *Server) Serve(listener net.Listener) error {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		go s.dispatch(conn)
	}
}

func (s *Server) dispatch(conn net.Conn) {
	bufReader := bufio.NewReader(conn)
	for {
		req, err := http.ReadRequest(bufReader)
		if err != nil {
			// Connection error or invalid request
			_ = conn.Close()
			return
		}
		if s.AuthFunc != nil {
			authOK := false
			// Check the Proxy-Authorization header
			pAuth := req.Header.Get("Proxy-Authorization")
			if strings.HasPrefix(strings.ToLower(pAuth), "basic ") {
				userPass, err := base64.StdEncoding.DecodeString(pAuth[6:])
				if err == nil {
					userPassParts := strings.SplitN(string(userPass), ":", 2)
					if len(userPassParts) == 2 {
						authOK = s.AuthFunc(userPassParts[0], userPassParts[1])
					}
				}
			}
			if !authOK {
				// Proxy authentication required
				_ = sendProxyAuthRequired(conn, req, s.AuthRealm)
				_ = conn.Close()
				return
			}
		}
		if req.Method == http.MethodConnect {
			if bufReader.Buffered() > 0 {
				// There is still data in the buffered reader.
				// We need to get it out and put it into a cachedConn,
				// so that handleConnect can read it.
				data := make([]byte, bufReader.Buffered())
				_, err := io.ReadFull(bufReader, data)
				if err != nil {
					// Read from buffer failed, is this possible?
					_ = conn.Close()
					return
				}
				cachedConn := &cachedConn{
					Conn:   conn,
					Buffer: *bytes.NewBuffer(data),
				}
				s.handleConnect(cachedConn, req)
			} else {
				// No data in the buffered reader, we can just pass the original connection.
				s.handleConnect(conn, req)
			}
			// handleConnect will take over the connection,
			// i.e. it will not return until the connection is closed.
			// When it returns, there will be no more requests from this connection,
			// so we simply exit the loop.
			return
		} else {
			// handleRequest on the other hand handles one request at a time,
			// and returns when the request is done. It returns a bool indicating
			// whether the connection should be kept alive, but itself never closes
			// the connection.
			keepAlive := s.handleRequest(conn, req)
			if !keepAlive {
				_ = conn.Close()
				return
			}
		}
	}
}

// cachedConn is a net.Conn wrapper that first Read()s from a buffer,
// and then from the underlying net.Conn when the buffer is drained.
type cachedConn struct {
	net.Conn
	Buffer bytes.Buffer
}

func (c *cachedConn) Read(b []byte) (int, error) {
	if c.Buffer.Len() > 0 {
		n, err := c.Buffer.Read(b)
		if err == io.EOF {
			// Buffer is drained, hide it from the caller
			err = nil
		}
		return n, err
	}
	return c.Conn.Read(b)
}

func (s *Server) handleConnect(conn net.Conn, req *http.Request) {
	defer conn.Close()

	port := req.URL.Port()
	if port == "" {
		// HTTP defaults to port 80
		port = "80"
	}
	reqAddr := net.JoinHostPort(req.URL.Hostname(), port)

	// Connect request & error log
	if s.EventLogger != nil {
		s.EventLogger.ConnectRequest(conn.RemoteAddr(), reqAddr)
	}
	var closeErr error
	defer func() {
		if s.EventLogger != nil {
			s.EventLogger.ConnectError(conn.RemoteAddr(), reqAddr, closeErr)
		}
	}()

	// Dial
	rConn, err := s.HyClient.TCP(reqAddr)
	if err != nil {
		_ = sendSimpleResponse(conn, req, http.StatusBadGateway)
		closeErr = err
		return
	}
	defer rConn.Close()

	// Send 200 OK response and start relaying
	_ = sendSimpleResponse(conn, req, http.StatusOK)
	copyErrChan := make(chan error, 2)
	go func() {
		_, err := io.Copy(rConn, conn)
		copyErrChan <- err
	}()
	go func() {
		_, err := io.Copy(conn, rConn)
		copyErrChan <- err
	}()
	closeErr = <-copyErrChan
}

func (s *Server) handleRequest(conn net.Conn, req *http.Request) bool {
	// Some clients use Connection, some use Proxy-Connection
	// https://www.oreilly.com/library/view/http-the-definitive/1565925092/re40.html
	keepAlive := req.ProtoAtLeast(1, 1) &&
		(strings.ToLower(req.Header.Get("Proxy-Connection")) == "keep-alive" ||
			strings.ToLower(req.Header.Get("Connection")) == "keep-alive")
	req.RequestURI = "" // Outgoing request should not have RequestURI

	removeHopByHopHeaders(req.Header)
	removeExtraHTTPHostPort(req)

	if req.URL.Scheme == "" || req.URL.Host == "" {
		_ = sendSimpleResponse(conn, req, http.StatusBadRequest)
		return false
	}

	// Request & error log
	if s.EventLogger != nil {
		s.EventLogger.HTTPRequest(conn.RemoteAddr(), req.URL.String())
	}
	var closeErr error
	defer func() {
		if s.EventLogger != nil {
			s.EventLogger.HTTPError(conn.RemoteAddr(), req.URL.String(), closeErr)
		}
	}()

	if s.httpClient == nil {
		s.initHTTPClient()
	}

	// Do the request and send the response back
	resp, err := s.httpClient.Do(req)
	if err != nil {
		closeErr = err
		_ = sendSimpleResponse(conn, req, http.StatusBadGateway)
		return false
	}

	removeHopByHopHeaders(resp.Header)
	if keepAlive {
		resp.Header.Set("Connection", "keep-alive")
		resp.Header.Set("Proxy-Connection", "keep-alive")
		resp.Header.Set("Keep-Alive", "timeout=60")
	}

	closeErr = resp.Write(conn)
	return closeErr == nil && keepAlive
}

func (s *Server) initHTTPClient() {
	s.httpClient = &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				// HyClient doesn't support context for now
				return s.HyClient.TCP(addr)
			},
			ResponseHeaderTimeout: httpResponseHeaderTimeout,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func removeHopByHopHeaders(header http.Header) {
	header.Del("Proxy-Connection") // Not in RFC but common
	// https://www.ietf.org/rfc/rfc2616.txt
	header.Del("Connection")
	header.Del("Keep-Alive")
	header.Del("Proxy-Authenticate")
	header.Del("Proxy-Authorization")
	header.Del("TE")
	header.Del("Trailers")
	header.Del("Transfer-Encoding")
	header.Del("Upgrade")
}

func removeExtraHTTPHostPort(req *http.Request) {
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	if pHost, port, err := net.SplitHostPort(host); err == nil && port == "80" {
		host = pHost
	}
	req.Host = host
	req.URL.Host = host
}

// sendSimpleResponse sends a simple HTTP response with the given status code.
func sendSimpleResponse(conn net.Conn, req *http.Request, statusCode int) error {
	resp := &http.Response{
		StatusCode: statusCode,
		Status:     http.StatusText(statusCode),
		Proto:      req.Proto,
		ProtoMajor: req.ProtoMajor,
		ProtoMinor: req.ProtoMinor,
		Header:     http.Header{},
	}
	// Remove the "Content-Length: 0" header, some clients (e.g. ffmpeg) may not like it.
	resp.ContentLength = -1
	// Also, prevent the "Connection: close" header.
	resp.Close = false
	resp.Uncompressed = true
	return resp.Write(conn)
}

// sendProxyAuthRequired sends a 407 Proxy Authentication Required response.
func sendProxyAuthRequired(conn net.Conn, req *http.Request, realm string) error {
	resp := &http.Response{
		StatusCode: http.StatusProxyAuthRequired,
		Status:     http.StatusText(http.StatusProxyAuthRequired),
		Proto:      req.Proto,
		ProtoMajor: req.ProtoMajor,
		ProtoMinor: req.ProtoMinor,
		Header:     http.Header{},
	}
	resp.Header.Set("Proxy-Authenticate", fmt.Sprintf("Basic realm=%q", realm))
	return resp.Write(conn)
}
