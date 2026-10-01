package sniff

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/apernet/hysteria/core/v2/server"
	"github.com/apernet/hysteria/extras/v2/utils"
)

const (
	sniffDefaultTimeout = 4 * time.Second
	sniffMaxTCPBytes    = 64 * 1024
	sniffMaxUDPPackets  = 8
)

var _ server.RequestHook = (*Sniffer)(nil)

// Sniffer is a server core RequestHook that performs packet inspection and possibly
// rewrites the request address based on what's in the protocol header.
// This is mainly for inbounds that inherently cannot get domain information (e.g. TUN),
// in which case sniffing can restore the domains and apply ACLs correctly.
// Currently supports HTTP, HTTPS (TLS) and QUIC.
type Sniffer struct {
	Timeout       time.Duration
	RewriteDomain bool // Whether to rewrite the address even when it's already a domain
	TCPPorts      utils.PortUnion
	UDPPorts      utils.PortUnion
}

func (h *Sniffer) Check(isUDP bool, reqAddr string) bool {
	// @ means it's internal (e.g. speed test)
	if strings.HasPrefix(reqAddr, "@") {
		return false
	}
	host, port, err := net.SplitHostPort(reqAddr)
	if err != nil {
		return false
	}
	if !h.RewriteDomain && net.ParseIP(host) == nil {
		// Is a domain and domain rewriting is disabled
		return false
	}
	portNum, err := strconv.Atoi(port)
	if err != nil {
		return false
	}
	if isUDP {
		return h.UDPPorts == nil || h.UDPPorts.Contains(uint16(portNum))
	} else {
		return h.TCPPorts == nil || h.TCPPorts.Contains(uint16(portNum))
	}
}

// TCP reads from the stream until it has an HTTP request header or a TLS ClientHello,
// or can tell it's neither, and returns everything read.
func (h *Sniffer) TCP(stream server.HyStream, reqAddr *string) ([]byte, error) {
	timeout := h.Timeout
	if timeout == 0 {
		timeout = sniffDefaultTimeout
	}
	if err := stream.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	// Make sure to reset the deadline after sniffing
	defer stream.SetReadDeadline(time.Time{})

	rec := &recorder{r: io.LimitReader(stream, sniffMaxTCPBytes)}
	rewrite(reqAddr, sniffStream(bufio.NewReader(rec)))
	return rec.buf, nil
}

// UDP looks for a QUIC ClientHello, which can span multiple packets.
func (h *Sniffer) UDP(packets [][]byte, reqAddr *string) (bool, error) {
	var c quicCrypto
	for i, p := range packets {
		if !c.feed(p) && i == 0 {
			// Not QUIC
			return true, nil
		}
	}
	hello, more := clientHello(c.stream())
	if more && len(packets) < sniffMaxUDPPackets {
		return false, nil
	}
	rewrite(reqAddr, serverName(hello))
	return true, nil
}

// sniffStream returns the domain in an HTTP request or a TLS ClientHello read from r.
func sniffStream(r *bufio.Reader) string {
	b, err := r.Peek(1)
	switch {
	case err != nil:
		return ""
	case b[0] == 0x16: // TLS handshake record
		return serverName(readClientHello(r))
	case isHTTP(r):
		req, err := http.ReadRequest(r)
		if err != nil {
			return ""
		}
		return req.Host
	}
	return ""
}

// isHTTP reports whether r starts with an HTTP method, like GET or M-SEARCH, and a space.
func isHTTP(r *bufio.Reader) bool {
	for i := 1; ; i++ {
		b, err := r.Peek(i)
		if err != nil {
			return false
		}
		switch c := b[i-1]; {
		case c == ' ':
			return i > 1
		case (c < 'A' || c > 'Z') && c != '-' && c != '_':
			return false
		}
	}
}

// rewrite replaces the host of reqAddr with a sniffed domain, keeping the port.
func rewrite(reqAddr *string, host string) {
	if h, _, err := net.SplitHostPort(host); err == nil {
		// HTTP Host can have a port
		host = h
	}
	_, port, err := net.SplitHostPort(*reqAddr)
	if err != nil || !isDomain(host) {
		return
	}
	*reqAddr = net.JoinHostPort(host, port)
}

func isDomain(s string) bool {
	if s == "" || len(s) > 253 || net.ParseIP(s) != nil {
		return false
	}
	for _, c := range []byte(s) {
		if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '-' || c == '.' || c == '_') {
			return false
		}
	}
	return true
}

// recorder records everything read through it.
type recorder struct {
	r   io.Reader
	buf []byte
}

func (r *recorder) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	r.buf = append(r.buf, p[:n]...)
	return n, err
}
