package acl

import (
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// Request is the input to CompiledRuleSet.Match.
type Request struct {
	Proto      Protocol // ProtocolTCP or ProtocolUDP
	Host       string   // Requested host, can be a domain name or an IP literal
	Port       uint16
	IPv4       net.IP   // Resolved IPv4 address, if any
	IPv6       net.IP   // Resolved IPv6 address, if any
	AuthID     string   // ID returned by the authenticator
	ClientAddr net.Addr // Client's address, can be nil
}

// Env is the environment that rule expressions are evaluated against.
// Field names in expressions come from the expr tags.
type Env struct {
	Proto  string `expr:"proto"` // "tcp" or "udp"
	Dst    Dst    `expr:"dst"`
	Auth   Auth   `expr:"auth"`
	Client Client `expr:"client"`
}

// Dst describes the destination of a request.
type Dst struct {
	Host string `expr:"host"` // Lower-cased, trailing dots removed. Can be an IP literal.
	Port int    `expr:"port"`
	IPv4 string `expr:"ipv4"` // Empty if not resolved
	IPv6 string `expr:"ipv6"` // Empty if not resolved

	hostInfo HostInfo // What the one-argument matcher functions match against
}

// Auth describes the authentication result of the client.
type Auth struct {
	ID string `expr:"id"`
}

// Client describes the client connection.
type Client struct {
	IP   string `expr:"ip"` // Empty if unknown
	Port int    `expr:"port"`
}

// normalizeHost lower-cases a host name or pattern and removes trailing dots.
func normalizeHost(host string) string {
	return strings.TrimRight(strings.ToLower(host), ".")
}

func ipString(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}

// clientAddrPort extracts the IP and port of a client address.
func clientAddrPort(addr net.Addr) (netip.Addr, uint16) {
	switch a := addr.(type) {
	case nil:
		return netip.Addr{}, 0
	case *net.UDPAddr:
		ap := a.AddrPort()
		return ap.Addr().Unmap(), ap.Port()
	case *net.TCPAddr:
		ap := a.AddrPort()
		return ap.Addr().Unmap(), ap.Port()
	default:
		host, port, err := net.SplitHostPort(addr.String())
		if err != nil {
			return netip.Addr{}, 0
		}
		ip, err := netip.ParseAddr(host)
		if err != nil {
			return netip.Addr{}, 0
		}
		p, _ := strconv.ParseUint(port, 10, 16)
		return ip.Unmap(), uint16(p)
	}
}

// newEnv builds the expression environment for a request.
// req.Host must already be normalized.
func newEnv(req *Request, clientIP netip.Addr, clientPort uint16) *Env {
	env := &Env{
		Proto: req.Proto.String(),
		Auth:  Auth{ID: req.AuthID},
		Client: Client{
			Port: int(clientPort),
		},
	}
	env.Dst = Dst{
		Host: req.Host,
		Port: int(req.Port),
		IPv4: ipString(req.IPv4),
		IPv6: ipString(req.IPv6),
		hostInfo: HostInfo{
			Name: req.Host,
			IPv4: req.IPv4,
			IPv6: req.IPv6,
		},
	}
	if clientIP.IsValid() {
		env.Client.IP = clientIP.String()
	}
	return env
}

// hostInfoFromString builds a HostInfo from an explicit value passed to a
// two-argument matcher function. An IP literal fills both the name (so that
// domain patterns behave like they do for IP-literal destinations) and the
// matching IP field.
func hostInfoFromString(s string) HostInfo {
	if ip := net.ParseIP(s); ip != nil {
		h := HostInfo{Name: s}
		if ip4 := ip.To4(); ip4 != nil {
			h.IPv4 = ip4
		} else {
			h.IPv6 = ip
		}
		return h
	}
	return HostInfo{Name: normalizeHost(s)}
}
