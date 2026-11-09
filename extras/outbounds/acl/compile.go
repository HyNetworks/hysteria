package acl

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/apernet/hysteria/extras/v2/outbounds/acl/v2geo"
)

type Protocol int

const (
	ProtocolBoth Protocol = iota
	ProtocolTCP
	ProtocolUDP
)

func (p Protocol) String() string {
	switch p {
	case ProtocolBoth:
		return "tcp+udp"
	case ProtocolTCP:
		return "tcp"
	case ProtocolUDP:
		return "udp"
	default:
		return fmt.Sprintf("Protocol(%d)", int(p))
	}
}

type Outbound interface {
	any
}

// HostInfo is what host matchers match against.
type HostInfo struct {
	Name string
	IPv4 net.IP
	IPv6 net.IP
}

// CompilationError is returned when a rule fails to compile.
// Source describes where the rule came from, e.g. "line 3" for a legacy
// rule, or "rules[2]" for a rule from a list.
type CompilationError struct {
	Source  string
	Message string
}

func (e *CompilationError) Error() string {
	return fmt.Sprintf("error at %s: %s", e.Source, e.Message)
}

type GeoLoader interface {
	LoadGeoIP() (map[string]*v2geo.GeoIP, error)
	LoadGeoSite() (map[string]*v2geo.GeoSite, error)
}

// protoPort is the parsed form of a legacy proto/port field.
type protoPort struct {
	Proto     Protocol
	HasPort   bool // false means any port
	StartPort uint16
	EndPort   uint16
}

// parseProtoPort parses the protocol and port from a protoPort string.
// protoPort must be in one of the following formats:
//
//	proto/port
//	proto/startPort-endPort
//	proto/*
//	proto
//	*/port
//	*/*
//	*
//	[empty] (same as *)
//
// proto must be either "tcp" or "udp", case-insensitive.
func parseProtoPort(s string) (protoPort, bool) {
	s = strings.ToLower(s)
	if s == "" || s == "*" || s == "*/*" {
		return protoPort{Proto: ProtocolBoth}, true
	}
	parts := strings.SplitN(s, "/", 2)
	var pp protoPort
	switch parts[0] {
	case "tcp":
		pp.Proto = ProtocolTCP
	case "udp":
		pp.Proto = ProtocolUDP
	case "*":
		// A bare "*" is handled above, so there is always a port part here.
		pp.Proto = ProtocolBoth
	default:
		return protoPort{}, false
	}
	if len(parts) == 1 || parts[1] == "*" {
		return pp, true
	}
	// We allow either a single port or a range (e.g. "1000-2000")
	ports := strings.SplitN(strings.TrimSpace(parts[1]), "-", 2)
	if len(ports) == 1 {
		p64, err := strconv.ParseUint(parts[1], 10, 16)
		if err != nil {
			return protoPort{}, false
		}
		pp.StartPort = uint16(p64)
		pp.EndPort = pp.StartPort
	} else {
		p64, err := strconv.ParseUint(ports[0], 10, 16)
		if err != nil {
			return protoPort{}, false
		}
		pp.StartPort = uint16(p64)
		p64, err = strconv.ParseUint(ports[1], 10, 16)
		if err != nil {
			return protoPort{}, false
		}
		pp.EndPort = uint16(p64)
		if pp.StartPort > pp.EndPort {
			return protoPort{}, false
		}
	}
	pp.HasPort = true
	return pp, true
}

// compileHostMatcher compiles a legacy address field into a host matcher.
// The returned string is an error message, empty on success.
func compileHostMatcher(addr string, geoLoader GeoLoader) (hostMatcher, string) {
	addr = normalizeHost(addr)
	if addr == "*" || addr == "all" {
		// Match all hosts
		return &allMatcher{}, ""
	}
	if strings.HasPrefix(addr, "geoip:") {
		return compileGeoIPMatcher(addr[6:], geoLoader)
	}
	if strings.HasPrefix(addr, "geosite:") {
		return compileGeoSiteMatcher(addr[8:], geoLoader)
	}
	if strings.HasPrefix(addr, "suffix:") {
		return compileSuffixMatcher(addr[7:])
	}
	if strings.Contains(addr, "/") {
		// CIDR matcher
		_, ipnet, err := net.ParseCIDR(addr)
		if err != nil {
			return nil, fmt.Sprintf("invalid CIDR address: %s", addr)
		}
		return &cidrMatcher{ipnet}, ""
	}
	if ip := net.ParseIP(addr); ip != nil {
		// Single IP matcher
		return &ipMatcher{ip}, ""
	}
	return compileDomainMatcher(addr), ""
}

// compileDomainMatcher compiles an exact or wildcard domain pattern.
// The pattern must already be normalized.
func compileDomainMatcher(pattern string) hostMatcher {
	if strings.Contains(pattern, "*") {
		return &domainMatcher{
			Pattern: pattern,
			Mode:    domainMatchWildcard,
		}
	}
	return &domainMatcher{
		Pattern: pattern,
		Mode:    domainMatchExact,
	}
}

// compileSuffixMatcher compiles a domain suffix pattern.
// The pattern must already be normalized.
func compileSuffixMatcher(suffix string) (hostMatcher, string) {
	if len(suffix) == 0 {
		return nil, "empty domain suffix"
	}
	return &domainMatcher{
		Pattern: suffix,
		Mode:    domainMatchSuffix,
	}, ""
}

// compileGeoIPMatcher compiles a GeoIP country code.
// The code must already be normalized.
func compileGeoIPMatcher(country string, geoLoader GeoLoader) (hostMatcher, string) {
	if len(country) == 0 {
		return nil, "empty GeoIP country code"
	}
	if geoLoader == nil {
		return nil, "GeoIP database not available"
	}
	gMap, err := geoLoader.LoadGeoIP()
	if err != nil {
		return nil, err.Error()
	}
	list, ok := gMap[country]
	if !ok || list == nil {
		return nil, fmt.Sprintf("GeoIP country code %s not found", country)
	}
	m, err := newGeoIPMatcher(list)
	if err != nil {
		return nil, err.Error()
	}
	return m, ""
}

// compileGeoSiteMatcher compiles a GeoSite name with optional @attributes.
// The name must already be normalized.
func compileGeoSiteMatcher(s string, geoLoader GeoLoader) (hostMatcher, string) {
	name, attrs := parseGeoSiteName(s)
	if len(name) == 0 {
		return nil, "empty GeoSite name"
	}
	if geoLoader == nil {
		return nil, "GeoSite database not available"
	}
	gMap, err := geoLoader.LoadGeoSite()
	if err != nil {
		return nil, err.Error()
	}
	list, ok := gMap[name]
	if !ok || list == nil {
		return nil, fmt.Sprintf("GeoSite name %s not found", name)
	}
	m, err := newGeositeMatcher(list, attrs)
	if err != nil {
		return nil, err.Error()
	}
	return m, ""
}

func parseGeoSiteName(s string) (string, []string) {
	parts := strings.Split(s, "@")
	base := strings.TrimSpace(parts[0])
	attrs := parts[1:]
	for i := range attrs {
		attrs[i] = strings.TrimSpace(attrs[i])
	}
	return base, attrs
}
