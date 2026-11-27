package acl

import (
	"net"
	"strings"

	"golang.org/x/net/idna"
)

const (
	domainMatchExact = uint8(iota)
	domainMatchWildcard
	domainMatchSuffix
)

type hostMatcher interface {
	Match(HostInfo) bool
}

type ipMatcher struct {
	IP net.IP
}

func (m *ipMatcher) Match(host HostInfo) bool {
	return m.IP.Equal(host.IPv4) || m.IP.Equal(host.IPv6)
}

type cidrMatcher struct {
	IPNet *net.IPNet
}

func (m *cidrMatcher) Match(host HostInfo) bool {
	return m.IPNet.Contains(host.IPv4) || m.IPNet.Contains(host.IPv6)
}

type domainMatcher struct {
	Pattern string
	Mode    uint8
}

func (m *domainMatcher) Match(host HostInfo) bool {
	name, err := idna.ToUnicode(host.Name)
	if err != nil {
		name = host.Name
	}
	name = normalizeHost(name)
	switch m.Mode {
	case domainMatchExact:
		return name == m.Pattern
	case domainMatchWildcard:
		return deepMatchRune([]rune(name), []rune(m.Pattern))
	case domainMatchSuffix:
		return name == m.Pattern || strings.HasSuffix(name, "."+m.Pattern)
	default:
		return false // Invalid mode
	}
}

func deepMatchRune(str, pattern []rune) bool {
	s, p := 0, 0
	star := -1
	mark := 0
	for s < len(str) {
		if p < len(pattern) && (pattern[p] == '*' || pattern[p] == str[s]) {
			if pattern[p] == '*' {
				star = p
				mark = s
				p++
				continue
			}
			s++
			p++
			continue
		}
		if star < 0 {
			return false
		}
		p = star + 1
		mark++
		s = mark
	}
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}

type allMatcher struct{}

func (m *allMatcher) Match(host HostInfo) bool {
	return true
}
