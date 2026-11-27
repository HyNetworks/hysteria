package acl

import (
	"bytes"
	"errors"
	"net"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/net/idna"

	"github.com/apernet/hysteria/extras/v2/outbounds/acl/v2geo"
)

var _ hostMatcher = (*geoipMatcher)(nil)

type geoipMatcher struct {
	N4      []*net.IPNet // sorted
	N6      []*net.IPNet // sorted
	Inverse bool
}

// matchIP tries to match the given IP address with the corresponding IPNets.
// Note that this function does NOT handle the Inverse flag.
func (m *geoipMatcher) matchIP(ip net.IP) bool {
	var n []*net.IPNet
	if ip4 := ip.To4(); ip4 != nil {
		// N4 stores IPv4 addresses in 4-byte form.
		// Make sure we use it here too, otherwise bytes.Compare will fail.
		ip = ip4
		n = m.N4
	} else {
		n = m.N6
	}
	left, right := 0, len(n)-1
	for left <= right {
		mid := (left + right) / 2
		if n[mid].Contains(ip) {
			return true
		} else if bytes.Compare(n[mid].IP, ip) < 0 {
			left = mid + 1
		} else {
			right = mid - 1
		}
	}
	return false
}

func (m *geoipMatcher) Match(host HostInfo) bool {
	if host.IPv4 != nil {
		if m.matchIP(host.IPv4) {
			return !m.Inverse
		}
	}
	if host.IPv6 != nil {
		if m.matchIP(host.IPv6) {
			return !m.Inverse
		}
	}
	return m.Inverse
}

func newGeoIPMatcher(list *v2geo.GeoIP) (*geoipMatcher, error) {
	n4 := make([]*net.IPNet, 0)
	n6 := make([]*net.IPNet, 0)
	for _, cidr := range list.Cidr {
		if len(cidr.Ip) == 4 {
			// IPv4
			n4 = append(n4, &net.IPNet{
				IP:   cidr.Ip,
				Mask: net.CIDRMask(int(cidr.Prefix), 32),
			})
		} else if len(cidr.Ip) == 16 {
			// IPv6
			n6 = append(n6, &net.IPNet{
				IP:   cidr.Ip,
				Mask: net.CIDRMask(int(cidr.Prefix), 128),
			})
		} else {
			return nil, errors.New("invalid IP length")
		}
	}
	// Sort the IPNets, so we can do binary search later.
	sort.Slice(n4, func(i, j int) bool {
		return bytes.Compare(n4[i].IP, n4[j].IP) < 0
	})
	sort.Slice(n6, func(i, j int) bool {
		return bytes.Compare(n6[i].IP, n6[j].IP) < 0
	})
	return &geoipMatcher{
		N4:      n4,
		N6:      n6,
		Inverse: list.InverseMatch,
	}, nil
}

var _ hostMatcher = (*geositeMatcher)(nil)

type geositeDomainType int

const (
	geositeDomainPlain geositeDomainType = iota
	geositeDomainRegex
	geositeDomainRoot
	geositeDomainFull
)

type geositeDomain struct {
	Type  geositeDomainType
	Value string
	Regex *regexp.Regexp
	Attrs map[string]bool
}

type geositeMatcher struct {
	Domains []geositeDomain
	// Attributes are matched using "and" logic - if you have multiple attributes here,
	// a domain must have all of those attributes to be considered a match.
	Attrs []string
}

func (m *geositeMatcher) matchDomain(domain geositeDomain, host HostInfo) bool {
	// Match attributes first
	if len(m.Attrs) > 0 {
		if len(domain.Attrs) == 0 {
			return false
		}
		for _, attr := range m.Attrs {
			if !domain.Attrs[attr] {
				return false
			}
		}
	}

	switch domain.Type {
	case geositeDomainPlain:
		return strings.Contains(host.Name, domain.Value)
	case geositeDomainRegex:
		if domain.Regex != nil {
			return domain.Regex.MatchString(host.Name)
		}
	case geositeDomainFull:
		return host.Name == domain.Value
	case geositeDomainRoot:
		if host.Name == domain.Value {
			return true
		}
		return strings.HasSuffix(host.Name, "."+domain.Value)
	default:
		return false
	}
	return false
}

func (m *geositeMatcher) Match(host HostInfo) bool {
	name, err := idna.ToUnicode(host.Name)
	if err != nil {
		name = host.Name
	}
	host.Name = normalizeHost(name)
	for _, domain := range m.Domains {
		if m.matchDomain(domain, host) {
			return true
		}
	}
	return false
}

func newGeositeMatcher(list *v2geo.GeoSite, attrs []string) (*geositeMatcher, error) {
	domains := make([]geositeDomain, len(list.Domain))
	for i, domain := range list.Domain {
		switch domain.Type {
		case v2geo.Domain_Plain:
			domains[i] = geositeDomain{
				Type:  geositeDomainPlain,
				Value: domain.Value,
				Attrs: domainAttributeToMap(domain.Attribute),
			}
		case v2geo.Domain_Regex:
			regex, err := regexp.Compile(domain.Value)
			if err != nil {
				return nil, err
			}
			domains[i] = geositeDomain{
				Type:  geositeDomainRegex,
				Regex: regex,
				Attrs: domainAttributeToMap(domain.Attribute),
			}
		case v2geo.Domain_Full:
			domains[i] = geositeDomain{
				Type:  geositeDomainFull,
				Value: domain.Value,
				Attrs: domainAttributeToMap(domain.Attribute),
			}
		case v2geo.Domain_RootDomain:
			domains[i] = geositeDomain{
				Type:  geositeDomainRoot,
				Value: domain.Value,
				Attrs: domainAttributeToMap(domain.Attribute),
			}
		default:
			return nil, errors.New("unsupported domain type")
		}
	}
	return &geositeMatcher{
		Domains: domains,
		Attrs:   attrs,
	}, nil
}

func domainAttributeToMap(attrs []*v2geo.Domain_Attribute) map[string]bool {
	m := make(map[string]bool)
	for _, attr := range attrs {
		// Supposedly there are also int attributes,
		// but nobody seems to use them, so we treat everything as boolean for now.
		m[attr.Key] = true
	}
	return m
}
