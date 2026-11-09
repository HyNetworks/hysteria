package acl

import (
	"fmt"
	"net"
	"strings"

	lru "github.com/hashicorp/golang-lru/v2"
)

// This file keeps the pre-expr ACL compiler, so that the translated rules can
// be checked against it (differential tests). It can be removed once the expr
// engine has been in a release.

type legacyCompiledRule[O Outbound] struct {
	Outbound      O
	HostMatcher   hostMatcher
	Protocol      Protocol
	StartPort     uint16
	EndPort       uint16
	HijackAddress net.IP
}

func (r *legacyCompiledRule[O]) Match(host HostInfo, proto Protocol, port uint16) bool {
	if r.Protocol != ProtocolBoth && r.Protocol != proto {
		return false
	}
	// Note the port-0 bug: a range starting at 0 matches every port.
	if r.StartPort != 0 && (port < r.StartPort || port > r.EndPort) {
		return false
	}
	return r.HostMatcher.Match(host)
}

type legacyMatchCacheKey struct {
	Host  string
	Proto Protocol
	Port  uint16
}

type legacyCompiledRuleSet[O Outbound] struct {
	Rules []legacyCompiledRule[O]
	Cache *lru.Cache[legacyMatchCacheKey, matchResult[O]]
}

func (s *legacyCompiledRuleSet[O]) Match(host HostInfo, proto Protocol, port uint16) (O, net.IP) {
	host.Name = strings.TrimRight(strings.ToLower(host.Name), ".")
	key := legacyMatchCacheKey{
		Host:  fmt.Sprintf("%s|%s|%s", host.Name, host.IPv4, host.IPv6),
		Proto: proto,
		Port:  port,
	}
	if result, ok := s.Cache.Get(key); ok {
		return result.Outbound, result.Hijack
	}
	for _, rule := range s.Rules {
		if rule.Match(host, proto, port) {
			result := matchResult[O]{rule.Outbound, rule.HijackAddress}
			s.Cache.Add(key, result)
			return result.Outbound, result.Hijack
		}
	}
	var zero O
	s.Cache.Add(key, matchResult[O]{zero, nil})
	return zero, nil
}

func legacyCompile[O Outbound](rules []TextRule, outbounds map[string]O,
	cacheSize int, geoLoader GeoLoader,
) (*legacyCompiledRuleSet[O], error) {
	compiledRules := make([]legacyCompiledRule[O], len(rules))
	for i, rule := range rules {
		src := fmt.Sprintf("line %d", rule.LineNum)
		outbound, ok := outbounds[strings.ToLower(rule.Outbound)]
		if !ok {
			return nil, &CompilationError{src, fmt.Sprintf("outbound %s not found", rule.Outbound)}
		}
		hm, errStr := compileHostMatcher(rule.Address, geoLoader)
		if errStr != "" {
			return nil, &CompilationError{src, errStr}
		}
		pp, ok := parseProtoPort(rule.ProtoPort)
		if !ok {
			return nil, &CompilationError{src, fmt.Sprintf("invalid protocol/port: %s", rule.ProtoPort)}
		}
		var hijackAddress net.IP
		if rule.HijackAddress != "" {
			hijackAddress = net.ParseIP(rule.HijackAddress)
			if hijackAddress == nil {
				return nil, &CompilationError{src, fmt.Sprintf("invalid hijack address (must be an IP address): %s", rule.HijackAddress)}
			}
		}
		compiledRules[i] = legacyCompiledRule[O]{outbound, hm, pp.Proto, pp.StartPort, pp.EndPort, hijackAddress}
	}
	cache, err := lru.New[legacyMatchCacheKey, matchResult[O]](cacheSize)
	if err != nil {
		return nil, err
	}
	return &legacyCompiledRuleSet[O]{compiledRules, cache}, nil
}
