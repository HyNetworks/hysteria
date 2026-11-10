package acl

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"

	lru "github.com/hashicorp/golang-lru/v2"
)

// Rule is a single ACL rule.
type Rule struct {
	Outbound string // Name of the outbound to use when the rule matches
	Match    string // Boolean expr expression. Empty means always match.
	Hijack   string // Optional IP address to redirect the request to
	Source   string // Where the rule came from, used in error messages (e.g. "line 3", "rules[2]")
}

type CompiledRuleSet[O Outbound] interface {
	// Match returns the outbound of the first matching rule and its hijack
	// address (nil if none). If no rule matches, it returns the zero value of O.
	Match(req *Request) (O, net.IP)
}

type compiledRule[O Outbound] struct {
	Outbound O
	Program  *vm.Program // nil means always match
	Hijack   net.IP
}

type matchResult[O Outbound] struct {
	Outbound O
	Hijack   net.IP
}

type matchCacheKey struct {
	Proto      Protocol
	Host       string
	Port       uint16
	IPv4       netip.Addr
	IPv6       netip.Addr
	AuthID     string
	ClientIP   netip.Addr
	ClientPort uint16
}

type compiledRuleSetImpl[O Outbound] struct {
	Rules  []compiledRule[O]
	Fields keyFields // Optional fields included in the cache key
	Cache  *lru.Cache[matchCacheKey, matchResult[O]]
	VMPool sync.Pool
}

func ipToAddr(ip net.IP) netip.Addr {
	a, _ := netip.AddrFromSlice(ip)
	return a.Unmap()
}

func (s *compiledRuleSetImpl[O]) Match(req *Request) (O, net.IP) {
	r := *req
	r.Host = normalizeHost(r.Host)
	clientIP, clientPort := clientAddrPort(r.ClientAddr)

	key := matchCacheKey{
		Proto: r.Proto,
		Host:  r.Host,
		Port:  r.Port,
		IPv4:  ipToAddr(r.IPv4),
		IPv6:  ipToAddr(r.IPv6),
	}
	if s.Fields&keyAuthID != 0 {
		key.AuthID = r.AuthID
	}
	if s.Fields&keyClientIP != 0 {
		key.ClientIP = clientIP
	}
	if s.Fields&keyClientPort != 0 {
		key.ClientPort = clientPort
	}
	if result, ok := s.Cache.Get(key); ok {
		return result.Outbound, result.Hijack
	}

	result := s.match(&r, clientIP, clientPort)
	// No match should also be cached
	s.Cache.Add(key, result)
	return result.Outbound, result.Hijack
}

func (s *compiledRuleSetImpl[O]) match(r *Request, clientIP netip.Addr, clientPort uint16) matchResult[O] {
	var env *Env
	var machine *vm.VM
	defer func() {
		if machine != nil {
			s.VMPool.Put(machine)
		}
	}()
	for _, rule := range s.Rules {
		if rule.Program != nil {
			if env == nil {
				env = newEnv(r, clientIP, clientPort)
				machine = s.VMPool.Get().(*vm.VM)
			}
			out, err := machine.Run(rule.Program, env)
			// A runtime error (e.g. a failed conversion in the expression)
			// counts as "no match" for that rule.
			if err != nil || out != true {
				continue
			}
		}
		return matchResult[O]{rule.Outbound, rule.Hijack}
	}
	return matchResult[O]{}
}

// Compile compiles rules into a CompiledRuleSet.
// Names in the outbounds map MUST be in all lower case.
// We want on-demand loading of GeoIP/GeoSite databases, so instead of passing the
// databases directly, we use a GeoLoader interface to load them only when needed
// by at least one rule.
func Compile[O Outbound](rules []Rule, outbounds map[string]O,
	cacheSize int, geoLoader GeoLoader,
) (CompiledRuleSet[O], error) {
	table := newMatcherTable(geoLoader)
	baseOpts := append([]expr.Option{
		expr.Env(&Env{}),
		expr.AsBool(),
		// Time-based rules would make match results non-deterministic,
		// which doesn't work with the match cache.
		expr.DisableBuiltin("now"),
		expr.DisableBuiltin("date"),
	}, exprMatcherOptions()...)

	var fields keyFields
	compiledRules := make([]compiledRule[O], len(rules))
	for i, rule := range rules {
		outbound, ok := outbounds[strings.ToLower(rule.Outbound)]
		if !ok {
			return nil, &CompilationError{rule.Source, fmt.Sprintf("outbound %s not found", rule.Outbound)}
		}
		var program *vm.Program
		match := strings.TrimSpace(rule.Match)
		if match != "" && match != "true" {
			mv := &matcherVisitor{Table: table}
			uv := &usageVisitor{}
			opts := append(baseOpts[:len(baseOpts):len(baseOpts)], expr.Patch(uv), expr.Patch(mv))
			p, err := expr.Compile(match, opts...)
			if mv.Err != "" {
				return nil, &CompilationError{rule.Source, mv.Err}
			}
			if err != nil {
				return nil, &CompilationError{rule.Source, err.Error()}
			}
			program = p
			fields |= uv.fields()
		}
		var hijack net.IP
		if rule.Hijack != "" {
			hijack = net.ParseIP(rule.Hijack)
			if hijack == nil {
				return nil, &CompilationError{rule.Source, fmt.Sprintf("invalid hijack address (must be an IP address): %s", rule.Hijack)}
			}
		}
		compiledRules[i] = compiledRule[O]{outbound, program, hijack}
	}
	cache, err := lru.New[matchCacheKey, matchResult[O]](cacheSize)
	if err != nil {
		return nil, err
	}
	return &compiledRuleSetImpl[O]{
		Rules:  compiledRules,
		Fields: fields,
		Cache:  cache,
		VMPool: sync.Pool{New: func() any { return &vm.VM{} }},
	}, nil
}
