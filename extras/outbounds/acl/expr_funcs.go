package acl

import (
	"fmt"
	"net"
	"strings"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/ast"
)

// Matcher functions available in rule expressions.
//
// Every function takes a pattern as its first argument, which must be a string
// literal so that the matcher can be built once when the rules are compiled.
//
//   - With one argument, e.g. geoip("cn"), the function matches the destination
//     the same way legacy rules do: the host name, or the resolved IPv4, or the
//     resolved IPv6 address. This form is equivalent to geoip("cn", dst).
//   - With two arguments, e.g. geoip("cn", client.ip), the function matches an
//     explicit string value (an IP literal or a host name).
type matcherFunc struct {
	Name    string
	Compile func(pattern string, geoLoader GeoLoader) (hostMatcher, string)
}

var matcherFuncs = []matcherFunc{
	{"domain", func(pattern string, _ GeoLoader) (hostMatcher, string) {
		pattern = normalizeHost(pattern)
		if pattern == "" {
			return nil, "empty domain"
		}
		return compileDomainMatcher(pattern), ""
	}},
	{"suffix", func(pattern string, _ GeoLoader) (hostMatcher, string) {
		return compileSuffixMatcher(normalizeHost(pattern))
	}},
	{"cidr", func(pattern string, _ GeoLoader) (hostMatcher, string) {
		pattern = strings.TrimSpace(pattern)
		if strings.Contains(pattern, "/") {
			_, ipnet, err := net.ParseCIDR(pattern)
			if err != nil {
				return nil, fmt.Sprintf("invalid CIDR address: %s", pattern)
			}
			return &cidrMatcher{ipnet}, ""
		}
		if ip := net.ParseIP(pattern); ip != nil {
			return &ipMatcher{ip}, ""
		}
		return nil, fmt.Sprintf("invalid CIDR or IP address: %s", pattern)
	}},
	{"geoip", func(pattern string, geoLoader GeoLoader) (hostMatcher, string) {
		return compileGeoIPMatcher(normalizeHost(strings.TrimSpace(pattern)), geoLoader)
	}},
	{"geosite", func(pattern string, geoLoader GeoLoader) (hostMatcher, string) {
		return compileGeoSiteMatcher(normalizeHost(strings.TrimSpace(pattern)), geoLoader)
	}},
	// legacy accepts any address from the legacy syntax (e.g. "geoip:cn",
	// "suffix:example.com", "1.2.3.0/24", "*.example.com") and classifies it
	// exactly like the legacy compiler did. Translated legacy rules use it.
	{"legacy", compileHostMatcher},
}

func findMatcherFunc(name string) *matcherFunc {
	for i := range matcherFuncs {
		if matcherFuncs[i].Name == name {
			return &matcherFuncs[i]
		}
	}
	return nil
}

type matcherKey struct {
	Func    string
	Pattern string
}

// compiledMatcher is a matcher built when the rules are compiled.
// The matcher visitor replaces the pattern literal of each matcher function
// call with its compiledMatcher, so nothing is looked up at match time.
type compiledMatcher struct {
	Matcher hostMatcher
}

// matcherTable holds the matchers built while compiling a rule set,
// so that rules using the same pattern share one matcher.
// It is only used during compilation.
type matcherTable struct {
	GeoLoader GeoLoader
	Matchers  map[matcherKey]*compiledMatcher
}

func newMatcherTable(geoLoader GeoLoader) *matcherTable {
	return &matcherTable{
		GeoLoader: geoLoader,
		Matchers:  make(map[matcherKey]*compiledMatcher),
	}
}

// exprMatcherOptions returns the expr options that register the matcher functions.
func exprMatcherOptions() []expr.Option {
	opts := make([]expr.Option, 0, len(matcherFuncs))
	for _, mf := range matcherFuncs {
		name := mf.Name
		fn := func(params ...any) (any, error) {
			m := params[0].(*compiledMatcher)
			switch v := params[1].(type) {
			case *Env:
				return m.Matcher.Match(v.Dst.hostInfo), nil
			case Dst:
				return m.Matcher.Match(v.hostInfo), nil
			case string:
				return m.Matcher.Match(hostInfoFromString(v)), nil
			default:
				return false, fmt.Errorf("%s: unsupported argument type %T", name, v)
			}
		}
		types := []any{
			new(func(*compiledMatcher, *Env) bool),
			new(func(*compiledMatcher, Dst) bool),
			new(func(*compiledMatcher, string) bool),
		}
		opts = append(opts, expr.Function(name, fn, types...))
	}
	return opts
}

// matcherVisitor is an expr patcher that:
//   - checks that the pattern of every matcher function call is a string literal,
//   - builds the matcher for it (so that errors like unknown GeoIP codes are
//     reported when the rules are compiled) and replaces the literal with it, and
//   - rewrites the one-argument form f("x") into f("x", $env), which is
//     equivalent to f("x", dst).
type matcherVisitor struct {
	Table *matcherTable
	Err   string // First error found, if any
}

func (v *matcherVisitor) Visit(node *ast.Node) {
	if v.Err != "" {
		return
	}
	call, ok := (*node).(*ast.CallNode)
	if !ok {
		return
	}
	ident, ok := call.Callee.(*ast.IdentifierNode)
	if !ok {
		return
	}
	mf := findMatcherFunc(ident.Value)
	if mf == nil {
		return
	}
	if len(call.Arguments) < 1 || len(call.Arguments) > 2 {
		v.Err = fmt.Sprintf("%s() takes 1 or 2 arguments, got %d", mf.Name, len(call.Arguments))
		return
	}
	lit, ok := call.Arguments[0].(*ast.StringNode)
	if !ok {
		v.Err = fmt.Sprintf("%s(): the pattern (first argument) must be a string literal", mf.Name)
		return
	}
	key := matcherKey{mf.Name, lit.Value}
	cm, ok := v.Table.Matchers[key]
	if !ok {
		m, errStr := mf.Compile(lit.Value, v.Table.GeoLoader)
		if errStr != "" {
			v.Err = errStr
			return
		}
		cm = &compiledMatcher{m}
		v.Table.Matchers[key] = cm
	}
	constant := &ast.ConstantNode{Value: cm}
	constant.SetLocation(lit.Location())
	call.Arguments[0] = constant
	if len(call.Arguments) == 1 {
		// Pass the env pointer rather than dst: dst is a struct value, and
		// passing it would copy it to the heap on every call.
		env := &ast.IdentifierNode{Value: "$env"}
		env.SetLocation(call.Location())
		call.Arguments = append(call.Arguments, env)
	}
}

// Env fields that are not always part of the match cache key.
type keyFields uint8

const (
	keyAuthID keyFields = 1 << iota
	keyClientIP
	keyClientPort

	keyAll = keyAuthID | keyClientIP | keyClientPort
)

// usageVisitor is an expr patcher that records which optional env fields an
// expression references, so that the match cache key only includes those.
// Proto and all destination fields are always part of the key.
// It must run before matcherVisitor, which adds $env arguments.
type usageVisitor struct {
	Fields keyFields

	clientIdents  int // Number of "client" identifiers
	clientMembers int // Number of "client.ip" / "client.port" member accesses
}

func (v *usageVisitor) Visit(node *ast.Node) {
	switch n := (*node).(type) {
	case *ast.IdentifierNode:
		switch n.Value {
		case "$env":
			v.Fields |= keyAll
		case "auth":
			v.Fields |= keyAuthID
		case "client":
			v.clientIdents++
		}
	case *ast.MemberNode:
		ident, ok := n.Node.(*ast.IdentifierNode)
		if !ok || ident.Value != "client" {
			return
		}
		prop, ok := n.Property.(*ast.StringNode)
		if !ok {
			return
		}
		switch prop.Value {
		case "ip":
			v.Fields |= keyClientIP
			v.clientMembers++
		case "port":
			v.Fields |= keyClientPort
			v.clientMembers++
		}
	}
}

// fields returns the referenced fields once the whole expression has been visited.
func (v *usageVisitor) fields() keyFields {
	f := v.Fields
	if v.clientIdents > v.clientMembers {
		// "client" is used in some way other than client.ip / client.port,
		// e.g. assigned to a variable. Be conservative.
		f |= keyClientIP | keyClientPort
	}
	return f
}
