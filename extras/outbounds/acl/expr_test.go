package acl

import (
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExprRules(t *testing.T) {
	obs := map[string]int{
		"reject":   1,
		"alice":    2,
		"team":     3,
		"jp_users": 4,
		"office":   5,
		"hijacked": 6,
		"dash-ok":  7,
		"direct":   8,
	}
	rules := []Rule{
		{Outbound: "reject", Match: `geosite("4chan") || suffix("ads.example.com")`},
		{Outbound: "alice", Match: `auth.id == "alice"`},
		{Outbound: "team", Match: `auth.id in ["bob", "carol"] && proto == "udp"`},
		{Outbound: "jp_users", Match: `geoip("jp", client.ip)`},
		{Outbound: "office", Match: `cidr("10.0.0.0/8", client.ip) && dst.port in 8000..8999`},
		{Outbound: "hijacked", Match: `dst.port == 53 && cidr("8.8.8.8")`, Hijack: "1.1.1.1"},
		{Outbound: "Dash-OK", Match: `domain("*.dash.test") || dst.host endsWith ".dash2.test"`},
		{Outbound: "direct", Match: `geoip("private") && client.port > 0`},
	}
	rs, err := Compile[int](rules, obs, 100, sharedGeoLoader)
	assert.NoError(t, err)

	client := func(ip string, port int) net.Addr {
		return &net.UDPAddr{IP: net.ParseIP(ip), Port: port}
	}
	tests := []struct {
		name       string
		req        Request
		wantOb     int
		wantHijack net.IP
	}{
		{"geosite sugar", Request{Proto: ProtocolTCP, Host: "boards.4chan.org", Port: 443, AuthID: "alice"}, 1, nil},
		{"suffix sugar", Request{Proto: ProtocolTCP, Host: "x.ads.example.com.", Port: 443, AuthID: "alice"}, 1, nil},
		{"auth id", Request{Proto: ProtocolTCP, Host: "example.com", Port: 443, AuthID: "alice"}, 2, nil},
		{"auth id list udp", Request{Proto: ProtocolUDP, Host: "example.com", Port: 443, AuthID: "bob"}, 3, nil},
		{"auth id list tcp", Request{Proto: ProtocolTCP, Host: "example.com", Port: 443, AuthID: "bob"}, 0, nil},
		{"client geoip", Request{Proto: ProtocolTCP, Host: "example.com", Port: 443, ClientAddr: client("210.140.92.183", 1234)}, 4, nil},
		{"client cidr", Request{Proto: ProtocolTCP, Host: "example.com", Port: 8080, ClientAddr: client("10.1.2.3", 1234)}, 5, nil},
		{"client cidr wrong port", Request{Proto: ProtocolTCP, Host: "example.com", Port: 9000, ClientAddr: client("10.1.2.3", 1234)}, 0, nil},
		{"client v4-mapped", Request{Proto: ProtocolTCP, Host: "example.com", Port: 8080, ClientAddr: client("::ffff:10.1.2.3", 1234)}, 5, nil},
		{"hijack", Request{Proto: ProtocolUDP, Host: "dns.google", Port: 53, IPv4: net.ParseIP("8.8.8.8")}, 6, net.ParseIP("1.1.1.1")},
		{"domain wildcard", Request{Proto: ProtocolTCP, Host: "a.dash.test", Port: 1}, 7, nil},
		{"builtin endsWith", Request{Proto: ProtocolTCP, Host: "a.dash2.test", Port: 1}, 7, nil},
		{"dst private ip", Request{Proto: ProtocolTCP, Host: "192.168.1.1", IPv4: net.ParseIP("192.168.1.1"), Port: 1, ClientAddr: client("203.0.113.1", 1)}, 8, nil},
		{"no client addr", Request{Proto: ProtocolTCP, Host: "192.168.1.1", IPv4: net.ParseIP("192.168.1.1"), Port: 1}, 0, nil},
		{"no match", Request{Proto: ProtocolTCP, Host: "example.com", Port: 443}, 0, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Run twice to also go through the cache
			for i := 0; i < 2; i++ {
				ob, hijack := rs.Match(&tt.req)
				assert.Equal(t, tt.wantOb, ob)
				assert.Equal(t, tt.wantHijack, hijack)
			}
		})
	}
}

func TestExprMatchOmitted(t *testing.T) {
	rs, err := Compile[int]([]Rule{
		{Outbound: "a", Match: `dst.port == 1`},
		{Outbound: "b"},
	}, map[string]int{"a": 1, "b": 2}, 100, nil)
	assert.NoError(t, err)
	ob, _ := rs.Match(&Request{Proto: ProtocolTCP, Port: 1})
	assert.Equal(t, 1, ob)
	ob, _ = rs.Match(&Request{Proto: ProtocolTCP, Port: 2})
	assert.Equal(t, 2, ob)
}

func TestExprCompileErrors(t *testing.T) {
	obs := map[string]int{"ob": 1}
	tests := []struct {
		name    string
		rule    Rule
		wantErr string // substring
	}{
		{"unknown field", Rule{Outbound: "ob", Match: `auth.idd == "x"`}, "has no field idd"},
		{"unknown variable", Rule{Outbound: "ob", Match: `user == "x"`}, "unknown name user"},
		{"not bool", Rule{Outbound: "ob", Match: `"x"`}, "expected bool"},
		{"pattern not literal", Rule{Outbound: "ob", Match: `suffix(auth.id)`}, "must be a string literal"},
		{"no args", Rule{Outbound: "ob", Match: `geoip()`}, "takes 1 or 2 arguments"},
		{"too many args", Rule{Outbound: "ob", Match: `cidr("1.1.1.1", "a", "b")`}, "takes 1 or 2 arguments"},
		{"bad second arg", Rule{Outbound: "ob", Match: `cidr("1.1.1.1", 1)`}, "cidr"},
		{"bad cidr", Rule{Outbound: "ob", Match: `cidr("nope")`}, "invalid CIDR or IP address: nope"},
		{"unknown geoip", Rule{Outbound: "ob", Match: `geoip("xx")`}, "GeoIP country code xx not found"},
		{"unknown geosite", Rule{Outbound: "ob", Match: `geosite("nonexistent")`}, "GeoSite name nonexistent not found"},
		{"empty suffix", Rule{Outbound: "ob", Match: `suffix("")`}, "empty domain suffix"},
		{"now disabled", Rule{Outbound: "ob", Match: `now().Hour() > 1`}, "now"},
		{"unknown outbound", Rule{Outbound: "nope", Match: `true`}, "outbound nope not found"},
		{"bad hijack", Rule{Outbound: "ob", Hijack: "example.com"}, "invalid hijack address"},
		{"syntax", Rule{Outbound: "ob", Match: `auth.id ==`}, "unexpected token"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.rule.Source = "rules[7]"
			_, err := Compile[int]([]Rule{tt.rule}, obs, 100, sharedGeoLoader)
			if assert.Error(t, err) {
				assert.Contains(t, err.Error(), "error at rules[7]: ")
				assert.Contains(t, err.Error(), tt.wantErr)
			}
		})
	}
}

func TestExprNoGeoLoad(t *testing.T) {
	// GeoIP/GeoSite databases must only be loaded when a rule uses them
	_, err := Compile[int]([]Rule{
		{Outbound: "ob", Match: `suffix("example.com") || cidr("10.0.0.0/8", client.ip)`},
		{Outbound: "ob", Match: `legacy("1.2.3.4")`},
	}, map[string]int{"ob": 1}, 100, nil)
	assert.NoError(t, err)
}

func TestExprCacheKeyFields(t *testing.T) {
	tests := []struct {
		match string
		want  keyFields
	}{
		{`legacy("geoip:cn") && proto == "udp" && dst.port == 443`, 0},
		{`suffix("a.com") && dst.ipv4 == "1.1.1.1"`, 0},
		{`auth.id == "alice"`, keyAuthID},
		{`cidr("10.0.0.0/8", client.ip)`, keyClientIP},
		{`client.port == 1`, keyClientPort},
		{`client?.ip == "1.1.1.1"`, keyClientIP},
		{`let c = client; c.ip == "1.1.1.1"`, keyClientIP | keyClientPort},
		{`$env.auth.id == "x"`, keyAll},
	}
	for _, tt := range tests {
		t.Run(tt.match, func(t *testing.T) {
			rs, err := Compile[int]([]Rule{{Outbound: "ob", Match: tt.match}}, map[string]int{"ob": 1}, 100, sharedGeoLoader)
			if assert.NoError(t, err) {
				assert.Equal(t, tt.want, rs.(*compiledRuleSetImpl[int]).Fields)
			}
		})
	}
}

// TestExprCacheIsolation makes sure the cache never returns a result computed
// for a different auth ID or client address.
func TestExprCacheIsolation(t *testing.T) {
	rs, err := Compile[int]([]Rule{
		{Outbound: "a", Match: `auth.id == "alice"`},
		{Outbound: "b", Match: `client.ip == "192.0.2.1"`},
		{Outbound: "c", Match: `client.port == 7`},
	}, map[string]int{"a": 1, "b": 2, "c": 3}, 100, nil)
	assert.NoError(t, err)
	req := func(auth, ip string, port int) *Request {
		return &Request{
			Proto: ProtocolTCP, Host: "example.com", Port: 443, AuthID: auth,
			ClientAddr: &net.UDPAddr{IP: net.ParseIP(ip), Port: port},
		}
	}
	for i := 0; i < 2; i++ {
		ob, _ := rs.Match(req("alice", "198.51.100.1", 1))
		assert.Equal(t, 1, ob)
		ob, _ = rs.Match(req("bob", "198.51.100.1", 1))
		assert.Equal(t, 0, ob)
		ob, _ = rs.Match(req("bob", "192.0.2.1", 1))
		assert.Equal(t, 2, ob)
		ob, _ = rs.Match(req("bob", "198.51.100.1", 7))
		assert.Equal(t, 3, ob)
	}
}

func TestExprRuntimeErrorIsNoMatch(t *testing.T) {
	rs, err := Compile[int]([]Rule{
		{Outbound: "a", Match: `int(auth.id) > 0`},
		{Outbound: "b"},
	}, map[string]int{"a": 1, "b": 2}, 100, nil)
	assert.NoError(t, err)
	ob, _ := rs.Match(&Request{Proto: ProtocolTCP, AuthID: "5"})
	assert.Equal(t, 1, ob)
	ob, _ = rs.Match(&Request{Proto: ProtocolTCP, AuthID: "not a number"})
	assert.Equal(t, 2, ob)
}

func BenchmarkExprMatchMiss(b *testing.B) {
	rs, err := Compile[int]([]Rule{
		{Outbound: "a", Match: `auth.id == "alice" && suffix("example.com") && proto == "tcp"`},
	}, map[string]int{"a": 1}, 1, nil)
	if err != nil {
		b.Fatal(err)
	}
	impl := rs.(*compiledRuleSetImpl[int])
	req := &Request{Proto: ProtocolTCP, Host: "www.example.com", Port: 443, AuthID: "alice"}
	b.ReportAllocs()
	for b.Loop() {
		impl.match(req, netip.Addr{}, 0)
	}
}

// TestExprMatcherForms checks that the one-argument form, the explicit dst
// argument, and an explicit string all match the same way.
func TestExprMatcherForms(t *testing.T) {
	req := &Request{Proto: ProtocolTCP, Host: "www.example.com", Port: 443, IPv4: net.ParseIP("8.8.8.8")}
	for _, match := range []string{
		`suffix("example.com")`,
		`suffix("example.com", dst)`,
		`suffix("example.com", dst.host)`,
		`cidr("8.8.8.0/24")`,
		`cidr("8.8.8.0/24", dst)`,
		`cidr("8.8.8.0/24", dst.ipv4)`,
		`let d = dst; cidr("8.8.8.0/24", d) && d.port == 443`,
	} {
		rs, err := Compile[int]([]Rule{{Outbound: "ob", Match: match}}, map[string]int{"ob": 1}, 100, nil)
		if !assert.NoError(t, err, match) {
			continue
		}
		ob, _ := rs.Match(req)
		assert.Equal(t, 1, ob, match)
		ob, _ = rs.Match(&Request{Proto: ProtocolTCP, Host: "other.test", Port: 443, IPv4: net.ParseIP("1.1.1.1")})
		assert.Equal(t, 0, ob, match)
	}
}
