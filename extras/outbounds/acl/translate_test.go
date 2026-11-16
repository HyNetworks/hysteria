package acl

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/apernet/hysteria/extras/v2/outbounds/acl/v2geo"

	"github.com/stretchr/testify/assert"
)

// cachingGeoLoader loads the test databases once.
type cachingGeoLoader struct {
	once    sync.Once
	geoip   map[string]*v2geo.GeoIP
	geosite map[string]*v2geo.GeoSite
	err     error
}

func (l *cachingGeoLoader) load() {
	l.once.Do(func() {
		l.geoip, l.err = v2geo.LoadGeoIP("v2geo/geoip.dat")
		if l.err != nil {
			return
		}
		l.geosite, l.err = v2geo.LoadGeoSite("v2geo/geosite.dat")
	})
}

func (l *cachingGeoLoader) LoadGeoIP() (map[string]*v2geo.GeoIP, error) {
	l.load()
	return l.geoip, l.err
}

func (l *cachingGeoLoader) LoadGeoSite() (map[string]*v2geo.GeoSite, error) {
	l.load()
	return l.geosite, l.err
}

var sharedGeoLoader = &cachingGeoLoader{}

func TestTranslateTextRule(t *testing.T) {
	tests := []struct {
		line       string
		wantMatch  string
		wantHijack string
		wantErr    bool
	}{
		{"reject(all)", "true", "", false},
		{"reject(*)", "true", "", false},
		{"reject(ALL, */*)", "true", "", false},
		{"reject(geoip:cn)", `legacy("geoip:cn")`, "", false},
		{"v6(suffix:google.com, tcp)", `legacy("suffix:google.com") && proto == "tcp"`, "", false},
		{"reject(all, udp/443)", `proto == "udp" && dst.port == 443`, "", false},
		{"x(1.2.3.0/24, */1000-2000)", `legacy("1.2.3.0/24") && dst.port >= 1000 && dst.port <= 2000`, "", false},
		{"x(all, udp/0-100)", `proto == "udp" && dst.port >= 0 && dst.port <= 100`, "", false},
		{"x(all, tcp/0)", `proto == "tcp" && dst.port == 0`, "", false},
		{"x(all, tcp/*)", `proto == "tcp"`, "", false},
		{"default(8.8.8.8, *, 1.1.1.1)", `legacy("8.8.8.8")`, "1.1.1.1", false},
		{`x(战狼*.中国)`, `legacy("战狼*.中国")`, "", false},
		{"x(all, sctp/1)", "", "", true},
		{"x(all, tcp/2-1)", "", "", true},
		{"x(all, tcp/70000)", "", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.line, func(t *testing.T) {
			trs, err := ParseTextRules(tt.line)
			assert.NoError(t, err)
			assert.Len(t, trs, 1)
			rule, err := translateTextRule(trs[0], "")
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.wantMatch, rule.Match)
			assert.Equal(t, tt.wantHijack, rule.Hijack)
			assert.Equal(t, "line 1", rule.Source)
		})
	}
}

func TestTranslateTextErrors(t *testing.T) {
	obs := map[string]int{"direct": 1}

	// Syntax error keeps the legacy message, prefixed with the source
	_, err := TranslateText("direct(all)\nboom()", "rules[2]")
	assert.EqualError(t, err, "rules[2]: invalid syntax at line 2: boom()")

	// Compile errors keep the legacy line number
	for _, tt := range []struct {
		text    string
		wantErr string
	}{
		{"direct(all)\nnope(all)", "error at line 2: outbound nope not found"},
		{"direct(geoip:xx)", "error at line 1: GeoIP country code xx not found"},
		{"direct(geosite:nonexistent)", "error at line 1: GeoSite name nonexistent not found"},
		{"direct(1.2.3.4/99)", "error at line 1: invalid CIDR address: 1.2.3.4/99"},
		{"direct(suffix:)", "error at line 1: empty domain suffix"},
		{"direct(all, *, example.com)", "error at line 1: invalid hijack address (must be an IP address): example.com"},
		{"direct(all, tcp/a)", "error at line 1: invalid protocol/port: tcp/a"},
	} {
		rules, err := TranslateText(tt.text, "")
		if err == nil {
			_, err = Compile[int](rules, obs, 100, sharedGeoLoader)
		}
		assert.EqualError(t, err, tt.wantErr, tt.text)
	}

	// Nested source
	rules, err := TranslateText("direct(all)\n\ndirect(geoip:xx)", "rules[3] (acl.txt)")
	assert.NoError(t, err)
	_, err = Compile[int](rules, obs, 100, sharedGeoLoader)
	assert.EqualError(t, err, "error at rules[3] (acl.txt) line 3: GeoIP country code xx not found")
}

// TestTranslatePortZero checks the one intentional behavior change:
// port ranges starting at 0 now only match the ports in the range.
func TestTranslatePortZero(t *testing.T) {
	trs, err := ParseTextRules("ob1(all, udp/0-100)\nob2(all, tcp/0)")
	assert.NoError(t, err)
	obs := map[string]int{"ob1": 1, "ob2": 2}
	legacy, err := legacyCompile[int](trs, obs, 100, nil)
	assert.NoError(t, err)
	rules, err := translateTextRules(trs, "")
	assert.NoError(t, err)
	compiled, err := Compile[int](rules, obs, 100, nil)
	assert.NoError(t, err)

	match := func(proto Protocol, port uint16) int {
		ob, _ := compiled.Match(&Request{Proto: proto, Host: "example.com", Port: port})
		return ob
	}

	// Legacy: the bug
	ob, _ := legacy.Match(HostInfo{Name: "example.com"}, ProtocolUDP, 5000)
	assert.Equal(t, 1, ob)
	ob, _ = legacy.Match(HostInfo{Name: "example.com"}, ProtocolTCP, 5000)
	assert.Equal(t, 2, ob)

	// Translated: fixed
	assert.Equal(t, 1, match(ProtocolUDP, 0))
	assert.Equal(t, 1, match(ProtocolUDP, 53))
	assert.Equal(t, 1, match(ProtocolUDP, 100))
	assert.Equal(t, 0, match(ProtocolUDP, 101))
	assert.Equal(t, 0, match(ProtocolUDP, 5000))
	assert.Equal(t, 2, match(ProtocolTCP, 0))
	assert.Equal(t, 0, match(ProtocolTCP, 5000))
}

// TestTranslateQuoting checks that addresses with characters that need
// escaping survive the round trip through an expr string literal.
func TestTranslateQuoting(t *testing.T) {
	for _, addr := range []string{`a"b`, `a\b`, `a'b`, "a\tb", `a\"b\\`, "战狼.中国", "x`y"} {
		rule, err := translateTextRule(TextRule{Outbound: "ob", Address: addr, LineNum: 1}, "")
		assert.NoError(t, err)
		compiled, err := Compile[int]([]Rule{rule}, map[string]int{"ob": 1}, 100, nil)
		if !assert.NoError(t, err, addr) {
			continue
		}
		ob, _ := compiled.Match(&Request{Proto: ProtocolTCP, Host: addr, Port: 1})
		assert.Equal(t, 1, ob, "%s -> %s", addr, rule.Match)
		ob, _ = compiled.Match(&Request{Proto: ProtocolTCP, Host: addr + "x", Port: 1})
		assert.Equal(t, 0, ob, "%s -> %s", addr, rule.Match)
	}
}

// Differential test: every legacy rule line below is compiled with both the
// legacy compiler and the translated expr engine, then matched against a grid
// of requests. Results must be identical, except for port ranges starting at 0.

var diffRuleLines = []string{
	"1.2.3.4",
	"1.2.3.4, tcp",
	"1.2.3.4, udp/53",
	"8.8.8.0/24, *, 1.1.1.1",
	"2606:4700::6810:85e5",
	"2606:4700::/44, */8888",
	"::ffff:1.2.3.4",
	"*.v2ex.com, udp",
	"v2ex.com",
	"crap.v2ex.com, tcp/80, 2.2.2.2",
	"*.google.*",
	"1.2.3.*",
	"suffix:microsoft.com",
	"suffix:Microsoft.com.",
	"Example.COM.",
	"战狼*.中国",
	"xn--4gq62f52gdss.xn--fiqs8s",
	"geoip:JP",
	"geoip:private",
	"geoip:cn, udp",
	"geosite:4chan",
	"geosite:google @cn",
	"geosite:google",
	"all, tcp/6881-6889",
	"all, */443",
	"all, udp/1000-1000",
	"all, udp/0-100",
	"all, tcp/0",
	"*",
	"all",
}

type diffRequest struct {
	host  HostInfo
	proto Protocol
	port  uint16
}

func diffRequests() []diffRequest {
	hosts := []HostInfo{
		{},
		{Name: "example.com"},
		{Name: "EXAMPLE.com."},
		{Name: "v2ex.com"},
		{Name: "www.v2ex.com"},
		{Name: "crap.v2ex.com", IPv4: net.ParseIP("104.20.9.1")},
		{Name: "www.google.co.jp"},
		{Name: "google.com", IPv4: net.ParseIP("142.250.1.1"), IPv6: net.ParseIP("2607:f8b0::1")},
		{Name: "mail.google.cn"},
		{Name: "microsoft.com"},
		{Name: "login.microsoft.com"},
		{Name: "notmicrosoft.com"},
		{Name: "战狼1.中国"},
		{Name: "xn--2-xi7at22i.xn--fiqs8s"}, // punycode of 战狼2.中国
		{Name: "xn--4gq62f52gdss.xn--fiqs8s"},
		{Name: "boards.4chan.org"},
		{Name: "1.2.3.4", IPv4: net.ParseIP("1.2.3.4")},
		{IPv4: net.ParseIP("1.2.3.4")},
		{IPv4: net.ParseIP("1.2.3.4").To16()},
		{IPv4: net.ParseIP("8.8.8.8")},
		{IPv4: net.ParseIP("10.0.0.1")},
		{IPv4: net.ParseIP("192.168.1.1")},
		{IPv4: net.ParseIP("210.140.92.183")},  // JP
		{IPv4: net.ParseIP("114.114.114.114")}, // CN
		{IPv6: net.ParseIP("2606:4700::6810:85e5")},
		{IPv6: net.ParseIP("2606:4700:1::1")},
		{Name: "both.example", IPv4: net.ParseIP("8.8.8.1"), IPv6: net.ParseIP("2606:4700::1")},
	}
	var reqs []diffRequest
	for _, h := range hosts {
		for _, proto := range []Protocol{ProtocolTCP, ProtocolUDP} {
			for _, port := range []uint16{0, 1, 53, 80, 100, 443, 1000, 6881, 6885, 6889, 6890, 8888, 65535} {
				reqs = append(reqs, diffRequest{h, proto, port})
			}
		}
	}
	return reqs
}

func hasPortZeroRange(protoPortField string) bool {
	pp, ok := parseProtoPort(strings.TrimSpace(protoPortField))
	return ok && pp.HasPort && pp.StartPort == 0
}

func TestDifferentialLegacy(t *testing.T) {
	reqs := diffRequests()
	obs := map[string]int{"ob": 1}

	// Each line on its own
	for _, line := range diffRuleLines {
		text := "ob(" + line + ")"
		trs, err := ParseTextRules(text)
		if !assert.NoError(t, err, text) {
			continue
		}
		if hasPortZeroRange(trs[0].ProtoPort) {
			continue // Covered by TestTranslatePortZero
		}
		diffCompare(t, text, trs, obs, reqs)
	}

	// All lines together, each with its own outbound, to check ordering
	var sb strings.Builder
	obsAll := map[string]int{}
	for i, line := range diffRuleLines {
		trs, _ := ParseTextRules("x(" + line + ")")
		if hasPortZeroRange(trs[0].ProtoPort) {
			continue
		}
		name := fmt.Sprintf("ob%d", i)
		obsAll[name] = i + 1
		sb.WriteString(name + "(" + line + ")\n")
	}
	trs, err := ParseTextRules(sb.String())
	assert.NoError(t, err)
	diffCompare(t, "all lines", trs, obsAll, reqs)

	// Sanity check that the grid exercises many different rules
	legacy, err := legacyCompile[int](trs, obsAll, 1024, sharedGeoLoader)
	assert.NoError(t, err)
	seen := map[int]bool{}
	for _, r := range reqs {
		ob, _ := legacy.Match(r.host, r.proto, r.port)
		seen[ob] = true
	}
	assert.GreaterOrEqual(t, len(seen), 15, "the request grid only hit %d distinct rules", len(seen))
}

func diffCompare(t *testing.T, name string, trs []TextRule, obs map[string]int, reqs []diffRequest) {
	t.Helper()
	legacy, err := legacyCompile[int](trs, obs, 1024, sharedGeoLoader)
	if !assert.NoError(t, err, name) {
		return
	}
	rules, err := translateTextRules(trs, "")
	if !assert.NoError(t, err, name) {
		return
	}
	compiled, err := Compile[int](rules, obs, 1024, sharedGeoLoader)
	if !assert.NoError(t, err, name) {
		return
	}
	for _, r := range reqs {
		wantOb, wantIP := legacy.Match(r.host, r.proto, r.port)
		gotOb, gotIP := compiled.Match(&Request{
			Proto: r.proto,
			Host:  r.host.Name,
			Port:  r.port,
			IPv4:  r.host.IPv4,
			IPv6:  r.host.IPv6,
		})
		if wantOb != gotOb || !wantIP.Equal(gotIP) {
			t.Errorf("%s: %s %s/%d: legacy (%d, %s), expr (%d, %s)",
				name, r.host, r.proto, r.port, wantOb, wantIP, gotOb, gotIP)
		}
	}
}

// FuzzTranslate checks that translation never panics, that it accepts and
// rejects the same rules as the legacy compiler, and that the results match.
func FuzzTranslate(f *testing.F) {
	for _, line := range diffRuleLines {
		f.Add("ob(" + line + ")")
	}
	f.Add("ob(a\"b)")
	f.Add("ob(all, tcp/1-2, 1.1.1.1)")
	f.Add("ob(geoip:)")
	f.Add("ob(geosite:@cn)")
	reqs := diffRequests()
	obs := map[string]int{"ob": 1}
	f.Fuzz(func(t *testing.T, text string) {
		trs, err := ParseTextRules(text)
		if err != nil || len(trs) == 0 {
			return
		}
		_, legacyErr := legacyCompile[int](trs, obs, 1024, sharedGeoLoader)
		rules, err := translateTextRules(trs, "")
		if err == nil {
			_, err = Compile[int](rules, obs, 1024, sharedGeoLoader)
		}
		if (legacyErr == nil) != (err == nil) {
			t.Fatalf("%q: legacy error %v, expr error %v", text, legacyErr, err)
		}
		if err != nil {
			return
		}
		for _, tr := range trs {
			if hasPortZeroRange(tr.ProtoPort) {
				return
			}
		}
		diffCompare(t, text, trs, obs, reqs)
	})
}
