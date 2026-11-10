package cmd

import (
	"bytes"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"

	"github.com/apernet/hysteria/extras/v2/outbounds/acl"
)

func writeTempFile(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	assert.NoError(t, os.WriteFile(p, []byte(content), 0o644))
	return p
}

// matchRules compiles rules and returns a function that matches a request
// to the name of the outbound.
func matchRules(t *testing.T, rules []acl.Rule, names ...string) func(req *acl.Request) string {
	t.Helper()
	obs := map[string]string{}
	for _, n := range names {
		obs[n] = n
	}
	rs, err := acl.Compile[string](rules, obs, 100, nil)
	assert.NoError(t, err)
	return func(req *acl.Request) string {
		ob, _ := rs.Match(req)
		return ob
	}
}

func TestACLRulesNone(t *testing.T) {
	rules, field, err := (&serverConfigACL{}).aclRules()
	assert.NoError(t, err)
	assert.Nil(t, rules)
	assert.Equal(t, "", field)
}

func TestACLRulesMutuallyExclusive(t *testing.T) {
	entries := []serverConfigACLRule{{Outbound: "direct"}}
	for _, c := range []serverConfigACL{
		{File: "a.txt", Inline: []string{"direct(all)"}},
		{File: "a.txt", Rules: entries},
		{Inline: []string{"direct(all)"}, RulesFile: "rules.yaml"},
		{Rules: entries, RulesFile: "rules.yaml"},
	} {
		_, field, err := c.aclRules()
		assert.Error(t, err)
		assert.Equal(t, "acl", field)
	}
}

func TestACLRulesLegacyKeys(t *testing.T) {
	file := writeTempFile(t, "acl.txt", "# comment\nreject(blocked.example)\ndirect(all)\n")
	rules, field, err := (&serverConfigACL{File: file}).aclRules()
	assert.NoError(t, err)
	assert.Equal(t, "acl.file", field)
	assert.Equal(t, []acl.Rule{
		{Outbound: "reject", Match: `legacy("blocked.example")`, Source: "line 2"},
		{Outbound: "direct", Match: "true", Source: "line 3"},
	}, rules)

	rules, field, err = (&serverConfigACL{Inline: []string{"reject(blocked.example)", "direct(all, udp/0-100)"}}).aclRules()
	assert.NoError(t, err)
	assert.Equal(t, "acl.inline", field)
	assert.Equal(t, []acl.Rule{
		{Outbound: "reject", Match: `legacy("blocked.example")`, Source: "line 1"},
		{Outbound: "direct", Match: `proto == "udp" && dst.port >= 0 && dst.port <= 100`, Source: "line 2"},
	}, rules)

	_, field, err = (&serverConfigACL{File: filepath.Join(t.TempDir(), "missing.txt")}).aclRules()
	assert.Error(t, err)
	assert.Equal(t, "acl.file", field)

	_, field, err = (&serverConfigACL{Inline: []string{"direct(all)", "boom()"}}).aclRules()
	assert.EqualError(t, err, "invalid syntax at line 2: boom()")
	assert.Equal(t, "acl.inline", field)
}

func TestACLRulesMixed(t *testing.T) {
	legacyFile := writeTempFile(t, "legacy.txt", "reject(geoip-free.example)\n\nreject(all, udp/443)\n")
	c := &serverConfigACL{Rules: []serverConfigACLRule{
		{Outbound: "alice_exit", Match: `auth.id == "alice"`},
		{Legacy: "reject(blocked.example)"},
		{Legacy: "# a block\nreject(suffix:ads.example)\nreject(all, tcp/25)\n"},
		{LegacyFile: legacyFile},
		{Outbound: "default", Match: `dst.port == 53`, Hijack: "1.1.1.1"},
		{Outbound: "direct"},
	}}
	rules, field, err := c.aclRules()
	assert.NoError(t, err)
	assert.Equal(t, "acl.rules", field)
	assert.Equal(t, []acl.Rule{
		{Outbound: "alice_exit", Match: `auth.id == "alice"`, Source: "rules[0]"},
		{Outbound: "reject", Match: `legacy("blocked.example")`, Source: "rules[1] line 1"},
		{Outbound: "reject", Match: `legacy("suffix:ads.example")`, Source: "rules[2] line 2"},
		{Outbound: "reject", Match: `proto == "tcp" && dst.port == 25`, Source: "rules[2] line 3"},
		{Outbound: "reject", Match: `legacy("geoip-free.example")`, Source: "rules[3] (" + legacyFile + ") line 1"},
		{Outbound: "reject", Match: `proto == "udp" && dst.port == 443`, Source: "rules[3] (" + legacyFile + ") line 3"},
		{Outbound: "default", Match: `dst.port == 53`, Hijack: "1.1.1.1", Source: "rules[4]"},
		{Outbound: "direct", Source: "rules[5]"},
	}, rules)

	// Order is preserved across native and legacy entries
	match := matchRules(t, rules, "alice_exit", "reject", "default", "direct")
	assert.Equal(t, "alice_exit", match(&acl.Request{Proto: acl.ProtocolTCP, Host: "blocked.example", Port: 443, AuthID: "alice"}))
	assert.Equal(t, "reject", match(&acl.Request{Proto: acl.ProtocolTCP, Host: "blocked.example", Port: 443, AuthID: "bob"}))
	assert.Equal(t, "reject", match(&acl.Request{Proto: acl.ProtocolTCP, Host: "x.ads.example", Port: 443}))
	assert.Equal(t, "reject", match(&acl.Request{Proto: acl.ProtocolUDP, Host: "example.com", Port: 443}))
	assert.Equal(t, "default", match(&acl.Request{Proto: acl.ProtocolUDP, Host: "example.com", Port: 53}))
	assert.Equal(t, "direct", match(&acl.Request{Proto: acl.ProtocolTCP, Host: "example.com", Port: 443}))
}

func TestACLRulesEntryErrors(t *testing.T) {
	legacyFile := writeTempFile(t, "legacy.txt", "direct(all)\nreject(geoip:xx)\n")
	tests := []struct {
		name    string
		entries []serverConfigACLRule
		wantErr string
	}{
		{"empty entry", []serverConfigACLRule{{}}, "rules[0]: exactly one of outbound, legacy and legacyFile must be set"},
		{"rule and legacy", []serverConfigACLRule{{Outbound: "a"}, {Outbound: "a", Legacy: "direct(all)"}}, "rules[1]: exactly one of"},
		{"legacy and file", []serverConfigACLRule{{Legacy: "direct(all)", LegacyFile: "x.txt"}}, "rules[0]: exactly one of"},
		{"match without outbound", []serverConfigACLRule{{Match: "true"}}, "rules[0]: outbound is required"},
		{"legacy syntax", []serverConfigACLRule{{Outbound: "a"}, {Legacy: "direct(all)\nboom()"}}, "rules[1]: invalid syntax at line 2: boom()"},
		{"missing legacy file", []serverConfigACLRule{{LegacyFile: filepath.Join(t.TempDir(), "missing.txt")}}, "rules[0]: open "},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, field, err := (&serverConfigACL{Rules: tt.entries}).aclRules()
			assert.Equal(t, "acl.rules", field)
			if assert.Error(t, err) {
				assert.Contains(t, err.Error(), tt.wantErr)
			}
		})
	}

	// Compile errors in a legacy file name the entry, the file and the line
	rules, _, err := (&serverConfigACL{Rules: []serverConfigACLRule{{LegacyFile: legacyFile}}}).aclRules()
	assert.NoError(t, err)
	_, err = acl.Compile[string](rules, map[string]string{"direct": "direct", "reject": "reject"}, 100, nil)
	assert.EqualError(t, err, "error at rules[0] ("+legacyFile+") line 2: GeoIP database not available")
}

func TestACLRulesFile(t *testing.T) {
	file := writeTempFile(t, "rules.yaml", `
- outbound: alice_exit
  match: auth.id == "alice" || cidr("10.0.0.0/8", client.ip)
- legacy: reject(blocked.example)
- outbound: direct
`)
	rules, field, err := (&serverConfigACL{RulesFile: file}).aclRules()
	assert.NoError(t, err)
	assert.Equal(t, "acl.rulesFile", field)
	assert.Equal(t, []acl.Rule{
		{Outbound: "alice_exit", Match: `auth.id == "alice" || cidr("10.0.0.0/8", client.ip)`, Source: "rules[0]"},
		{Outbound: "reject", Match: `legacy("blocked.example")`, Source: "rules[1] line 1"},
		{Outbound: "direct", Source: "rules[2]"},
	}, rules)

	match := matchRules(t, rules, "alice_exit", "reject", "direct")
	assert.Equal(t, "alice_exit", match(&acl.Request{
		Proto: acl.ProtocolTCP, Host: "blocked.example", Port: 443,
		ClientAddr: &net.UDPAddr{IP: net.ParseIP("10.1.1.1"), Port: 1234},
	}))
	assert.Equal(t, "reject", match(&acl.Request{
		Proto: acl.ProtocolTCP, Host: "blocked.example", Port: 443,
		ClientAddr: &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 1234},
	}))

	// Typos are rejected
	file = writeTempFile(t, "typo.yaml", "- outbound: direct\n  macth: true\n")
	_, field, err = (&serverConfigACL{RulesFile: file}).aclRules()
	assert.Error(t, err)
	assert.Equal(t, "acl.rulesFile", field)
	assert.Contains(t, err.Error(), "macth")

	// Not a list
	file = writeTempFile(t, "notalist.yaml", "outbound: direct\n")
	_, _, err = (&serverConfigACL{RulesFile: file}).aclRules()
	assert.Error(t, err)

	// Empty
	file = writeTempFile(t, "empty.yaml", "# nothing\n")
	_, _, err = (&serverConfigACL{RulesFile: file}).aclRules()
	assert.EqualError(t, err, "no rules in file")
}

func TestACLTranslateCommand(t *testing.T) {
	input := `# legacy rules
reject(geoip:cn)
v6_only(suffix:google.com, tcp)
default(8.8.8.8, udp/53, 1.1.1.1)
reject(all, udp/0-100)
direct(all)
`
	want := `acl:
  rules:
    - outbound: reject
      match: legacy("geoip:cn")
    - outbound: v6_only
      match: legacy("suffix:google.com") && proto == "tcp"
    - outbound: default
      match: legacy("8.8.8.8") && proto == "udp" && dst.port == 53
      hijack: 1.1.1.1
    - outbound: reject
      match: proto == "udp" && dst.port >= 0 && dst.port <= 100
    - outbound: direct
`
	// From a file
	cmd := newACLTranslateCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{writeTempFile(t, "acl.txt", input)})
	assert.NoError(t, cmd.Execute())
	assert.Equal(t, want, out.String())

	// From stdin
	cmd = newACLTranslateCmd()
	out.Reset()
	cmd.SetOut(&out)
	cmd.SetIn(strings.NewReader(input))
	cmd.SetArgs([]string{"-"})
	assert.NoError(t, cmd.Execute())
	assert.Equal(t, want, out.String())

	// The output loads back as acl.rules with the same rules
	file := writeTempFile(t, "translated.yaml", strings.TrimPrefix(strings.ReplaceAll(want, "\n    ", "\n"), "acl:\n  rules:\n"))
	fromYAML, _, err := (&serverConfigACL{RulesFile: file}).aclRules()
	assert.NoError(t, err)
	direct, err := acl.TranslateText(input, "")
	assert.NoError(t, err)
	assert.Len(t, fromYAML, len(direct))
	for i := range direct {
		wantMatch := direct[i].Match
		if wantMatch == "true" {
			wantMatch = ""
		}
		assert.Equal(t, wantMatch, fromYAML[i].Match)
		assert.Equal(t, direct[i].Outbound, fromYAML[i].Outbound)
		assert.Equal(t, direct[i].Hijack, fromYAML[i].Hijack)
	}

	// Syntax errors are reported
	cmd = newACLTranslateCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetIn(strings.NewReader("direct(all)\nboom()\n"))
	cmd.SetArgs([]string{})
	assert.EqualError(t, cmd.Execute(), "invalid syntax at line 2: boom()")
}

func runACLTestWithConfig(t *testing.T, config, target string, opts aclTestOptions) (string, error) {
	t.Helper()
	v := viper.New()
	v.SetConfigFile(writeTempFile(t, "server.yaml", config))
	var out bytes.Buffer
	err := runACLTest(v, target, opts, &out)
	return out.String(), err
}

const aclTestConfig = `
outbounds:
  - name: main
    type: direct
  - name: alice_exit
    type: socks5
    socks5:
      addr: 127.0.0.1:1080
acl:
  rules:
    - outbound: alice_exit
      match: auth.id == "alice"
    - outbound: reject
      match: cidr("10.0.0.0/8", client.ip)
    - outbound: default
      match: dst.port == 53 && cidr("8.8.8.8")
      hijack: 1.1.1.1
    - legacy: |
        reject(blocked.example)
        direct(suffix:direct.example)
`

func TestACLTestCommand(t *testing.T) {
	tests := []struct {
		name   string
		target string
		opts   aclTestOptions
		want   string
	}{
		{
			"auth id", "example.com:443",
			aclTestOptions{Proto: "tcp", AuthID: "alice", NoResolve: true},
			`Request:   tcp example.com:443, auth.id "alice"
Resolved:  no addresses (given)
Rule:      rules[0]: alice_exit, match: auth.id == "alice"
Outbound:  alice_exit
`,
		},
		{
			"client ip", "example.com:443",
			aclTestOptions{Proto: "tcp", AuthID: "bob", Client: "10.1.2.3:4567", NoResolve: true},
			`Request:   tcp example.com:443, auth.id "bob", client 10.1.2.3:4567
Resolved:  no addresses (given)
Rule:      rules[1]: reject, match: cidr("10.0.0.0/8", client.ip)
Outbound:  reject (built-in)
`,
		},
		{
			"hijack to default", "dns.example:53",
			aclTestOptions{Proto: "udp", IPv4: "8.8.8.8", Client: "192.0.2.1"},
			`Request:   udp dns.example:53, client 192.0.2.1:0
Resolved:  ipv4 8.8.8.8 (given)
Rule:      rules[2]: default, match: dst.port == 53 && cidr("8.8.8.8")
Outbound:  main
Hijacked:  1.1.1.1:53
`,
		},
		{
			"legacy entry", "blocked.example:80",
			aclTestOptions{Proto: "tcp", NoResolve: true},
			`Request:   tcp blocked.example:80
Resolved:  no addresses (given)
Rule:      rules[3] line 1: reject, match: legacy("blocked.example")
Outbound:  reject (built-in)
`,
		},
		{
			"legacy entry direct", "www.direct.example:80",
			aclTestOptions{Proto: "tcp", IPv6: "2001:db8::1"},
			`Request:   tcp www.direct.example:80
Resolved:  ipv6 2001:db8::1 (given)
Rule:      rules[3] line 2: direct, match: legacy("suffix:direct.example")
Outbound:  direct (built-in)
`,
		},
		{
			"no match", "example.com:443",
			aclTestOptions{Proto: "tcp", NoResolve: true},
			`Request:   tcp example.com:443
Resolved:  no addresses (given)
Rule:      none matched, using the default outbound
Outbound:  main
`,
		},
		{
			// An IP literal resolves locally with the system resolver
			"system resolver", "8.8.8.8:53",
			aclTestOptions{Proto: "UDP"},
			`Request:   udp 8.8.8.8:53
Resolved:  ipv4 8.8.8.8
Rule:      rules[2]: default, match: dst.port == 53 && cidr("8.8.8.8")
Outbound:  main
Hijacked:  1.1.1.1:53
`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := runACLTestWithConfig(t, aclTestConfig, tt.target, tt.opts)
			assert.NoError(t, err)
			assert.Equal(t, tt.want, out)
		})
	}
}

func TestACLTestCommandOverrides(t *testing.T) {
	// User-defined outbounds named like the built-ins replace them,
	// and without outbounds the default is a direct outbound named "default".
	out, err := runACLTestWithConfig(t, `
outbounds:
  - name: Direct
    type: direct
    direct:
      mode: 4
acl:
  inline:
    - direct(all)
`, "example.com:443", aclTestOptions{Proto: "tcp", NoResolve: true})
	assert.NoError(t, err)
	assert.Contains(t, out, "Rule:      line 1: direct, match: true\nOutbound:  Direct\n")

	out, err = runACLTestWithConfig(t, `
acl:
  inline:
    - reject(blocked.example)
`, "example.com:443", aclTestOptions{Proto: "tcp", NoResolve: true})
	assert.NoError(t, err)
	assert.Contains(t, out, "Outbound:  default\n")
}

func TestACLTestCommandErrors(t *testing.T) {
	tests := []struct {
		name    string
		config  string
		target  string
		opts    aclTestOptions
		wantErr string
	}{
		{"no acl", "outbounds: []\n", "example.com:443", aclTestOptions{Proto: "tcp"}, "no ACL configured"},
		{"bad rule", "acl:\n  rules:\n    - outbound: direct\n      match: auth.idd == \"x\"\n", "example.com:443", aclTestOptions{Proto: "tcp"}, "invalid config: acl.rules: error at rules[0]: type acl.Auth has no field idd"},
		{"unknown outbound", "acl:\n  inline:\n    - nope(all)\n", "example.com:443", aclTestOptions{Proto: "tcp"}, "outbound nope not found"},
		{"no port", aclTestConfig, "example.com", aclTestOptions{Proto: "tcp"}, "invalid target"},
		{"bad port", aclTestConfig, "example.com:http", aclTestOptions{Proto: "tcp"}, "invalid port"},
		{"bad proto", aclTestConfig, "example.com:443", aclTestOptions{Proto: "sctp"}, "invalid protocol"},
		{"bad client", aclTestConfig, "example.com:443", aclTestOptions{Proto: "tcp", Client: "nope"}, "invalid client address"},
		{"v6 as ipv4", aclTestConfig, "example.com:443", aclTestOptions{Proto: "tcp", IPv4: "2001:db8::1"}, "invalid IPv4 address"},
		{"v4 as ipv6", aclTestConfig, "example.com:443", aclTestOptions{Proto: "tcp", IPv6: "192.0.2.1"}, "invalid IPv6 address"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := runACLTestWithConfig(t, tt.config, tt.target, tt.opts)
			if assert.Error(t, err) {
				assert.Contains(t, err.Error(), tt.wantErr)
			}
		})
	}
}
