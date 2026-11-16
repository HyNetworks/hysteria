package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.yaml.in/yaml/v3"

	"github.com/apernet/hysteria/core/v2/server"
	"github.com/apernet/hysteria/extras/v2/outbounds"
	"github.com/apernet/hysteria/extras/v2/outbounds/acl"
)

// serverConfigACLRule is an entry of acl.rules (or of the list in acl.rulesFile).
// It is either an expr rule (outbound, plus optional match and hijack), or
// legacy rules (legacy or legacyFile) that are translated and spliced in place.
type serverConfigACLRule struct {
	Outbound   string `mapstructure:"outbound" yaml:"outbound,omitempty"`
	Match      string `mapstructure:"match" yaml:"match,omitempty"`
	Hijack     string `mapstructure:"hijack" yaml:"hijack,omitempty"`
	Legacy     string `mapstructure:"legacy" yaml:"legacy,omitempty"`
	LegacyFile string `mapstructure:"legacyFile" yaml:"legacyFile,omitempty"`
}

// aclRules converts the ACL config into a list of rules.
// field is the config field the rules came from, for error messages.
// If no ACL is configured, it returns nil rules and an empty field.
func (c *serverConfigACL) aclRules() (rules []acl.Rule, field string, err error) {
	set := 0
	for _, ok := range []bool{c.File != "", len(c.Inline) > 0, len(c.Rules) > 0, c.RulesFile != ""} {
		if ok {
			set++
		}
	}
	if set > 1 {
		return nil, "acl", errors.New("only one of acl.file, acl.inline, acl.rules and acl.rulesFile can be set")
	}
	switch {
	case c.File != "":
		bs, err := os.ReadFile(c.File)
		if err != nil {
			return nil, "acl.file", err
		}
		rules, err = acl.TranslateText(string(bs), "")
		return rules, "acl.file", err
	case len(c.Inline) > 0:
		rules, err = acl.TranslateText(strings.Join(c.Inline, "\n"), "")
		return rules, "acl.inline", err
	case len(c.Rules) > 0:
		rules, err = convertACLRules(c.Rules)
		return rules, "acl.rules", err
	case c.RulesFile != "":
		entries, err := loadACLRulesFile(c.RulesFile)
		if err != nil {
			return nil, "acl.rulesFile", err
		}
		rules, err = convertACLRules(entries)
		return rules, "acl.rulesFile", err
	default:
		return nil, "", nil
	}
}

func convertACLRules(entries []serverConfigACLRule) ([]acl.Rule, error) {
	var rules []acl.Rule
	for i, e := range entries {
		src := fmt.Sprintf("rules[%d]", i)
		isRule := e.Outbound != "" || e.Match != "" || e.Hijack != ""
		forms := 0
		for _, ok := range []bool{isRule, e.Legacy != "", e.LegacyFile != ""} {
			if ok {
				forms++
			}
		}
		if forms != 1 {
			return nil, fmt.Errorf("%s: exactly one of outbound, legacy and legacyFile must be set", src)
		}
		switch {
		case isRule:
			if e.Outbound == "" {
				return nil, fmt.Errorf("%s: outbound is required", src)
			}
			rules = append(rules, acl.Rule{
				Outbound: e.Outbound,
				Match:    e.Match,
				Hijack:   e.Hijack,
				Source:   src,
			})
		case e.Legacy != "":
			rs, err := acl.TranslateText(e.Legacy, src)
			if err != nil {
				return nil, err
			}
			rules = append(rules, rs...)
		case e.LegacyFile != "":
			bs, err := os.ReadFile(e.LegacyFile)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", src, err)
			}
			rs, err := acl.TranslateText(string(bs), fmt.Sprintf("%s (%s)", src, e.LegacyFile))
			if err != nil {
				return nil, err
			}
			rules = append(rules, rs...)
		}
	}
	return rules, nil
}

// loadACLRulesFile loads a YAML file containing a list of ACL rule entries.
// Unknown keys are rejected to catch typos.
func loadACLRulesFile(filename string) ([]serverConfigACLRule, error) {
	bs, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var entries []serverConfigACLRule
	dec := yaml.NewDecoder(bytes.NewReader(bs))
	dec.KnownFields(true)
	if err := dec.Decode(&entries); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, errors.New("no rules in file")
	}
	return entries, nil
}

func init() {
	rootCmd.AddCommand(newACLCmd())
}

func newACLCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "acl",
		Short: "ACL utilities",
	}
	cmd.AddCommand(newACLTranslateCmd())
	cmd.AddCommand(newACLTestCmd())
	return cmd
}

func newACLTranslateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "translate [file]",
		Short: "Translate legacy ACL rules into acl.rules config",
		Long: "Translate rules in the legacy ACL syntax (acl.file / acl.inline) into the equivalent " +
			"expr-based acl.rules config, which is what the server runs internally. " +
			"Reads from standard input if no file (or \"-\") is given.\n\n" +
			"Only the syntax is checked: outbound names and GeoIP/GeoSite names are validated " +
			"when the server loads the rules.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var bs []byte
			var err error
			if len(args) == 0 || args[0] == "-" {
				bs, err = io.ReadAll(cmd.InOrStdin())
			} else {
				bs, err = os.ReadFile(args[0])
			}
			if err != nil {
				return err
			}
			out, err := translateLegacyACL(string(bs))
			if err != nil {
				return err
			}
			_, err = cmd.OutOrStdout().Write(out)
			return err
		},
	}
}

// translateLegacyACL translates legacy ACL text into an "acl.rules" YAML snippet.
func translateLegacyACL(text string) ([]byte, error) {
	rules, err := acl.TranslateText(text, "")
	if err != nil {
		return nil, err
	}
	entries := make([]serverConfigACLRule, len(rules))
	for i, r := range rules {
		entries[i] = serverConfigACLRule{
			Outbound: r.Outbound,
			Hijack:   r.Hijack,
		}
		if r.Match != "true" {
			entries[i].Match = r.Match
		}
	}
	doc := struct {
		ACL struct {
			Rules []serverConfigACLRule `yaml:"rules"`
		} `yaml:"acl"`
	}{}
	doc.ACL.Rules = entries
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(doc); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

type aclTestOptions struct {
	Proto     string
	AuthID    string
	Client    string
	IPv4      string
	IPv6      string
	NoResolve bool
}

func newACLTestCmd() *cobra.Command {
	var opts aclTestOptions
	cmd := &cobra.Command{
		Use:   "test <host:port>",
		Short: "Show how the server's ACL handles a request",
		Long: "Load the server config (-c) and show which ACL rule and outbound a request would use, " +
			"without connecting anywhere.\n\n" +
			"The host is resolved with the configured resolver, like the server does, unless " +
			"--ipv4/--ipv6 or --no-resolve is given. Sniffing is not simulated: the host is used as given.",
		Example: "  hysteria acl test -c server.yaml example.com:443\n" +
			"  hysteria acl test -c server.yaml --auth alice --client 203.0.113.7 --proto udp 8.8.8.8:53",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			return runACLTest(defaultViper, args[0], opts, cmd.OutOrStdout())
		},
	}
	cmd.Flags().StringVar(&opts.Proto, "proto", "tcp", "protocol: tcp or udp")
	cmd.Flags().StringVar(&opts.AuthID, "auth", "", "authentication ID of the client (auth.id)")
	cmd.Flags().StringVar(&opts.Client, "client", "", "client address, IP or IP:port (client.ip, client.port)")
	cmd.Flags().StringVar(&opts.IPv4, "ipv4", "", "use this as the resolved IPv4 address instead of resolving")
	cmd.Flags().StringVar(&opts.IPv6, "ipv6", "", "use this as the resolved IPv6 address instead of resolving")
	cmd.Flags().BoolVar(&opts.NoResolve, "no-resolve", false, "don't resolve the host (no IP addresses)")
	return cmd
}

// aclTestRecorder is a stand-in for an outbound that records that it was
// chosen, and the request it received (after hijacking).
type aclTestRecorder struct {
	Name   string
	Chosen **aclTestRecorder
	Addr   *outbounds.AddrEx
}

func (r *aclTestRecorder) record(reqAddr *outbounds.AddrEx) {
	*r.Chosen = r
	a := *reqAddr
	r.Addr = &a
}

func (r *aclTestRecorder) TCP(reqAddr *outbounds.AddrEx) (net.Conn, error) {
	r.record(reqAddr)
	return nil, nil
}

func (r *aclTestRecorder) UDP(reqAddr *outbounds.AddrEx) (outbounds.UDPConn, error) {
	r.record(reqAddr)
	return nil, nil
}

func (r *aclTestRecorder) CheckUDP(reqAddr *outbounds.AddrEx) error {
	r.record(reqAddr)
	return nil
}

// aclTestProbe records the request as the ACL engine receives it
// (after resolution), then passes it on.
type aclTestProbe struct {
	Next outbounds.PluggableOutbound
	Addr *outbounds.AddrEx
}

func (p *aclTestProbe) record(reqAddr *outbounds.AddrEx) {
	a := *reqAddr
	p.Addr = &a
}

func (p *aclTestProbe) TCP(reqAddr *outbounds.AddrEx) (net.Conn, error) {
	p.record(reqAddr)
	return p.Next.TCP(reqAddr)
}

func (p *aclTestProbe) UDP(reqAddr *outbounds.AddrEx) (outbounds.UDPConn, error) {
	p.record(reqAddr)
	return p.Next.UDP(reqAddr)
}

func (p *aclTestProbe) CheckUDP(reqAddr *outbounds.AddrEx) error {
	p.record(reqAddr)
	return p.Next.CheckUDP(reqAddr)
}

func parseACLTestClient(s string) (net.Addr, error) {
	if s == "" {
		return nil, nil
	}
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return net.UDPAddrFromAddrPort(ap), nil
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return net.UDPAddrFromAddrPort(netip.AddrPortFrom(a, 0)), nil
	}
	return nil, fmt.Errorf("invalid client address %q (want IP or IP:port)", s)
}

func parseACLTestIP(s string, v4 bool) (net.IP, error) {
	if s == "" {
		return nil, nil
	}
	ip := net.ParseIP(s)
	if ip == nil || (ip.To4() != nil) != v4 {
		if v4 {
			return nil, fmt.Errorf("invalid IPv4 address %q", s)
		}
		return nil, fmt.Errorf("invalid IPv6 address %q", s)
	}
	if v4 {
		return ip.To4(), nil
	}
	return ip, nil
}

// runACLTest runs a request through the server's resolver and ACL engine,
// with every outbound replaced by a recorder, and prints the result.
func runACLTest(v *viper.Viper, target string, opts aclTestOptions, out io.Writer) error {
	// Request
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return fmt.Errorf("invalid target %q: %w", target, err)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return fmt.Errorf("invalid port %q", portStr)
	}
	proto := strings.ToLower(opts.Proto)
	if proto != "tcp" && proto != "udp" {
		return fmt.Errorf("invalid protocol %q (want tcp or udp)", opts.Proto)
	}
	clientAddr, err := parseACLTestClient(opts.Client)
	if err != nil {
		return err
	}
	ipv4, err := parseACLTestIP(opts.IPv4, true)
	if err != nil {
		return err
	}
	ipv6, err := parseACLTestIP(opts.IPv6, false)
	if err != nil {
		return err
	}
	manualIPs := ipv4 != nil || ipv6 != nil || opts.NoResolve

	// Config
	if err := v.ReadInConfig(); err != nil {
		return fmt.Errorf("failed to read server config: %w", err)
	}
	var config serverConfig
	if err := v.Unmarshal(&config); err != nil {
		return fmt.Errorf("failed to parse server config: %w", err)
	}
	rules, aclField, err := config.ACL.aclRules()
	if err != nil {
		return configError{Field: aclField, Err: err}
	}
	if aclField == "" {
		return errors.New("no ACL configured (acl.file, acl.inline, acl.rules or acl.rulesFile)")
	}
	obs, err := config.outboundEntries()
	if err != nil {
		return err
	}

	// Replace the outbounds with recorders. The built-in direct and reject
	// outbounds get recorders too, unless the config overrides them.
	var chosen *aclTestRecorder
	names := make(map[string]bool)
	for i := range obs {
		names[strings.ToLower(obs[i].Name)] = true
		obs[i].Outbound = &aclTestRecorder{Name: obs[i].Name, Chosen: &chosen}
	}
	for _, name := range []string{"direct", "reject"} {
		if !names[name] {
			obs = append(obs, outbounds.OutboundEntry{
				Name:     name,
				Outbound: &aclTestRecorder{Name: name + " (built-in)", Chosen: &chosen},
			})
		}
	}
	gLoader := config.geoLoader()
	engine, err := outbounds.NewACLEngine(rules, obs, gLoader)
	if err != nil {
		return configError{Field: aclField, Err: err}
	}
	probe := &aclTestProbe{Next: engine}
	var pipeline outbounds.PluggableOutbound = probe
	if !manualIPs {
		pipeline, err = config.wrapResolver(pipeline, true)
		if err != nil {
			return err
		}
	}

	// A copy of the rules where each rule has its own "outbound", to find out
	// which rule matched.
	indexRules := make([]acl.Rule, len(rules))
	indexOutbounds := make(map[string]int, len(rules))
	for i, r := range rules {
		r.Outbound = strconv.Itoa(i)
		indexRules[i] = r
		indexOutbounds[r.Outbound] = i + 1 // 0 means no match
	}
	indexSet, err := acl.Compile[int](indexRules, indexOutbounds, 1, gLoader)
	if err != nil {
		return configError{Field: aclField, Err: err}
	}

	// Run the request
	reqAddr := &outbounds.AddrEx{
		Host: host,
		Port: uint16(port),
		Info: &server.RequestInfo{AuthID: opts.AuthID, ClientAddr: clientAddr},
	}
	if manualIPs {
		reqAddr.ResolveInfo = &outbounds.ResolveInfo{IPv4: ipv4, IPv6: ipv6}
	}
	aclProto := acl.ProtocolTCP
	if proto == "udp" {
		aclProto = acl.ProtocolUDP
		_, _ = pipeline.UDP(reqAddr)
	} else {
		_, _ = pipeline.TCP(reqAddr)
	}
	seen := probe.Addr
	if seen == nil || chosen == nil {
		return errors.New("request did not reach the ACL engine")
	}
	req := acl.Request{Proto: aclProto, Host: seen.Host, Port: seen.Port, AuthID: opts.AuthID, ClientAddr: clientAddr}
	if seen.ResolveInfo != nil {
		req.IPv4 = seen.ResolveInfo.IPv4
		req.IPv6 = seen.ResolveInfo.IPv6
	}
	index, _ := indexSet.Match(&req)

	// Print
	w := func(label, format string, a ...any) {
		_, _ = fmt.Fprintf(out, "%-10s %s\n", label+":", fmt.Sprintf(format, a...))
	}
	desc := fmt.Sprintf("%s %s", proto, net.JoinHostPort(host, portStr))
	if opts.AuthID != "" {
		desc += fmt.Sprintf(", auth.id %q", opts.AuthID)
	}
	if clientAddr != nil {
		desc += ", client " + clientAddr.String()
	}
	w("Request", "%s", desc)
	switch {
	case manualIPs:
		w("Resolved", "%s (given)", formatACLTestIPs(req.IPv4, req.IPv6))
	case seen.ResolveInfo != nil && seen.ResolveInfo.Err != nil && req.IPv4 == nil && req.IPv6 == nil:
		w("Resolved", "failed: %v", seen.ResolveInfo.Err)
	default:
		w("Resolved", "%s", formatACLTestIPs(req.IPv4, req.IPv6))
	}
	if index == 0 {
		w("Rule", "none matched, using the default outbound")
	} else {
		r := rules[index-1]
		match := r.Match
		if strings.TrimSpace(match) == "" {
			match = "true"
		}
		w("Rule", "%s: %s, match: %s", r.Source, r.Outbound, match)
	}
	w("Outbound", "%s", chosen.Name)
	if final := chosen.Addr; final != nil && (final.Host != seen.Host || final.Port != seen.Port) {
		w("Hijacked", "%s", final.String())
	}
	return nil
}

func formatACLTestIPs(ipv4, ipv6 net.IP) string {
	var parts []string
	if ipv4 != nil {
		parts = append(parts, "ipv4 "+ipv4.String())
	}
	if ipv6 != nil {
		parts = append(parts, "ipv6 "+ipv6.String())
	}
	if len(parts) == 0 {
		return "no addresses"
	}
	return strings.Join(parts, ", ")
}
