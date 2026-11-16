package acl

import (
	"fmt"
	"strconv"
	"strings"
)

// translateTextRule translates a rule in the legacy text syntax into an
// expr-based Rule with the same behavior. The only intentional difference is
// that port ranges starting at 0 (e.g. "udp/0-100") now match only the ports
// in the range; the legacy compiler treated them as "any port".
//
// source is prepended to "line N" in the rule's Source (can be empty).
func translateTextRule(r TextRule, source string) (Rule, error) {
	src := fmt.Sprintf("line %d", r.LineNum)
	if source != "" {
		src = source + " " + src
	}
	pp, ok := parseProtoPort(r.ProtoPort)
	if !ok {
		return Rule{}, &CompilationError{src, fmt.Sprintf("invalid protocol/port: %s", r.ProtoPort)}
	}
	var conds []string
	if addr := normalizeHost(r.Address); addr != "*" && addr != "all" {
		conds = append(conds, "legacy("+strconv.Quote(r.Address)+")")
	}
	switch pp.Proto {
	case ProtocolTCP:
		conds = append(conds, `proto == "tcp"`)
	case ProtocolUDP:
		conds = append(conds, `proto == "udp"`)
	}
	if pp.HasPort {
		if pp.StartPort == pp.EndPort {
			conds = append(conds, fmt.Sprintf("dst.port == %d", pp.StartPort))
		} else {
			conds = append(conds, fmt.Sprintf("dst.port >= %d && dst.port <= %d", pp.StartPort, pp.EndPort))
		}
	}
	match := "true"
	if len(conds) > 0 {
		match = strings.Join(conds, " && ")
	}
	return Rule{
		Outbound: r.Outbound,
		Match:    match,
		Hijack:   r.HijackAddress,
		Source:   src,
	}, nil
}

// translateTextRules translates a list of legacy rules. See translateTextRule.
func translateTextRules(rules []TextRule, source string) ([]Rule, error) {
	out := make([]Rule, len(rules))
	for i, r := range rules {
		rule, err := translateTextRule(r, source)
		if err != nil {
			return nil, err
		}
		out[i] = rule
	}
	return out, nil
}

// TranslateText parses and translates rules in the legacy text syntax.
// source describes where the text came from and is used in error messages
// (can be empty).
func TranslateText(text, source string) ([]Rule, error) {
	trs, err := ParseTextRules(text)
	if err != nil {
		if source != "" {
			return nil, fmt.Errorf("%s: %w", source, err)
		}
		return nil, err
	}
	return translateTextRules(trs, source)
}
