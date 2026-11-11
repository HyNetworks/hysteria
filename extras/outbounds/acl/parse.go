package acl

import (
	"fmt"
	"regexp"
	"strings"
)

var linePattern = regexp.MustCompile(`^([\w-]+)\s*\(([^,]+)(?:,([^,]+))?(?:,([^,]+))?\)$`)

type InvalidSyntaxError struct {
	Line    string
	LineNum int
}

func (e *InvalidSyntaxError) Error() string {
	return fmt.Sprintf("invalid syntax at line %d: %s", e.LineNum, e.Line)
}

// TextRule is the struct representation of a (non-comment) line parsed from an ACL file.
// A line can be parsed into a TextRule as long as it matches one of the following patterns:
//
//	outbound(address)
//	outbound(address,protoPort)
//	outbound(address,protoPort,hijackAddress)
//
// It does not check whether any of the fields is valid - it's up to the compiler to do so.
type TextRule struct {
	Outbound      string
	Address       string
	ProtoPort     string
	HijackAddress string
	LineNum       int
}

func parseLine(line string, num int) *TextRule {
	matches := linePattern.FindStringSubmatch(line)
	if matches == nil {
		return nil
	}
	return &TextRule{
		Outbound:      matches[1],
		Address:       strings.TrimSpace(matches[2]),
		ProtoPort:     strings.TrimSpace(matches[3]),
		HijackAddress: strings.TrimSpace(matches[4]),
		LineNum:       num,
	}
}

func ParseTextRules(text string) ([]TextRule, error) {
	rules := make([]TextRule, 0)
	lineNum := 0
	for _, line := range strings.Split(text, "\n") {
		lineNum++
		// Remove comments
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		// Skip empty lines
		if len(line) == 0 {
			continue
		}
		// Parse line
		rule := parseLine(line, lineNum)
		if rule == nil {
			return nil, &InvalidSyntaxError{line, lineNum}
		}
		rules = append(rules, *rule)
	}
	return rules, nil
}
