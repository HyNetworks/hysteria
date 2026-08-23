package l2tp

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIDRouterExactMatch(t *testing.T) {
	rr := NewIDRouter([]RouteRule{
		{Pattern: "alice", Group: "groupA"},
		{Pattern: "bob@ispB.net", Group: "groupB"},
	})
	assert.Equal(t, "groupA", rr.Match("alice"))
	assert.Equal(t, "groupB", rr.Match("bob@ispB.net"))
	assert.Equal(t, "", rr.Match("mallory"))
}

func TestIDRouterSuffixWildcard(t *testing.T) {
	rr := NewIDRouter([]RouteRule{
		{Pattern: "*@ispa.net", Group: "groupA"},
		{Pattern: "*.example.net", Group: "groupC"},
		{Pattern: "exact", Group: "groupB"},
	})
	assert.Equal(t, "groupA", rr.Match("alice@ispa.net"))
	assert.Equal(t, "", rr.Match("@ispa.net"), "the suffix form needs something in front of it")
	assert.Equal(t, "groupC", rr.Match("host.example.net"))
	assert.Equal(t, "groupB", rr.Match("exact"))
	assert.Equal(t, "", rr.Match("not-exact"))
}

// A bare "*" is the catch-all every single-LNS deployment wants, and it has to
// match the empty identity too -- a server with no authentication still hands
// the handler an empty id, and those subscribers must route somewhere rather
// than be silently refused.
func TestIDRouterCatchAll(t *testing.T) {
	rr := NewIDRouter([]RouteRule{{Pattern: "*", Group: "all"}})
	for _, id := range []string{"alice", "bob@ispa.net", "", "anything at all"} {
		assert.Equal(t, "all", rr.Match(id), "id %q", id)
	}
}

func TestIDRouterFirstMatchWins(t *testing.T) {
	rr := NewIDRouter([]RouteRule{
		{Pattern: "*@example.net", Group: "wildcard"},
		{Pattern: "vip@example.net", Group: "exact"},
	})
	assert.Equal(t, "wildcard", rr.Match("vip@example.net"),
		"rules are evaluated in order, so a catch-all above an exact rule shadows it")
}

// No rule matching must mean no group, never a default. Routing a subscriber to
// an arbitrary LNS is worse than refusing them.
func TestIDRouterNoRulesMatchesNothing(t *testing.T) {
	rr := NewIDRouter(nil)
	assert.Equal(t, "", rr.Match("alice"))
	assert.Equal(t, "", rr.Match(""))
}

func TestLoadBalancerRoundRobin(t *testing.T) {
	lb := NewLoadBalancer(map[string][]LNSConfig{
		"group1": {
			{Address: "lns1:1701", Weight: 1},
			{Address: "lns2:1701", Weight: 1},
		},
	})

	// Should alternate between lns1 and lns2
	results := make(map[string]int)
	for i := 0; i < 10; i++ {
		cfg, ok := lb.PickSticky("group1", "")
		assert.True(t, ok)
		results[cfg.Address]++
	}
	assert.Equal(t, 5, results["lns1:1701"])
	assert.Equal(t, 5, results["lns2:1701"])
}

func TestLoadBalancerWeightedRoundRobin(t *testing.T) {
	lb := NewLoadBalancer(map[string][]LNSConfig{
		"group1": {
			{Address: "lns1:1701", Weight: 2},
			{Address: "lns2:1701", Weight: 1},
		},
	})

	// With weight 2:1, should get lns1 twice for every lns2
	results := make(map[string]int)
	for i := 0; i < 9; i++ {
		cfg, ok := lb.PickSticky("group1", "")
		assert.True(t, ok)
		results[cfg.Address]++
	}
	assert.Equal(t, 6, results["lns1:1701"])
	assert.Equal(t, 3, results["lns2:1701"])
}

func TestLoadBalancerUnknownGroup(t *testing.T) {
	lb := NewLoadBalancer(map[string][]LNSConfig{
		"group1": {{Address: "lns1:1701", Weight: 1}},
	})
	_, ok := lb.PickSticky("nonexistent", "")
	assert.False(t, ok)
}

func TestLoadBalancerDefaultWeight(t *testing.T) {
	lb := NewLoadBalancer(map[string][]LNSConfig{
		"group1": {
			{Address: "lns1:1701", Weight: 0},  // should default to 1
			{Address: "lns2:1701", Weight: -1}, // should default to 1
		},
	})

	results := make(map[string]int)
	for i := 0; i < 10; i++ {
		cfg, ok := lb.PickSticky("group1", "")
		assert.True(t, ok)
		results[cfg.Address]++
	}
	assert.Equal(t, 5, results["lns1:1701"])
	assert.Equal(t, 5, results["lns2:1701"])
}

// An empty identity carries no stickiness, so it round-robins rather than
// pinning every anonymous session onto one LNS.
func TestPickStickyEmptyIdentityRoundRobins(t *testing.T) {
	lb := NewLoadBalancer(map[string][]LNSConfig{
		"group1": {{Address: "lns1:1701", Weight: 1}, {Address: "lns2:1701", Weight: 1}},
	})
	results := make(map[string]int)
	for i := 0; i < 10; i++ {
		cfg, ok := lb.PickSticky("group1", "")
		assert.True(t, ok)
		results[cfg.Address]++
	}
	assert.Equal(t, 5, results["lns1:1701"])
	assert.Equal(t, 5, results["lns2:1701"])
}

// The point of stickiness: one subscriber always lands on the same LNS, so a
// reconnect reaches the box that still holds their state.
func TestPickStickyIsStableForOneIdentity(t *testing.T) {
	lb := NewLoadBalancer(map[string][]LNSConfig{
		"group1": {
			{Address: "lns1:1701", Weight: 1},
			{Address: "lns2:1701", Weight: 1},
			{Address: "lns3:1701", Weight: 1},
		},
	})
	first, ok := lb.PickSticky("group1", "alice@ispa.net")
	assert.True(t, ok)
	for i := 0; i < 20; i++ {
		again, ok := lb.PickSticky("group1", "alice@ispa.net")
		assert.True(t, ok)
		assert.Equal(t, first.Address, again.Address, "call %d moved the subscriber", i)
	}
}

// And different subscribers spread out, or the stickiness would be a single
// point of load.
func TestPickStickySpreadsDistinctIdentities(t *testing.T) {
	lb := NewLoadBalancer(map[string][]LNSConfig{
		"group1": {
			{Address: "lns1:1701", Weight: 1},
			{Address: "lns2:1701", Weight: 1},
			{Address: "lns3:1701", Weight: 1},
		},
	})
	seen := make(map[string]bool)
	for i := 0; i < 60; i++ {
		cfg, ok := lb.PickSticky("group1", fmt.Sprintf("user%d@ispa.net", i))
		assert.True(t, ok)
		seen[cfg.Address] = true
	}
	assert.Len(t, seen, 3, "every LNS in the group should receive some subscribers")
}

func TestPickStickyWeighted(t *testing.T) {
	lb := NewLoadBalancer(map[string][]LNSConfig{
		"group1": {{Address: "heavy:1701", Weight: 3}, {Address: "light:1701", Weight: 1}},
	})
	counts := make(map[string]int)
	for i := 0; i < 400; i++ {
		cfg, ok := lb.PickSticky("group1", fmt.Sprintf("user%d", i))
		assert.True(t, ok)
		counts[cfg.Address]++
	}
	assert.Greater(t, counts["heavy:1701"], counts["light:1701"],
		"weight must still bias the sticky choice")
}

func TestPickStickyUnknownGroup(t *testing.T) {
	lb := NewLoadBalancer(map[string][]LNSConfig{"group1": {{Address: "lns1:1701", Weight: 1}}})
	_, ok := lb.PickSticky("nope", "alice")
	assert.False(t, ok)
	_, ok = lb.PickSticky("nope", "")
	assert.False(t, ok)
}

func TestMatchPattern(t *testing.T) {
	tests := []struct {
		pattern string
		id      string
		want    bool
	}{
		{"alice", "alice", true},
		{"alice", "bob", false},
		{"*@ispa.net", "alice@ispa.net", true},
		{"*@ispa.net", "@ispa.net", false},
		{"*@ispa.net", "alice@ispb.net", false},
		{"*.example.net", "foo.example.net", true},
		{"*.example.net", "example.net", false},
		{"*.example.net", "deep.sub.example.net", true},
		{"*", "anything", true},
		{"*", "", true},
		{"", "", true},
		{"", "alice", false},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, matchPattern(tt.pattern, tt.id),
			"matchPattern(%q, %q)", tt.pattern, tt.id)
	}
}
