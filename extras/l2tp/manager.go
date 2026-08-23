package l2tp

import (
	"errors"
	"fmt"
	"hash/fnv"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

// TunnelManager manages on-demand L2TP tunnels to LNS endpoints.
// Tunnels are created when first needed and reused by multiple sessions.
// When the last session on a tunnel closes, the tunnel is torn down.
type TunnelManager struct {
	hostname      string
	helloInterval time.Duration
	logger        *zap.Logger

	mu      sync.Mutex
	closed  bool
	tunnels map[string]*Tunnel // keyed by LNS address
	nextTID uint16
}

// NewTunnelManager creates a new tunnel manager.
func NewTunnelManager(hostname string, helloInterval time.Duration, logger *zap.Logger) *TunnelManager {
	return &TunnelManager{
		hostname:      hostname,
		helloInterval: helloInterval,
		logger:        logger,
		tunnels:       make(map[string]*Tunnel),
		nextTID:       uint16(1 + rand.Intn(65534)),
	}
}

// CreateSession establishes (or reuses) a tunnel to the given LNS address
// and creates a new L2TP session with the provided proxy information.
func (m *TunnelManager) CreateSession(lnsAddr, secret, subscriber, callingNumber string) (*Session, error) {
	t, err := m.getOrCreateTunnel(lnsAddr, secret)
	if err != nil {
		return nil, err
	}

	session, err := t.CreateSession(subscriber, callingNumber)
	if err != nil {
		return nil, fmt.Errorf("create session to %s: %w", lnsAddr, err)
	}

	m.logger.Info("L2TP session established",
		zap.String("lns", lnsAddr),
		zap.Uint16("tunnelID", t.localTunnelID),
		zap.Uint16("sessionID", session.localSessionID),
		zap.String("subscriber", subscriber))

	return session, nil
}

func tunnelCacheKey(lnsAddr, secret string) string {
	return lnsAddr + "\x00" + secret
}

func (m *TunnelManager) getOrCreateTunnel(lnsAddr, secret string) (*Tunnel, error) {
	key := tunnelCacheKey(lnsAddr, secret)
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil, errManagerClosed
	}

	// Check for existing alive tunnel
	if t, ok := m.tunnels[key]; ok && t.Alive() {
		m.mu.Unlock()
		return t, nil
	}

	// Clean up dead tunnel entry if present
	delete(m.tunnels, key)

	// Allocate tunnel ID
	tid := m.nextTID
	m.nextTID++
	if m.nextTID == 0 {
		m.nextTID = 1
	}

	m.mu.Unlock()

	// Establish new tunnel (outside lock to avoid blocking)
	conn, err := net.Dial("udp", lnsAddr)
	if err != nil {
		return nil, fmt.Errorf("dial LNS %s: %w", lnsAddr, err)
	}

	var secretBytes []byte
	if secret != "" {
		secretBytes = []byte(secret)
	}

	t := newTunnel(conn, tid, m.hostname, secretBytes, m.helloInterval, m.logger)
	t.onClose = func() {
		m.mu.Lock()
		if existing, ok := m.tunnels[key]; ok && existing == t {
			delete(m.tunnels, key)
		}
		m.mu.Unlock()
	}

	if err := t.Establish(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("establish tunnel to %s: %w", lnsAddr, err)
	}

	m.logger.Info("L2TP tunnel established",
		zap.String("lns", lnsAddr),
		zap.Uint16("tunnelID", tid))

	m.mu.Lock()
	if existing, ok := m.tunnels[key]; ok && existing.Alive() {
		m.mu.Unlock()
		t.Close()
		return existing, nil
	}
	if m.closed {
		// Close ran while this tunnel was being established. Registering it now
		// would leave a live tunnel nothing ever tears down.
		m.mu.Unlock()
		t.Close()
		return nil, errManagerClosed
	}
	m.tunnels[key] = t
	m.mu.Unlock()

	return t, nil
}

// Close tears down every tunnel, which sends each LNS a StopCCN so it can
// release the sessions immediately instead of waiting out its HELLO timeout.
//
// It satisfies io.Closer so it can be chained into the server's Cleanup hook;
// see fillPPPConfigL2TP.
var errManagerClosed = errors.New("l2tp: tunnel manager is closed")

func (m *TunnelManager) Close() error {
	m.mu.Lock()
	m.closed = true
	tunnels := make([]*Tunnel, 0, len(m.tunnels))
	for _, t := range m.tunnels {
		tunnels = append(tunnels, t)
	}
	m.tunnels = make(map[string]*Tunnel)
	m.mu.Unlock()

	for _, t := range tunnels {
		t.Close()
	}
	return nil
}

// LNSConfig holds configuration for a single LNS endpoint.
type LNSConfig struct {
	Address string
	Secret  string
	Weight  int
}

// IDRouter maps a subscriber's Hysteria2 authentication identity to an LNS group.
//
// A classic LAC answers an anonymous dial-in and has to run PPP authentication
// just to learn who is calling, then routes on the realm in that username. This
// one does not: the subscriber has already authenticated to Hysteria2 before a
// single PPP frame moves, so the identity is known before the tunnel is chosen
// and the LAC never needs to terminate PPP at all.
type IDRouter struct {
	rules []routeRule
}

type routeRule struct {
	pattern string
	group   string
}

// RouteRule is a configuration-level identity routing rule.
type RouteRule struct {
	Pattern string
	Group   string
}

// NewIDRouter creates a router from a list of pattern->group mappings.
// Rules are evaluated in order; first match wins.
func NewIDRouter(rules []RouteRule) *IDRouter {
	rr := &IDRouter{}
	for _, r := range rules {
		rr.rules = append(rr.rules, routeRule{pattern: r.Pattern, group: r.Group})
	}
	return rr
}

// Match finds the LNS group for an identity. Returns empty string if no rule
// matches, which the caller must treat as "refuse the session" rather than
// "pick something": routing a subscriber to an arbitrary LNS is worse than
// telling them their account is not configured.
func (r *IDRouter) Match(id string) string {
	for _, rule := range r.rules {
		if matchPattern(rule.pattern, id) {
			return rule.group
		}
	}
	return ""
}

// matchPattern matches an identity against a pattern.
//
//	"*"          matches every identity, including the empty one
//	"*<suffix>"  matches any identity ending in suffix, e.g. "*@ispa.net"
//	anything else is an exact match
//
// The suffix form requires something before the suffix, so "*@ispa.net" does not
// match the bare identity "@ispa.net".
func matchPattern(pattern, id string) bool {
	if pattern == "*" {
		return true
	}
	if pattern == id {
		return true
	}
	if len(pattern) > 1 && pattern[0] == '*' {
		suffix := pattern[1:]
		return len(id) > len(suffix) && id[len(id)-len(suffix):] == suffix
	}
	return false
}

// LoadBalancer provides weighted round-robin selection across LNS groups.
type LoadBalancer struct {
	groups map[string]*lbGroup
}

type lbGroup struct {
	flatList []LNSConfig
	counter  atomic.Uint64
}

// NewLoadBalancer creates a load balancer from group configurations.
func NewLoadBalancer(groups map[string][]LNSConfig) *LoadBalancer {
	lb := &LoadBalancer{groups: make(map[string]*lbGroup)}
	for name, lnsList := range groups {
		g := &lbGroup{}
		for _, lns := range lnsList {
			w := lns.Weight
			if w <= 0 {
				w = 1
			}
			for range w {
				g.flatList = append(g.flatList, lns)
			}
		}
		lb.groups[name] = g
	}
	return lb
}

// PickSticky selects an LNS from a group, keyed for session affinity.
//
// The key is the subscriber's Hysteria2 identity, so every link a subscriber
// brings up lands on the same LNS -- which is what lets the LNS bundle them into
// one Multilink PPP session. Weight is honoured because the group is flattened
// into one entry per unit of weight before hashing.
//
// An empty key falls back to round robin: it carries no affinity, and hashing it
// would send every keyless session to the same LNS.
func (lb *LoadBalancer) PickSticky(group, key string) (LNSConfig, bool) {
	g, ok := lb.groups[group]
	if !ok || len(g.flatList) == 0 {
		return LNSConfig{}, false
	}
	// An empty key carries no stickiness, so fall back to round robin rather than
	// sending every anonymous session to the same LNS.
	if key == "" {
		idx := g.counter.Add(1) - 1
		return g.flatList[idx%uint64(len(g.flatList))], true
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(key))
	return g.flatList[h.Sum32()%uint32(len(g.flatList))], true
}
