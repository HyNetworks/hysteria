package cmd

import (
	"errors"
	"os"
	"testing"

	"github.com/apernet/hysteria/core/v2/server"
	"github.com/apernet/hysteria/extras/v2/pppbridge"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// The server's PPP configuration surface.
//
// This is where an operator's YAML becomes a running LAC, and it is the last
// place a mistake can be caught cheaply. A route pointing at a group that does
// not exist, or a group with no LNS in it, must stop the server at startup with
// the field named -- not produce a LAC that accepts subscribers and then has
// nowhere to send them.

// withTestLogger installs a logger for the duration of a test. The package-level
// one is nil until the CLI initialises it, and every path here logs.
func withTestLogger(t *testing.T) {
	t.Helper()
	prev := logger
	logger = zap.NewNop()
	t.Cleanup(func() { logger = prev })
}

func fieldOf(t *testing.T, err error) string {
	t.Helper()
	var ce configError
	require.ErrorAs(t, err, &ce, "a configuration problem must name its field")
	return ce.Field
}

func TestFillPPPConfigDoesNothingWhenPPPIsOff(t *testing.T) {
	withTestLogger(t)
	var hy server.Config
	c := &serverConfig{}
	require.NoError(t, c.fillPPPConfig(&hy))
	assert.Nil(t, hy.PPPRequestHandler, "a disabled ppp block must not install a handler")
}

func TestFillPPPConfigRejectsAnUnknownMode(t *testing.T) {
	withTestLogger(t)
	var hy server.Config
	c := &serverConfig{}
	c.PPP.Enabled = true
	c.PPP.Mode = "l2tpv3"
	assert.Equal(t, "ppp.mode", fieldOf(t, c.fillPPPConfig(&hy)))
}

// Local mode is the default, and an unset pppd path has to resolve to the usual
// one rather than to the empty string.
func TestFillPPPConfigLocalDefaults(t *testing.T) {
	withTestLogger(t)
	var hy server.Config
	c := &serverConfig{}
	c.PPP.Enabled = true
	c.PPP.IPv4Pool = "10.10.0.0/24"
	c.PPP.DNS = []string{"1.1.1.1"}
	c.PPP.MTU = 1380
	c.Obfs.Type = "Salamander"

	require.NoError(t, c.fillPPPConfig(&hy))
	h, ok := hy.PPPRequestHandler.(*pppbridge.ServerPPPHandler)
	require.True(t, ok, "local mode installs the local handler")
	assert.Equal(t, "/usr/sbin/pppd", h.PPPDPath)
	assert.Equal(t, 1380, h.MTU)
	assert.Equal(t, []string{"1.1.1.1"}, h.DNS)
	require.NotNil(t, h.IPv4Pool)
	assert.Equal(t, "10.10.0.1", h.IPv4Pool.Gateway())
	assert.True(t, h.Salamander,
		"the obfuscation costs 8 octets per packet, so the MTU calculation has to know about it")
}

// No pool at all is a valid IPv6-only deployment, not an error.
func TestFillPPPConfigLocalWithoutAnIPv4Pool(t *testing.T) {
	withTestLogger(t)
	var hy server.Config
	c := &serverConfig{}
	c.PPP.Enabled = true
	c.PPP.Mode = "LOCAL" // the mode is matched case-insensitively
	c.PPP.PPPDPath = "/opt/sbin/pppd"

	require.NoError(t, c.fillPPPConfig(&hy))
	h := hy.PPPRequestHandler.(*pppbridge.ServerPPPHandler)
	assert.Nil(t, h.IPv4Pool)
	assert.Equal(t, "/opt/sbin/pppd", h.PPPDPath)
}

func TestFillPPPConfigLocalRejectsABadPool(t *testing.T) {
	withTestLogger(t)
	var hy server.Config
	c := &serverConfig{}
	c.PPP.Enabled = true
	c.PPP.IPv4Pool = "10.10.0.0/31" // too small to hold a gateway and a client
	assert.Equal(t, "ppp.ipv4Pool", fieldOf(t, c.fillPPPConfig(&hy)))
}

// l2tpServer returns a minimally valid LAC configuration for a test to spoil.
func l2tpServer() *serverConfig {
	c := &serverConfig{}
	c.PPP.Enabled = true
	c.PPP.Mode = "l2tp"
	c.PPP.L2TP.Hostname = "test-lac"
	c.PPP.L2TP.Groups = map[string]pppL2TPGroupConfig{
		"core": {LNS: []pppLNSConfig{{Address: "198.51.100.1:1701", Secret: "s"}}},
	}
	c.PPP.L2TP.Routes = []pppRouteConfig{{ID: "*", Group: "core"}}
	return c
}

func TestFillPPPConfigL2TPBuildsTheLAC(t *testing.T) {
	withTestLogger(t)
	var hy server.Config
	c := l2tpServer()
	c.PPP.L2TP.HelloInterval = 60

	require.NoError(t, c.fillPPPConfig(&hy))
	h, ok := hy.PPPRequestHandler.(*pppbridge.L2TPPPPHandler)
	require.True(t, ok, "l2tp mode installs the LAC handler")
	require.NotNil(t, h.TunnelManager)
	require.NotNil(t, h.IDRouter)
	require.NotNil(t, h.LoadBalancer)

	assert.Equal(t, "core", h.IDRouter.Match("anyone@example.net"),
		"a catch-all route must accept an identity nothing else claimed")
	lns, ok := h.LoadBalancer.PickSticky("core", "anyone@example.net")
	require.True(t, ok)
	assert.Equal(t, "198.51.100.1:1701", lns.Address)

	// The tunnels have to be torn down with the server, or the LNS holds every
	// subscriber's session until its own HELLO timeout expires.
	require.NotNil(t, hy.Cleanup, "the tunnel manager must be closed on shutdown")
	assert.NoError(t, hy.Cleanup.Close())
}

// Each of these is a configuration that would produce a LAC unable to place a
// call. All of them must be refused at startup, with the offending field named.
func TestFillPPPConfigL2TPRejectsIncompleteConfigurations(t *testing.T) {
	tests := []struct {
		name  string
		spoil func(c *serverConfig)
		field string
	}{
		{
			name:  "no groups at all",
			spoil: func(c *serverConfig) { c.PPP.L2TP.Groups = nil },
			field: "ppp.l2tp.groups",
		},
		{
			name: "a group with no LNS in it",
			spoil: func(c *serverConfig) {
				c.PPP.L2TP.Groups = map[string]pppL2TPGroupConfig{"core": {}}
			},
			field: "ppp.l2tp.groups.core.lns",
		},
		{
			name: "an LNS with no address",
			spoil: func(c *serverConfig) {
				c.PPP.L2TP.Groups = map[string]pppL2TPGroupConfig{
					"core": {LNS: []pppLNSConfig{{Secret: "s"}}},
				}
			},
			field: "ppp.l2tp.groups.core.lns.address",
		},
		{
			name:  "no routes at all",
			spoil: func(c *serverConfig) { c.PPP.L2TP.Routes = nil },
			field: "ppp.l2tp.routes",
		},
		{
			name: "a route with no identity",
			spoil: func(c *serverConfig) {
				c.PPP.L2TP.Routes = []pppRouteConfig{{Group: "core"}}
			},
			field: "ppp.l2tp.routes.id",
		},
		{
			name: "a route pointing at a group that does not exist",
			spoil: func(c *serverConfig) {
				c.PPP.L2TP.Routes = []pppRouteConfig{{ID: "*", Group: "typo"}}
			},
			field: "ppp.l2tp.routes.group",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withTestLogger(t)
			var hy server.Config
			c := l2tpServer()
			tt.spoil(c)
			err := c.fillPPPConfig(&hy)
			assert.Equal(t, tt.field, fieldOf(t, err))
			assert.Nil(t, hy.PPPRequestHandler, "a refused configuration must install nothing")
		})
	}
}

// The LAC's hostname reaches the LNS in the SCCRQ and is what an operator sees
// in their logs. It falls back to the environment, then to the machine's own
// name.
func TestFillPPPConfigL2TPHostnameFallback(t *testing.T) {
	withTestLogger(t)
	t.Setenv("HYSTERIA_LAC_HOSTNAME", "lac-from-env")

	var hy server.Config
	c := l2tpServer()
	c.PPP.L2TP.Hostname = ""
	require.NoError(t, c.fillPPPConfig(&hy))
	require.NotNil(t, hy.Cleanup)
	t.Cleanup(func() { _ = hy.Cleanup.Close() })

	// With the environment empty it falls back to the host's own name, which is
	// whatever this machine is called.
	t.Setenv("HYSTERIA_LAC_HOSTNAME", "")
	var hy2 server.Config
	c2 := l2tpServer()
	c2.PPP.L2TP.Hostname = ""
	host, err := os.Hostname()
	if err != nil || host == "" {
		t.Skip("this machine has no hostname to fall back to")
	}
	require.NoError(t, c2.fillPPPConfig(&hy2))
	require.NotNil(t, hy2.Cleanup)
	assert.NoError(t, hy2.Cleanup.Close())
}

// Weight is how an operator sends more calls to a bigger LNS. A weight of zero
// or below means "no preference", not "never pick this one".
func TestFillPPPConfigL2TPTreatsAnUnsetWeightAsOne(t *testing.T) {
	withTestLogger(t)
	var hy server.Config
	c := l2tpServer()
	c.PPP.L2TP.Groups = map[string]pppL2TPGroupConfig{
		"core": {LNS: []pppLNSConfig{
			{Address: "198.51.100.1:1701"},
			{Address: "198.51.100.2:1701", Weight: -5},
		}},
	}
	require.NoError(t, c.fillPPPConfig(&hy))
	h := hy.PPPRequestHandler.(*pppbridge.L2TPPPPHandler)
	t.Cleanup(func() { _ = hy.Cleanup.Close() })

	seen := map[string]bool{}
	for _, id := range []string{"a", "b", "c", "d", "e", "f", "g", "h"} {
		lns, ok := h.LoadBalancer.PickSticky("core", id)
		require.True(t, ok)
		seen[lns.Address] = true
	}
	assert.Len(t, seen, 2, "both LNS must be reachable, whatever weight they were given")
}

// ---------------------------------------------------------------------------
// chainCloser
// ---------------------------------------------------------------------------

// The server may already have a Cleanup by the time PPP configuration runs, and
// replacing it would leak whatever it was closing. Every closer must run, and
// one that fails must not stop the others.
func TestChainCloserClosesEverythingAndKeepsEveryError(t *testing.T) {
	var order []string
	failing := closerFunc(func() error { order = append(order, "a"); return errors.New("a failed") })
	working := closerFunc(func() error { order = append(order, "b"); return nil })
	alsoFailing := closerFunc(func() error { order = append(order, "c"); return errors.New("c failed") })

	err := chainCloser(nil, failing, nil, working, alsoFailing).Close()
	assert.Equal(t, []string{"a", "b", "c"}, order, "a failure must not stop the chain")
	assert.ErrorContains(t, err, "a failed")
	assert.ErrorContains(t, err, "c failed")

	// A single closer is passed through rather than wrapped.
	only := closerFunc(func() error { return nil })
	assert.NotNil(t, chainCloser(nil, only))
	assert.NoError(t, chainCloser(nil, only).Close())
}
