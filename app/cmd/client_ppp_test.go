package cmd

import (
	"net"
	"strconv"
	"testing"

	"github.com/apernet/hysteria/extras/v2/pppbridge"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The client's pppd command line.
//
// This decides the MTU the link is brought up at, and on OpenWrt it decides
// whether a pppd is spawned at all -- netifd owns the process there and the
// client is its child. Getting either wrong produces an interface that comes up
// and then does not pass full-size traffic, which is the hardest kind of fault
// for a subscriber to describe.

// argValue returns the value following flag, which is how pppd's command line is
// shaped: "mtu 1396", not "--mtu=1396".
func argValue(t *testing.T, args []string, flag string) string {
	t.Helper()
	for i, a := range args {
		if a == flag {
			require.Less(t, i+1, len(args), "%s has no value after it", flag)
			return args[i+1]
		}
	}
	t.Fatalf("%s is not in %v", flag, args)
	return ""
}

func argInt(t *testing.T, args []string, flag string) int {
	t.Helper()
	n, err := strconv.Atoi(argValue(t, args, flag))
	require.NoError(t, err)
	return n
}

func testRemote() net.Addr { return &net.UDPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 443} }

// nospawn is the OpenWrt case: netifd's pppd runs the client over its pty, so
// there is no command line to build at all.
func TestClientPPPNoSpawnBuildsNoCommand(t *testing.T) {
	inv, err := clientPPPDInvocation(pppConfig{Mode: "NoSpawn"}, testRemote(), false)
	require.NoError(t, err)
	assert.True(t, inv.noSpawn)
	assert.Empty(t, inv.path)
	assert.Empty(t, inv.args)
}

// nospawn hands the link to a pppd this process does not own, and SSTP works by
// spawning one. Asking for both is a configuration that cannot be satisfied.
func TestClientPPPNoSpawnRefusesSSTP(t *testing.T) {
	_, err := clientPPPDInvocation(pppConfig{Mode: "nospawn", SSTP: &pppSSTPConfig{}}, testRemote(), false)
	assert.Equal(t, "ppp.mode", fieldOf(t, err))
}

func TestClientPPPRejectsAnUnknownMode(t *testing.T) {
	_, err := clientPPPDInvocation(pppConfig{Mode: "l2tp"}, testRemote(), false)
	assert.Equal(t, "ppp.mode", fieldOf(t, err))
}

// The default command line is what nearly every client runs. LCP echo is the
// only thing that notices a link which is nominally up but silently dropping
// frames, so its absence would be a real regression rather than a cosmetic one.
func TestClientPPPDefaultCommandLine(t *testing.T) {
	inv, err := clientPPPDInvocation(pppConfig{}, testRemote(), false)
	require.NoError(t, err)
	assert.False(t, inv.noSpawn)
	assert.Equal(t, "pppd", inv.path)
	assert.False(t, inv.serverRoute, "without SSTP there is no server route to add")

	for _, want := range []string{
		"nodetach", "local", "+ipv6", "multilink",
		"lcp-echo-interval", "lcp-echo-failure", "lcp-echo-adaptive",
	} {
		assert.Contains(t, inv.args, want)
	}

	// The two size arguments are deliberately absent here. They depend on what
	// the session turns out to carry, and pppd reads them once at startup, so
	// they are applied to the child rather than decided in advance.
	assert.NotContains(t, inv.args, "mtu")
	assert.NotContains(t, inv.args, "mru")

	// What is fixed here is their shape: the MTU is the link ceiling less the
	// multilink header, the MRU is the ceiling itself, because what arrives is
	// not bundled.
	require.NotNil(t, inv.mtuArgsFn)
	sized := inv.mtuArgsFn(1400)
	assert.Equal(t, 1400, argInt(t, sized, "mru"))
	assert.Equal(t, 1400-pppbridge.MLPPPOverhead, argInt(t, sized, "mtu"),
		"multilink costs six octets on the way out and none on the way in")

	// With no negotiated figure the link falls back to exactly the estimate it
	// used to run on unconditionally.
	assert.Equal(t, pppbridge.AutoPPPMTU(pppbridge.MTUParams{RemoteAddr: testRemote()}), inv.fallbackMRU)
}

// An operator's explicit mtu is used for both directions verbatim: they have
// measured something the calculation cannot see, and second-guessing it would
// make the setting useless.
func TestClientPPPHonoursAnExplicitMTU(t *testing.T) {
	inv, err := clientPPPDInvocation(pppConfig{MTU: 1300}, testRemote(), false)
	require.NoError(t, err)
	assert.Equal(t, "1300", argValue(t, inv.args, "mtu"))
	assert.Equal(t, "1300", argValue(t, inv.args, "mru"))
	assert.Nil(t, inv.mtuArgsFn,
		"a number the operator chose is not one the session gets to move")
}

// Salamander costs 8 octets on every packet, and whether the client is using it
// has to reach the MTU calculation -- a regression that dropped the flag would
// be invisible until a subscriber on a narrow path could not pass full-size
// traffic.
//
// The two sizes can come out equal: on a path wide enough that quic-go's own
// 1452-octet packet cap binds first, there is nothing for the 8 octets to take
// from. So this pins the value against the calculation rather than asserting one
// is smaller, which would only hold on some hosts.
func TestClientPPPChargesForSalamander(t *testing.T) {
	for _, salamander := range []bool{false, true} {
		inv, err := clientPPPDInvocation(pppConfig{}, testRemote(), salamander)
		require.NoError(t, err)
		assert.Equal(t,
			pppbridge.AutoPPPMTU(pppbridge.MTUParams{RemoteAddr: testRemote(), Salamander: salamander}),
			inv.fallbackMRU,
			"salamander=%v must reach the MTU calculation", salamander)
	}
}

// A caller that supplies its own arguments gets them untouched -- no MTU is
// computed and nothing is appended.
func TestClientPPPLeavesSuppliedArgumentsAlone(t *testing.T) {
	given := []string{"nodetach", "debug", "mtu", "1000"}
	inv, err := clientPPPDInvocation(pppConfig{PPPDArgs: given, PPPDPath: "/opt/pppd"}, testRemote(), false)
	require.NoError(t, err)
	assert.Equal(t, given, inv.args)
	assert.Equal(t, "/opt/pppd", inv.path)
	assert.Nil(t, inv.mtuArgsFn,
		"nothing is appended to arguments the caller wrote, including a better MTU")
}

// ---------------------------------------------------------------------------
// SSTP
// ---------------------------------------------------------------------------

// With SSTP the local pppd is replaced by ppp-sstp, its own arguments come
// first, and the server's address is routed around the tunnel by default --
// otherwise the tunnel's own packets would be routed into it.
func TestClientPPPSSTPCommandLine(t *testing.T) {
	prev := logLevel
	logLevel = "debug"
	t.Cleanup(func() { logLevel = prev })

	inv, err := clientPPPDInvocation(pppConfig{SSTP: &pppSSTPConfig{}}, testRemote(), false)
	require.NoError(t, err)
	assert.Equal(t, "ppp-sstp", inv.path)
	assert.True(t, inv.serverRoute, "the server's address must not be routed into the tunnel")

	assert.Equal(t, "debug", argValue(t, inv.args, "-l"),
		"the SSTP helper inherits the client's log level unless told otherwise")
	assert.Equal(t, "127.0.0.1:8443", argValue(t, inv.args, "listen"))
	assert.Equal(t, []string{"-l", "debug", "listen", "127.0.0.1:8443"}, inv.args[:4],
		"ppp-sstp's own arguments come before pppd's")

	// SSTP is a single link, not a bundle, so both directions get the ceiling.
	require.NotNil(t, inv.mtuArgsFn)
	sized := inv.mtuArgsFn(1400)
	assert.Equal(t, "1400", argValue(t, sized, "mru"))
	assert.Equal(t, "1400", argValue(t, sized, "mtu"))
}

func TestClientPPPSSTPPassesEveryConfiguredOption(t *testing.T) {
	clamp := 1360
	no := false
	inv, err := clientPPPDInvocation(pppConfig{SSTP: &pppSSTPConfig{
		BinaryPath:  "/opt/ppp-sstp",
		Listen:      "0.0.0.0:8443",
		CertDir:     "/etc/sstp",
		Endpoint:    "vpn.example.net",
		User:        "alice",
		Password:    "hunter2",
		MSSClamp:    &clamp,
		ServerRoute: &no,
		LogLevel:    "warn",
	}}, testRemote(), false)
	require.NoError(t, err)

	assert.Equal(t, "/opt/ppp-sstp", inv.path)
	assert.False(t, inv.serverRoute, "an explicit false must be honoured, not treated as unset")
	assert.Equal(t, "warn", argValue(t, inv.args, "-l"))
	assert.Equal(t, "0.0.0.0:8443", argValue(t, inv.args, "listen"))
	assert.Equal(t, "/etc/sstp", argValue(t, inv.args, "cert-dir"))
	assert.Equal(t, "vpn.example.net", argValue(t, inv.args, "endpoint"))
	assert.Equal(t, "alice", argValue(t, inv.args, "user"))
	assert.Equal(t, "hunter2", argValue(t, inv.args, "password"))
	assert.Equal(t, "1360", argValue(t, inv.args, "mss-clamp"))
}

// An MSS clamp of zero is "off", which is a different instruction from "decide
// for me" -- so it has to reach the helper rather than being dropped as a zero
// value.
func TestClientPPPSSTPPassesAZeroMSSClamp(t *testing.T) {
	off := 0
	args := buildSSTPArgs(&pppSSTPConfig{MSSClamp: &off})
	assert.Equal(t, "0", argValue(t, args, "mss-clamp"))

	auto := buildSSTPArgs(&pppSSTPConfig{})
	assert.NotContains(t, auto, "mss-clamp", "nil means the helper chooses")
}

// The path is only defaulted; an explicit pppdPath wins over the SSTP binary
// path, because that is the more specific instruction.
func TestClientPPPSSTPPathPrecedence(t *testing.T) {
	inv, err := clientPPPDInvocation(pppConfig{
		PPPDPath: "/usr/local/bin/sstp-wrapper",
		SSTP:     &pppSSTPConfig{BinaryPath: "/opt/ppp-sstp"},
	}, testRemote(), false)
	require.NoError(t, err)
	assert.Equal(t, "/usr/local/bin/sstp-wrapper", inv.path)
}
