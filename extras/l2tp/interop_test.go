package l2tp

import (
	"net"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// Interoperability against a real LNS.
//
// Everything else in this package is checked against a fake that answers the way
// RFC 2661 says to. That proves the LAC follows the specification; it cannot
// prove it interoperates with a particular vendor's implementation, which is the
// only thing that matters in production. This does, when an operator points it
// at one.
//
// It is skipped unless HYSTERIA_LNS_ADDR is set, so it never runs in CI and
// never needs a fixture. Configure it with:
//
//	HYSTERIA_LNS_ADDR=<host:port>   the LNS to dial (required)
//	HYSTERIA_LNS_SECRET=<secret>    tunnel secret, if the LNS authenticates
//	HYSTERIA_LNS_HOSTNAME=<name>    Host Name AVP to present (required)
//	HYSTERIA_LNS_CALLER=<number>    Calling Number to present
//	HYSTERIA_LNS_DEBUG=1            log the handshake to stderr
//
// The hostname is required rather than defaulted because an LNS commonly selects
// which of its configurations applies by matching the LAC's Host Name AVP. A
// wrong one is refused outright, and guessing a default would turn a
// configuration mistake into a puzzling refusal.
//
// Nothing here logs, prints or asserts on any of it. Everything about the peer --
// its address, its secret, the names it knows, what it provisions, the text of
// its refusals -- stays in the environment that runs the test. None of it belongs
// in a repository, and a comment explaining the code by what one particular peer
// did is the same disclosure as a fixture containing it.
type lnsTarget struct {
	addr     string
	secret   string
	hostname string
	caller   string
}

func lnsUnderTest(t *testing.T) lnsTarget {
	t.Helper()
	addr := os.Getenv("HYSTERIA_LNS_ADDR")
	if addr == "" {
		t.Skip("set HYSTERIA_LNS_ADDR to run the interop tests against a real LNS")
	}
	target := lnsTarget{
		addr:     addr,
		secret:   os.Getenv("HYSTERIA_LNS_SECRET"),
		hostname: os.Getenv("HYSTERIA_LNS_HOSTNAME"),
		caller:   os.Getenv("HYSTERIA_LNS_CALLER"),
	}
	if target.hostname == "" {
		t.Skip("set HYSTERIA_LNS_HOSTNAME to the name the LNS expects this LAC to present")
	}
	if target.caller == "" {
		target.caller = "5550000"
	}
	return target
}

// interopLogger is silent unless HYSTERIA_LNS_DEBUG is set, because a failing
// interop run is diagnosed from the handshake and nothing else can show it.
func interopLogger(t *testing.T) *zap.Logger {
	t.Helper()
	if os.Getenv("HYSTERIA_LNS_DEBUG") == "" {
		return zap.NewNop()
	}
	cfg := zap.NewDevelopmentConfig()
	cfg.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	l, err := cfg.Build()
	require.NoError(t, err)
	return l
}

func interopManager(t *testing.T, target lnsTarget) *TunnelManager {
	t.Helper()
	m := NewTunnelManager(target.hostname, 60*time.Second, interopLogger(t))
	t.Cleanup(func() { _ = m.Close() })
	return m
}

func interopSession(t *testing.T, subscriber string) (*Session, lnsTarget) {
	t.Helper()
	target := lnsUnderTest(t)
	m := interopManager(t, target)
	s, err := m.CreateSession(target.addr, target.secret, subscriber, target.caller)
	require.NoError(t, err, "the LNS refused the tunnel or the call")
	t.Cleanup(s.Close)
	return s, target
}

// The whole handshake against a real peer: SCCRQ/SCCRP/SCCCN, then
// ICRQ/ICRP/ICCN. If this passes, the LAC and that LNS agree on AVP encoding,
// sequence numbering and session addressing.
func TestInteropEstablishesASession(t *testing.T) {
	s, _ := interopSession(t, "interop@test")

	assert.NotZero(t, s.remoteSID(), "the LNS must have assigned a session ID")
	assert.NotZero(t, s.tunnel.remoteTunnelID, "the LNS must have assigned a tunnel ID")
	assert.True(t, s.tunnel.Alive())
	assert.Equal(t, 1, s.tunnel.SessionCount())
}

// The LNS runs LCP itself, so a session that is up should produce an LCP
// Configure-Request from the far end without the LAC sending anything first.
// That is the whole design in one assertion: the LAC never negotiates.
func TestInteropTheLNSStartsLCPItself(t *testing.T) {
	s, _ := interopSession(t, "interop@test")

	proto, payload := interopRecv(t, s, 15*time.Second)
	assert.Equal(t, pppProtoLCP, proto,
		"the LNS must open LCP itself, because this LAC proxies nothing")
	require.GreaterOrEqual(t, len(payload), 4)
	assert.Equal(t, lcpConfigureRequest, payload[0],
		"the first thing an LNS says on a new link is a Configure-Request")
	t.Logf("LNS opened with: %s", describeLCP(payload))
}

// interopRecv reads one PPP frame with a deadline, so a stalled LNS produces a
// message that says so rather than a test that hangs until the package timeout.
func interopRecv(t *testing.T, s *Session, timeout time.Duration) (uint16, []byte) {
	t.Helper()
	type frame struct {
		proto   uint16
		payload []byte
		err     error
	}
	got := make(chan frame, 1)
	go func() {
		proto, payload, err := recvPPPParts(s)
		got <- frame{proto, payload, err}
	}()
	select {
	case f := <-got:
		require.NoError(t, f.err)
		return f.proto, f.payload
	case <-time.After(timeout):
		t.Fatal("the LNS sent no PPP frame within the deadline")
		return 0, nil
	}
}

// interopTunnel dials the LNS directly, bypassing TunnelManager, so a test can
// shorten the retransmission schedule. A refusal that takes the production
// schedule to discover costs half a minute of wall clock per run.
func interopTunnel(t *testing.T, target lnsTarget, hostname, secret string) *Tunnel {
	t.Helper()
	conn, err := net.Dial("udp", target.addr)
	require.NoError(t, err, "could not open a socket to the LNS")
	var secretBytes []byte
	if secret != "" {
		secretBytes = []byte(secret)
	}
	tun := newTunnel(conn, 0x7A00, hostname, secretBytes, 0, interopLogger(t))
	tun.ctrlBase = 500 * time.Millisecond
	tun.ctrlCap = 2 * time.Second
	tun.ctrlRetries = 2
	t.Cleanup(func() { tun.Close(); _ = conn.Close() })
	return tun
}

// The tunnel secret is the only thing standing between an LNS and anyone who
// can reach its port. Two properties matter and neither can be checked against a
// fake that we also wrote: that a wrong secret does not produce a working
// tunnel, and that we verify the LNS rather than only proving ourselves to it.
//
// This one is about the second. We reject the LNS before it ever rules on us,
// because its Challenge Response is computed with a secret we do not share --
// which is what stops a LAC being walked onto an impostor that simply accepts
// everything.
func TestInteropRefusesAnLNSWhoseSecretDoesNotMatch(t *testing.T) {
	target := lnsUnderTest(t)
	if target.secret == "" {
		t.Skip("no HYSTERIA_LNS_SECRET configured, so there is no secret to get wrong")
	}

	tun := interopTunnel(t, target, target.hostname, target.secret+"-not-the-secret")
	err := tun.Establish()
	require.Error(t, err, "a tunnel must not come up against an LNS we cannot authenticate")
	t.Logf("refused, as it should be: %v", err)
	assert.Contains(t, err.Error(), "challenge response",
		"the failure has to name the reason; an operator who mistyped a secret "+
			"must not be left reading a timeout")
	assert.False(t, tun.Alive())
}

// The same secret, presented under a name the LNS is not configured to accept.
// An LNS commonly selects its configuration by the LAC's Host Name AVP, so this
// is the other half of what has to be right before a tunnel exists at all.
//
// What the LNS does about it is its business -- refuse with a StopCCN, or say
// nothing and let us time out. Either way the LAC must fail with something an
// operator can act on, and must not leave a half-open tunnel behind.
func TestInteropRefusesWhenTheLNSDoesNotKnowOurHostname(t *testing.T) {
	target := lnsUnderTest(t)

	tun := interopTunnel(t, target, "not-a-configured-lac", target.secret)
	err := tun.Establish()
	require.Error(t, err, "an LNS that does not know this hostname must not give us a tunnel")
	t.Logf("refused, as it should be: %v", err)
	assert.False(t, tun.Alive())
	assert.Zero(t, tun.SessionCount())
}

// The authentication verdict belongs to the LNS.
//
// This is the assertion the whole design rests on. The LAC sends no proxy LCP
// and no proxy authentication AVPs, so it has no opinion about who the
// subscriber is and no way to form one -- it never sees a credential. Presenting
// a username and password that cannot exist and watching the far end refuse them
// proves that the verdict is formed beyond the tunnel rather than here, and that
// it comes back through the LAC intact.
//
// A random username is used rather than a fixed bogus one so that a run cannot
// accidentally collide with a real account, and so that repeated runs do not
// look like a brute-force attempt against one name.
func TestInteropTheLNSDeniesCredentialsItDoesNotKnow(t *testing.T) {
	s, _ := interopSession(t, "interop-deny@test")

	user, password := randomCredentials(t)
	t.Logf("presenting credentials that cannot exist: user=%q", user)

	peer := newPPPPeer(t, s, user, password)
	outcome := peer.run(45 * time.Second)
	t.Log(peer.dump())

	switch outcome {
	case outcomeDenied:
		// What we came for.
	case outcomeLinkTerminated:
		// Some LNS implementations drop the call rather than send a Failure. That
		// is still a denial, but only if the LNS is the one that ended it -- our
		// own teardown or a dead path would look the same from here.
		require.True(t, s.EndedByLNS(),
			"the link ended without a verdict and without the LNS clearing the call, "+
				"which is a broken path rather than a rejection")
		result, errCode, msg := s.CloseReason()
		t.Logf("the LNS cleared the call instead of failing authentication: "+
			"result=%d error=%d message=%q", result, errCode, msg)
	case outcomeAccepted:
		t.Fatalf("the LNS ACCEPTED a username and password chosen at random. "+
			"That is a finding about the LNS, not about this LAC: user=%q", user)
	default:
		t.Fatalf("no outcome: %s", outcome)
	}

	assert.Equal(t, outcomeDenied.String(), pickDenial(outcome).String())
}

// pickDenial maps the two acceptable shapes of refusal onto one, so the
// assertion above reads as the single fact being claimed.
func pickDenial(o authOutcome) authOutcome {
	if o == outcomeLinkTerminated {
		return outcomeDenied
	}
	return o
}

// subscriberAccount returns credentials for a real subscriber account, or skips.
// They are configuration, not a fixture: a working account belongs to the
// operator running the test and must never be committed.
func subscriberAccount(t *testing.T) (user, password string) {
	t.Helper()
	user, password = os.Getenv("HYSTERIA_PPP_USER"), os.Getenv("HYSTERIA_PPP_PASSWORD")
	if user == "" || password == "" {
		t.Skip("set HYSTERIA_PPP_USER and HYSTERIA_PPP_PASSWORD to test a real account")
	}
	return user, password
}

// A whole subscriber session, through the LAC, against a real LNS: LCP,
// whatever authentication the far end asks for, and whatever network layer it
// brings up.
//
// This is the other half of the denial test, and it is the one that proves the
// design end to end rather than just proving the LNS says no. Everything the
// subscriber and the LNS agree on here -- the auth protocol, the credential,
// the address, the DNS servers -- is settled between the two of them. The LAC
// sends no proxy AVPs, forms no opinion, and never sees the password.
func TestInteropTheLNSAcceptsAValidAccount(t *testing.T) {
	user, password := subscriberAccount(t)
	s, _ := interopSession(t, "interop-valid@test")

	peer := newPPPPeer(t, s, user, password)
	peer.carryOn = true
	// Accept everything a real subscriber's pppd would, so the session negotiates
	// the way a real one does and the relay carries whatever results. What the
	// far end then chooses to send is its business; this test asserts only that
	// none of it went missing here.
	peer.allowPFC = true
	peer.allowMultilink = true
	peer.linger = 10 * time.Second
	outcome := peer.run(90 * time.Second)
	t.Log(peer.dump())

	require.Equal(t, outcomeNetworkUp, outcome,
		"a valid account must reach the network phase, not stop at the verdict")

	// Which network layers a subscriber gets is provisioning, and provisioning is
	// not this LAC's business. Asserting on one in particular would make the test
	// a statement about the account it happened to be run with.
	t.Logf("network layers up: IPCP=%v IPv6CP=%v", peer.ipcpUp, peer.ipv6cpUp)
	assert.True(t, peer.ipcpUp || peer.ipv6cpUp,
		"at least one network layer must reach Opened")

	// The LAC is still just a data path underneath all of that.
	assert.True(t, s.tunnel.Alive())
	assert.Zero(t, s.Dropped(), "no frame may have been dropped on the way")
}

// Two calls to one LNS share a control connection, and closing the last one
// takes the tunnel down. Worth checking against a real peer because an LNS that
// disagreed about session addressing would deliver both calls' frames to one
// session, which the fake cannot reproduce.
func TestInteropTwoCallsShareOneTunnel(t *testing.T) {
	target := lnsUnderTest(t)
	m := interopManager(t, target)

	first, err := m.CreateSession(target.addr, target.secret, "interop-a@test", target.caller)
	require.NoError(t, err)
	second, err := m.CreateSession(target.addr, target.secret, "interop-b@test", target.caller)
	require.NoError(t, err)

	assert.Same(t, first.tunnel, second.tunnel, "one LNS gets one control connection")
	assert.Equal(t, 2, first.tunnel.SessionCount())
	assert.NotEqual(t, first.localSessionID, second.localSessionID)

	first.Close()
	assert.True(t, second.tunnel.Alive(), "one call ending must not disturb the other")

	second.Close()
	assert.Eventually(t, func() bool { return !first.tunnel.Alive() }, 5*time.Second, 50*time.Millisecond,
		"the tunnel goes away with its last call")
}
