package pppbridge

import (
	"testing"
	"time"

	"github.com/apernet/hysteria/extras/v2/l2tp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// Disruptions to a session that is already up and carrying traffic.
//
// The lifecycle tests in e2e_test.go walk a session from LCP to teardown along
// the path everything works. These start from a working session and break it the
// ways it actually breaks in service: the subscriber's uplink disappears, the LNS
// goes down for maintenance, the subscriber hangs up. What matters in each case
// is not only that the session ends, but that the far side is told and the
// resources go back.

// awaitSeen waits for a control message of the given type to reach the LNS.
func (f *fakeLNS) awaitSeen(t *testing.T, want uint16, why string) {
	t.Helper()
	deadline := time.After(testTimeout)
	for {
		select {
		case got := <-f.seen:
			if got == want {
				return
			}
		case <-deadline:
			t.Fatalf("the LNS never received message type %d: %s", want, why)
		}
	}
}

// upWithLNSAccepting brings an L2TP-mode session all the way to carrying user
// data: negotiated, proxied to the LNS, accepted, auth result delivered, and the
// LNS's IPCP relayed through. Returns with nothing outstanding on either side.
func upAndCarryingTraffic(t *testing.T, h *l2tpHarness) {
	t.Helper()
	h.bringUp(t)

	// The LNS is mid-negotiation with the subscriber; the LAC neither knows nor
	// cares how far along it is.
	h.lns.sendPPP(pppProtoIPCP, buildLCPPacket(lcpConfigRequest, 0x31, []byte{0x03, 0x06, 10, 0, 0, 1}))
	proto, _ := h.client.recvPacket()
	require.Equal(t, pppProtoIPCP, proto)

	h.client.sendPacket(pppProtoIPv4, []byte{0x45, 0x00, 0x00, 0x14})
	got := h.lns.nextData(t)
	require.Equal(t, pppProtoIPv4, got.proto)
}

// The subscriber's uplink disappears -- a phone leaving coverage, a router
// rebooting. This is the most common way a session ends in service, and it is
// the one the LAC has to handle without being told anything.
//
// The LNS must be told promptly. Without a CDN it holds the call up until its
// own HELLO timeout expires, keeping the subscriber's address allocated and, on
// many LNS implementations, refusing a reconnect from the same subscriber while
// the stale call is open. "It timed out eventually" is not good enough.
func TestL2TPModeClientTransportDropTearsDownTheLNSSession(t *testing.T) {
	h := newL2TPHarness(t)
	upAndCarryingTraffic(t, h)

	// The client's QUIC connection dies underneath the session.
	h.pair.shutdown()

	select {
	case <-h.handlerDone:
	case <-time.After(testTimeout):
		t.Fatal("the LAC did not notice its client had gone")
	}

	h.lns.awaitSeen(t, l2tp.MsgTypeCDN,
		"a client that vanished must still produce a CDN, or the LNS holds the call "+
			"and the subscriber's address until its HELLO timeout")

	// The tunnel had only this session, so it goes too rather than lingering.
	h.lns.awaitSeen(t, l2tp.MsgTypeStopCCN,
		"the last session ending must take its tunnel with it")
}

// The LNS goes away mid-session -- a maintenance window, or a control connection
// reset. RFC 2661 s3.3 makes StopCCN an implicit teardown of every session in the
// tunnel, and it says nothing about any subscriber's credentials, so the client
// has to be told something it will retry.
func TestL2TPModeStopCCNMidSessionReachesTheClientAsRetryable(t *testing.T) {
	h := newL2TPHarness(t)
	upAndCarryingTraffic(t, h)

	h.lns.sendStopCCN(1, 0, "shutting down for maintenance")

	select {
	case <-h.handlerDone:
	case <-time.After(testTimeout):
		t.Fatal("a StopCCN must end the session it implicitly terminated")
	}

	reason := h.control.awaitReason(t)
	assert.Equal(t, ReasonLNSDisconnected, reason.Code)
	assert.False(t, reason.Code.Permanent(),
		"an LNS going down for maintenance must not stop the subscriber redialling")
	assert.Equal(t, "shutting down for maintenance", reason.Message,
		"what the LNS said is the only specific thing there is to pass on")
}

// The subscriber hangs up cleanly. A Terminate-Request is just another PPP frame:
// the LAC must relay it to the LNS rather than interpreting it, because the LNS
// owns the PPP session and is the side that answers.
//
// This also pins the design decision that PPP events do not reach the link --
// the LAC must not tear its own session down on seeing one.
func TestL2TPModeClientTerminateRequestIsRelayedNotInterpreted(t *testing.T) {
	h := newL2TPHarness(t)
	upAndCarryingTraffic(t, h)

	term := buildLCPPacket(lcpTermRequest, 0x51, []byte("bye"))
	h.client.sendPacket(pppProtoLCP, term)

	got := h.lns.nextData(t)
	assert.Equal(t, pppProtoLCP, got.proto, "a Terminate-Request must reach the LNS")
	assert.Equal(t, term, got.payload, "verbatim -- the LAC does not rewrite PPP")

	// The LAC has not decided anything on its own: the session is still up, and
	// the LNS's Terminate-Ack still gets through.
	select {
	case <-h.handlerDone:
		t.Fatal("the LAC tore its own session down on a PPP frame; only the LNS may answer")
	case <-time.After(150 * time.Millisecond):
	}

	ack := buildLCPPacket(lcpTermAck, 0x51, nil)
	h.lns.sendPPP(pppProtoLCP, ack)
	proto, pkt := h.client.recvPacket()
	assert.Equal(t, pppProtoLCP, proto)
	assert.Equal(t, lcpTermAck, pkt[0], "the LNS's answer reaches the subscriber")
}

func TestLocalModeSessionComesBackUpAfterALinkDrop(t *testing.T) {
	first := newLocalHarness(t)
	first.bringUp(t)
	require.Equal(t, lcpConfigRequest, first.server.recv()[4])
	_ = first.client.recv()
	first.relayed(t, first.client, first.server, "client -> server: IPv4",
		buildPPPFrame(pppProtoIPv4, []byte{0x45, 0x00}))

	// The uplink goes away.
	first.pair.shutdown()
	select {
	case <-first.clientDone:
	case <-time.After(testTimeout):
		t.Fatal("a dropped link must end the client's session")
	}
	var linkDown *LinkDownError
	require.ErrorAs(t, first.clientErr, &linkDown,
		"the caller has to be told it was the link, so it knows to rebuild")

	// The caller rebuilds, which is what netifd does. A second session must come
	// up exactly like the first.
	second := newLocalHarness(t)
	second.bringUp(t)
	require.Equal(t, lcpConfigRequest, second.server.recv()[4],
		"the rebuilt session must carry LCP again")
	_ = second.client.recv()
	second.relayed(t, second.client, second.server, "client -> server: IPv4 after redial",
		buildPPPFrame(pppProtoIPv4, []byte{0x45, 0x11}))
	second.relayed(t, second.server, second.client, "server -> client: IPv4 after redial",
		buildPPPFrame(pppProtoIPv4, []byte{0x45, 0x22}))
}

// Two subscribers down one tunnel, which is the whole point of a LAC.
//
// Both calls share a single L2TP control connection, so every frame the LNS sends
// has to be demultiplexed by session ID. A mistake here does not fail loudly --
// it delivers one subscriber's traffic to another, which is a correctness and a
// privacy failure at once. The bug this class produces is real: handleCDN used to
// resolve sessions by scanning a field it read without synchronisation, and could
// close the wrong call.
//
// The calls are brought up one after the other so the mapping between subscriber
// and session ID is unambiguous; what is being tested is two *live* sessions, not
// racing setup.
func TestL2TPModeTwoSubscribersShareOneTunnelWithoutCrosstalk(t *testing.T) {
	lns := newFakeLNS(t)
	tm := l2tp.NewTunnelManager("test-lac", 0, zap.NewNop())
	t.Cleanup(func() { _ = tm.Close() })

	alice := newL2TPHarness(t, withSharedInfra(lns, tm))
	upAndCarryingTraffic(t, alice)

	bob := newL2TPHarness(t, withSharedInfra(lns, tm))
	upAndCarryingTraffic(t, bob)

	// One tunnel, two calls.
	assert.EqualValues(t, 1, lns.sccrqs.Load(),
		"the second call must reuse the tunnel, not build a second one")
	callA, callB := lns.call(t, 0), lns.call(t, 1)
	assert.NotEqual(t, callA.lac, callB.lac, "each call needs its own LAC session ID")
	assert.NotEqual(t, callA.lns, callB.lns, "and its own LNS session ID")

	// Downstream: a frame addressed to one call must reach only that subscriber.
	toAlice := buildLCPPacket(lcpConfigRequest, 0xA1, []byte{0x03, 0x06, 10, 0, 0, 7})
	lns.sendPPPTo(callA.lac, pppProtoIPCP, toAlice)

	proto, pkt := alice.client.recvPacket()
	assert.Equal(t, pppProtoIPCP, proto)
	assert.Equal(t, toAlice, pkt, "alice gets her own frame")
	bob.client.assertSilent("bob must not see traffic addressed to alice")

	toBob := buildLCPPacket(lcpConfigRequest, 0xB1, []byte{0x03, 0x06, 10, 0, 0, 8})
	lns.sendPPPTo(callB.lac, pppProtoIPCP, toBob)

	proto, pkt = bob.client.recvPacket()
	assert.Equal(t, pppProtoIPCP, proto)
	assert.Equal(t, toBob, pkt, "bob gets his own frame")
	alice.client.assertSilent("alice must not see traffic addressed to bob")

	// Upstream: each subscriber's frames reach the LNS tagged with their own
	// session, so the LNS can tell them apart too.
	alice.client.sendPacket(pppProtoIPv4, []byte{0x45, 0xAA})
	bob.client.sendPacket(pppProtoIPv4, []byte{0x45, 0xBB})

	bySession := map[uint16][]byte{}
	for i := 0; i < 2; i++ {
		d := lns.nextData(t)
		bySession[d.session] = d.payload
	}
	assert.Equal(t, []byte{0x45, 0xAA}, bySession[callA.lns], "alice's frame arrives as alice's session")
	assert.Equal(t, []byte{0x45, 0xBB}, bySession[callB.lns], "bob's frame arrives as bob's session")

	// One subscriber hanging up must not disturb the other, and must not take the
	// shared tunnel with it.
	alice.pair.shutdown()
	select {
	case <-alice.handlerDone:
	case <-time.After(testTimeout):
		t.Fatal("alice's session did not end")
	}
	lns.awaitSeen(t, l2tp.MsgTypeCDN, "alice's call must be disconnected at the LNS")

	select {
	case <-bob.handlerDone:
		t.Fatal("bob's session ended when alice hung up")
	case <-time.After(200 * time.Millisecond):
	}

	// And bob still works afterwards.
	stillWorks := buildLCPPacket(lcpConfigRequest, 0xB2, nil)
	lns.sendPPPTo(callB.lac, pppProtoIPCP, stillWorks)
	proto, pkt = bob.client.recvPacket()
	assert.Equal(t, pppProtoIPCP, proto)
	assert.Equal(t, stillWorks, pkt, "bob's session survives alice's teardown")
}
