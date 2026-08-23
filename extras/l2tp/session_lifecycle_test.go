package l2tp

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// establishSessionAs is establishSession with the session ID the LNS assigns
// under the caller's control, so one tunnel can carry two sessions that are
// actually distinguishable from the LNS side.
func establishSessionAs(t *testing.T, tun *Tunnel, f *fakeLNS, lnsSID uint16) *Session {
	t.Helper()
	type result struct {
		s   *Session
		err error
	}
	resCh := make(chan result, 1)
	go func() {
		s, err := tun.CreateSession(testSubscriber, "5551234")
		resCh <- result{s, err}
	}()

	icrq := f.mustNextControl(MsgTypeICRQ)
	sidAVP := FindAVP(icrq.avps, 0, AVPAssignedSessionID)
	require.NotNil(t, sidAVP)
	localSID, err := AVPUint16(sidAVP)
	require.NoError(t, err)

	f.send(icrq.hdr.Ns+1, localSID, buildICRP(lnsSID))
	iccn := f.mustNextControl(MsgTypeICCN)
	f.sendZLB(iccn.hdr.Ns + 1)

	select {
	case r := <-resCh:
		require.NoError(t, r.err)
		require.NotNil(t, r.s)
		return r.s
	case <-time.After(waitFor):
		t.Fatal("CreateSession did not return")
	}
	return nil
}

// The whole call, message by message, with every sequence number checked as it
// goes: SCCRQ -> SCCRP -> SCCCN -> ICRQ -> ICRP -> ICCN -> data both ways ->
// CDN. Individual pieces are covered elsewhere; what this pins is that they
// compose -- that Ns advances by exactly one per control message across the
// tunnel and session handshakes alike, that Nr tracks the LNS across both, that
// ZLB acks slot in between without consuming anything, and that the data plane
// leaves the control sequence untouched.
func TestFullSessionLifecycleOrderingAndSequencing(t *testing.T) {
	f, lacConn := newFakeLNS(t)
	tun := newTunnel(lacConn, lacTunnelID, "test-lac", nil, 0, zap.NewNop())
	t.Cleanup(tun.Close)

	errCh := make(chan error, 1)
	go func() { errCh <- tun.Establish() }()

	// 1. SCCRQ: the first control message on a fresh tunnel.
	sccrq := f.mustNextPacket()
	require.False(t, sccrq.zlb)
	assert.Equal(t, MsgTypeSCCRQ, sccrq.msgType(t))
	assert.Equal(t, uint16(0), sccrq.hdr.Ns)
	assert.Equal(t, uint16(0), sccrq.hdr.Nr)
	assert.Equal(t, uint16(0), sccrq.hdr.Tunnel, "the LNS has not named itself yet")

	// 2. SCCRP from the LNS at its Ns=0, acking the SCCRQ.
	f.send(sccrq.hdr.Ns+1, 0, buildSCCRP(lnsTunnelID))

	// 3. The LAC acks it with a ZLB, which consumes no Ns.
	zlb := f.mustNextPacket()
	require.True(t, zlb.zlb, "expected a ZLB for the SCCRP, got %x", zlb.raw)
	assert.Equal(t, uint16(1), zlb.hdr.Ns, "a ZLB carries the next Ns without taking it")
	assert.Equal(t, uint16(1), zlb.hdr.Nr)

	// 4. SCCCN, taking the Ns the ZLB only advertised.
	scccn := f.mustNextPacket()
	require.False(t, scccn.zlb)
	assert.Equal(t, MsgTypeSCCCN, scccn.msgType(t))
	assert.Equal(t, uint16(1), scccn.hdr.Ns)
	assert.Equal(t, uint16(1), scccn.hdr.Nr)
	assert.Equal(t, lnsTunnelID, scccn.hdr.Tunnel, "now addressed to the LNS's assigned tunnel ID")

	// 5. Acked, and the tunnel is up.
	f.sendZLB(scccn.hdr.Ns + 1)
	select {
	case err := <-errCh:
		require.NoError(t, err)
	case <-time.After(waitFor):
		t.Fatal("Establish did not return")
	}

	// 6. ICRQ opens the call. Ns continues from the tunnel handshake: the
	//    control channel is one sequence space shared by tunnel and sessions.
	type sessResult struct {
		s   *Session
		err error
	}
	sessCh := make(chan sessResult, 1)
	go func() {
		s, err := tun.CreateSession(testSubscriber, "5551234")
		sessCh <- sessResult{s, err}
	}()

	icrq := f.mustNextPacket()
	require.False(t, icrq.zlb)
	assert.Equal(t, MsgTypeICRQ, icrq.msgType(t))
	assert.Equal(t, uint16(2), icrq.hdr.Ns, "Ns continues across the session handshake")
	assert.Equal(t, uint16(1), icrq.hdr.Nr)
	assert.Equal(t, lnsTunnelID, icrq.hdr.Tunnel)
	assert.Equal(t, uint16(0), icrq.hdr.Session,
		"the LNS has not named the session yet, so the ICRQ is tunnel-addressed")

	sidAVP := FindAVP(icrq.avps, 0, AVPAssignedSessionID)
	require.NotNil(t, sidAVP, "ICRQ must offer the LAC's own session ID")
	localSID, err := AVPUint16(sidAVP)
	require.NoError(t, err)

	// 7. ICRP names the LNS's session, at the LNS's Ns=1.
	f.send(icrq.hdr.Ns+1, localSID, buildICRP(lnsSessionID))

	// 8. The ICRP is acked before the ICCN goes out.
	ack := f.mustNextPacket()
	require.True(t, ack.zlb, "expected a ZLB for the ICRP, got %x", ack.raw)
	assert.Equal(t, uint16(3), ack.hdr.Ns)
	assert.Equal(t, uint16(2), ack.hdr.Nr, "Nr advanced past the ICRP")

	// 9. ICCN, addressed to the session the LNS just assigned.
	iccn := f.mustNextPacket()
	require.False(t, iccn.zlb)
	assert.Equal(t, MsgTypeICCN, iccn.msgType(t))
	assert.Equal(t, uint16(3), iccn.hdr.Ns)
	assert.Equal(t, uint16(2), iccn.hdr.Nr)
	assert.Equal(t, lnsSessionID, iccn.hdr.Session)

	// 10. Acked, and the call is up.
	f.sendZLB(iccn.hdr.Ns + 1)
	var s *Session
	select {
	case r := <-sessCh:
		require.NoError(t, r.err)
		s = r.s
	case <-time.After(waitFor):
		t.Fatal("CreateSession did not return")
	}
	require.Equal(t, localSID, s.localSessionID)
	require.Equal(t, lnsSessionID, s.remoteSID())
	assert.Equal(t, 1, tun.SessionCount())
	assert.Equal(t, uint32(4), tun.ns.Load(), "four control messages have been sent")
	assert.Equal(t, uint32(2), tun.nr.Load(), "two have been received")

	// 11. Data in both directions. Data messages are outside the reliable
	//     control channel and must not touch Ns or Nr at either end.
	f.write(append(EncodeDataHeader(lacTunnelID, localSID), 0x80, 0x21, 0x01, 0x01, 0x00, 0x04))
	proto, payload, err := recvPPPParts(s)
	require.NoError(t, err)
	assert.Equal(t, uint16(0x8021), proto)
	assert.Equal(t, []byte{0x01, 0x01, 0x00, 0x04}, payload)

	require.NoError(t, sendPPPParts(s, 0x8021, []byte{0x02, 0x01, 0x00, 0x04}))
	out := f.mustNextPacket()
	require.False(t, out.hdr.IsControl)
	assert.Equal(t, lnsTunnelID, out.hdr.Tunnel)
	assert.Equal(t, lnsSessionID, out.hdr.Session, "outbound data is addressed to the LNS's session")
	assert.Equal(t, []byte{0x80, 0x21, 0x02, 0x01, 0x00, 0x04}, out.raw[out.off:])

	assert.Equal(t, uint32(4), tun.ns.Load(), "the data plane consumes no control sequence numbers")
	assert.Equal(t, uint32(2), tun.nr.Load())

	// 12. The LNS clears the call at its Ns=2.
	f.send(uint16(tun.ns.Load()), localSID, BuildCDN(lnsSessionID, 3, 0, "call cleared"))

	cdnAck := f.mustNextPacket()
	require.True(t, cdnAck.zlb, "expected a ZLB for the CDN, got %x", cdnAck.raw)
	assert.Equal(t, uint16(4), cdnAck.hdr.Ns)
	assert.Equal(t, uint16(3), cdnAck.hdr.Nr, "Nr advanced past the CDN")

	requireSessionGone(t, tun, s, 0)
	result, errCode, msg := s.CloseReason()
	assert.Equal(t, uint16(3), result)
	assert.Zero(t, errCode)
	assert.Equal(t, "call cleared", msg)

	// 13. The call is gone; the control connection is not. A CDN clears one
	//     call, and the LAC keeps the tunnel for the next one -- unlike
	//     Session.Close, which takes the tunnel down with the last session.
	assert.True(t, tun.Alive())
	f.assertSilent("clearing the last call must not make the LAC say anything more")

	_, err = s.RecvPPP()
	assert.ErrorIs(t, err, errSessionClosed)
	assert.ErrorIs(t, sendPPPParts(s, 0x8021, []byte{1}), errSessionClosed)
}

// One tunnel carries many calls, and setting several up at once means several
// goroutines sending control messages down one control channel. The sequence
// space is shared, so each Ns must be handed to exactly one message and none
// may be skipped -- a gap stalls the peer until a retransmission fills it, a
// repeat makes the peer discard a message it never saw.
func TestConcurrentControlSendsAllocateEachNsExactlyOnce(t *testing.T) {
	conn := &timeoutConn{}
	tun := newTunnel(conn, lacTunnelID, "test-lac", nil, 0, zap.NewNop())
	tun.remoteTunnelID = lnsTunnelID

	const senders = 64
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range senders {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			assert.NoError(t, tun.sendControl(tun.remoteTunnelID, 0, BuildHello()))
		}()
	}
	close(start)
	wg.Wait()

	sent := conn.sent()
	require.Len(t, sent, senders, "every send must reach the socket exactly once")

	seen := make(map[uint16]int, senders)
	outOfOrder := 0
	var prev uint16
	for i, pkt := range sent {
		hdr, _, err := DecodeHeader(pkt)
		require.NoError(t, err, "packet %d", i)
		require.True(t, hdr.IsControl)
		seen[hdr.Ns]++
		if i > 0 && int16(hdr.Ns-prev) <= 0 {
			outOfOrder++
		}
		prev = hdr.Ns
	}
	for ns := range uint16(senders) {
		assert.Equal(t, 1, seen[ns], "Ns %d must belong to exactly one control message", ns)
	}
	assert.Len(t, seen, senders, "no Ns outside the allocated range was used")
	assert.Equal(t, uint32(senders), tun.ns.Load())

	// Whether any of them actually overtook each other on this run is up to the
	// scheduler, so it is reported rather than asserted. That the reordering is
	// *possible* is asserted deterministically by the test below.
	t.Logf("%d of %d control messages reached the socket out of Ns order", outOfOrder, senders)
}

// buildControl consumes an Ns and returns; writePacket takes writeMu and
// writes. Nothing holds the two together, so between them another sender can
// take the next Ns and put it on the wire first.
//
// This drives that interleaving directly instead of hoping the scheduler
// produces it: sender A's allocated-but-unwritten packet is held while sender B
// completes a whole send, and the socket then shows Ns=1 ahead of Ns=0. RFC
// 2661 s5.8 lets a receiver discard a control message that arrives out of
// order, so a strict LNS drops the Ns=0 message and the LAC only recovers via
// the retransmit ladder -- 1+2+4+8+10+10s before it gives up.
// This pins the current behaviour so a future fix is a deliberate change.
func TestNsIsAllocatedBeforeTheWriteLockSoTheWireOrderCanInvert(t *testing.T) {
	conn := &timeoutConn{}
	tun := newTunnel(conn, lacTunnelID, "test-lac", nil, 0, zap.NewNop())
	tun.remoteTunnelID = lnsTunnelID

	// Sender A gets as far as having a packet built. Its Ns is already spent.
	pktA := tun.buildControl(tun.remoteTunnelID, 0, BuildHello())
	require.Equal(t, uint32(1), tun.ns.Load(), "buildControl consumed Ns=0")
	require.Empty(t, conn.sent(), "and nothing has reached the socket for it")

	// Sender B, running on another goroutine, now takes Ns=1 and completes.
	require.NoError(t, tun.sendControl(tun.remoteTunnelID, 0, BuildHello()))
	// Only then does A finish.
	require.NoError(t, tun.writePacket(pktA))

	sent := conn.sent()
	require.Len(t, sent, 2)
	nsOf := func(pkt []byte) uint16 {
		hdr, _, err := DecodeHeader(pkt)
		require.NoError(t, err)
		return hdr.Ns
	}
	assert.Equal(t, uint16(1), nsOf(sent[0]), "the later-allocated message reached the wire first")
	assert.Equal(t, uint16(0), nsOf(sent[1]), "and the earlier one followed it")
}

// Session ID 0 addresses the tunnel itself and a live ID must not be reissued,
// so allocation steps over both. The counter is fast-forwarded rather than making
// 65536 calls; that is the only thing the test does for itself.
func TestSessionIDAllocationSkipsZeroAndLiveIDs(t *testing.T) {
	tun, f := establishTunnel(t, 0)

	setNextSID := func(sid uint16) {
		tun.mu.Lock()
		tun.nextSID = sid
		tun.mu.Unlock()
	}

	setNextSID(0xFFFE)
	first := establishSessionAs(t, tun, f, 0x4242)
	require.Equal(t, uint16(0xFFFF), first.localSessionID)

	// 0xFFFF + 1 would be 0, which addresses the tunnel; allocation steps over it.
	second := establishSessionAs(t, tun, f, 0x4343)
	assert.Equal(t, uint16(1), second.localSessionID, "zero is never handed out")

	// And an ID still in use is not reissued: rewind onto the live one.
	setNextSID(0)
	third := establishSessionAs(t, tun, f, 0x4444)
	assert.NotEqual(t, second.localSessionID, third.localSessionID,
		"a live session ID must not be handed out twice")
	assert.NotZero(t, third.localSessionID)
}

// Two calls on one tunnel, torn down one at a time: only the last one takes the
// control connection with it.
func TestOnlyTheLastSessionClosingTearsTheTunnelDown(t *testing.T) {
	tun, f := establishTunnel(t, 0)
	first := establishSessionAs(t, tun, f, 0x4242)
	second := establishSessionAs(t, tun, f, 0x4343)
	require.Equal(t, 2, tun.SessionCount())
	require.NotEqual(t, first.localSessionID, second.localSessionID)

	first.Close()
	cdn := f.mustNextControl(MsgTypeCDN)
	assert.Equal(t, uint16(0x4242), cdn.hdr.Session, "the CDN is addressed to that call at the LNS")
	assert.True(t, sessionIsClosed(first))
	assert.False(t, sessionIsClosed(second), "the other call is untouched")
	assert.Equal(t, 1, tun.SessionCount())
	assert.True(t, tun.Alive())

	second.Close()
	assert.True(t, sessionIsClosed(second))
	assert.Equal(t, 0, tun.SessionCount())
	assert.Eventually(t, func() bool { return !tun.Alive() }, waitFor, 5*time.Millisecond,
		"the last call closing takes the tunnel with it")
}

// RFC 2661 s3.3 gives StopCCN the job of tearing the whole control connection
// down, and says it implicitly terminates every session in the tunnel. So with
// live calls on it, Close must still send exactly one StopCCN and must not also
// send a CDN per call: the sessions are ended locally.
func TestTunnelCloseWithLiveSessionsSendsStopCCNAndNoCDNs(t *testing.T) {
	tun, f := establishTunnel(t, 0)
	first := establishSessionAs(t, tun, f, 0x4242)
	second := establishSessionAs(t, tun, f, 0x4343)
	require.Equal(t, 2, tun.SessionCount())
	f.drain()

	tun.Close()

	stop := f.mustNextControl(MsgTypeStopCCN)
	assert.Equal(t, lnsTunnelID, stop.hdr.Tunnel, "StopCCN is addressed to the LNS's tunnel ID")
	assert.Equal(t, uint16(0), stop.hdr.Session, "StopCCN is a tunnel-level message")
	tid := FindAVP(stop.avps, 0, AVPAssignedTunnelID)
	require.NotNil(t, tid)
	got, err := AVPUint16(tid)
	require.NoError(t, err)
	assert.Equal(t, lacTunnelID, got, "the AVP carries the LAC's own tunnel ID")

	for {
		p, ok := f.nextPacket(waitNot)
		if !ok {
			break
		}
		if p.zlb || !p.hdr.IsControl {
			continue
		}
		assert.NotEqual(t, MsgTypeCDN, p.msgType(t),
			"StopCCN implicitly terminates every session; per-session CDNs are redundant")
	}

	assert.False(t, tun.Alive())
	assert.True(t, sessionIsClosed(first))
	assert.True(t, sessionIsClosed(second))
	for _, s := range []*Session{first, second} {
		_, err := s.RecvPPP()
		assert.ErrorIs(t, err, errSessionClosed)
		assert.ErrorIs(t, sendPPPParts(s, 0x8021, []byte{1}), errSessionClosed)
		result, errCode, msg := s.CloseReason()
		assert.Zero(t, result, "a local teardown is not a reason from the LNS")
		assert.Zero(t, errCode)
		assert.Empty(t, msg)
	}
}

// One subscriber who stops reading must not take the tunnel with them.
//
// deliverPPP runs on the tunnel's single demux loop, which carries every
// session's data and all of its control traffic. It used to fall back to a
// blocking send when a session's queue filled up, so a client that stalled
// froze ICRP, CDN and HELLO for the whole tunnel -- every other subscriber on
// that LNS went down with it, and the LAC could not even tear the tunnel down
// afterwards.
//
// PPP is a lossy link and the layers above it retransmit, so the answer is to
// drop the frame. What must keep moving is everyone else.
func TestAStalledSessionDoesNotBlockTheTunnelDemuxLoop(t *testing.T) {
	tun, f := establishTunnel(t, 0)
	stalled := establishSessionAs(t, tun, f, 0x0601)
	healthy := establishSessionAs(t, tun, f, 0x0602)

	data := func(sid uint16, marker byte) []byte {
		return append(EncodeDataHeader(lacTunnelID, sid),
			0x80, 0x21, 0x01, marker, 0x00, 0x04)
	}

	// Nobody reads `stalled`. Overfill its queue by a wide margin: net.Pipe is
	// synchronous, so a demux loop that blocks here blocks these writes too.
	overfill := cap(stalled.recvCh) + 32
	sent := make(chan struct{})
	go func() {
		defer close(sent)
		for i := 0; i < overfill; i++ {
			f.write(data(stalled.localSessionID, byte(i)))
		}
	}()
	select {
	case <-sent:
	case <-time.After(waitFor):
		t.Fatal("the demux loop stopped reading: one stalled session blocked the tunnel")
	}

	// The tunnel is still demultiplexing, which is the whole point.
	f.write(data(healthy.localSessionID, 0x7F))
	proto, payload, err := recvPPPParts(healthy)
	require.NoError(t, err)
	assert.Equal(t, uint16(0x8021), proto)
	require.Len(t, payload, 4)
	assert.Equal(t, byte(0x7F), payload[1], "the healthy session got its own frame")

	// And the loss is counted rather than silent, because a non-zero count is the
	// only sign that a reader is falling behind.
	assert.Positive(t, stalled.Dropped(), "overflow must be recorded")
	assert.Len(t, stalled.recvCh, cap(stalled.recvCh), "the queue is full, not drained")
}

// Two calls being set up at the same moment on one tunnel.
//
// establish's own comment claims this works -- "each session has its own channel
// so concurrent session setups on the same tunnel don't interfere" -- and until
// now nothing checked it. The risk is specific: both sessions are waiting for an
// ICRP on the same control connection, so a shared waiter would hand one
// session's ICRP to the other, and each would then believe the LNS had assigned
// it the wrong session ID. Every data frame afterwards would carry the wrong
// header, which is a silent cross-subscriber mix-up rather than a failure.
//
// The two ICRPs are answered out of order on purpose: in-order replies would pass
// even with a single shared waiter.
func TestConcurrentSessionSetupsDoNotStealEachOthersICRP(t *testing.T) {
	tun, f := establishTunnel(t, 0)

	type result struct {
		s   *Session
		err error
	}
	resCh := make(chan result, 2)
	for i := 0; i < 2; i++ {
		go func() {
			s, err := tun.CreateSession(testSubscriber, "5551234")
			resCh <- result{s, err}
		}()
	}

	// Collect both ICRQs before answering either, so both sessions are genuinely
	// in flight at the same time.
	type pending struct {
		localSID uint16
		ns       uint16
	}
	var reqs []pending
	for len(reqs) < 2 {
		icrq := f.mustNextControl(MsgTypeICRQ)
		sidAVP := FindAVP(icrq.avps, 0, AVPAssignedSessionID)
		require.NotNil(t, sidAVP, "ICRQ must carry the session ID the LAC chose")
		sid, err := AVPUint16(sidAVP)
		require.NoError(t, err)
		reqs = append(reqs, pending{localSID: sid, ns: icrq.hdr.Ns})
	}
	require.NotEqual(t, reqs[0].localSID, reqs[1].localSID,
		"concurrent setups must not be handed the same session ID")

	// Answer the second request first. Each ICRP names the session it belongs to
	// both in the header and in the Assigned Session ID AVP; a session that took
	// the wrong one would adopt the wrong remote ID.
	lnsFor := map[uint16]uint16{
		reqs[0].localSID: 0x0701,
		reqs[1].localSID: 0x0702,
	}
	f.send(reqs[1].ns+1, reqs[1].localSID, buildICRP(lnsFor[reqs[1].localSID]))
	f.send(reqs[0].ns+1, reqs[0].localSID, buildICRP(lnsFor[reqs[0].localSID]))

	// Both send ICCN; ack each.
	for i := 0; i < 2; i++ {
		iccn := f.mustNextControl(MsgTypeICCN)
		f.sendZLB(iccn.hdr.Ns + 1)
	}

	sessions := make([]*Session, 0, 2)
	for i := 0; i < 2; i++ {
		select {
		case r := <-resCh:
			require.NoError(t, r.err, "both concurrent setups must succeed")
			require.NotNil(t, r.s)
			sessions = append(sessions, r.s)
		case <-time.After(waitFor):
			t.Fatal("a concurrent CreateSession never returned")
		}
	}

	// The property that matters: each session adopted the remote ID that was sent
	// for its own local ID, not the other one's.
	for _, s := range sessions {
		want, ok := lnsFor[s.localSessionID]
		require.True(t, ok, "unexpected local session ID %d", s.localSessionID)
		assert.Equal(t, want, s.remoteSID(),
			"session %d took the ICRP meant for the other call", s.localSessionID)
	}
	assert.NotEqual(t, sessions[0].remoteSID(), sessions[1].remoteSID(),
		"two calls cannot share one remote session ID")
	assert.Equal(t, 2, tun.SessionCount(), "both calls are registered on the tunnel")
}
