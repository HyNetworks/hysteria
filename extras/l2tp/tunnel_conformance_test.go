package l2tp

import (
	"crypto/md5"
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// This file drives Tunnel against a hand-written fake LNS over net.Pipe so
// every byte on the wire is under test control. It covers the reliable
// control channel of RFC 2661 Section 5.8 (Ns/Nr, acknowledgement,
// retransmission, out-of-order handling) plus tunnel/session teardown.
//
// All intervals here are in the tens of milliseconds; the one exception is
// TestEstablishRetransmitsSCCRQUntilItGivesUp, which drives the retry loop
// through a connection whose reads fail instantly so no wall-clock time is
// consumed at all.

const (
	// Identifiers the fake LNS assigns to itself.
	lnsTunnelID  uint16 = 0x2020
	lnsSessionID uint16 = 0x4242

	lacTunnelID uint16 = 0x0101

	// How long to wait for a packet that is expected to arrive.
	waitFor = 2 * time.Second
	// How long to wait to be convinced a packet will NOT arrive.
	waitNot = 80 * time.Millisecond
)

// ---------------------------------------------------------------------------
// Fake LNS
// ---------------------------------------------------------------------------

type lnsPacket struct {
	raw  []byte
	hdr  Header
	off  int
	avps []AVP
	// zlb is true for a control message with an empty body (an ack).
	zlb bool
}

func (p lnsPacket) msgType(t *testing.T) uint16 {
	t.Helper()
	mt, err := GetMessageType(p.avps)
	require.NoError(t, err)
	return mt
}

type fakeLNS struct {
	t    *testing.T
	conn net.Conn
	recv chan lnsPacket

	mu sync.Mutex
	ns uint16 // next Ns the LNS will put on a non-ZLB control message
}

// newFakeLNS returns the fake LNS and the net.Conn the LAC side should use.
func newFakeLNS(t *testing.T) (*fakeLNS, net.Conn) {
	t.Helper()
	lacSide, lnsSide := net.Pipe()
	f := &fakeLNS{t: t, conn: lnsSide, recv: make(chan lnsPacket, 128)}
	go f.readLoop()
	t.Cleanup(func() {
		_ = lnsSide.Close()
		_ = lacSide.Close()
	})
	return f, lacSide
}

func (f *fakeLNS) readLoop() {
	buf := make([]byte, maxPacketSize)
	for {
		n, err := f.conn.Read(buf)
		if err != nil {
			return
		}
		raw := make([]byte, n)
		copy(raw, buf[:n])

		p := lnsPacket{raw: raw}
		hdr, off, derr := DecodeHeader(raw)
		if derr != nil {
			p.off = -1
		} else {
			p.hdr, p.off = hdr, off
			if off >= n {
				p.zlb = true
			} else if avps, aerr := DecodeAVPs(raw[off:n]); aerr == nil {
				p.avps = avps
			}
		}
		select {
		case f.recv <- p:
		default:
		}
	}
}

// nextPacket returns the next packet the LAC sent, ZLBs included.
func (f *fakeLNS) nextPacket(timeout time.Duration) (lnsPacket, bool) {
	select {
	case p := <-f.recv:
		return p, true
	case <-time.After(timeout):
		return lnsPacket{}, false
	}
}

func (f *fakeLNS) mustNextPacket() lnsPacket {
	f.t.Helper()
	p, ok := f.nextPacket(waitFor)
	require.True(f.t, ok, "timed out waiting for a packet from the LAC")
	return p
}

// mustNextControl returns the next control message of the wanted type. ZLB
// acks are skipped, and so are Hello keepalives (which the helloLoop can
// interleave at any moment) unless a Hello is what is being waited for.
func (f *fakeLNS) mustNextControl(want uint16) lnsPacket {
	f.t.Helper()
	deadline := time.Now().Add(waitFor)
	for time.Now().Before(deadline) {
		p, ok := f.nextPacket(time.Until(deadline))
		if !ok {
			break
		}
		if p.zlb {
			continue
		}
		require.True(f.t, p.hdr.IsControl, "expected a control message, got %x", p.raw)
		got := p.msgType(f.t)
		if got == MsgTypeHello && want != MsgTypeHello {
			continue
		}
		require.Equal(f.t, want, got, "unexpected control message %x", p.raw)
		return p
	}
	f.t.Fatalf("timed out waiting for control message type %d", want)
	return lnsPacket{}
}

// drain discards everything the LAC has sent so far.
func (f *fakeLNS) drain() {
	for {
		select {
		case <-f.recv:
		default:
			return
		}
	}
}

// assertSilent asserts the LAC sends nothing at all for a short while.
func (f *fakeLNS) assertSilent(reason string) {
	f.t.Helper()
	p, ok := f.nextPacket(waitNot)
	if ok {
		f.t.Fatalf("%s: unexpected packet %x", reason, p.raw)
	}
}

// barrier sends a Hello and waits for the ZLB that acknowledges it.
//
// recvLoop reads and dispatches one datagram at a time, so by the time it has
// even looked at this Hello it has returned from handling everything sent
// before it. That matters because handleControl emits the ZLB for a message
// *before* acting on it: seeing the ack for a CDN proves only that the CDN was
// sequenced, not that handleCDN has run. Waiting for the next message's ack
// does prove it, without a sleep.
//
// Callers must have consumed the acks for everything they sent earlier, and
// must not be asserting on Nr afterwards: this consumes one of the LNS's Ns
// and advances the LAC's Nr by one.
func (f *fakeLNS) barrier(tun *Tunnel) {
	f.t.Helper()
	f.send(uint16(tun.ns.Load()), 0, BuildHello())
	p := f.mustNextPacket()
	require.True(f.t, p.zlb, "expected the ZLB acknowledging the barrier Hello, got %x", p.raw)
}

// send writes a control message with the LNS's next Ns, consuming a sequence
// number.
func (f *fakeLNS) send(nr, session uint16, payload []byte) uint16 {
	f.t.Helper()
	f.mu.Lock()
	ns := f.ns
	f.ns++
	f.mu.Unlock()
	f.sendAt(ns, nr, session, payload)
	return ns
}

// sendAt writes a control message with an explicit Ns (for duplicate and
// out-of-order tests). It does not consume a sequence number.
func (f *fakeLNS) sendAt(ns, nr, session uint16, payload []byte) {
	f.t.Helper()
	pkt := append(EncodeControlHeader(lacTunnelID, session, ns, nr, len(payload)), payload...)
	f.write(pkt)
}

// sendZLB writes a Zero-Length Body ack carrying the LNS's next Ns.
func (f *fakeLNS) sendZLB(nr uint16) {
	f.t.Helper()
	f.mu.Lock()
	ns := f.ns
	f.mu.Unlock()
	f.write(EncodeControlHeader(lacTunnelID, 0, ns, nr, 0))
}

func (f *fakeLNS) write(pkt []byte) {
	f.t.Helper()
	require.NoError(f.t, f.conn.SetWriteDeadline(time.Now().Add(waitFor)))
	_, err := f.conn.Write(pkt)
	require.NoError(f.t, err)
}

// ---------------------------------------------------------------------------
// Payload builders for the LNS side
// ---------------------------------------------------------------------------

func buildSCCRP(tunnelID uint16, extra ...[]byte) []byte {
	var buf []byte
	buf = append(buf, EncodeUint16AVP(AVPMessageType, MsgTypeSCCRP)...)
	buf = append(buf, EncodeAVP(AVPProtocolVersion, []byte{ProtocolVersion, ProtocolRevision})...)
	buf = append(buf, EncodeStringAVP(AVPHostName, "fake-lns")...)
	buf = append(buf, EncodeUint32AVP(AVPFramingCapabilities, FramingAsync|FramingSync)...)
	buf = append(buf, EncodeUint16AVP(AVPAssignedTunnelID, tunnelID)...)
	for _, e := range extra {
		buf = append(buf, e...)
	}
	return buf
}

func buildICRP(sessionID uint16) []byte {
	var buf []byte
	buf = append(buf, EncodeUint16AVP(AVPMessageType, MsgTypeICRP)...)
	buf = append(buf, EncodeUint16AVP(AVPAssignedSessionID, sessionID)...)
	return buf
}

// testSubscriber is the Hysteria2 identity a test call belongs to. It replaces
// the ProxyInfo this LAC used to collect: nothing about the subscriber's PPP
// session is known here any more, because the LNS runs it.
const testSubscriber = "user@ispA.com"

// ---------------------------------------------------------------------------
// Frames as (protocol, payload)
// ---------------------------------------------------------------------------
//
// A Session carries whole PPP frames and does not look inside them. Plenty of
// tests are about which protocol was demuxed where, though, so these two put the
// old shape back on top of the new API -- in the tests, where being wrong about
// Protocol-Field-Compression costs an assertion rather than a subscriber's
// traffic.

// framePPP builds the frame an uncompressed sender would emit: no address and
// control octets, protocol in full. It is what this LAC itself used to put on
// the wire, so wire-format assertions written against that still hold.
func framePPP(proto uint16, payload []byte) []byte {
	f := make([]byte, 2+len(payload))
	f[0], f[1] = byte(proto>>8), byte(proto)
	copy(f[2:], payload)
	return f
}

// splitPPP is the RFC 1661 s2 reading: an optional FF 03, then a protocol field
// that is a single odd octet when compressed and an even-led pair when not.
func splitPPP(frame []byte) (uint16, []byte) {
	b := frame
	if len(b) >= 3 && b[0] == 0xFF && b[1] == 0x03 {
		b = b[2:]
	}
	if len(b) == 0 {
		return 0, nil
	}
	if b[0]&1 == 1 {
		return uint16(b[0]), b[1:]
	}
	if len(b) < 2 {
		return 0, nil
	}
	return uint16(b[0])<<8 | uint16(b[1]), b[2:]
}

func recvPPPParts(s *Session) (uint16, []byte, error) {
	frame, err := s.RecvPPP()
	if err != nil {
		return 0, nil, err
	}
	proto, payload := splitPPP(frame)
	return proto, payload, nil
}

func sendPPPParts(s *Session, proto uint16, payload []byte) error {
	return s.SendPPP(framePPP(proto, payload))
}

// ---------------------------------------------------------------------------
// Handshake helpers
// ---------------------------------------------------------------------------

// establishTunnel runs SCCRQ -> SCCRP -> SCCCN -> ZLB against the fake LNS and
// returns the established tunnel.
func establishTunnel(t *testing.T, helloInterval time.Duration) (*Tunnel, *fakeLNS) {
	t.Helper()
	f, lacConn := newFakeLNS(t)
	tun := newTunnel(lacConn, lacTunnelID, "test-lac", nil, helloInterval, zap.NewNop())
	t.Cleanup(tun.Close)

	errCh := make(chan error, 1)
	go func() { errCh <- tun.Establish() }()

	sccrq := f.mustNextControl(MsgTypeSCCRQ)
	f.send(sccrq.hdr.Ns+1, 0, buildSCCRP(lnsTunnelID))

	scccn := f.mustNextControl(MsgTypeSCCCN)
	f.sendZLB(scccn.hdr.Ns + 1)

	select {
	case err := <-errCh:
		require.NoError(t, err)
	case <-time.After(waitFor):
		t.Fatal("Establish did not return")
	}
	require.Equal(t, lnsTunnelID, tun.remoteTunnelID)
	return tun, f
}

// establishSession runs ICRQ -> ICRP -> ICCN -> ZLB and returns the session.
func establishSession(t *testing.T, tun *Tunnel, f *fakeLNS) *Session {
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

	// RFC 2661 s3.1: the Session ID in a header addresses the session at the
	// *receiver*, so the LNS echoes the LAC's assigned session ID.
	f.send(icrq.hdr.Ns+1, localSID, buildICRP(lnsSessionID))

	iccn := f.mustNextControl(MsgTypeICCN)
	assert.Equal(t, lnsSessionID, iccn.hdr.Session,
		"ICCN must be addressed to the session ID the LNS assigned")
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

func sessionIsClosed(s *Session) bool {
	select {
	case <-s.closed:
		return true
	default:
		return false
	}
}

// requireSessionGone waits for a session to be both closed and deregistered.
//
// closeDueToLNS closes s.closed and only then calls tunnel.removeSession, so a
// poll that watches the channel alone can catch the tunnel mid-update and read
// a SessionCount that is one too high. Asserting both together closes that
// window instead of relying on the two statements not being preempted.
func requireSessionGone(t *testing.T, tun *Tunnel, s *Session, wantCount int) {
	t.Helper()
	require.Eventually(t, func() bool {
		return sessionIsClosed(s) && tun.SessionCount() == wantCount
	}, waitFor, 5*time.Millisecond,
		"the session must end up closed and deregistered, leaving %d on the tunnel", wantCount)
}

// ---------------------------------------------------------------------------
// Reliable control channel: Ns / Nr (RFC 2661 Section 5.8)
// ---------------------------------------------------------------------------

func TestEstablishSequenceNumbering(t *testing.T) {
	f, lacConn := newFakeLNS(t)
	tun := newTunnel(lacConn, lacTunnelID, "test-lac", nil, 0, zap.NewNop())
	t.Cleanup(tun.Close)

	errCh := make(chan error, 1)
	go func() { errCh <- tun.Establish() }()

	// 1. SCCRQ is the first control message: Ns=0, Nr=0, tunnel/session 0.
	sccrq := f.mustNextPacket()
	require.False(t, sccrq.zlb)
	assert.True(t, sccrq.hdr.IsControl)
	assert.True(t, sccrq.hdr.HasLength)
	assert.Equal(t, uint16(len(sccrq.raw)), sccrq.hdr.Length, "Length covers the whole datagram")
	assert.Equal(t, uint16(0), sccrq.hdr.Tunnel, "tunnel ID is unknown until SCCRP")
	assert.Equal(t, uint16(0), sccrq.hdr.Session)
	assert.Equal(t, uint16(0), sccrq.hdr.Ns)
	assert.Equal(t, uint16(0), sccrq.hdr.Nr)
	assert.Equal(t, MsgTypeSCCRQ, sccrq.msgType(t))

	// 2. LNS answers with SCCRP at Ns=0, acking SCCRQ with Nr=1.
	f.send(1, 0, buildSCCRP(lnsTunnelID))

	// 3. The LAC acks SCCRP with a ZLB. A ZLB carries the *next* Ns without
	//    consuming it, and Nr advances to 1.
	zlb := f.mustNextPacket()
	require.True(t, zlb.zlb, "expected a ZLB ack for SCCRP, got %x", zlb.raw)
	assert.Equal(t, uint16(1), zlb.hdr.Ns, "ZLB carries the next Ns")
	assert.Equal(t, uint16(1), zlb.hdr.Nr, "Nr echoes the highest in-order Ns received, plus one")

	// CONFORMANCE GAP (RFC 2661 s3.1): "The Tunnel ID in each message is that
	// of the intended recipient, not the sender. Tunnel IDs are selected and
	// exchanged as Assigned Tunnel ID AVPs during the creation of a tunnel."
	// So an outgoing header must carry the Assigned Tunnel ID the LNS sent in
	// its SCCRP. recvControlDirect calls sendZLB
	// while still inside the receive path, before Establish has parsed that
	// AVP into t.remoteTunnelID, so the ZLB acknowledging the SCCRP goes out
	// addressed to Tunnel ID 0. An LNS that demultiplexes strictly on Tunnel
	// ID will not attribute this ack to the tunnel and will retransmit its
	// SCCRP. This test pins the current behaviour so a future fix is a
	// deliberate change.
	assert.Equal(t, uint16(0), zlb.hdr.Tunnel,
		"the ack for SCCRP still carries Tunnel ID 0, not the assigned %#04x", lnsTunnelID)

	// 4. SCCCN reuses Ns=1: the ZLB did not consume a sequence number.
	scccn := f.mustNextPacket()
	require.False(t, scccn.zlb)
	assert.Equal(t, MsgTypeSCCCN, scccn.msgType(t))
	assert.Equal(t, uint16(1), scccn.hdr.Ns, "Ns increments by exactly one per control message")
	assert.Equal(t, uint16(1), scccn.hdr.Nr)
	assert.Equal(t, lnsTunnelID, scccn.hdr.Tunnel)

	// 5. Ack SCCCN and the handshake completes.
	f.sendZLB(2)
	select {
	case err := <-errCh:
		require.NoError(t, err)
	case <-time.After(waitFor):
		t.Fatal("Establish did not return")
	}

	assert.Equal(t, uint32(2), tun.ns.Load(), "next Ns to send")
	assert.Equal(t, uint32(1), tun.nr.Load(), "next Ns expected from the peer")
	tun.peerNrMu.Lock()
	assert.Equal(t, uint16(2), tun.peerNr)
	tun.peerNrMu.Unlock()
}

func TestControlMessagesAreAckedAndZLBsAreNot(t *testing.T) {
	tun, f := establishTunnel(t, 0)

	// A Hello from the LNS must be acknowledged.
	f.send(2, 0, BuildHello())
	ack := f.mustNextPacket()
	require.True(t, ack.zlb, "an inbound control message must be acknowledged")
	assert.Equal(t, uint16(2), ack.hdr.Ns, "the ack does not consume a sequence number")
	assert.Equal(t, uint16(2), ack.hdr.Nr, "Nr advanced past the Hello")

	// RFC 2661 s5.8: a ZLB carries no body and consumes no sequence number, so
	// there is nothing to acknowledge and acking one would never terminate.
	// (Paraphrase of s5.8, not a literal quote.)
	f.sendZLB(2)
	f.assertSilent("a ZLB must never be acknowledged")
	assert.Equal(t, uint32(2), tun.nr.Load(), "a ZLB does not advance Nr")
	assert.True(t, tun.Alive())
}

func TestDuplicateAndOutOfOrderControlMessages(t *testing.T) {
	tun, f := establishTunnel(t, 0)

	// In-order Hello at Ns=1 -> acked, Nr becomes 2.
	f.sendAt(1, 2, 0, BuildHello())
	ack := f.mustNextPacket()
	require.True(t, ack.zlb)
	assert.Equal(t, uint16(2), ack.hdr.Nr)
	assert.Equal(t, uint32(2), tun.nr.Load())

	tests := []struct {
		name   string
		ns     uint16
		wantNr uint16
	}{
		{"exact duplicate of the last message", 1, 2},
		{"a message from before the last one", 0, 2},
		{"a message from the future", 5, 2},
		{"a wildly out-of-order message", 0xFFFF, 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f.sendAt(tt.ns, 2, 0, BuildHello())
			// RFC 2661 s5.8 requires a retransmitted (duplicate) message to be
			// discarded but still acknowledged, since the retransmission means
			// the previous ack was lost. What to do with a message from ahead
			// of the expected Ns is a receive-window question the RFC leaves
			// open (queue or drop); this implementation always drops and acks
			// with the unchanged Nr, and that is what is pinned here.
			dup := f.mustNextPacket()
			require.True(t, dup.zlb, "out-of-order messages get a ZLB, not a body")
			assert.Equal(t, tt.wantNr, dup.hdr.Nr, "Nr must not move for out-of-order input")
			assert.Equal(t, uint32(tt.wantNr), tun.nr.Load())
		})
	}

	// The next in-order message is still accepted afterwards.
	f.sendAt(2, 2, 0, BuildHello())
	next := f.mustNextPacket()
	require.True(t, next.zlb)
	assert.Equal(t, uint16(3), next.hdr.Nr, "Nr resumes at the right place")
	assert.True(t, tun.Alive())
}

func TestUpdatePeerNrSequenceComparison(t *testing.T) {
	// updatePeerNr uses int16(nr - t.peerNr) > 0, i.e. RFC 1982-style serial
	// number arithmetic over a 16-bit space, so it must handle the
	// 0xFFFF -> 0x0000 wrap without treating it as a rollback.
	tests := []struct {
		name       string
		start      uint16
		incoming   uint16
		wantPeerNr uint16
		wantSignal bool
	}{
		{"first advance", 0, 1, 1, true},
		{"repeat of the current value", 5, 5, 5, false},
		{"stale value", 5, 3, 5, false},
		{"wrap 0xFFFF -> 0x0000 advances", 0xFFFF, 0x0000, 0x0000, true},
		{"wrap 0xFFFE -> 0x0002 advances", 0xFFFE, 0x0002, 0x0002, true},
		{"0x0000 -> 0xFFFF is a rollback, ignored", 0x0000, 0xFFFF, 0x0000, false},
		{"0x0002 -> 0xFFFE is a rollback, ignored", 0x0002, 0xFFFE, 0x0002, false},
		{"largest forward jump that still counts", 0, 0x7FFF, 0x7FFF, true},
		// A jump of exactly half the sequence space is ambiguous under serial
		// arithmetic and is treated as a rollback. Unreachable in practice:
		// the receive window advertised by BuildSCCRQ is 4.
		{"jump of exactly 0x8000 is treated as a rollback", 0, 0x8000, 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, lacConn := net.Pipe()
			t.Cleanup(func() { _ = lacConn.Close() })
			tun := newTunnel(lacConn, lacTunnelID, "lac", nil, 0, zap.NewNop())
			tun.peerNr = tt.start
			ch := tun.peerNrCh

			tun.updatePeerNr(tt.incoming)

			tun.peerNrMu.Lock()
			got := tun.peerNr
			sameCh := tun.peerNrCh == ch
			tun.peerNrMu.Unlock()
			assert.Equal(t, tt.wantPeerNr, got)

			signalled := false
			select {
			case <-ch:
				signalled = true
			default:
			}
			assert.Equal(t, tt.wantSignal, signalled, "waiters must be woken exactly on advance")
			assert.Equal(t, !tt.wantSignal, sameCh, "the wait channel is recreated on advance")
		})
	}
}

func TestWaitForPeerAckAcrossWraparound(t *testing.T) {
	tests := []struct {
		name    string
		peerNr  uint16
		sentNs  uint16
		wantAck bool
	}{
		{"exact ack", 3, 2, true},
		{"cumulative ack past the message", 9, 2, true},
		{"not yet acked", 2, 2, false},
		{"wrapped ack of a wrapped Ns", 0x0000, 0xFFFF, true},
		{"wrapped cumulative ack", 0x0003, 0xFFFE, true},
		{"stale Nr across the wrap", 0xFFFE, 0xFFFF, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, lacConn := net.Pipe()
			t.Cleanup(func() { _ = lacConn.Close() })
			tun := newTunnel(lacConn, lacTunnelID, "lac", nil, 0, zap.NewNop())
			tun.peerNr = tt.peerNr

			err := tun.waitForPeerAck(tt.sentNs, 20*time.Millisecond)
			if tt.wantAck {
				assert.NoError(t, err)
			} else {
				assert.ErrorIs(t, err, errControlTimeout)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Retransmission (RFC 2661 Section 5.8)
// ---------------------------------------------------------------------------

// timeoutConn is a net.Conn whose reads always fail immediately with a
// timeout error, which lets the retry loop be exercised without burning the
// several seconds of real backoff that ctrlRetryBaseTimeout would impose.
type timeoutConn struct {
	mu     sync.Mutex
	writes [][]byte
	closed bool
}

type fakeTimeoutError struct{}

func (fakeTimeoutError) Error() string   { return "i/o timeout" }
func (fakeTimeoutError) Timeout() bool   { return true }
func (fakeTimeoutError) Temporary() bool { return true }

func (c *timeoutConn) Read([]byte) (int, error) { return 0, fakeTimeoutError{} }

func (c *timeoutConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, net.ErrClosed
	}
	cp := make([]byte, len(b))
	copy(cp, b)
	c.writes = append(c.writes, cp)
	return len(b), nil
}

func (c *timeoutConn) sent() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([][]byte, len(c.writes))
	copy(out, c.writes)
	return out
}

func (c *timeoutConn) Close() error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	return nil
}
func (c *timeoutConn) LocalAddr() net.Addr              { return dummyAddr{} }
func (c *timeoutConn) RemoteAddr() net.Addr             { return dummyAddr{} }
func (c *timeoutConn) SetDeadline(time.Time) error      { return nil }
func (c *timeoutConn) SetReadDeadline(time.Time) error  { return nil }
func (c *timeoutConn) SetWriteDeadline(time.Time) error { return nil }

type dummyAddr struct{}

func (dummyAddr) Network() string { return "udp" }
func (dummyAddr) String() string  { return "203.0.113.1:1701" }

func TestEstablishRetransmitsSCCRQUntilItGivesUp(t *testing.T) {
	conn := &timeoutConn{}
	tun := newTunnel(conn, lacTunnelID, "test-lac", nil, 0, zap.NewNop())

	err := tun.Establish()
	require.Error(t, err, "Establish must fail rather than retry forever")
	assert.ErrorContains(t, err, "recv SCCRP")
	assert.ErrorContains(t, err, "after 5 retries")

	sent := conn.sent()
	decode := func(pkt []byte) (Header, uint16) {
		t.Helper()
		hdr, off, derr := DecodeHeader(pkt)
		require.NoError(t, derr)
		avps, aerr := DecodeAVPs(pkt[off:])
		require.NoError(t, aerr)
		mt, gerr := GetMessageType(avps)
		require.NoError(t, gerr)
		return hdr, mt
	}

	// Giving up tells the LNS, which matters when it was the SCCRP that was lost
	// rather than the SCCRQ: the LNS then holds a control connection for a LAC
	// that has already stopped waiting, and only a StopCCN releases it.
	require.NotEmpty(t, sent)
	_, lastType := decode(sent[len(sent)-1])
	assert.Equal(t, MsgTypeStopCCN, lastType, "a tunnel that gave up must say so")
	retries := sent[:len(sent)-1]

	// The initial transmission plus maxCtrlRetries retransmissions, and no more.
	require.Len(t, retries, maxCtrlRetries+1, "retry count must be bounded by maxCtrlRetries")

	for i, pkt := range retries {
		hdr, mt := decode(pkt)
		assert.Equal(t, MsgTypeSCCRQ, mt, "every retransmission is the same SCCRQ")
		// RFC 2661 s5.8: a retransmission reuses the original Ns.
		assert.Equal(t, uint16(0), hdr.Ns, "retransmission %d must reuse Ns=0", i)
		assert.Equal(t, retries[0], pkt, "retransmissions are byte-identical")
	}

	assert.False(t, tun.Alive(), "a tunnel that never came up must not report itself alive")
}

func TestEstablishRetransmitsSCCRQUntilTheLNSAnswers(t *testing.T) {
	if testing.Short() {
		t.Skip("exercises the 1s ctrlRetryBaseTimeout")
	}
	f, lacConn := newFakeLNS(t)
	tun := newTunnel(lacConn, lacTunnelID, "test-lac", nil, 0, zap.NewNop())
	t.Cleanup(tun.Close)

	errCh := make(chan error, 1)
	go func() { errCh <- tun.Establish() }()

	// Withhold the ack: the first SCCRQ goes unanswered.
	first := f.mustNextControl(MsgTypeSCCRQ)
	assert.Equal(t, uint16(0), first.hdr.Ns)

	// ctrlRetryBaseTimeout later the LAC retransmits it verbatim.
	second, ok := f.nextPacket(ctrlRetryBaseTimeout + waitFor)
	require.True(t, ok, "SCCRQ was not retransmitted")
	assert.Equal(t, first.raw, second.raw, "the retransmission is byte-identical, same Ns")

	f.send(second.hdr.Ns+1, 0, buildSCCRP(lnsTunnelID))
	scccn := f.mustNextControl(MsgTypeSCCCN)
	f.sendZLB(scccn.hdr.Ns + 1)

	select {
	case err := <-errCh:
		require.NoError(t, err)
	case <-time.After(waitFor):
		t.Fatal("Establish did not return")
	}
	assert.Equal(t, uint32(1), tun.nr.Load(), "the duplicate transmission did not disturb Nr")
}

// ---------------------------------------------------------------------------
// Hello keepalive (RFC 2661 Section 5.5; the HELLO message itself is s6.5)
// ---------------------------------------------------------------------------

func TestHelloKeepaliveIsSentAndSequenced(t *testing.T) {
	const interval = 25 * time.Millisecond
	tun, f := establishTunnel(t, interval)

	var lastNs uint16 = 1 // SCCCN used Ns=1
	for i := 0; i < 3; i++ {
		hello := f.mustNextControl(MsgTypeHello)
		assert.Equal(t, lastNs+1, hello.hdr.Ns, "each Hello consumes exactly one Ns")
		assert.Equal(t, lnsTunnelID, hello.hdr.Tunnel)
		assert.Equal(t, uint16(0), hello.hdr.Session, "Hello is a tunnel-level message")
		lastNs = hello.hdr.Ns
		// Keep the tunnel alive by acking.
		f.sendZLB(hello.hdr.Ns + 1)
	}
	assert.True(t, tun.Alive())
}

func TestTunnelDiesWhenPeerStopsResponding(t *testing.T) {
	const interval = 25 * time.Millisecond
	tun, f := establishTunnel(t, interval)
	s := establishSession(t, tun, f)
	require.True(t, tun.Alive())

	// From here the LNS reads but never writes. recvLoop sets a read deadline
	// of helloInterval*3, so the read fails and the tunnel is torn down.
	assert.Eventually(t, func() bool { return !tun.Alive() }, waitFor, 5*time.Millisecond,
		"a silent peer must cause the tunnel to be torn down")
	assert.Eventually(t, func() bool { return sessionIsClosed(s) }, waitFor, 5*time.Millisecond,
		"tunnel death must close its sessions")

	_, err := s.RecvPPP()
	assert.ErrorIs(t, err, errSessionClosed)
	assert.ErrorIs(t, sendPPPParts(s, 0xC021, []byte{1}), errSessionClosed)
}

// ---------------------------------------------------------------------------
// Mandatory AVPs (RFC 2661 Section 4.1)
// ---------------------------------------------------------------------------

// CONFORMANCE GAP (RFC 2661 s4.1): "If the M bit is set on an unrecognized
// AVP within a message associated with a particular session, the session
// associated with this message MUST be terminated. If the M bit is set on an
// unrecognized AVP within a message associated with the overall tunnel, the
// entire tunnel [...] MUST be terminated." Tunnel.handleControl never
// inspects AVP.Mandatory at all: unknown AVPs are decoded, ignored, and the
// message is acknowledged as if nothing were wrong, so an LNS that requires a
// feature this LAC does not implement is silently ignored instead of tearing
// the tunnel down. This test pins the current behaviour so a future fix is a
// deliberate change.
func TestUnknownMandatoryAVPDoesNotTerminateAnything(t *testing.T) {
	tun, f := establishTunnel(t, 0)
	s := establishSession(t, tun, f)

	tests := []struct {
		name    string
		session uint16
		payload []byte
	}{
		{
			name:    "tunnel-level message with an unknown mandatory AVP",
			session: 0,
			payload: append(BuildHello(), EncodeAVPWithFlags(0x0FFF, []byte{0xDE, 0xAD}, true)...),
		},
		{
			name:    "session-level message with an unknown mandatory AVP",
			session: s.localSessionID,
			payload: append(BuildHello(), EncodeAVPWithFlags(0x0FEE, []byte{0xBE, 0xEF}, true)...),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nrBefore := tun.nr.Load()
			f.send(uint16(tun.ns.Load()), tt.session, tt.payload)

			ack := f.mustNextPacket()
			assert.True(t, ack.zlb, "the message is simply acknowledged")
			assert.Equal(t, uint16(nrBefore+1), ack.hdr.Nr)

			assert.True(t, tun.Alive(), "the tunnel is NOT terminated")
			assert.False(t, sessionIsClosed(s), "the session is NOT terminated")
			assert.Equal(t, 1, tun.SessionCount())
		})
	}
}

// CONFORMANCE GAP (RFC 2661 s4.4.1): the M bit of the Message Type AVP has a
// different meaning from every other AVP's -- "Rather than an indication as to
// whether the AVP itself should be ignored if not recognized, it is an
// indication as to whether the control message itself should be ignored. Thus,
// if the M-bit is set within the Message Type AVP and the Message Type is
// unknown to the implementation, the tunnel MUST be shut down." Every builder
// in this package emits the Message Type AVP with M=1 via EncodeUint16AVP, and
// a conformant LNS does the same, so an unknown message type arriving with M=1
// is the ordinary case. Tunnel.handleControl's `default:` branch (tunnel.go)
// logs "unhandled control message" at Debug level and returns: the message is
// acked with a ZLB, the tunnel stays up, and the sender is left believing a
// message the LAC never understood was processed.
// This test pins the current behaviour so a future fix is a deliberate change.
func TestUnknownMessageTypeWithMBitDoesNotShutDownTheTunnel(t *testing.T) {
	tun, f := establishTunnel(t, 0)
	s := establishSession(t, tun, f)

	// Message Type 0x00FF is not assigned by RFC 2661 and is not one of the
	// MsgType* constants this package knows.
	mt := EncodeUint16AVP(AVPMessageType, 0x00FF)
	avps, err := DecodeAVPs(mt)
	require.NoError(t, err)
	require.True(t, avps[0].Mandatory, "the builder sets M=1 on the Message Type AVP")

	nrBefore := tun.nr.Load()
	f.send(uint16(tun.ns.Load()), 0, append(mt, EncodeAVP(AVPHostName, []byte("lns"))...))

	ack := f.mustNextPacket()
	require.True(t, ack.zlb, "the unknown message is acknowledged like any other")
	assert.Equal(t, uint16(nrBefore+1), ack.hdr.Nr)

	// A conformant LAC would have torn the tunnel down here.
	time.Sleep(waitNot)
	assert.True(t, tun.Alive(), "the tunnel is NOT shut down")
	assert.False(t, sessionIsClosed(s), "the session survives too")
	assert.Equal(t, 1, tun.SessionCount())
}

// ---------------------------------------------------------------------------
// Teardown: StopCCN / CDN / Close
// ---------------------------------------------------------------------------

func TestStopCCNFromLNSTearsDownTunnelAndSessions(t *testing.T) {
	tun, f := establishTunnel(t, 0)
	s := establishSession(t, tun, f)
	require.Equal(t, 1, tun.SessionCount())

	f.send(uint16(tun.ns.Load()), 0, BuildStopCCN(lnsTunnelID, 2, 6, "shutting down"))

	assert.Eventually(t, func() bool { return !tun.Alive() }, waitFor, 5*time.Millisecond,
		"StopCCN must tear the tunnel down")
	assert.Eventually(t, func() bool { return sessionIsClosed(s) }, waitFor, 5*time.Millisecond,
		"StopCCN must close every session on the tunnel")

	_, err := s.RecvPPP()
	assert.ErrorIs(t, err, errSessionClosed)
}

func TestCDNFromLNS(t *testing.T) {
	// RFC 2661 s4.4.4: the Assigned Session ID AVP "encodes the ID being
	// assigned to this session by this peer", so in a CDN sent by the LNS it
	// names the LNS's own session -- the value the LNS handed over in its ICRP
	// and that the LAC keeps as Session.remoteSessionID. handleCDN matches on
	// exactly that, so what a conformant LNS puts on the wire is what closes
	// the session.
	t.Run("CDN carrying the LNS's own session ID closes the session", func(t *testing.T) {
		tun, f := establishTunnel(t, 0)
		s := establishSession(t, tun, f)
		require.Equal(t, lnsSessionID, s.remoteSID())

		// Header Session = the LAC's session ID (s3.1: "the Session ID in each
		// message is that of the intended recipient"), AVP = the LNS's own.
		f.send(uint16(tun.ns.Load()), s.localSessionID,
			BuildCDN(lnsSessionID, 3, 0, "call cleared"))

		requireSessionGone(t, tun, s, 0)
		// A CDN does not take the tunnel with it.
		assert.True(t, tun.Alive())
	})

	// RFC 2661 s3.1 makes the header's Session field the identifier of the local
	// session, so a peer that misfills the Assigned Session ID AVP with the
	// receiver's own ID -- a confusion the AVP's wording invites -- is still
	// understood. handleCDN resolves on the header first and only falls back to
	// the AVP, which also means the common path never reads a session's own
	// fields and so cannot race establish().
	t.Run("CDN is resolved by the header Session field even when the AVP is wrong", func(t *testing.T) {
		tun, f := establishTunnel(t, 0)
		s := establishSession(t, tun, f)
		require.NotEqual(t, s.remoteSID(), s.localSessionID)

		f.send(uint16(tun.ns.Load()), s.localSessionID,
			BuildCDN(s.localSessionID, 3, 0, "call cleared"))

		ack := f.mustNextPacket()
		require.True(t, ack.zlb, "the CDN is acknowledged")

		// The ack goes out before handleCDN runs, so it proves nothing on its
		// own; the barrier is what proves the CDN was seen and rejected.
		f.barrier(tun)
		assert.True(t, sessionIsClosed(s), "the header Session field addresses the session")
	})

	t.Run("CDN without an Assigned Session ID AVP is resolved by the header", func(t *testing.T) {
		tun, f := establishTunnel(t, 0)
		s := establishSession(t, tun, f)

		payload := append(EncodeUint16AVP(AVPMessageType, MsgTypeCDN),
			EncodeAVP(AVPResultCode, []byte{0, 3, 0, 0})...)
		f.send(uint16(tun.ns.Load()), s.localSessionID, payload)

		ack := f.mustNextPacket()
		require.True(t, ack.zlb)
		f.barrier(tun)
		assert.True(t, sessionIsClosed(s), "the header alone is enough to address the session")
	})

	// A malformed Assigned Session ID AVP no longer matters either: the header
	// resolves the session before the AVP is consulted at all.
	t.Run("CDN with a truncated Assigned Session ID AVP is resolved by the header", func(t *testing.T) {
		tun, f := establishTunnel(t, 0)
		s := establishSession(t, tun, f)

		payload := append(EncodeUint16AVP(AVPMessageType, MsgTypeCDN),
			EncodeAVP(AVPAssignedSessionID, []byte{0x42})...)
		f.send(uint16(tun.ns.Load()), s.localSessionID, payload)

		ack := f.mustNextPacket()
		require.True(t, ack.zlb)
		f.barrier(tun)
		assert.True(t, sessionIsClosed(s),
			"a malformed AVP no longer matters once the header has addressed the session")
	})
}

// CONFORMANCE GAP (RFC 2661 s3.1): the same unenforced Length field that
// TestDecodeHeaderDoesNotEnforceLengthShorterThanBuffer pins in the codec,
// shown costing a real message on the wire. Tunnel.recvLoop hands
// handleControl buf[off:n] -- the rest of the *datagram*, not the rest of the
// declared message -- so trailing octets past hdr.Length are fed to DecodeAVPs
// along with the body. Here a StopCCN arrives with four octets of padding
// after its declared end: DecodeAVPs rejects the combined buffer with
// ErrBadAVP, handleControl logs at Debug and returns, and the teardown request
// is lost. The LAC still ZLB-acks the datagram, so the LNS believes its
// StopCCN was received while this end keeps the tunnel and its session open.
// This test pins the current behaviour so a future fix is a deliberate change.
func TestTrailingPaddingPastTheDeclaredLengthDiscardsTheMessage(t *testing.T) {
	tun, f := establishTunnel(t, 0)
	s := establishSession(t, tun, f)

	payload := BuildStopCCN(lnsTunnelID, 2, 6, "shutting down")
	pkt := append(EncodeControlHeader(lacTunnelID, 0, uint16(tun.nr.Load()), uint16(tun.ns.Load()), len(payload)), payload...)
	declared := binary.BigEndian.Uint16(pkt[2:4])

	// Four zero octets: not a valid AVP (declared AVP length 0 < 6), so the
	// combined buffer cannot be parsed at all.
	pkt = append(pkt, 0x00, 0x00, 0x00, 0x00)
	require.Greater(t, len(pkt), int(declared), "the datagram outruns the declared Length")

	nrBefore := tun.nr.Load()
	f.write(pkt)

	// The datagram is accepted at the header/sequencing layer...
	ack := f.mustNextPacket()
	require.True(t, ack.zlb, "the padded StopCCN is acknowledged, got %x", ack.raw)
	assert.Equal(t, uint16(nrBefore+1), ack.hdr.Nr, "Nr advanced past a message that was then dropped")

	// ...and then thrown away. A conformant receiver, parsing only the first
	// hdr.Length octets, would have seen a perfectly good StopCCN and died.
	time.Sleep(waitNot)
	assert.True(t, tun.Alive(), "the StopCCN was silently discarded")
	assert.False(t, sessionIsClosed(s))
	assert.Equal(t, 1, tun.SessionCount())

	// Proof that the message itself was well-formed: trimmed to hdr.Length it
	// is exactly the StopCCN the LNS meant to send.
	trimmed, err := DecodeAVPs(pkt[12:declared])
	require.NoError(t, err)
	mt, err := GetMessageType(trimmed)
	require.NoError(t, err)
	assert.Equal(t, MsgTypeStopCCN, mt)

	// And the untrimmed buffer -- what handleControl actually parses -- does not.
	_, err = DecodeAVPs(pkt[12:])
	assert.ErrorIs(t, err, ErrBadAVP)
}

func TestSessionCloseSendsCDNAndTearsDownTheLastTunnel(t *testing.T) {
	tun, f := establishTunnel(t, 0)
	s := establishSession(t, tun, f)

	s.Close()

	cdn := f.mustNextControl(MsgTypeCDN)
	assert.Equal(t, lnsSessionID, cdn.hdr.Session, "CDN is addressed to the LNS's session ID")
	sid := FindAVP(cdn.avps, 0, AVPAssignedSessionID)
	require.NotNil(t, sid)
	v, err := AVPUint16(sid)
	require.NoError(t, err)
	assert.Equal(t, s.localSessionID, v, "the AVP carries the LAC's own session ID")

	assert.True(t, sessionIsClosed(s))
	assert.Equal(t, 0, tun.SessionCount())
	// The last session closing takes the tunnel with it.
	assert.Eventually(t, func() bool { return !tun.Alive() }, waitFor, 5*time.Millisecond)
}

func TestTunnelCloseTearsDownSessions(t *testing.T) {
	tun, f := establishTunnel(t, 0)
	s := establishSession(t, tun, f)

	tun.Close()

	assert.False(t, tun.Alive())
	assert.True(t, sessionIsClosed(s), "Close must tear down every session")
	_, err := s.RecvPPP()
	assert.ErrorIs(t, err, errSessionClosed)
	assert.ErrorIs(t, sendPPPParts(s, 0xC021, []byte{1}), errSessionClosed)

	// Close is idempotent.
	assert.NotPanics(t, func() {
		tun.Close()
		tun.Close()
	})
	f.drain()
}

// Superseded by TestTunnelCloseSendsStopCCNToTheLNS in shutdown_test.go: Close
// now transmits StopCCN before marking the tunnel closed, so the behaviour this
// test pinned no longer exists.

// ---------------------------------------------------------------------------
// Data plane demultiplexing
// ---------------------------------------------------------------------------

func TestDataPlaneDemux(t *testing.T) {
	tun, f := establishTunnel(t, 0)
	s := establishSession(t, tun, f)

	dataPkt := func(session uint16, body []byte) []byte {
		return append(EncodeDataHeader(lacTunnelID, session), body...)
	}

	// Everything below is one property stated several ways: a data frame reaches
	// the session as the exact bytes that arrived.
	//
	// The LAC used to take the frame apart -- strip a leading FF 03, read a
	// two-octet protocol field -- and put it back together on the way out.
	//
	// That round trip happened to be lossless, because the octets it wrote back
	// were the ones it had skipped: a Protocol-Field-Compressed field was misread
	// and then reassembled identically. But nothing between the two ever used the
	// result, and its correctness rested on that cancellation rather than on
	// anything stated. Whether PFC or address/control compression is in use is
	// agreed between the subscriber's pppd and the LNS, through this tunnel and
	// without telling the LAC, so the property worth having is the one below:
	// the bytes that arrive are the bytes that are delivered, whatever they are.
	t.Run("a frame arrives as the bytes that were sent", func(t *testing.T) {
		for _, tc := range []struct {
			name  string
			frame []byte
		}{
			{"uncompressed, no address/control", []byte{0xC0, 0x21, 0x01, 0x02, 0x03}},
			{"with address/control", []byte{0xFF, 0x03, 0x80, 0x21, 0xAA}},
			{"PFC IPv4", []byte{0x21, 0x45, 0x00}},
			{"PFC IPv6", []byte{0x57, 0x60, 0x00}},
			{"PFC multilink", []byte{0x3D, 0xC0, 0x01}},
			{"PFC after address/control", []byte{0xFF, 0x03, 0x21, 0x45}},
			{"a protocol field and nothing else", []byte{0x21}},
			// Malformed PPP still crosses: validating it is the subscriber's
			// pppd's job, and a LAC that dropped what it did not understand
			// would be deciding for an endpoint it cannot see.
			{"half a protocol field", []byte{0xC0}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				f.write(dataPkt(s.localSessionID, tc.frame))
				got, err := s.RecvPPP()
				require.NoError(t, err)
				assert.Equal(t, tc.frame, got)
			})
		}
	})

	t.Run("data for an unknown session is dropped without disturbing the tunnel", func(t *testing.T) {
		f.write(dataPkt(s.localSessionID+7, []byte{0xC0, 0x21, 0x99}))
		f.write(dataPkt(s.localSessionID, []byte{0xC0, 0x21, 0x77}))
		got, err := s.RecvPPP()
		require.NoError(t, err)
		assert.Equal(t, []byte{0xC0, 0x21, 0x77}, got)
		assert.True(t, tun.Alive())
	})

	t.Run("an empty data message is not a frame", func(t *testing.T) {
		f.write(dataPkt(s.localSessionID, nil))
		f.write(dataPkt(s.localSessionID, []byte{0xC0, 0x21, 0x55}))
		got, err := s.RecvPPP()
		require.NoError(t, err)
		assert.Equal(t, []byte{0xC0, 0x21, 0x55}, got, "the empty one must not have been delivered")
		assert.True(t, tun.Alive())
	})

	t.Run("outbound data is addressed to the LNS session and otherwise untouched", func(t *testing.T) {
		for _, frame := range [][]byte{
			{0xC0, 0x21, 0x0A, 0x0B},       // uncompressed
			{0xFF, 0x03, 0xC0, 0x21, 0x0A}, // with address/control
			{0x21, 0x45, 0x00, 0x14},       // Protocol-Field-Compressed
		} {
			require.NoError(t, s.SendPPP(frame))
			p := f.mustNextPacket()
			require.False(t, p.hdr.IsControl)
			assert.Equal(t, lnsTunnelID, p.hdr.Tunnel)
			assert.Equal(t, lnsSessionID, p.hdr.Session,
				"RFC 2661 s3.1: the header addresses the session at the receiver")
			assert.Equal(t, frame, p.raw[p.off:],
				"what the subscriber sent is what the LNS gets")
		}
	})
}

func TestGarbageOnTheWireDoesNotKillTheTunnel(t *testing.T) {
	tun, f := establishTunnel(t, 0)

	nrBefore := tun.nr.Load()
	garbage := [][]byte{
		{0x00}, // too short for a header
		{0xC8, 0x03, 0x00, 0x0C, 0, 0, 0, 0, 0, 0, 0, 0}, // bad version
		{0x02, 0x02, 0x00, 0x01, 0x00, 0x00, 0xFF, 0xFF}, // offset pad past end of packet
		// A control message whose body is not a valid AVP stream. Sent
		// out-of-sequence so it cannot legitimately move Nr either.
		append(EncodeControlHeader(lacTunnelID, 0, 0x7000, 1, 3), 0x01, 0x02, 0x03),
	}
	for _, g := range garbage {
		f.write(g)
	}
	time.Sleep(waitNot)
	assert.True(t, tun.Alive(), "malformed input must be discarded, not fatal")
	assert.Equal(t, nrBefore, tun.nr.Load(), "garbage must not advance Nr")
	f.drain()

	// A well-formed, in-order Hello still gets through afterwards.
	f.sendAt(uint16(nrBefore), uint16(tun.ns.Load()), 0, BuildHello())
	ack := f.mustNextPacket()
	require.True(t, ack.zlb, "expected a ZLB ack, got %x", ack.raw)
	assert.Equal(t, uint16(nrBefore+1), ack.hdr.Nr)
}

// ---------------------------------------------------------------------------
// Tunnel authentication (RFC 2661 Section 5.1.1) over the wire
// ---------------------------------------------------------------------------

func TestEstablishWithSharedSecret(t *testing.T) {
	secret := []byte("tunnelsecret")

	newAuthTunnel := func(t *testing.T) (*Tunnel, *fakeLNS, chan error) {
		f, lacConn := newFakeLNS(t)
		tun := newTunnel(lacConn, lacTunnelID, "test-lac", secret, 0, zap.NewNop())
		t.Cleanup(tun.Close)
		errCh := make(chan error, 1)
		go func() { errCh <- tun.Establish() }()
		return tun, f, errCh
	}

	t.Run("mutual challenge/response succeeds and is RFC 2661 s5.1.1 shaped", func(t *testing.T) {
		_, f, errCh := newAuthTunnel(t)

		sccrq := f.mustNextControl(MsgTypeSCCRQ)
		lacChallenge := FindAVP(sccrq.avps, 0, AVPChallenge)
		require.NotNil(t, lacChallenge, "a LAC with a secret must challenge the LNS")
		assert.Len(t, lacChallenge.Value, 16)

		// Both sides of this exchange are computed with md5.Sum here rather
		// than with ComputeChallengeResponse, so the test cannot pass by
		// agreeing with the implementation about a construction that is wrong:
		// RFC 2661 s5.1.1 is MD5(message-type octet || secret || challenge).
		lnsChallenge := []byte{9, 9, 9, 9, 9, 9, 9, 9, 8, 8, 8, 8, 8, 8, 8, 8}
		wantLNSResponse := md5.Sum(append(append([]byte{byte(MsgTypeSCCRP)}, secret...), lacChallenge.Value...))
		f.send(sccrq.hdr.Ns+1, 0, buildSCCRP(
			lnsTunnelID,
			EncodeBytesAVP(AVPChallenge, lnsChallenge),
			EncodeBytesAVP(AVPChallengeResponse, wantLNSResponse[:]),
		))

		scccn := f.mustNextControl(MsgTypeSCCCN)
		cr := FindAVP(scccn.avps, 0, AVPChallengeResponse)
		require.NotNil(t, cr, "the LAC must answer the LNS challenge")
		wantLACResponse := md5.Sum(append(append([]byte{byte(MsgTypeSCCCN)}, secret...), lnsChallenge...))
		assert.Equal(t, wantLACResponse[:], cr.Value)

		f.sendZLB(scccn.hdr.Ns + 1)
		select {
		case err := <-errCh:
			require.NoError(t, err)
		case <-time.After(waitFor):
			t.Fatal("Establish did not return")
		}
	})

	tests := []struct {
		name    string
		extra   func(challenge []byte) [][]byte
		wantErr string
	}{
		{
			name:    "missing Challenge Response is rejected",
			extra:   func([]byte) [][]byte { return nil },
			wantErr: "LNS did not respond to our challenge",
		},
		{
			name: "wrong Challenge Response is rejected",
			extra: func([]byte) [][]byte {
				return [][]byte{EncodeBytesAVP(AVPChallengeResponse, make([]byte, 16))}
			},
			wantErr: "invalid challenge response",
		},
		{
			name: "short Challenge Response is rejected",
			extra: func([]byte) [][]byte {
				return [][]byte{EncodeBytesAVP(AVPChallengeResponse, []byte{0x01, 0x02})}
			},
			wantErr: "invalid challenge response",
		},
		{
			name: "Challenge Response computed over the wrong message type is rejected",
			extra: func(challenge []byte) [][]byte {
				return [][]byte{EncodeBytesAVP(AVPChallengeResponse,
					ComputeChallengeResponse(byte(MsgTypeSCCCN), secret, challenge))}
			},
			wantErr: "invalid challenge response",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, f, errCh := newAuthTunnel(t)
			sccrq := f.mustNextControl(MsgTypeSCCRQ)
			challenge := FindAVP(sccrq.avps, 0, AVPChallenge)
			require.NotNil(t, challenge)

			f.send(sccrq.hdr.Ns+1, 0, buildSCCRP(lnsTunnelID, tt.extra(challenge.Value)...))

			select {
			case err := <-errCh:
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			case <-time.After(waitFor):
				t.Fatal("Establish did not return")
			}
		})
	}
}

func TestEstablishRejectsBadSCCRP(t *testing.T) {
	tests := []struct {
		name    string
		payload []byte
		wantErr string
	}{
		{
			name:    "StopCCN instead of SCCRP",
			payload: BuildStopCCN(lnsTunnelID, 2, 6, "no"),
			wantErr: "LNS rejected tunnel with StopCCN",
		},
		{
			name:    "unexpected message type",
			payload: BuildHello(),
			wantErr: "expected SCCRP",
		},
		{
			name: "SCCRP without an Assigned Tunnel ID",
			payload: append(EncodeUint16AVP(AVPMessageType, MsgTypeSCCRP),
				EncodeStringAVP(AVPHostName, "lns")...),
			wantErr: "Assigned Tunnel ID",
		},
		{
			name: "SCCRP with a truncated Assigned Tunnel ID",
			payload: append(EncodeUint16AVP(AVPMessageType, MsgTypeSCCRP),
				EncodeAVP(AVPAssignedTunnelID, []byte{0x01})...),
			wantErr: "expected 2 bytes",
		},
		{
			name:    "no Message Type AVP at all",
			payload: EncodeStringAVP(AVPHostName, "lns"),
			wantErr: "Message Type",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, lacConn := newFakeLNS(t)
			tun := newTunnel(lacConn, lacTunnelID, "test-lac", nil, 0, zap.NewNop())
			t.Cleanup(tun.Close)

			errCh := make(chan error, 1)
			go func() { errCh <- tun.Establish() }()

			sccrq := f.mustNextControl(MsgTypeSCCRQ)
			f.send(sccrq.hdr.Ns+1, 0, tt.payload)

			select {
			case err := <-errCh:
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			case <-time.After(waitFor):
				t.Fatal("Establish did not return")
			}
		})
	}
}

func TestSessionEstablishRejectsBadICRP(t *testing.T) {
	tests := []struct {
		name    string
		payload func(localSID uint16) []byte
		wantErr string
	}{
		{
			name:    "CDN instead of ICRP",
			payload: func(uint16) []byte { return BuildCDN(lnsSessionID, 2, 0, "busy") },
			wantErr: "LNS rejected session with CDN",
		},
		{
			name: "ICRP without an Assigned Session ID",
			payload: func(uint16) []byte {
				return EncodeUint16AVP(AVPMessageType, MsgTypeICRP)
			},
			wantErr: "Assigned Session ID in ICRP",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tun, f := establishTunnel(t, 0)

			errCh := make(chan error, 1)
			go func() {
				_, err := tun.CreateSession(testSubscriber, "5551234")
				errCh <- err
			}()

			icrq := f.mustNextControl(MsgTypeICRQ)
			sidAVP := FindAVP(icrq.avps, 0, AVPAssignedSessionID)
			require.NotNil(t, sidAVP)
			localSID, err := AVPUint16(sidAVP)
			require.NoError(t, err)

			f.send(icrq.hdr.Ns+1, localSID, tt.payload(localSID))

			select {
			case err := <-errCh:
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			case <-time.After(waitFor):
				t.Fatal("CreateSession did not return")
			}
			// A failed session must not be left in the registry.
			assert.Equal(t, 0, tun.SessionCount())
		})
	}
}

func TestBuildControlHeaderFieldsMatchTunnelState(t *testing.T) {
	// Cross-check the encoder against the tunnel's own counters: every
	// control message must carry the Ns the tunnel allocated and the Nr it
	// currently expects.
	tun, f := establishTunnel(t, 0)

	for i := 0; i < 4; i++ {
		wantNs := uint16(tun.ns.Load())
		wantNr := uint16(tun.nr.Load())
		require.NoError(t, tun.sendControl(tun.remoteTunnelID, 0, BuildHello()))

		p := f.mustNextControl(MsgTypeHello)
		assert.Equal(t, wantNs, p.hdr.Ns, "iteration %d", i)
		assert.Equal(t, wantNr, p.hdr.Nr, "iteration %d", i)
		assert.Equal(t, uint16(len(p.raw)), p.hdr.Length)
		assert.Equal(t, uint32(wantNs)+1, tun.ns.Load(), "Ns increments by exactly one")

		f.sendZLB(p.hdr.Ns + 1)
		// Feed one inbound control message so Nr moves too.
		f.send(uint16(tun.ns.Load()), 0, BuildHello())
		ack := f.mustNextPacket()
		require.True(t, ack.zlb, "expected a ZLB ack, got %x", ack.raw)
		assert.Equal(t, uint16(wantNr+1), ack.hdr.Nr, "Nr echoes the message just received")
		assert.Equal(t, uint32(wantNr)+1, tun.nr.Load())
	}
}
