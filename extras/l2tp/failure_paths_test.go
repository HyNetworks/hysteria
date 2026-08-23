package l2tp

import (
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

// What happens when the wire, or the LNS, misbehaves.
//
// The happy paths are covered elsewhere. These are the ones a LAC in production
// actually meets: an LNS that answers the handshake and then goes quiet, a
// socket that stops accepting writes mid-session, a peer that sends something
// that does not decode. None of them may hang, and none may take a tunnel down
// that other subscribers are still using.
//
// The control retransmission schedule is per-tunnel (ctrlBase/ctrlCap/
// ctrlRetries) so these run in milliseconds instead of the tens of seconds the
// production 1s-doubling schedule would cost.

// fastRetries shortens a tunnel's control retransmission schedule. It must be
// called before Establish.
func fastRetries(t *Tunnel) {
	t.ctrlBase = 5 * time.Millisecond
	t.ctrlCap = 20 * time.Millisecond
	t.ctrlRetries = 2
}

// writeFailConn allows a fixed number of writes through to the wrapped
// connection and fails every one after that, which is how a socket that goes
// away part-way through a handshake behaves. A negative allowance means "no
// limit", so a test can let the tunnel come up and then take the wire away.
type writeFailConn struct {
	net.Conn
	mu    sync.Mutex
	allow int
	sent  int
}

var errWireGone = errors.New("wire is gone")

const unlimitedWrites = -1

func (c *writeFailConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	if c.allow == 0 {
		c.mu.Unlock()
		return 0, errWireGone
	}
	if c.allow > 0 {
		c.allow--
	}
	c.sent++
	c.mu.Unlock()
	return c.Conn.Write(b)
}

// stopWrites makes every subsequent write fail.
func (c *writeFailConn) stopWrites() { c.setAllowance(0) }

func (c *writeFailConn) setAllowance(n int) {
	c.mu.Lock()
	c.allow = n
	c.mu.Unlock()
}

func (c *writeFailConn) writes() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sent
}

// deadWireConn accepts nothing and delivers nothing: writes fail immediately
// and reads block until it is closed.
type deadWireConn struct{ closed chan struct{} }

func newDeadWire() *deadWireConn { return &deadWireConn{closed: make(chan struct{})} }

func (c *deadWireConn) Read([]byte) (int, error) {
	<-c.closed
	return 0, net.ErrClosed
}
func (c *deadWireConn) Write([]byte) (int, error) { return 0, errWireGone }

func (c *deadWireConn) Close() error {
	select {
	case <-c.closed:
	default:
		close(c.closed)
	}
	return nil
}
func (c *deadWireConn) LocalAddr() net.Addr              { return dummyAddr{} }
func (c *deadWireConn) RemoteAddr() net.Addr             { return dummyAddr{} }
func (c *deadWireConn) SetDeadline(time.Time) error      { return nil }
func (c *deadWireConn) SetReadDeadline(time.Time) error  { return nil }
func (c *deadWireConn) SetWriteDeadline(time.Time) error { return nil }

// ---------------------------------------------------------------------------
// Tunnel handshake against a wire that fails
// ---------------------------------------------------------------------------

func TestEstablishReportsASocketThatCannotSendTheSCCRQ(t *testing.T) {
	_, lacConn := newFakeLNS(t)
	tun := newTunnel(&writeFailConn{Conn: lacConn, allow: 0}, lacTunnelID, "test-lac", nil, 0, zap.NewNop())
	fastRetries(tun)

	err := tun.Establish()
	require.Error(t, err)
	assert.ErrorContains(t, err, "send SCCRQ")
	assert.ErrorIs(t, err, errWireGone)
}

// A read error that is not a timeout is not something a retransmission can fix,
// so it must end the handshake rather than burn the whole retry budget.
func TestEstablishGivesUpImmediatelyOnANonTimeoutReadError(t *testing.T) {
	f, lacConn := newFakeLNS(t)
	tun := newTunnel(lacConn, lacTunnelID, "test-lac", nil, 0, zap.NewNop())
	fastRetries(tun)

	errCh := make(chan error, 1)
	go func() { errCh <- tun.Establish() }()

	f.mustNextControl(MsgTypeSCCRQ)
	require.NoError(t, f.conn.Close()) // the LNS vanishes: EOF, not a timeout

	select {
	case err := <-errCh:
		require.Error(t, err)
		assert.ErrorContains(t, err, "recv SCCRP")
		assert.NotContains(t, err.Error(), "retries",
			"an EOF is final; retransmitting into a closed socket is pointless")
	case <-time.After(waitFor):
		t.Fatal("Establish did not return after the LNS went away")
	}
}

// The SCCCN is the last message of the handshake and the socket can fail on it
// like any other. The tunnel must be torn down rather than left half-open.
func TestEstablishTearsDownWhenTheSCCCNCannotBeSent(t *testing.T) {
	f, lacConn := newFakeLNS(t)
	// SCCRQ and the ZLB acknowledging the SCCRP get through; the SCCCN does not.
	wire := &writeFailConn{Conn: lacConn, allow: 2}
	tun := newTunnel(wire, lacTunnelID, "test-lac", nil, 0, zap.NewNop())
	fastRetries(tun)

	errCh := make(chan error, 1)
	go func() { errCh <- tun.Establish() }()

	sccrq := f.mustNextControl(MsgTypeSCCRQ)
	f.send(sccrq.hdr.Ns+1, 0, buildSCCRP(lnsTunnelID))

	select {
	case err := <-errCh:
		require.Error(t, err)
		assert.ErrorContains(t, err, "send SCCCN")
	case <-time.After(waitFor):
		t.Fatal("Establish did not return after the SCCCN could not be sent")
	}
	assert.False(t, tun.Alive(), "a handshake that failed must not leave the tunnel alive")
	assert.Equal(t, 2, wire.writes(), "the StopCCN could not go out either, and that is not fatal")
}

// An LNS that answers the SCCRQ and then never acknowledges the SCCCN leaves the
// control connection unusable. The LAC retransmits, then gives up.
func TestEstablishRetransmitsTheSCCCNAndThenGivesUp(t *testing.T) {
	f, lacConn := newFakeLNS(t)
	tun := newTunnel(lacConn, lacTunnelID, "test-lac", nil, 0, zap.NewNop())
	fastRetries(tun)

	errCh := make(chan error, 1)
	go func() { errCh <- tun.Establish() }()

	sccrq := f.mustNextControl(MsgTypeSCCRQ)
	f.send(sccrq.hdr.Ns+1, 0, buildSCCRP(lnsTunnelID))

	// Every transmission of the SCCCN carries the same Ns (RFC 2661 s5.8).
	first := f.mustNextControl(MsgTypeSCCCN)
	for range tun.ctrlRetries {
		again := f.mustNextControl(MsgTypeSCCCN)
		assert.Equal(t, first.raw, again.raw, "an SCCCN retransmission is byte-identical")
	}

	select {
	case err := <-errCh:
		require.Error(t, err)
		assert.ErrorContains(t, err, "SCCCN ack")
	case <-time.After(waitFor):
		t.Fatal("Establish did not give up on the unacknowledged SCCCN")
	}
	assert.False(t, tun.Alive())
}

// ---------------------------------------------------------------------------
// recvControlDirect: what the pre-recvLoop reader tolerates
// ---------------------------------------------------------------------------

// Everything up to the last message here has to be skipped without ending the
// read, because during the handshake there is no recvLoop yet to absorb it: if
// this reader gave up on the first stray datagram, a single misdirected packet
// on a shared LNS port would stop a tunnel coming up.
func TestRecvControlDirectSkipsWhatItCannotUse(t *testing.T) {
	f, lacConn := newFakeLNS(t)
	tun := newTunnel(lacConn, lacTunnelID, "test-lac", nil, 0, zap.NewNop())
	t.Cleanup(tun.Close)

	type res struct {
		avps []AVP
		err  error
	}
	resCh := make(chan res, 1)
	go func() {
		avps, err := tun.recvControlDirect(waitFor)
		resCh <- res{avps, err}
	}()

	// Not an L2TP header at all.
	f.write([]byte{0x00, 0x01, 0x02})
	// A data message: this reader only wants control.
	f.write(append(EncodeDataHeader(lacTunnelID, 7), 0x00, 0x21, 0xAA))
	// A control message out of sequence: acknowledged, not acted on.
	f.sendAt(9, 0, 0, BuildHello())
	// A zero-length body at the expected Ns: a ZLB ack carries nothing to return.
	f.sendAt(0, 0, 0, nil)
	// Finally something with a body that does not decode as AVPs.
	f.sendAt(1, 0, 0, []byte{0x00, 0x06})

	select {
	case r := <-resCh:
		require.Error(t, r.err)
		assert.ErrorContains(t, r.err, "decode AVPs")
	case <-time.After(waitFor):
		t.Fatal("recvControlDirect neither skipped nor returned")
	}
	assert.Equal(t, uint32(2), tun.nr.Load(),
		"only the two in-sequence control messages advanced Nr")
}

// ---------------------------------------------------------------------------
// Waiting for control responses
// ---------------------------------------------------------------------------

func TestWaitForControlEndsOnTimeoutAndOnTunnelClose(t *testing.T) {
	_, lacConn := newFakeLNS(t)
	tun := newTunnel(lacConn, lacTunnelID, "test-lac", nil, 0, zap.NewNop())

	ch := make(chan controlMsg, 1)
	_, _, err := tun.waitForControl(ch, 10*time.Millisecond)
	assert.ErrorIs(t, err, errControlTimeout)

	tun.Close()
	_, _, err = tun.waitForControl(ch, waitFor)
	assert.ErrorIs(t, err, errTunnelClosed, "a closed tunnel must not make a waiter sit out its timeout")
}

func TestAClosedTunnelRefusesToSendAnything(t *testing.T) {
	_, lacConn := newFakeLNS(t)
	tun := newTunnel(lacConn, lacTunnelID, "test-lac", nil, 0, zap.NewNop())
	tun.Close()

	assert.ErrorIs(t, tun.sendControl(lnsTunnelID, 0, BuildHello()), errTunnelClosed)
	assert.ErrorIs(t, tun.writePacket(EncodeControlHeader(lnsTunnelID, 0, 0, 0, 0)), errTunnelClosed)
	assert.ErrorIs(t, tun.SendData(1, framePPP(0x0021, []byte{0x45})), errTunnelClosed)
	assert.ErrorIs(t, tun.waitForPeerAck(0, waitFor), errTunnelClosed,
		"a waiter must be released when the tunnel dies, not left until its deadline")
}

// ---------------------------------------------------------------------------
// Session IDs
// ---------------------------------------------------------------------------

// Session ID 0 addresses the tunnel itself, so a tunnel has 65535 usable IDs.
// A LAC that somehow held all of them must refuse the next call rather than
// hand out a duplicate, which would make the LNS's replies ambiguous.
func TestATunnelWithNoFreeSessionIDRefusesTheCall(t *testing.T) {
	_, lacConn := newFakeLNS(t)
	tun := newTunnel(lacConn, lacTunnelID, "test-lac", nil, 0, zap.NewNop())
	t.Cleanup(tun.Close)

	// Placeholders rather than real sessions: 65535 of those would allocate a
	// 256-frame receive queue each for no benefit. They still need the fields
	// the tunnel's teardown touches.
	for sid := 1; sid <= 0xFFFF; sid++ {
		tun.sessions[uint16(sid)] = &Session{
			tunnel: tun, logger: zap.NewNop(), localSessionID: uint16(sid),
			closed: make(chan struct{}),
		}
	}
	s, err := tun.CreateSession("crowded", "5551234")
	require.Error(t, err)
	assert.Nil(t, s)
	assert.ErrorContains(t, err, "no free session ID")
}

// ---------------------------------------------------------------------------
// Session handshake failures
// ---------------------------------------------------------------------------

func TestSessionEstablishReportsASocketThatCannotSendTheICRQ(t *testing.T) {
	f, lacConn := newFakeLNS(t)
	wire := &writeFailConn{Conn: lacConn, allow: unlimitedWrites}
	tun := newTunnel(wire, lacTunnelID, "test-lac", nil, 0, zap.NewNop())
	fastRetries(tun)
	t.Cleanup(tun.Close)

	errCh := make(chan error, 1)
	go func() { errCh <- tun.Establish() }()
	sccrq := f.mustNextControl(MsgTypeSCCRQ)
	f.send(sccrq.hdr.Ns+1, 0, buildSCCRP(lnsTunnelID))
	scccn := f.mustNextControl(MsgTypeSCCCN)
	f.sendZLB(scccn.hdr.Ns + 1)
	require.NoError(t, <-errCh)

	wire.stopWrites() // the socket goes away with the tunnel already up

	_, err := tun.CreateSession(testSubscriber, "5551234")
	require.Error(t, err)
	assert.ErrorContains(t, err, "send ICRQ")
	assert.Equal(t, 0, tun.SessionCount(), "a call that never left must not stay registered")
}

// An ICRQ that draws no ICRP is retransmitted and then abandoned. The session
// must be deregistered, or the tunnel would never reach zero sessions and would
// stay up forever.
func TestSessionEstablishRetransmitsTheICRQAndThenGivesUp(t *testing.T) {
	tun, f := establishTunnel(t, 0)
	fastRetries(tun)

	errCh := make(chan error, 1)
	go func() {
		_, err := tun.CreateSession(testSubscriber, "5551234")
		errCh <- err
	}()

	first := f.mustNextControl(MsgTypeICRQ)
	for range tun.ctrlRetries {
		again := f.mustNextControl(MsgTypeICRQ)
		assert.Equal(t, first.raw, again.raw, "an ICRQ retransmission is byte-identical")
	}

	select {
	case err := <-errCh:
		require.Error(t, err)
		assert.ErrorContains(t, err, "recv ICRP")
	case <-time.After(waitFor):
		t.Fatal("CreateSession did not give up on the unanswered ICRQ")
	}
	assert.Equal(t, 0, tun.SessionCount())
	assert.True(t, tun.Alive(), "one failed call does not take the control connection down")
}

// The Assigned Session ID is two octets (RFC 2661 s4.4.4). Anything else is not
// a session ID we can address, so the call fails rather than proceeding with a
// guess.
func TestSessionEstablishRejectsAMalformedAssignedSessionID(t *testing.T) {
	tun, f := establishTunnel(t, 0)
	fastRetries(tun)

	errCh := make(chan error, 1)
	go func() {
		_, err := tun.CreateSession(testSubscriber, "5551234")
		errCh <- err
	}()

	icrq := f.mustNextControl(MsgTypeICRQ)
	localSID, err := AVPUint16(FindAVP(icrq.avps, 0, AVPAssignedSessionID))
	require.NoError(t, err)

	bad := append(EncodeUint16AVP(AVPMessageType, MsgTypeICRP),
		EncodeAVP(AVPAssignedSessionID, []byte{0x01})...)
	f.send(icrq.hdr.Ns+1, localSID, bad)

	select {
	case err := <-errCh:
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrBadAVP,
			"the call must fail on the malformed AVP, not stumble on to the ICCN")
	case <-time.After(waitFor):
		t.Fatal("CreateSession accepted a malformed Assigned Session ID")
	}
	assert.Equal(t, 0, tun.SessionCount())
	// The ICRP is still acknowledged -- it arrived in sequence -- but nothing
	// else may follow: an ICCN would complete a call whose session ID we could
	// not read.
	for {
		p, ok := f.nextPacket(waitNot)
		if !ok {
			break
		}
		assert.True(t, p.zlb, "only the ZLB acknowledging the ICRP may follow, got %x", p.raw)
	}
}

// The ICCN completes the call, and an LNS that never acknowledges it has not
// accepted it. Retransmit, then fail -- with the session deregistered.
func TestSessionEstablishRetransmitsTheICCNAndThenGivesUp(t *testing.T) {
	tun, f := establishTunnel(t, 0)
	fastRetries(tun)

	errCh := make(chan error, 1)
	go func() {
		_, err := tun.CreateSession(testSubscriber, "5551234")
		errCh <- err
	}()

	icrq := f.mustNextControl(MsgTypeICRQ)
	localSID, err := AVPUint16(FindAVP(icrq.avps, 0, AVPAssignedSessionID))
	require.NoError(t, err)
	f.send(icrq.hdr.Ns+1, localSID, buildICRP(lnsSessionID))

	first := f.mustNextControl(MsgTypeICCN)
	for range tun.ctrlRetries {
		again := f.mustNextControl(MsgTypeICCN)
		assert.Equal(t, first.raw, again.raw, "an ICCN retransmission is byte-identical")
	}

	select {
	case err := <-errCh:
		require.Error(t, err)
		assert.ErrorContains(t, err, "ICCN ack")
	case <-time.After(waitFor):
		t.Fatal("CreateSession did not give up on the unacknowledged ICCN")
	}
	assert.Equal(t, 0, tun.SessionCount())
}

func TestSessionEstablishReportsASocketThatCannotSendTheICCN(t *testing.T) {
	f, lacConn := newFakeLNS(t)
	wire := &writeFailConn{Conn: lacConn, allow: unlimitedWrites}
	tun := newTunnel(wire, lacTunnelID, "test-lac", nil, 0, zap.NewNop())
	fastRetries(tun)
	t.Cleanup(tun.Close)

	errCh := make(chan error, 1)
	go func() { errCh <- tun.Establish() }()
	sccrq := f.mustNextControl(MsgTypeSCCRQ)
	f.send(sccrq.hdr.Ns+1, 0, buildSCCRP(lnsTunnelID))
	scccn := f.mustNextControl(MsgTypeSCCCN)
	f.sendZLB(scccn.hdr.Ns + 1)
	require.NoError(t, <-errCh)

	sessCh := make(chan error, 1)
	go func() {
		_, err := tun.CreateSession(testSubscriber, "5551234")
		sessCh <- err
	}()

	icrq := f.mustNextControl(MsgTypeICRQ)
	localSID, err := AVPUint16(FindAVP(icrq.avps, 0, AVPAssignedSessionID))
	require.NoError(t, err)

	// The wire dies between the ICRQ and the ICCN: the ZLB acknowledging the
	// ICRP is the last write that gets through.
	wire.setAllowance(1)
	f.send(icrq.hdr.Ns+1, localSID, buildICRP(lnsSessionID))

	select {
	case err := <-sessCh:
		require.Error(t, err)
		assert.ErrorContains(t, err, "send ICCN")
	case <-time.After(waitFor):
		t.Fatal("CreateSession did not report the failed ICCN")
	}
}

// ---------------------------------------------------------------------------
// Inbound frames the demux loop must survive
// ---------------------------------------------------------------------------

// A control message whose AVPs decode but carry no Message Type is malformed.
// It must be dropped, not treated as message type zero.
func TestAControlMessageWithNoMessageTypeIsDropped(t *testing.T) {
	tun, f := establishTunnel(t, 0)
	f.drain()

	f.send(uint16(tun.ns.Load()), 0, EncodeStringAVP(AVPHostName, "no-message-type"))
	f.barrier(tun)

	assert.True(t, tun.Alive(), "a malformed control message must not take the tunnel down")
}

// A session whose reader has stopped must not stall the tunnel's demux loop:
// every other subscriber on that LNS shares it. Frames are dropped and counted
// instead, and only the first drop is logged at warn level -- a black-holing
// session would otherwise flood the log at line rate.
func TestAStalledSessionDropsFramesInsteadOfBlockingTheTunnel(t *testing.T) {
	core, logs := observer.New(zap.DebugLevel)
	tun, f := establishTunnel(t, 0)
	s := establishSession(t, tun, f)
	s.logger = zap.New(core)

	full := cap(s.recvCh)
	for range full {
		s.deliverPPP([]byte{0x00, 0x21, 0x45})
	}
	require.Zero(t, s.Dropped(), "nothing may be dropped while there is room")

	for range 3 {
		s.deliverPPP([]byte{0x00, 0x21, 0x45})
	}
	assert.Equal(t, uint64(3), s.Dropped())
	assert.Len(t, logs.FilterLevelExact(zap.WarnLevel).All(), 1,
		"only the first drop is worth a warning")
	assert.Len(t, logs.FilterMessage("L2TP session frame dropped").All(), 2,
		"the rest are debug, so a black-holing session cannot flood the log")

	// The frames that did fit are still there, in order.
	proto, payload, err := recvPPPParts(s)
	require.NoError(t, err)
	assert.Equal(t, uint16(0x0021), proto)
	assert.Equal(t, []byte{0x45}, payload)
}

// Once a session is closed, a frame still in flight for it is discarded rather
// than queued for a reader that will never come back.
func TestAClosedSessionDiscardsFramesStillInFlight(t *testing.T) {
	tun, f := establishTunnel(t, 0)
	s := establishSession(t, tun, f)

	for range cap(s.recvCh) {
		s.deliverPPP([]byte{0x00, 0x21, 0x45})
	}
	s.Close()

	before := s.Dropped()
	s.deliverPPP([]byte{0x00, 0x21, 0x45})
	assert.Equal(t, before, s.Dropped(),
		"a frame for a closed session is not a frame the reader fell behind on")
}

// Both directions refuse work once the session is gone, so a relay that has not
// noticed yet ends rather than blocking on a queue nobody serves.
func TestAClosedSessionRefusesToCarryAnything(t *testing.T) {
	tun, f := establishTunnel(t, 0)
	s := establishSession(t, tun, f)
	s.Close()

	_, err := s.RecvPPP()
	assert.ErrorIs(t, err, errSessionClosed)
	assert.ErrorIs(t, sendPPPParts(s, 0x0021, []byte{0x45}), errSessionClosed)
}

// ---------------------------------------------------------------------------
// Keepalives
// ---------------------------------------------------------------------------

// The HELLO loop is what holds a quiet tunnel open. If the socket stops taking
// writes it must end rather than spin, because the tunnel is finished either way
// and recvLoop is about to notice.
func TestHelloLoopStopsWhenTheSocketStopsAcceptingWrites(t *testing.T) {
	wire := newDeadWire()
	tun := newTunnel(wire, lacTunnelID, "test-lac", nil, time.Millisecond, zap.NewNop())
	t.Cleanup(func() { _ = wire.Close() })

	done := make(chan struct{})
	go func() { defer close(done); tun.helloLoop() }()

	select {
	case <-done:
	case <-time.After(waitFor):
		t.Fatal("helloLoop kept going against a socket that refuses writes")
	}
}

// ---------------------------------------------------------------------------
// TunnelManager
// ---------------------------------------------------------------------------

func TestCreateSessionReportsAnLNSItCannotDial(t *testing.T) {
	m := newTestManager(t)
	s, err := m.CreateSession("no-port-here", "", "someone", "5551234")
	require.Error(t, err)
	assert.Nil(t, s)
	assert.ErrorContains(t, err, "dial LNS")
	assert.Zero(t, tunnelCount(m), "a tunnel that never dialled must not be cached")
}

// A LAC configured with a tunnel secret requires the LNS to prove it holds the
// same one (RFC 2661 s5.1.1). An LNS that answers the SCCRQ without a Challenge
// Response has not, so the tunnel must not come up -- silently continuing would
// send subscriber traffic to an unauthenticated peer.
func TestCreateSessionRefusesAnLNSThatDoesNotAnswerTheChallenge(t *testing.T) {
	lns := newUDPLNS(t)
	m := newTestManager(t)

	s, err := m.CreateSession(lns.addr, "shared-secret", "someone", "5551234")
	require.Error(t, err)
	assert.Nil(t, s)
	assert.ErrorContains(t, err, "establish tunnel")
	assert.ErrorContains(t, err, "challenge")
	assert.Zero(t, tunnelCount(m), "a tunnel that failed to authenticate must not be cached")
}

// An LNS that takes the tunnel but refuses the call must fail that subscriber
// and nothing else: the control connection stays up for everyone already on it,
// and for the next subscriber to try.
func TestCreateSessionReportsACallTheLNSRefuses(t *testing.T) {
	lns := newUDPLNS(t)
	lns.mu.Lock()
	lns.refuseCalls = true
	lns.mu.Unlock()
	m := newTestManager(t)

	s, err := m.CreateSession(lns.addr, "", "unwanted", "5551234")
	require.Error(t, err)
	assert.Nil(t, s)
	assert.ErrorContains(t, err, "create session to "+lns.addr)
	assert.ErrorContains(t, err, "CDN")
	assert.Equal(t, 1, tunnelCount(m), "the tunnel itself came up and stays up")

	lns.mu.Lock()
	lns.refuseCalls = false
	lns.mu.Unlock()
	next := mustCreateSession(t, m, lns)
	t.Cleanup(next.Close)
	assert.Equal(t, 1, tunnelCount(m), "and the next call rides the same tunnel")
}

// Tunnel IDs are 16 bits and the allocator simply counts, so it wraps. Zero is
// reserved for a tunnel that has not been assigned one yet, so the counter must
// skip it.
func TestTunnelIDAllocationSkipsZeroOnWraparound(t *testing.T) {
	lns := newUDPLNS(t)
	m := newTestManager(t)
	m.mu.Lock()
	m.nextTID = 0xFFFF
	m.mu.Unlock()

	s := mustCreateSession(t, m, lns)
	t.Cleanup(s.Close)

	assert.Equal(t, uint16(0xFFFF), s.tunnel.localTunnelID)
	m.mu.Lock()
	next := m.nextTID
	m.mu.Unlock()
	assert.Equal(t, uint16(1), next, "0 addresses an unassigned tunnel and must never be handed out")
}

// Two subscribers arriving at once for the same LNS both start a handshake,
// because neither can see the other's tunnel until it is registered. Exactly one
// registration may win, and the loser must close the tunnel it built -- a
// second live control connection to the same LNS would be nothing's
// responsibility to tear down.
func TestConcurrentTunnelSetupToOneLNSKeepsOneTunnel(t *testing.T) {
	lns := newUDPLNS(t)
	m := newTestManager(t)

	arrived, release := lns.holdSCCRQ()

	type result struct {
		s   *Session
		err error
	}
	firstCh := make(chan result, 1)
	go func() {
		s, err := m.CreateSession(lns.addr, "", "subscriber-a", "5550001")
		firstCh <- result{s, err}
	}()

	select {
	case <-arrived:
	case <-time.After(waitFor):
		t.Fatal("the first SCCRQ never reached the LNS")
	}

	// The second subscriber gets all the way through while the first is parked,
	// and is the one that registers the tunnel.
	second, err := m.CreateSession(lns.addr, "", "subscriber-b", "5550002")
	require.NoError(t, err)
	t.Cleanup(second.Close)
	require.Equal(t, 1, tunnelCount(m))

	release()
	var first result
	select {
	case first = <-firstCh:
	case <-time.After(waitFor):
		t.Fatal("the parked handshake never finished")
	}
	require.NoError(t, first.err)
	t.Cleanup(first.s.Close)

	assert.Equal(t, 1, tunnelCount(m), "the losing tunnel must not be left registered")
	assert.Same(t, second.tunnel, first.s.tunnel,
		"both calls must end up on the tunnel that won the race")
	assert.Equal(t, 2, second.tunnel.SessionCount())
}

// ---------------------------------------------------------------------------
// Diagnostics
// ---------------------------------------------------------------------------

// frameProtocol exists only to name a protocol in a debug line, and it is the
// one place this package looks inside a frame. It has to read both forms
// (RFC 1661 s2) and it has to be unable to panic on anything a peer can send,
// because a peer can send anything.
func TestFrameProtocolReadsBothFormsAndNeverPanics(t *testing.T) {
	for _, tc := range []struct {
		name  string
		frame []byte
		want  uint16
	}{
		{"uncompressed LCP", []byte{0xC0, 0x21, 0x01}, 0xC021},
		{"uncompressed IPv4", []byte{0x00, 0x21, 0x45}, 0x0021},
		{"with address and control", []byte{0xFF, 0x03, 0x80, 0x21, 0xAA}, 0x8021},
		{"compressed IPv4", []byte{0x21, 0x45}, 0x0021},
		{"compressed after address and control", []byte{0xFF, 0x03, 0x21, 0x45}, 0x0021},
		{"compressed multilink", []byte{0x3D, 0xC0}, 0x003D},
		{"nothing at all", nil, 0},
		{"empty", []byte{}, 0},
		{"half an uncompressed field", []byte{0xC0}, 0},
		{"bare address and control", []byte{0xFF, 0x03}, 0x00FF},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.NotPanics(t, func() {
				assert.Equal(t, tc.want, frameProtocol(tc.frame))
			})
		})
	}
}

// A refusal is only useful if it says why. An operator whose hostname or secret
// does not match what the LNS expects gets one of these and nothing else.
func TestDescribeResultCode(t *testing.T) {
	rc := func(result, errCode uint16, msg string) []AVP {
		v := make([]byte, 4+len(msg))
		v[0], v[1] = byte(result>>8), byte(result)
		v[2], v[3] = byte(errCode>>8), byte(errCode)
		copy(v[4:], msg)
		avps, err := DecodeAVPs(EncodeAVP(AVPResultCode, v))
		require.NoError(t, err)
		return avps
	}

	assert.Equal(t, `result=4 (not authorized) message="no such tunnel"`,
		describeResultCode(rc(4, 0, "no such tunnel")))
	assert.Equal(t, "result=2 (general error) error=6",
		describeResultCode(rc(2, 6, "")))
	assert.Equal(t, "result=5 (unsupported protocol version)",
		describeResultCode(rc(5, 0, "")))
	assert.Equal(t, "result=7", describeResultCode(rc(7, 0, "")),
		"a code with no name still has to be reported, not swallowed")

	avps, err := DecodeAVPs(EncodeUint16AVP(AVPMessageType, MsgTypeStopCCN))
	require.NoError(t, err)
	assert.Equal(t, "no Result Code given", describeResultCode(avps),
		"the AVP is mandatory in a StopCCN, but a peer that omits it must not "+
			"produce an error message that looks like it said something")
}
