package l2tp

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// TunnelManager dials the LNS itself, so it cannot be driven over net.Pipe like
// Tunnel can. udpLNS is the smallest LNS that will satisfy it: a real UDP
// socket on the loopback interface that answers SCCRQ, ICRQ and the acks in
// between, keeping per-peer sequence state so several LACs (or several sockets
// from one manager) can talk to it at once.
type udpLNS struct {
	pc   net.PacketConn
	addr string

	mu       sync.Mutex
	peers    map[string]*udpPeer
	sccrqs   int
	stopCCNs int
	cdns     int
	nextTID  uint16
	nextSID  uint16

	// Set by holdSCCRQ to park the next SCCRQ before it is answered.
	sccrqSeen chan struct{}
	sccrqGate chan struct{}

	// refuseCalls makes the LNS answer every ICRQ with a CDN, the way one does
	// when it has no capacity or no account for the caller.
	refuseCalls bool
}

type udpPeer struct {
	ns     uint16 // next Ns the LNS will use towards this peer
	nr     uint16 // one past the highest Ns seen from this peer
	lacTID uint16 // the tunnel ID this peer assigned to itself
	seen   map[uint16]bool
}

func newUDPPeer() *udpPeer {
	return &udpPeer{seen: make(map[uint16]bool)}
}

func newUDPLNS(t *testing.T) *udpLNS {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	l := &udpLNS{
		pc:      pc,
		addr:    pc.LocalAddr().String(),
		peers:   make(map[string]*udpPeer),
		nextTID: 0x1000,
		nextSID: 0x2000,
	}
	go l.serve()
	t.Cleanup(func() { _ = pc.Close() })
	return l
}

func (l *udpLNS) serve() {
	buf := make([]byte, maxPacketSize)
	for {
		n, addr, err := l.pc.ReadFrom(buf)
		if err != nil {
			return
		}
		raw := make([]byte, n)
		copy(raw, buf[:n])
		l.handle(addr, raw)
	}
}

func (l *udpLNS) handle(addr net.Addr, raw []byte) {
	hdr, off, err := DecodeHeader(raw)
	if err != nil || !hdr.IsControl || off >= len(raw) {
		return // data messages and ZLB acks need no reply
	}
	avps, err := DecodeAVPs(raw[off:])
	if err != nil {
		return
	}
	msgType, err := GetMessageType(avps)
	if err != nil {
		return
	}

	// Park before touching any state, so a held SCCRQ blocks only this LNS's
	// reply and not the mutex.
	if msgType == MsgTypeSCCRQ {
		l.mu.Lock()
		seen, gate := l.sccrqSeen, l.sccrqGate
		l.sccrqSeen, l.sccrqGate = nil, nil
		l.mu.Unlock()
		if seen != nil {
			close(seen)
		}
		if gate != nil {
			// Wait on a goroutine of its own. serve reads and dispatches one
			// datagram at a time, so parking here would stall every other peer
			// as well -- and a handshake is usually held precisely so that a
			// second LAC can race past it while the first is stuck.
			go func() {
				<-gate
				l.dispatch(addr, hdr, avps, msgType)
			}()
			return
		}
	}
	l.dispatch(addr, hdr, avps, msgType)
}

func (l *udpLNS) dispatch(addr net.Addr, hdr Header, avps []AVP, msgType uint16) {
	l.mu.Lock()
	defer l.mu.Unlock()

	key := addr.String()
	p := l.peers[key]
	// An SCCRQ at Ns=0 starts a new control connection, which matters because
	// the ephemeral source port of a closed UDP socket can be handed straight
	// back to the next one.
	if p == nil || (msgType == MsgTypeSCCRQ && hdr.Ns == 0) {
		p = newUDPPeer()
		l.peers[key] = p
	}

	reply := func(session uint16, payload []byte) {
		pkt := append(EncodeControlHeader(p.lacTID, session, p.ns, p.nr, len(payload)), payload...)
		p.ns++
		_, _ = l.pc.WriteTo(pkt, addr)
	}
	ack := func() {
		_, _ = l.pc.WriteTo(EncodeControlHeader(p.lacTID, 0, p.ns, p.nr, 0), addr)
	}

	if p.seen[hdr.Ns] {
		ack() // a retransmission: acknowledge it, do not act on it twice
		return
	}
	p.seen[hdr.Ns] = true
	// Every Ns not seen before is acted on, whether or not the ones before it
	// have arrived. A conformant LNS may instead hold it for the gap to fill,
	// which is exactly what makes Tunnel's out-of-order emission expensive --
	// see TestConcurrentControlSendsAllocateEachNsExactlyOnce. This LNS is
	// deliberately permissive so the manager tests measure the manager.
	if int16(hdr.Ns+1-p.nr) > 0 {
		p.nr = hdr.Ns + 1
	}

	switch msgType {
	case MsgTypeSCCRQ:
		l.sccrqs++
		if a := FindAVP(avps, 0, AVPAssignedTunnelID); a != nil {
			p.lacTID, _ = AVPUint16(a)
		}
		l.nextTID++
		reply(0, buildSCCRP(l.nextTID))
	case MsgTypeICRQ:
		var lacSID uint16
		if a := FindAVP(avps, 0, AVPAssignedSessionID); a != nil {
			lacSID, _ = AVPUint16(a)
		}
		if l.refuseCalls {
			// RFC 2661 s4.4.2 result 2: the call was disconnected for the reason
			// in the Error Code.
			reply(lacSID, BuildCDN(l.nextSID, 2, 0, "no capacity"))
			return
		}
		l.nextSID++
		// RFC 2661 s3.1: the header addresses the recipient's session.
		reply(lacSID, buildICRP(l.nextSID))
	case MsgTypeStopCCN:
		l.stopCCNs++
	case MsgTypeCDN:
		l.cdns++
		ack()
	default: // SCCCN, ICCN, Hello
		ack()
	}
}

func (l *udpLNS) counts() (sccrqs, stopCCNs, cdns int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.sccrqs, l.stopCCNs, l.cdns
}

// holdSCCRQ makes the LNS stop dead on the next SCCRQ instead of answering it,
// which pins a LAC inside Tunnel.Establish for exactly as long as the test
// wants. It returns a channel closed once that SCCRQ has arrived and a function
// that lets the LNS get on with replying.
func (l *udpLNS) holdSCCRQ() (arrived <-chan struct{}, release func()) {
	seen := make(chan struct{})
	gate := make(chan struct{})
	l.mu.Lock()
	l.sccrqSeen, l.sccrqGate = seen, gate
	l.mu.Unlock()
	var once sync.Once
	return seen, func() { once.Do(func() { close(gate) }) }
}

func newTestManager(t *testing.T) *TunnelManager {
	t.Helper()
	m := NewTunnelManager("test-lac", 0, zap.NewNop())
	t.Cleanup(func() { _ = m.Close() })
	return m
}

func tunnelCount(m *TunnelManager) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.tunnels)
}

func mustCreateSession(t *testing.T, m *TunnelManager, lns *udpLNS) *Session {
	t.Helper()
	s, err := m.CreateSession(lns.addr, "", testSubscriber, "5551234")
	require.NoError(t, err)
	require.NotNil(t, s)
	return s
}

// A tunnel is per-LNS, not per-call: the second call to the same LNS must ride
// the control connection the first one set up, and a call to a different LNS
// must get its own.
func TestTunnelManagerReusesOneTunnelPerLNS(t *testing.T) {
	lnsA := newUDPLNS(t)
	lnsB := newUDPLNS(t)
	m := newTestManager(t)

	first := mustCreateSession(t, m, lnsA)
	second := mustCreateSession(t, m, lnsA)

	assert.Same(t, first.tunnel, second.tunnel, "a second call to the same LNS reuses the tunnel")
	assert.Equal(t, 2, first.tunnel.SessionCount())
	assert.NotEqual(t, first.localSessionID, second.localSessionID,
		"sessions on one tunnel get distinct local IDs")
	sccrqs, _, _ := lnsA.counts()
	assert.Equal(t, 1, sccrqs, "only one control connection was ever set up")
	assert.Equal(t, 1, tunnelCount(m))

	third := mustCreateSession(t, m, lnsB)
	assert.NotSame(t, first.tunnel, third.tunnel, "a different LNS gets its own tunnel")
	assert.Equal(t, 1, third.tunnel.SessionCount())
	sccrqsB, _, _ := lnsB.counts()
	assert.Equal(t, 1, sccrqsB)
	sccrqs, _, _ = lnsA.counts()
	assert.Equal(t, 1, sccrqs, "and does not disturb the first")
	assert.Equal(t, 2, tunnelCount(m))
}

// Reuse is keyed on the secret as well as the address, because two tunnels to
// the same LNS authenticated with different secrets are not interchangeable.
func TestTunnelCacheKeySeparatesAddressFromSecret(t *testing.T) {
	tests := []struct {
		name     string
		aAddr    string
		aSecret  string
		bAddr    string
		bSecret  string
		wantSame bool
	}{
		{"same address and secret", "lns:1701", "s", "lns:1701", "s", true},
		{"same address, different secret", "lns:1701", "s", "lns:1701", "t", false},
		{"same address, one without a secret", "lns:1701", "", "lns:1701", "s", false},
		{"different address, same secret", "a:1701", "s", "b:1701", "s", false},
		{"the separator is not forgeable by concatenation", "lns:1701x", "", "lns:1701", "x", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := tunnelCacheKey(tt.aAddr, tt.aSecret)
			b := tunnelCacheKey(tt.bAddr, tt.bSecret)
			assert.Equal(t, tt.wantSame, a == b)
		})
	}
}

// The control connection exists to carry calls, so it goes away with the last
// of them -- and the LNS is told, rather than being left to time the tunnel out.
func TestTunnelManagerLastSessionClosingTearsTheTunnelDown(t *testing.T) {
	lns := newUDPLNS(t)
	m := newTestManager(t)

	first := mustCreateSession(t, m, lns)
	second := mustCreateSession(t, m, lns)
	tun := first.tunnel
	require.Equal(t, 2, tun.SessionCount())

	first.Close()
	assert.True(t, tun.Alive(), "one call ending is not the tunnel ending")
	assert.Equal(t, 1, tun.SessionCount())

	second.Close()
	assert.False(t, tun.Alive())
	assert.Equal(t, 0, tun.SessionCount())
	assert.Eventually(t, func() bool {
		_, stopCCNs, _ := lns.counts()
		return stopCCNs == 1
	}, waitFor, 5*time.Millisecond, "the LNS must be told the control connection is going away")

	// Close runs the same onClose callback die() does, so the manager is told and
	// drops the tunnel rather than holding a pointer to a dead one. The common
	// path reaches Close, not die: the last session ending tears the tunnel down.
	assert.Equal(t, 0, tunnelCount(m), "the dead tunnel is deregistered")

	third := mustCreateSession(t, m, lns)
	assert.NotSame(t, tun, third.tunnel, "a fresh tunnel is built, not the dead one reused")
	assert.True(t, third.tunnel.Alive())
	assert.Equal(t, 1, tunnelCount(m))
	sccrqs, _, _ := lns.counts()
	assert.Equal(t, 2, sccrqs, "a second control connection had to be set up")
}

// Close is reachable from the server's Cleanup hook while calls are still being
// set up, so it has to be safe against a CreateSession in flight: no panic, no
// data race, and no half-registered tunnel left in the map.
func TestTunnelManagerCloseIsSafeConcurrentlyWithCreateSession(t *testing.T) {
	lns := newUDPLNS(t)
	m := NewTunnelManager("test-lac", 0, zap.NewNop())

	const creators = 8
	var wg sync.WaitGroup
	sessions := make(chan *Session, creators)
	start := make(chan struct{})

	for range creators {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			s, err := m.CreateSession(lns.addr, "", testSubscriber, "5551234")
			if err == nil {
				sessions <- s
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		assert.NoError(t, m.Close())
	}()

	close(start)
	wg.Wait()
	close(sessions)

	require.NoError(t, m.Close(), "a second Close is not an error")

	// Whatever survived the race is still a coherent session on a live or dead
	// tunnel, never a corrupt one.
	for s := range sessions {
		require.NotNil(t, s.tunnel)
		s.tunnel.Close()
	}
	assert.Equal(t, 0, tunnelCount(m))
}

// Close retires the manager: it is wired into the server's Cleanup hook, so
// anything asking for a tunnel afterwards is asking on a server that is going
// away and must be refused rather than quietly given a tunnel nothing will ever
// close.
func TestTunnelManagerCloseIsTerminal(t *testing.T) {
	lns := newUDPLNS(t)
	m := newTestManager(t)

	require.NoError(t, m.Close())

	_, err := m.CreateSession(lns.addr, "", "alice", "id")
	require.ErrorIs(t, err, errManagerClosed)
	assert.Equal(t, 0, tunnelCount(m))

	require.NoError(t, m.Close(), "closing twice is not an error")
}

// The consequence of that, driven deterministically: getOrCreateTunnel
// establishes outside the lock and registers afterwards, so a CreateSession
// that is inside Establish when Close runs registers its tunnel into the map
// Close has already emptied. Nothing will ever tear that tunnel down -- its
// recvLoop and its socket outlive the manager, and the LNS is never sent a
// StopCCN, so it holds the call open until its own HELLO timeout.
//
// TunnelManager.Close is wired into the server's Cleanup hook (manager.go), so
// this leaks past shutdown.
// This pins the current behaviour so a future fix is a deliberate change.
func TestTunnelManagerCloseDoesNotLeakATunnelEstablishedWhileItRuns(t *testing.T) {
	lns := newUDPLNS(t)
	m := NewTunnelManager("test-lac", 0, zap.NewNop())

	arrived, release := lns.holdSCCRQ()

	type result struct {
		s   *Session
		err error
	}
	resCh := make(chan result, 1)
	go func() {
		s, err := m.CreateSession(lns.addr, "", testSubscriber, "5551234")
		resCh <- result{s, err}
	}()

	select {
	case <-arrived:
	case <-time.After(waitFor):
		t.Fatal("the LNS never saw the SCCRQ")
	}

	// Close runs while that tunnel is still inside Establish: there is nothing
	// in the map for it to find.
	require.NoError(t, m.Close())
	require.Equal(t, 0, tunnelCount(m), "Close drained a map the tunnel was not in yet")

	release()

	var r result
	select {
	case r = <-resCh:
	case <-time.After(waitFor):
		t.Fatal("CreateSession did not return")
	}
	// The tunnel finished establishing after Close had drained the map. Registering
	// it would leave something live that nothing ever tears down, so registration
	// re-checks the flag and closes it instead.
	require.ErrorIs(t, r.err, errManagerClosed)
	require.Nil(t, r.s)
	assert.Equal(t, 0, tunnelCount(m), "nothing was registered into the drained map")
}

// A tunnel that dies of its own accord (here: the LNS stops answering Hellos)
// must be dropped by the manager, so the next call dials a fresh one instead of
// handing out a corpse.
func TestTunnelManagerDropsATunnelThatDies(t *testing.T) {
	lns := newUDPLNS(t)
	m := NewTunnelManager("test-lac", 25*time.Millisecond, zap.NewNop())
	t.Cleanup(func() { _ = m.Close() })

	s, err := m.CreateSession(lns.addr, "", testSubscriber, "5551234")
	require.NoError(t, err)
	tun := s.tunnel
	require.Equal(t, 1, tunnelCount(m))

	// Take the LNS away. recvLoop's next read fails -- either at once, because
	// the kernel reports the now-unreachable port on this connected UDP socket,
	// or when the helloInterval*3 read deadline expires -- and either way the
	// failure path is die(), which is what runs onClose.
	require.NoError(t, lns.pc.Close())

	assert.Eventually(t, func() bool { return !tun.Alive() }, waitFor, 5*time.Millisecond,
		"a tunnel whose peer has gone silent must die")
	assert.Eventually(t, func() bool { return sessionIsClosed(s) }, waitFor, 5*time.Millisecond)
	assert.Eventually(t, func() bool { return tunnelCount(m) == 0 }, waitFor, 5*time.Millisecond,
		"die() runs onClose, which deregisters the tunnel")
}
