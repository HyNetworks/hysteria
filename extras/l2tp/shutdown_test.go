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

// Regression test. Tunnel.Close used to close t.closed before sending StopCCN,
// and writePacket short-circuits on that channel, so the notification was
// silently dropped: the LNS kept the tunnel and every session in it alive until
// its own HELLO timeout expired. RFC 2661 s3.3 gives StopCCN the job of tearing
// the control connection down, so it has to actually reach the wire.
func TestTunnelCloseSendsStopCCNToTheLNS(t *testing.T) {
	lns, lacConn := newFakeLNS(t)
	tun := newTunnel(lacConn, 7, "test-lac", nil, 0, zap.NewNop())
	tun.remoteTunnelID = 9

	tun.Close()

	pkt := lns.mustNextControl(MsgTypeStopCCN)
	msgType, err := GetMessageType(pkt.avps)
	require.NoError(t, err)
	assert.Equal(t, MsgTypeStopCCN, msgType)
	assert.Equal(t, uint16(9), pkt.hdr.Tunnel,
		"StopCCN must be addressed to the LNS's tunnel ID")

	// The Assigned Tunnel ID AVP carries our own ID so the LNS can match it.
	avp := FindAVP(pkt.avps, 0, AVPAssignedTunnelID)
	require.NotNil(t, avp, "StopCCN must carry Assigned Tunnel ID")
	tid, err := AVPUint16(avp)
	require.NoError(t, err)
	assert.Equal(t, uint16(7), tid)

	// And a Result Code, which is what tells the LNS this was deliberate.
	assert.NotNil(t, FindAVP(pkt.avps, 0, AVPResultCode),
		"StopCCN must carry a Result Code")
}

// Close stays idempotent: a second call must not send a second StopCCN or panic
// on the already-closed channel.
func TestTunnelCloseIsIdempotent(t *testing.T) {
	lns, lacConn := newFakeLNS(t)
	tun := newTunnel(lacConn, 7, "test-lac", nil, 0, zap.NewNop())
	tun.remoteTunnelID = 9

	tun.Close()
	_ = lns.mustNextControl(MsgTypeStopCCN)

	require.NotPanics(t, func() { tun.Close() })
	if p, ok := lns.nextPacket(150 * 1e6); ok {
		msgType, err := GetMessageType(p.avps)
		if err == nil {
			assert.NotEqual(t, MsgTypeStopCCN, msgType,
				"a second Close must not re-send StopCCN")
		}
	}
}

// TunnelManager.Close is an io.Closer so it can be chained into the server's
// Cleanup hook, and it must tear down every tunnel it is holding.
func TestTunnelManagerCloseIsAnIoCloserAndClosesEveryTunnel(t *testing.T) {
	m := NewTunnelManager("lac", 0, zap.NewNop())

	lnsA, connA := newFakeLNS(t)
	lnsB, connB := newFakeLNS(t)
	tunA := newTunnel(connA, 1, "lac", nil, 0, zap.NewNop())
	tunA.remoteTunnelID = 11
	tunB := newTunnel(connB, 2, "lac", nil, 0, zap.NewNop())
	tunB.remoteTunnelID = 22

	m.mu.Lock()
	m.tunnels["a"] = tunA
	m.tunnels["b"] = tunB
	m.mu.Unlock()

	require.NoError(t, m.Close(), "Close reports errors so it can satisfy io.Closer")

	// Both LNSes were told, not just the first.
	for _, lns := range []*fakeLNS{lnsA, lnsB} {
		msgType, err := GetMessageType(lns.mustNextControl(MsgTypeStopCCN).avps)
		require.NoError(t, err)
		assert.Equal(t, MsgTypeStopCCN, msgType)
	}

	assert.False(t, tunA.Alive())
	assert.False(t, tunB.Alive())

	m.mu.Lock()
	assert.Empty(t, m.tunnels, "the manager must not keep closed tunnels")
	m.mu.Unlock()

	require.NoError(t, m.Close(), "closing an empty manager is not an error")
}

// gatedConn holds one write open until the test releases it. It exists to put
// two teardown paths inside each other's critical sections deliberately, which
// is the only way to make a lock-ordering bug reproducible rather than a rare
// production hang.
type gatedConn struct {
	net.Conn
	match func([]byte) bool
	armed chan struct{} // closed once the matching write is parked
	gate  chan struct{} // closed to release it
	once  sync.Once
}

func (c *gatedConn) Write(p []byte) (int, error) {
	if c.match(p) {
		c.once.Do(func() { close(c.armed) })
		<-c.gate
	}
	return c.Conn.Write(p)
}

func isStopCCN(pkt []byte) bool {
	_, off, err := DecodeHeader(pkt)
	if err != nil || off < 0 || off > len(pkt) {
		return false
	}
	avps, err := DecodeAVPs(pkt[off:])
	if err != nil {
		return false
	}
	msgType, err := GetMessageType(avps)
	return err == nil && msgType == MsgTypeStopCCN
}

// Regression test for a deadlock between the two ways a tunnel goes away.
//
// Session.Close used to call Tunnel.Close from inside its own sync.Once, and
// Tunnel.Close closes every session it still holds -- so a Tunnel.Close running
// at the same moment would sit inside the tunnel's Once waiting on the session's,
// while the session sat inside its Once waiting on the tunnel's. Both are
// reachable together: TunnelManager.Close during a server shutdown is one side
// and a subscriber hanging up is the other, which makes this a shutdown that
// never finishes.
//
// The interleaving is forced rather than raced for: StopCCN is parked mid-write
// while holding the tunnel's write lock, which strands Session.Close inside its
// own Once with the session still in the tunnel's map.
func TestSessionCloseRacingTunnelCloseDoesNotDeadlock(t *testing.T) {
	f, lacConn := newFakeLNS(t)
	gc := &gatedConn{
		Conn:  lacConn,
		match: isStopCCN,
		armed: make(chan struct{}),
		gate:  make(chan struct{}),
	}
	tun := newTunnel(gc, lacTunnelID, "test-lac", nil, 0, zap.NewNop())
	t.Cleanup(tun.Close)

	errCh := make(chan error, 1)
	go func() { errCh <- tun.Establish() }()
	sccrq := f.mustNextControl(MsgTypeSCCRQ)
	f.send(sccrq.hdr.Ns+1, 0, buildSCCRP(lnsTunnelID))
	scccn := f.mustNextControl(MsgTypeSCCCN)
	f.sendZLB(scccn.hdr.Ns + 1)
	require.NoError(t, <-errCh)

	s := establishSession(t, tun, f)

	// The tunnel goes down first and parks inside its Once, holding the write lock.
	tunDone := make(chan struct{})
	go func() { defer close(tunDone); tun.Close() }()
	<-gc.armed

	// The session hangs up at the same moment. Its CDN blocks on that write lock,
	// leaving it inside its own Once and still registered with the tunnel.
	sesDone := make(chan struct{})
	go func() { defer close(sesDone); s.Close() }()
	// Waiting for a goroutine to block on a mutex is not observable, so this is a
	// plain sleep. Too short only weakens the test -- it cannot fail it, because
	// the interleaving it is looking for simply will not have been set up.
	time.Sleep(50 * time.Millisecond)

	close(gc.gate) // StopCCN completes; Tunnel.Close now reaches the session map

	for _, w := range []struct {
		name string
		done <-chan struct{}
	}{
		{"Session.Close", sesDone},
		{"Tunnel.Close", tunDone},
	} {
		select {
		case <-w.done:
		case <-time.After(5 * time.Second):
			t.Fatalf("%s deadlocked against the concurrent teardown", w.name)
		}
	}
}
