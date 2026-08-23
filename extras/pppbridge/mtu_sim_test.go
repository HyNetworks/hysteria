package pppbridge

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// End-to-end check of the MTU arithmetic in mtu.go against what quic-go will
// actually carry, over a path that behaves like the public Internet: a bottleneck
// link that silently discards oversized packets with no ICMP reply. That is the
// case DPLPMTUD exists for and the case where a wrong MTU turns into a black hole
// rather than an error.
//
// The number that matters is the headroom:
//
//	headroom = maxDatagramPayload - PPPHeaderLen - CalculatePPPMTU(...)
//
// SendData hands the bridge a raw PPP frame, which is the 4-byte PPP header plus
// the inner IP packet, so headroom < 0 means pppd is allowed an MTU whose frames
// quic-go will refuse -- and bridge.go drops those silently.

const (
	simIPv4Header = 20
	simIPv6Header = 40
	simUDPHeader  = 8
)

// pathMTUConn emulates a bottleneck link. Anything larger than the path allows is
// dropped without notice, exactly like a middlebox that does not send ICMP
// Fragmentation Needed.
type pathMTUConn struct {
	net.PacketConn
	maxUDP  atomic.Int64 // emulated path capacity, changeable mid-connection
	dropped atomic.Int64
	passed  atomic.Int64
}

func newPathMTUConn(pc net.PacketConn, maxUDPPayload int) *pathMTUConn {
	c := &pathMTUConn{PacketConn: pc}
	c.maxUDP.Store(int64(maxUDPPayload))
	return c
}

func (c *pathMTUConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if int64(len(p)) > c.maxUDP.Load() {
		c.dropped.Add(1)
		return len(p), nil // black hole: report success, deliver nothing
	}
	c.passed.Add(1)
	return c.PacketConn.WriteTo(p, addr)
}

func simTLSConfigs(t *testing.T) (server, client *tls.Config) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "mtu-sim"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"mtu-sim"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(cert)

	return &tls.Config{
			Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key, Leaf: cert}},
			NextProtos:   []string{"mtu-sim"},
		}, &tls.Config{
			RootCAs:    pool,
			ServerName: "mtu-sim",
			NextProtos: []string{"mtu-sim"},
		}
}

// simQUICConfig mirrors what core/client and core/server actually set.
func simQUICConfig(disablePMTUD bool) *quic.Config {
	return &quic.Config{
		MaxIdleTimeout:                 30 * time.Second,
		KeepAlivePeriod:                time.Second,
		EnableDatagrams:                true,
		MaxDatagramFrameSize:           65535,
		AssumePeerMaxDatagramFrameSize: 65535,
		DisablePathMTUDiscovery:        disablePMTUD,
	}
}

// currentDatagramBudget asks quic-go how much datagram payload fits right now.
// SendDatagram reports the limit in the error rather than sending anything.
func currentDatagramBudget(c *quic.Conn) int {
	err := c.SendDatagram(make([]byte, 65535))
	var tooLarge *quic.DatagramTooLargeError
	if errors.As(err, &tooLarge) {
		return int(tooLarge.MaxDatagramPayloadSize)
	}
	return -1
}

type simResult struct {
	pathMTU         int
	initial         int // budget immediately after handshake
	converged       int // budget once DPLPMTUD settles
	convergeTime    time.Duration
	computed        int // what CalculatePPPMTU tells pppd to use
	headroom        int // converged - PPPHeaderLen - computed
	initHeadroom    int // same, at t=0
	droppedTX       int64
	handshakeFailed bool
	underLoad       int // budget after sustained traffic, 0 if not measured
}

func runMTUSim(t *testing.T, pathMTU int, disablePMTUD bool) simResult {
	t.Helper()
	maxPayload := pathMTU - simIPv4Header - simUDPHeader

	serverPC, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	srvConn := newPathMTUConn(serverPC, maxPayload)
	defer srvConn.Close()

	clientPC, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	cliConn := newPathMTUConn(clientPC, maxPayload)
	defer cliConn.Close()

	tlsServer, tlsClient := simTLSConfigs(t)

	srvTr := &quic.Transport{Conn: srvConn}
	defer srvTr.Close()
	ln, err := srvTr.Listen(tlsServer, simQUICConfig(disablePMTUD))
	require.NoError(t, err)
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	accepted := make(chan *quic.Conn, 1)
	go func() {
		c, aerr := ln.Accept(ctx)
		if aerr == nil {
			accepted <- c
		}
	}()

	cliTr := &quic.Transport{Conn: cliConn}
	defer cliTr.Close()
	dialCtx, dialCancel := context.WithTimeout(ctx, 8*time.Second)
	defer dialCancel()
	conn, err := cliTr.Dial(dialCtx, serverPC.LocalAddr(), tlsClient, simQUICConfig(disablePMTUD))
	if err != nil {
		// A path too narrow for quic-go's initial packet size cannot complete a
		// handshake at all. Report it rather than failing: it is a result.
		return simResult{pathMTU: pathMTU, handshakeFailed: true, computed: CalculatePPPMTU(pathMTU, false, false, 0)}
	}
	defer conn.CloseWithError(0, "")

	var srv *quic.Conn
	select {
	case srv = <-accepted:
	case <-time.After(10 * time.Second):
		t.Fatal("server never accepted the connection")
	}
	defer srv.CloseWithError(0, "")

	// Drain datagrams server-side so the client keeps getting acknowledgements.
	go func() {
		for {
			if _, rerr := srv.ReceiveDatagram(ctx); rerr != nil {
				return
			}
		}
	}()

	initial := currentDatagramBudget(conn)

	// DPLPMTUD probes every 5 RTTs and needs traffic to elicit ACKs. Keep a light
	// stream of small datagrams going and watch the budget until it stops moving.
	start := time.Now()
	last := initial
	stableFor := 0
	converged := initial
	convergeTime := time.Duration(0)
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		_ = conn.SendDatagram(make([]byte, 64))
		time.Sleep(10 * time.Millisecond)
		b := currentDatagramBudget(conn)
		if b != last {
			last = b
			stableFor = 0
			convergeTime = time.Since(start)
			continue
		}
		stableFor++
		if stableFor >= 60 { // ~600ms with no change
			break
		}
	}
	converged = last

	// Packet-number encoding grows with the number of packets in flight, and it
	// sits inside the same budget. Push real traffic through and re-measure: a
	// budget that shrinks after the MTU was fixed at setup is a latent black hole.
	underLoad := converged
	for i := 0; i < 4000; i++ {
		_ = conn.SendDatagram(make([]byte, 900))
		if i%200 == 0 {
			if b := currentDatagramBudget(conn); b > 0 && b < underLoad {
				underLoad = b
			}
		}
	}
	if b := currentDatagramBudget(conn); b > 0 && b < underLoad {
		underLoad = b
	}

	computed := CalculatePPPMTU(pathMTU, false, false, 0)
	return simResult{
		pathMTU:      pathMTU,
		initial:      initial,
		converged:    converged,
		convergeTime: convergeTime,
		computed:     computed,
		headroom:     converged - PPPHeaderLen - computed,
		initHeadroom: initial - PPPHeaderLen - computed,
		droppedTX:    cliConn.dropped.Load(),
		underLoad:    underLoad,
	}
}

// simHandshakeSucceeds dials across an emulated bottleneck and reports whether
// the QUIC handshake completed. It deliberately skips the convergence
// measurement runMTUSim does: a ladder of these costs one handshake per rung
// rather than a full DPLPMTUD settle plus a load phase.
//
// dialTimeout is short on purpose. A loopback handshake that is going to
// complete completes in single-digit milliseconds; a path too narrow for the
// first flight never completes at all, so the timeout is pure waiting and each
// second of it is a second on the suite's clock.
func simHandshakeSucceeds(t *testing.T, pathMTU int) bool {
	t.Helper()
	const dialTimeout = 1500 * time.Millisecond
	maxPayload := pathMTU - simIPv4Header - simUDPHeader

	serverPC, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	srvConn := newPathMTUConn(serverPC, maxPayload)
	defer srvConn.Close()

	clientPC, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	cliConn := newPathMTUConn(clientPC, maxPayload)
	defer cliConn.Close()

	tlsServer, tlsClient := simTLSConfigs(t)

	srvTr := &quic.Transport{Conn: srvConn}
	defer srvTr.Close()
	ln, err := srvTr.Listen(tlsServer, simQUICConfig(false))
	require.NoError(t, err)
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*dialTimeout)
	defer cancel()
	go func() {
		if c, aerr := ln.Accept(ctx); aerr == nil {
			c.CloseWithError(0, "")
		}
	}()

	cliTr := &quic.Transport{Conn: cliConn}
	defer cliTr.Close()
	dialCtx, dialCancel := context.WithTimeout(ctx, dialTimeout)
	defer dialCancel()
	conn, err := cliTr.Dial(dialCtx, serverPC.LocalAddr(), tlsClient, simQUICConfig(false))
	if err != nil {
		return false
	}
	conn.CloseWithError(0, "")
	return true
}

// The narrowest path on which a connection can be established at all. quic-go
// sends its first flight at InitialPacketSize (1280 octets of UDP payload) and
// DPLPMTUD only ever searches upward from there, so a path that cannot carry
// that first flight never completes a handshake and never gets a chance to
// discover anything smaller.
//
// This matters to the PPP feature because it bounds recovery: the whole
// narrowed-path story in mtuprobe.go ends in "tear the session down so a fresh
// connection can re-converge". If the path narrowed below this floor there is no
// re-converging to be done -- the rebuild cannot connect at all.
func TestMTUSimulationHandshakeFloor(t *testing.T) {
	if testing.Short() {
		t.Skip("network simulation")
	}

	// 1280 + IPv4 + UDP headers is the arithmetic floor. The rungs straddle it,
	// with one comfortably clear rung at the top.
	const arithmeticFloor = 1280 + simIPv4Header + simUDPHeader // 1308
	rungs := []int{1280, 1300, arithmeticFloor - 1, arithmeticFloor, 1350}

	results := make(map[int]bool, len(rungs))
	for _, pmtu := range rungs {
		ok := simHandshakeSucceeds(t, pmtu)
		results[pmtu] = ok
		t.Logf("pathMTU=%-5d handshake=%v", pmtu, ok)
	}

	assert.False(t, results[1280],
		"the IPv6 minimum link MTU (1280) is below quic-go's own first-flight size, "+
			"so a conforming IPv6 path can be too narrow to connect at all")
	assert.False(t, results[arithmeticFloor-1],
		"one octet below InitialPacketSize+headers must not complete a handshake")
	assert.True(t, results[arithmeticFloor],
		"exactly InitialPacketSize+IPv4+UDP headers must be enough")
	assert.True(t, results[1350], "a comfortably wide path must connect")

	// Monotonic: once a rung connects, every wider rung must connect too. A
	// non-monotonic ladder would mean the failures are flakes, not the floor.
	connected := false
	for _, pmtu := range rungs {
		if results[pmtu] {
			connected = true
		} else if connected {
			t.Errorf("pathMTU=%d failed after a narrower path succeeded; "+
				"the floor is not a floor", pmtu)
		}
	}
}

// Real path MTUs worth caring about: plain Ethernet, PPPoE (very common on
// consumer DSL/FTTH), a typical tunnelled path, quic-go's own 1452 ceiling, and
// mobile/VPN paths.
//
// Paths below the handshake floor are deliberately absent. They cannot connect,
// so they produce no headroom figure to check, and each one costs a full dial
// timeout. TestMTUSimulationHandshakeFloor owns that case and asserts it in a
// fraction of the time.
var simPathMTUs = []int{1500, 1492, 1480, 1452, 1420, 1400, 1350}

func TestMTUSimulationAgainstRealQUIC(t *testing.T) {
	if testing.Short() {
		t.Skip("network simulation")
	}

	t.Logf("%-8s %-9s %-10s %-9s %-9s %-9s %-9s %-9s",
		"pathMTU", "computed", "converged", "headroom", "initial", "initHead", "converge", "underLoad")

	var failures []string
	for _, pmtu := range simPathMTUs {
		r := runMTUSim(t, pmtu, false)
		if !assert.Falsef(t, r.handshakeFailed,
			"pathMTU=%d is above the handshake floor and must connect", pmtu) {
			continue
		}
		t.Logf("%-8d %-9d %-10d %-+9d %-9d %-+9d %-9s %-9d",
			r.pathMTU, r.computed, r.converged, r.headroom, r.initial, r.initHeadroom,
			r.convergeTime.Round(time.Millisecond), r.underLoad)
		if r.headroom < 0 {
			failures = append(failures, fmt.Sprintf(
				"pathMTU=%d: CalculatePPPMTU says %d but quic-go only carries %d of payload "+
					"(short by %d bytes) -- full-size frames would be dropped silently",
				r.pathMTU, r.computed, r.converged, -r.headroom,
			))
		}
	}
	for _, f := range failures {
		t.Error(f)
	}
}

// With Path MTU discovery off the packet size never leaves quic-go's initial
// 1280, so the budget is pinned no matter how wide the path really is. This is
// why the feature measures the transport instead of computing from the path:
// CalculatePPPMTU sizes pppd against the real path MTU and would hand it an MTU
// the transport refuses.
func TestMTUSimulationWithPMTUDDisabled(t *testing.T) {
	if testing.Short() {
		t.Skip("network simulation")
	}

	var budgets []int
	for _, pmtu := range []int{1500, 1400} {
		r := runMTUSim(t, pmtu, true)
		require.False(t, r.handshakeFailed, "pathMTU=%d should still connect with PMTUD off", pmtu)
		t.Logf("pathMTU=%d PMTUD=off: computed=%d converged=%d initial=%d headroom=%+d",
			r.pathMTU, r.computed, r.converged, r.initial, r.headroom)

		assert.Equal(t, r.initial, r.converged,
			"pathMTU=%d: with discovery disabled the budget must never grow past the initial one", pmtu)
		// The datagram payload rides inside a 1280-octet packet, so it cannot
		// reach 1280 however wide the path is.
		assert.Less(t, r.converged, 1280,
			"pathMTU=%d: the budget must stay pinned inside InitialPacketSize, got %d", pmtu, r.converged)
		budgets = append(budgets, r.converged)
	}

	require.Len(t, budgets, 2)
	assert.Equal(t, budgets[0], budgets[1],
		"with discovery off the budget is a constant: a 1500-byte path and a 1400-byte "+
			"path must yield the same ceiling, which is exactly why it cannot be derived "+
			"from the path")
}

// The budget right after the handshake is smaller than the converged one, so
// there is a window where pppd may already be sending full-size frames that
// quic-go cannot carry yet. This is the window StableDatagramBudget exists to
// wait out, so the window has to be real.
func TestMTUSimulationStartupWindow(t *testing.T) {
	if testing.Short() {
		t.Skip("network simulation")
	}

	r := runMTUSim(t, 1500, false)
	require.False(t, r.handshakeFailed)
	t.Logf("pathMTU=1500: budget at handshake=%d, converged=%d after %s (grew by %d bytes)",
		r.initial, r.converged, r.convergeTime.Round(time.Millisecond), r.converged-r.initial)

	assert.Greater(t, r.initial, 0, "the handshake budget must be reportable")
	assert.Greater(t, r.converged, r.initial,
		"on a 1500-byte path discovery must find more room than the handshake started with; "+
			"without a gap here there would be nothing for StableDatagramBudget to settle on")
	assert.Negative(t, r.initHeadroom,
		"frames sized for the converged MTU must not fit at handshake time -- that gap is "+
			"the startup window")
	assert.GreaterOrEqual(t, r.headroom, 0,
		"once converged, the computed MTU must fit inside the budget")
}

// What happens when the path narrows after the MTU has already been discovered:
// a route change, a new tunnel on the path, a failover to a different uplink.
// quic-go's mtuFinder.CurrentSize() returns f.min, and f.min is only ever raised
// (mtu_discoverer.go OnAcked) or cleared on path migration -- there is no downward
// revision. So the question is not whether the estimate self-corrects, it is how
// long the connection takes to fail so that something above it can rebuild.
func TestMTUSimulationPathShrinksMidConnection(t *testing.T) {
	if testing.Short() {
		t.Skip("network simulation")
	}

	const wide, narrow = 1500, 1300

	serverPC, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	srvConn := newPathMTUConn(serverPC, wide-simIPv4Header-simUDPHeader)
	defer srvConn.Close()

	clientPC, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	cliConn := newPathMTUConn(clientPC, wide-simIPv4Header-simUDPHeader)
	defer cliConn.Close()

	tlsServer, tlsClient := simTLSConfigs(t)
	srvTr := &quic.Transport{Conn: srvConn}
	defer srvTr.Close()
	ln, err := srvTr.Listen(tlsServer, simQUICConfig(false))
	require.NoError(t, err)
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	accepted := make(chan *quic.Conn, 1)
	go func() {
		if c, aerr := ln.Accept(ctx); aerr == nil {
			accepted <- c
		}
	}()

	cliTr := &quic.Transport{Conn: cliConn}
	defer cliTr.Close()
	conn, err := cliTr.Dial(ctx, serverPC.LocalAddr(), tlsClient, simQUICConfig(false))
	require.NoError(t, err)
	defer conn.CloseWithError(0, "")
	srv := <-accepted
	defer srv.CloseWithError(0, "")
	go func() {
		for {
			if _, rerr := srv.ReceiveDatagram(ctx); rerr != nil {
				return
			}
		}
	}()

	for i := 0; i < 80; i++ {
		_ = conn.SendDatagram(make([]byte, 64))
		time.Sleep(10 * time.Millisecond)
	}
	wideBudget := currentDatagramBudget(conn)
	t.Logf("converged on the %d-byte path: budget=%d", wide, wideBudget)
	require.Greater(t, wideBudget, narrow,
		"the test needs a budget the narrowed path cannot carry, otherwise there is "+
			"no black hole to observe")

	// The path narrows. Nothing tells the endpoints; oversized packets just vanish.
	narrowPayload := int64(narrow - simIPv4Header - simUDPHeader)
	cliConn.maxUDP.Store(narrowPayload)
	srvConn.maxUDP.Store(narrowPayload)
	droppedBefore := cliConn.dropped.Load()
	t.Logf("path narrowed to %d without notice", narrow)

	// The observation window is deliberately short. The claim under test is not
	// "the connection survives for N seconds" -- that is a property of the idle
	// timeout, and asserting it costs exactly N seconds of suite time for no extra
	// information. The claim is that the budget is never revised *downward*, which
	// is a step function: once it is shown not to move while full-size packets are
	// being blackholed, waiting longer only re-observes the same non-event.
	const observeFor = 4 * time.Second

	// A datagram that fits the old budget but not the new path. It is accepted by
	// quic-go and destroyed on the wire, which is the whole failure mode.
	oversizeOnNewPath := make([]byte, narrow)

	shrinkStart := time.Now()
	var finalBudget int
	var connErr error
	acceptedWhileBlackholed := 0
	for time.Since(shrinkStart) < observeFor {
		if err := conn.SendDatagram(oversizeOnNewPath); err != nil {
			var tooLarge *quic.DatagramTooLargeError
			if !errors.As(err, &tooLarge) {
				connErr = err
				t.Logf("connection failed after %s: %v",
					time.Since(shrinkStart).Round(time.Millisecond), err)
				break
			}
		} else {
			acceptedWhileBlackholed++
		}
		b := currentDatagramBudget(conn)
		if b > 0 {
			assert.GreaterOrEqualf(t, b, wideBudget,
				"the budget dropped from %d to %d after %s -- if quic-go really did revise "+
					"its estimate downward, mtuprobe.go's whole reason for existing is gone",
				wideBudget, b, time.Since(shrinkStart).Round(time.Millisecond))
			finalBudget = b
		}
		time.Sleep(50 * time.Millisecond)
	}

	// 1. The connection does not notice. Nothing errors, nothing closes.
	assert.NoError(t, connErr,
		"the connection must stay up: a narrowed path produces no error, which is why "+
			"something above QUIC has to detect it")

	// 2. quic-go keeps accepting frames the path can no longer carry.
	assert.Positive(t, acceptedWhileBlackholed,
		"SendDatagram must keep succeeding for frames that are now too big -- that is the "+
			"black hole the MTU probe exists to find")

	// 3. And those frames really are being destroyed rather than delivered.
	assert.Greater(t, cliConn.dropped.Load(), droppedBefore,
		"the emulated bottleneck must actually be discarding the oversized packets")

	// 4. The estimate is unchanged, which is the load-bearing fact.
	assert.Equal(t, wideBudget, finalBudget,
		"quic-go's MTU estimate is only ever raised (mtu_discoverer.go raises f.min on "+
			"OnAcked and never lowers it), so recovery cannot come from QUIC -- it has to "+
			"come from tearing the session down and re-dialling, which is what "+
			"errPathNarrowed does")
}
