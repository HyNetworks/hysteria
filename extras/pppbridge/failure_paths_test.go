package pppbridge

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apernet/hysteria/core/v2/ppp"
	"github.com/apernet/hysteria/extras/v2/l2tp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

// What the two server handlers and the relay do when something underneath them
// fails.
//
// The lifecycle tests all walk a working session. These are the paths that run
// when the client's connection dies mid-handshake, when the transport refuses a
// frame, or when the LNS hangs up -- the ones a LAC in production takes far more
// often than anyone would like, and where a leak costs an address or a whole
// session's worth of hung relay.

// deadControl is a control stream that cannot be written to and never delivers
// anything, which is what a QUIC stream looks like once its connection is gone.
type deadControl struct {
	closed chan struct{}
	writes atomic.Int32
}

func newDeadControl() *deadControl { return &deadControl{closed: make(chan struct{})} }

var errControlGone = errors.New("control stream is gone")

func (c *deadControl) Read([]byte) (int, error) {
	<-c.closed
	return 0, io.EOF
}

func (c *deadControl) Write([]byte) (int, error) {
	c.writes.Add(1)
	return 0, errControlGone
}

func (c *deadControl) Close() error {
	select {
	case <-c.closed:
	default:
		close(c.closed)
	}
	return nil
}

func testParams() ppp.SessionParams {
	return ppp.SessionParams{ClientMaxFrame: 1404, ServerMaxFrame: 1404}
}

func testAddr() net.Addr { return &net.TCPAddr{IP: net.IPv4(203, 0, 113, 9), Port: 51000} }

// ---------------------------------------------------------------------------
// Local termination
// ---------------------------------------------------------------------------

// A client that disappears between its request and the response leaves nothing
// to serve. The address it was allocated has to go back, or a flapping client
// would drain the pool one reconnect at a time.
func TestServerPPPHandlerReleasesTheAddressWhenItCannotAnswer(t *testing.T) {
	pool, err := NewIPPool("10.9.2.0/29")
	require.NoError(t, err)
	before := poolSize(t, pool)

	h := &ServerPPPHandler{
		PPPDPath: "/nonexistent/pppd", // must never be reached
		IPv4Pool: pool,
		Logger:   zap.NewNop(),
	}
	ctl := newDeadControl()

	done := make(chan struct{})
	go func() {
		defer close(done)
		h.HandlePPP(ctl, testParams(), func() (ppp.PPPDataIO, error) {
			t.Error("no data transport may be built for a client we cannot answer")
			return nil, nil
		}, testAddr(), "vanished")
	}()

	select {
	case <-done:
	case <-time.After(testTimeout):
		t.Fatal("HandlePPP did not return after the control stream failed")
	}
	assert.Equal(t, before, poolSize(t, pool),
		"the whole pool must be available again once the session is abandoned")
}

// The data transport is built after the response, and it can fail: the client
// may be gone, or out of stream credit. The address goes back the same way.
func TestServerPPPHandlerReleasesTheAddressWhenTheTransportCannotBeBuilt(t *testing.T) {
	pool, err := NewIPPool("10.9.3.0/29")
	require.NoError(t, err)
	before := poolSize(t, pool)

	h := &ServerPPPHandler{PPPDPath: "/nonexistent/pppd", IPv4Pool: pool, Logger: zap.NewNop()}
	rawCtl, serverCtl := net.Pipe()
	ctl := &recordingConn{Conn: rawCtl}
	t.Cleanup(func() { _ = rawCtl.Close() })

	done := make(chan struct{})
	go func() {
		defer close(done)
		h.HandlePPP(serverCtl, testParams(),
			func() (ppp.PPPDataIO, error) { return nil, errors.New("no stream credit") },
			testAddr(), "unlucky")
	}()

	ok, _, _, _, err := readPPPResponse(ctl)
	require.NoError(t, err)
	require.True(t, ok, "the session was accepted before the transport was built")

	select {
	case <-done:
	case <-time.After(testTimeout):
		t.Fatal("HandlePPP did not return after the data transport failed")
	}
	assert.Equal(t, before, poolSize(t, pool))
}

// poolSize reports how many addresses a pool has available, leaving it exactly
// as it found it.
func poolSize(t *testing.T, p *IPPool) int {
	t.Helper()
	got := drainPool(t, p)
	for _, ip := range got {
		p.Release(ip)
	}
	return len(got)
}

// The server has one connection to give. A Bridge that retried its dial would
// otherwise be handed the same single-use streams twice and relay a second
// session into a transport the first still owns.
func TestOneShotDialRefusesASecondAttempt(t *testing.T) {
	ctl := newDeadControl()
	pair := newFramePair(1)
	_, data := pair.ends()
	var cancelled atomic.Bool

	dial := oneShotDial(ctl, data, func() { cancelled.Store(true) })

	gotCtl, gotData, closeFn, err := dial()
	require.NoError(t, err)
	assert.Same(t, ctl, gotCtl)
	assert.Equal(t, ppp.PPPDataIO(data), gotData)
	closeFn()
	assert.True(t, cancelled.Load(), "the close function is what cancels the session context")

	_, _, _, err = dial()
	require.Error(t, err)
	assert.True(t, isPermanentDialError(err),
		"a second attempt must stop the retry loop rather than back off and try again")
}

// The MTU the link comes up at is the one number an operator needs when a
// subscriber reports that large downloads stall, so it has to reach the log.
func TestServerPPPHandlerLogsTheMTUItBroughtTheLinkUpAt(t *testing.T) {
	core, logs := observer.New(zap.DebugLevel)
	// No PPPDArgs, so the handler generates them and computes an MTU. /bin/sh
	// will not understand pppd's arguments and exits at once, which is all this
	// test needs: the log line is written before the child is spawned.
	h := &ServerPPPHandler{PPPDPath: "/bin/sh", Logger: zap.New(core), MTU: 1380}

	pair := newFramePair(4)
	_, serverData := pair.ends()
	rawCtl, serverCtl := net.Pipe()
	ctl := &recordingConn{Conn: rawCtl}
	t.Cleanup(func() { _ = rawCtl.Close(); pair.shutdown() })

	done := make(chan struct{})
	go func() {
		defer close(done)
		h.HandlePPP(serverCtl, testParams(),
			func() (ppp.PPPDataIO, error) { return serverData, nil }, testAddr(), "logged")
	}()

	_, _, _, _, err := readPPPResponse(ctl)
	require.NoError(t, err)
	ctl.reset()
	go func() {
		buf := make([]byte, 256)
		for {
			if _, err := ctl.Read(buf); err != nil {
				return
			}
		}
	}()

	select {
	case <-done:
	case <-time.After(testTimeout):
		t.Fatal("HandlePPP did not return")
	}

	started := logs.FilterMessage("PPP session started").All()
	require.Len(t, started, 1)
	fields := started[0].ContextMap()
	require.Contains(t, fields, "mtu", "the session-start log must say what MTU was used")
	assert.Equal(t, int64(1380), fields["mtu"])
}

// An operator's explicit mtu is used verbatim; otherwise the measured transport
// ceiling decides, clamped to what PPP allows. Both clamps matter: a transport
// that reports something absurd must not produce an unusable link.
func TestBuildPPPDArgsClampsTheLinkMRU(t *testing.T) {
	h := &ServerPPPHandler{Logger: zap.NewNop()}

	_, tooBig := h.buildPPPDArgs("10.0.0.1", "10.0.0.2", "id", testAddr(), 0, maxPPPMTU+400)
	assert.Equal(t, maxPPPMTU-MLPPPOverhead, tooBig,
		"PPP cannot carry more than 1500, whatever the transport claims")

	_, tooSmall := h.buildPPPDArgs("10.0.0.1", "10.0.0.2", "id", testAddr(), 0, 200)
	assert.Equal(t, minPPPMTU-MLPPPOverhead, tooSmall,
		"a link below the PPP minimum is brought up at the minimum rather than refused")
}

// ---------------------------------------------------------------------------
// LAC mode
// ---------------------------------------------------------------------------

// newTestL2TPHandler is a LAC whose routing is configured but whose tunnel
// manager is nil: these tests all fail before a tunnel could be dialled, and a
// nil manager is how they prove it.
func newTestL2TPHandler(t *testing.T) *L2TPPPPHandler {
	t.Helper()
	return &L2TPPPPHandler{
		IDRouter: l2tp.NewIDRouter([]l2tp.RouteRule{{Pattern: testClientID, Group: "grp"}}),
		LoadBalancer: l2tp.NewLoadBalancer(map[string][]l2tp.LNSConfig{
			"grp": {{Address: "198.51.100.1:1701"}},
		}),
		Logger: zap.NewNop(),
	}
}

// A client that goes away before the response lands must not cost an L2TP
// session: nothing may be dialled towards the LNS for a call nobody is on.
func TestL2TPHandlerBuildsNothingWhenItCannotAnswer(t *testing.T) {
	h := newTestL2TPHandler(t)
	ctl := newDeadControl()

	done := make(chan struct{})
	go func() {
		defer close(done)
		h.HandlePPP(ctl, testParams(), func() (ppp.PPPDataIO, error) {
			t.Error("no data transport may be built for a client we cannot answer")
			return nil, nil
		}, testAddr(), testClientID)
	}()

	select {
	case <-done:
	case <-time.After(testTimeout):
		t.Fatal("HandlePPP did not return after the control stream failed")
	}
	assert.Equal(t, int32(1), ctl.writes.Load(), "one attempt, then give up")
}

// Same on the next step: a transport that cannot be built means no session, and
// the routing decision must not have happened yet.
func TestL2TPHandlerDialsNoLNSWhenTheTransportCannotBeBuilt(t *testing.T) {
	h := newTestL2TPHandler(t)
	rawCtl, serverCtl := net.Pipe()
	ctl := &recordingConn{Conn: rawCtl}
	t.Cleanup(func() { _ = rawCtl.Close() })

	done := make(chan struct{})
	go func() {
		defer close(done)
		h.HandlePPP(serverCtl, testParams(),
			func() (ppp.PPPDataIO, error) { return nil, errors.New("no stream credit") },
			testAddr(), testClientID)
	}()

	ok, _, _, _, err := readPPPResponse(ctl)
	require.NoError(t, err)
	require.True(t, ok)

	select {
	case <-done:
	case <-time.After(testTimeout):
		t.Fatal("HandlePPP did not return after the data transport failed")
	}
}

// An LNS that hangs up without a Result Code is out of spec, but the fact that
// it hung up is still worth passing on: it is the difference between "the far
// end cleared your call" and "the path to it broke", and only the first means
// the subscriber should stop retrying immediately.
func TestL2TPModeReportsAnLNSThatHangsUpWithoutSayingWhy(t *testing.T) {
	h := newL2TPHarness(t)
	h.bringUp(t)

	h.lns.sendBareCDN()

	select {
	case <-h.handlerDone:
	case <-time.After(testTimeout):
		t.Fatal("a CDN must end the session whether or not it carries a Result Code")
	}
	assert.Equal(t, SessionReason{
		Code:    ReasonLNSDisconnected,
		Message: "the LNS disconnected the session",
	}, h.control.awaitReason(t))
}

// ---------------------------------------------------------------------------
// The relay
// ---------------------------------------------------------------------------

// A dead endpoint ends the relay, and the error says which side went: the caller
// treats a dead pppd as "rebuild quietly" and a dead transport as "the link
// dropped, report it".
func TestRelayReportsWhichSideFailed(t *testing.T) {
	t.Run("endpoint", func(t *testing.T) {
		pair := newFramePair(4)
		client, server := pair.ends()
		ep := newFrameRWSpy()
		ep.failSends(errors.New("pppd is gone"))
		r := newRelay(server, ep, zap.NewNop(), nil)

		errCh := make(chan error, 1)
		go func() { errCh <- r.run(context.Background()) }()
		require.NoError(t, client.SendData(buildPPPFrame(pppProtoLCP, []byte{0x01})))

		err := awaitRelayError(t, errCh)
		var re *relayError
		require.ErrorAs(t, err, &re)
		assert.True(t, re.fromEndpoint, "the endpoint refused the frame, so the endpoint is what failed")
	})

	t.Run("transport", func(t *testing.T) {
		pair := newFramePair(4)
		_, server := pair.ends()
		ep := newFrameRWSpy()
		r := newRelay(server, ep, zap.NewNop(), nil)

		errCh := make(chan error, 1)
		go func() { errCh <- r.run(context.Background()) }()
		pair.shutdown()

		err := awaitRelayError(t, errCh)
		var re *relayError
		require.ErrorAs(t, err, &re)
		assert.False(t, re.fromEndpoint)
	})
}

func awaitRelayError(t *testing.T, errCh <-chan error) error {
	t.Helper()
	select {
	case err := <-errCh:
		require.Error(t, err)
		return err
	case <-time.After(testTimeout):
		t.Fatal("the relay did not end")
		return nil
	}
}

// A probe request has to be answered, and if the answer cannot be sent the
// transport is gone -- that ends the session rather than leaving a relay pumping
// into nothing.
func TestRelayEndsWhenAProbeReplyCannotBeSent(t *testing.T) {
	pair := newFramePair(4)
	client, server := pair.ends()
	ep := newFrameRWSpy()
	r := newRelay(&closeOnSendDataIO{pairedDataIO: server, pair: pair}, ep, zap.NewNop(), nil)

	errCh := make(chan error, 1)
	go func() { errCh <- r.run(context.Background()) }()
	require.NoError(t, client.SendData(buildMTUProbe(mtuProbeRequest, 1, mtuProbeHeaderLen+8)))

	err := awaitRelayError(t, errCh)
	var re *relayError
	require.ErrorAs(t, err, &re)
	assert.False(t, re.fromEndpoint, "the transport is what refused the reply")
	ep.assertSilent(t, "an MTU probe is answered by the relay and never reaches the endpoint")
}

// closeOnSendDataIO fails the first send and shuts the pair down, which is a
// transport that dies exactly as the relay tries to answer a probe.
type closeOnSendDataIO struct {
	*pairedDataIO
	pair *framePair
	once sync.Once
}

func (d *closeOnSendDataIO) SendData(frame []byte) error {
	d.once.Do(d.pair.shutdown)
	return d.pairedDataIO.SendData(frame)
}

// A probe that cannot be sent is inconclusive, not fatal: giving up would leave
// the session running with black-hole detection switched off, which is the one
// thing the probe exists to catch.
func TestProbeLoopSurvivesASendThatFails(t *testing.T) {
	pair := newFramePair(4)
	_, server := pair.ends()
	sized := &refusingDataIO{pairedDataIO: server, max: 900}
	ep := newFrameRWSpy()

	core, logs := observer.New(zap.DebugLevel)
	r := newRelay(sized, ep, zap.New(core), nil)
	r.ProbeInterval, r.ProbeGrace, r.ProbeFailures = 20*time.Millisecond, time.Millisecond, 3

	errCh := make(chan error, 1)
	go func() { errCh <- r.run(context.Background()) }()

	require.Eventually(t, func() bool {
		return len(logs.FilterMessage("MTU probe send failed").All()) >= 2
	}, testTimeout, 5*time.Millisecond, "the probe loop must keep trying")

	select {
	case err := <-errCh:
		t.Fatalf("a refused probe must not end the session: %v", err)
	default:
	}
	pair.shutdown()
	<-errCh
}

// refusingDataIO reports a frame ceiling and then refuses every frame that size,
// which is what a transport looks like when quic-go's budget drops below what it
// advertised.
type refusingDataIO struct {
	*pairedDataIO
	max int
}

func (d *refusingDataIO) MaxFrameSize() int { return d.max }

func (d *refusingDataIO) SendData(frame []byte) error {
	if len(frame) >= d.max {
		return errors.New("the path will not take it")
	}
	return d.pairedDataIO.SendData(frame)
}

// A transport's ceiling is not fixed: quic-go revises it as path discovery
// runs, and it can stop reporting a usable one entirely. That is "we do not
// know", not "the path narrowed" -- probing at a size that means nothing, and
// then counting the silence as a failure, would tear down a session that is
// perfectly healthy.
func TestProbeLoopSkipsAnUnusableProbeSize(t *testing.T) {
	for name, shrunk := range map[string]int{
		"the transport stops reporting a size": 0,
		"it reports more than PPP can carry":   maxPPPMTU + 1,
	} {
		t.Run(name, func(t *testing.T) {
			pair := newFramePair(8)
			_, server := pair.ends()
			// Worth probing when the relay decides whether to start the loop, and
			// unusable from the loop's first tick onwards.
			data := &shrinkingDataIO{pairedDataIO: server, max: 1200, then: &shrunk}
			ep := newFrameRWSpy()
			r := newRelay(data, ep, zap.NewNop(), nil)
			r.ProbeInterval, r.ProbeGrace, r.ProbeFailures = 10*time.Millisecond, time.Millisecond, 2

			errCh := make(chan error, 1)
			go func() { errCh <- r.run(context.Background()) }()

			// Long enough for more probe intervals than ProbeFailures allows.
			time.Sleep(80 * time.Millisecond)
			select {
			case err := <-errCh:
				t.Fatalf("no probe was sent, so nothing may have failed: %v", err)
			default:
			}
			assert.Empty(t, data.probes(), "an unusable size must produce no probe at all")

			pair.shutdown()
			<-errCh
		})
	}
}

// shrinkingDataIO reports one ceiling to the first caller and another to every
// caller after it, and records the probes that went out.
//
// Switching on the read rather than on a timer is what makes the test
// deterministic: the first read is the relay deciding whether the transport is
// worth probing at all, and every read after it is the probe loop sizing a
// frame.
type shrinkingDataIO struct {
	*pairedDataIO
	mu   sync.Mutex
	max  int
	then *int
	sent [][]byte
}

func (d *shrinkingDataIO) MaxFrameSize() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.max
	if d.then != nil {
		d.max, d.then = *d.then, nil
	}
	return now
}

func (d *shrinkingDataIO) SendData(frame []byte) error {
	if _, _, ok := parseMTUProbe(frame); ok {
		d.mu.Lock()
		d.sent = append(d.sent, append([]byte(nil), frame...))
		d.mu.Unlock()
	}
	return d.pairedDataIO.SendData(frame)
}

func (d *shrinkingDataIO) probes() [][]byte {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([][]byte(nil), d.sent...)
}

// ---------------------------------------------------------------------------
// The bridge
// ---------------------------------------------------------------------------

// pppd's first frame is what brings the link up, and it is sent before the relay
// starts. A transport that refuses it is not a reason to abandon the session:
// pppd retransmits its Configure-Request on its own Restart timer.
func TestBridgeSurvivesAFirstFrameThatCannotBeSent(t *testing.T) {
	fromChild, childSpeaks := io.Pipe()
	t.Cleanup(func() { _ = childSpeaks.Close() })

	core, logs := observer.New(zap.DebugLevel)
	b := &Bridge{NoSpawn: true, In: fromChild, Out: &discardWriteCloser{}, Logger: zap.New(core)}

	pair := newFramePair(4)
	client, server := pair.ends()
	refuse := &refuseFirstDataIO{pairedDataIO: server}

	errCh := make(chan error, 1)
	go func() {
		errCh <- b.Run(context.Background(), func() (io.ReadWriteCloser, ppp.PPPDataIO, func(), error) {
			return newDeadControl(), refuse, func() {}, nil
		})
	}()

	// pppd speaks first.
	_, err := childSpeaks.Write(EncodeHDLC(buildPPPFrame(pppProtoLCP, buildLCPPacket(lcpConfigRequest, 1, nil))))
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		return len(logs.FilterMessage("initial frame could not be sent").All()) == 1
	}, testTimeout, 5*time.Millisecond, "the refusal must be logged, not swallowed")

	// The session is still up: a second frame gets through.
	_, err = childSpeaks.Write(EncodeHDLC(buildPPPFrame(pppProtoLCP, buildLCPPacket(lcpConfigRequest, 2, nil))))
	require.NoError(t, err)
	got := make(chan []byte, 1)
	go func() {
		f, err := client.ReceiveData()
		if err == nil {
			got <- f
		}
	}()
	select {
	case frame := <-got:
		proto, _ := parsePPPFrame(frame)
		assert.Equal(t, pppProtoLCP, proto)
	case <-time.After(testTimeout):
		t.Fatal("the relay stopped after the first frame was refused")
	}

	pair.shutdown()
	_ = childSpeaks.Close()
	select {
	case <-errCh:
	case <-time.After(testTimeout):
		t.Fatal("Run did not return")
	}
}

// refuseFirstDataIO refuses exactly one frame, standing in for a transport whose
// budget has not settled when pppd's first Configure-Request arrives.
type refuseFirstDataIO struct {
	*pairedDataIO
	refused atomic.Bool
}

func (d *refuseFirstDataIO) SendData(frame []byte) error {
	if d.refused.CompareAndSwap(false, true) {
		return errors.New("not yet")
	}
	return d.pairedDataIO.SendData(frame)
}

type discardWriteCloser struct{}

func (discardWriteCloser) Write(p []byte) (int, error) { return len(p), nil }
func (discardWriteCloser) Close() error                { return nil }

// pppd exiting is the end of the session, not a link failure: there is nothing
// left to carry, and reporting a link that never broke would make a client
// retry against a server that is perfectly healthy.
func TestBridgeReportsNoLinkFailureWhenTheChildEndsTheSession(t *testing.T) {
	fromChild, childSpeaks := io.Pipe()
	b := &Bridge{
		NoSpawn: true, In: fromChild, Out: &discardWriteCloser{},
		ReadReason: true, Logger: zap.NewNop(),
	}

	pair := newFramePair(4)
	_, server := pair.ends()
	t.Cleanup(pair.shutdown)

	errCh := make(chan error, 1)
	go func() {
		errCh <- b.Run(context.Background(), func() (io.ReadWriteCloser, ppp.PPPDataIO, func(), error) {
			return newDeadControl(), server, func() {}, nil
		})
	}()

	_, err := childSpeaks.Write(EncodeHDLC(buildPPPFrame(pppProtoLCP, buildLCPPacket(lcpConfigRequest, 1, nil))))
	require.NoError(t, err)
	require.NoError(t, childSpeaks.Close()) // pppd exits

	select {
	case err := <-errCh:
		assert.NoError(t, err, "a child that ended the session is not a link that went down")
	case <-time.After(testTimeout):
		t.Fatal("Run did not return after the child went away")
	}
}
