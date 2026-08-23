package pppbridge

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/apernet/hysteria/core/v2/ppp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

// The bridge is transport-only: it finds HDLC frame boundaries and hands every
// frame to PPPDataIO, whatever the frame turns out to be. These tests pin that
// property, because the whole point of the design is that no PPP protocol
// parsing happens here -- a frame's contents must never change its path.

const testTimeout = 2 * time.Second

// fakeDataIO is a PPPDataIO that records what was sent and replays what the test
// queues for receipt.
type fakeDataIO struct {
	sent   chan []byte
	recv   chan []byte
	closed chan struct{}
	once   sync.Once
}

func newFakeDataIO() *fakeDataIO {
	return &fakeDataIO{
		sent:   make(chan []byte, 64),
		recv:   make(chan []byte, 64),
		closed: make(chan struct{}),
	}
}

func (f *fakeDataIO) SendData(frame []byte) error {
	cp := append([]byte(nil), frame...)
	select {
	case f.sent <- cp:
		return nil
	case <-f.closed:
		return io.ErrClosedPipe
	}
}

func (f *fakeDataIO) ReceiveData() ([]byte, error) {
	select {
	case b := <-f.recv:
		return b, nil
	case <-f.closed:
		return nil, io.EOF
	}
}

func (f *fakeDataIO) Close() error {
	f.once.Do(func() { close(f.closed) })
	return nil
}

// bridgeHarness drives a NoSpawn Bridge over pipes, standing in for pppd.
type bridgeHarness struct {
	toBridge   *os.File // test writes here; the bridge reads it as "pppd output"
	fromBridge *os.File // test reads here; the bridge writes it as "pppd input"
	control    net.Conn // the test's end of the control stream
	data       *fakeDataIO
	bridge     *Bridge
	cancel     context.CancelFunc

	// runDone closes once Run returns, with runErrVal holding its error. A
	// channel of one would be consumed by whichever of the test or the cleanup
	// read it first, so both would race for the same value.
	runDone   chan struct{}
	runErrVal error

	// logs captures everything the bridge logs. Several of the bridge's
	// decisions -- dropping a frame while a dial is pending, for one -- have no
	// other observable effect, and waiting on the log entry is what makes a test
	// about them ordered rather than timing-dependent.
	logs *observer.ObservedLogs

	// dialGate, when non-nil, holds dialFn until releaseDial is called.
	dialGate chan struct{}
}

// harnessCfg tweaks what newBridgeHarness builds.
type harnessCfg struct {
	// wrap replaces the PPPDataIO handed to the bridge with a decorator around
	// the plain fake, so a test can make SendData fail or advertise a frame
	// ceiling while nextSent still observes whatever did get through.
	// See withTransportWrapper in bridge_mtu_test.go.
	wrap func(*fakeDataIO) ppp.PPPDataIO

	// gateDial makes the dial block until the test releases it, so a test can
	// establish exactly what the bridge did during the window where it had
	// nowhere to put frames.
	gateDial bool

	// probe overrides the MTU probe timings so the teardown decision can be
	// exercised in milliseconds instead of the production minute.
	probeInterval time.Duration
	probeGrace    time.Duration
	probeFailures int

	// mtuFixed builds the bridge the way nospawn does, where the PPP MTU came
	// from outside this process and a rebuild could not change it.
	mtuFixed bool

	// noReasonReader builds the bridge the way the server builds one: writing
	// reasons rather than reading them.
	noReasonReader bool

	// counters attaches a caller-owned set of traffic counters, which is how the
	// OpenWrt client publishes what one link of a bundle carried.
	counters *Counters
}

// withoutReasonReader clears ReadReason, which is how every server-side Bridge
// is configured.
// withFixedMTU marks the MTU as not this process's to choose, which is what
// nospawn does.
func withFixedMTU() harnessOption {
	return func(c *harnessCfg) { c.mtuFixed = true }
}

func withoutReasonReader() harnessOption {
	return func(c *harnessCfg) { c.noReasonReader = true }
}

// withProbeTimings shortens the MTU probe schedule.
func withProbeTimings(interval, grace time.Duration, failures int) harnessOption {
	return func(c *harnessCfg) {
		c.probeInterval, c.probeGrace, c.probeFailures = interval, grace, failures
	}
}

type harnessOption func(*harnessCfg)

// withGatedDial holds the dial open until releaseDial is called.
func withGatedDial() harnessOption {
	return func(c *harnessCfg) { c.gateDial = true }
}

func newBridgeHarness(t *testing.T, opts ...harnessOption) *bridgeHarness {
	t.Helper()

	var cfg harnessCfg
	for _, o := range opts {
		o(&cfg)
	}

	childR, testW, err := os.Pipe() // bridge reads childR, test writes testW
	require.NoError(t, err)
	testR, childW, err := os.Pipe() // bridge writes childW, test reads testR
	require.NoError(t, err)

	bridgeCtl, testCtl := net.Pipe()
	data := newFakeDataIO()
	var transport ppp.PPPDataIO = data
	if cfg.wrap != nil {
		transport = cfg.wrap(data)
	}

	// Debug level: the drop path this harness needs to observe only logs there.
	core, logs := observer.New(zap.DebugLevel)

	b := &Bridge{
		NoSpawn:       true,
		ReadReason:    !cfg.noReasonReader,
		Logger:        zap.New(core),
		In:            childR,
		Out:           childW,
		ProbeInterval: cfg.probeInterval,
		ProbeGrace:    cfg.probeGrace,
		ProbeFailures: cfg.probeFailures,
		MTUFixed:      cfg.mtuFixed,
		Counters:      cfg.counters,
	}

	ctx, cancel := context.WithCancel(context.Background())
	h := &bridgeHarness{
		toBridge:   testW,
		fromBridge: testR,
		control:    testCtl,
		data:       data,
		bridge:     b,
		runDone:    make(chan struct{}),
		cancel:     cancel,
		logs:       logs,
	}
	if cfg.gateDial {
		h.dialGate = make(chan struct{})
	}

	// One-shot dial. Run dials once per call, so the second attempt only happens
	// if the first dial itself failed and dialWithRetry came back round; a
	// permanent error is how we stop that loop rather than let it spin.
	var dialed bool
	dialFn := func() (io.ReadWriteCloser, ppp.PPPDataIO, func(), error) {
		if h.dialGate != nil {
			select {
			case <-h.dialGate:
			case <-ctx.Done():
				return nil, nil, nil, permanentDialError{ctx.Err()}
			}
		}
		if dialed {
			return nil, nil, nil, permanentDialError{errors.New("one-shot")}
		}
		dialed = true
		return bridgeCtl, transport, func() { _ = bridgeCtl.Close() }, nil
	}

	go func() {
		h.runErrVal = b.Run(ctx, dialFn)
		close(h.runDone)
	}()

	t.Cleanup(func() {
		cancel()
		_ = testW.Close()
		_ = testCtl.Close()
		data.Close()
		select {
		case <-h.runDone:
		case <-time.After(testTimeout):
			t.Error("Bridge.Run did not return")
		}
		_ = testR.Close()
	})
	return h
}

// releaseDial lets a gated dial complete.
func (h *bridgeHarness) releaseDial() { close(h.dialGate) }

// awaitLogged waits until the bridge has logged msg at least n times, and
// returns once it has. It is the ordering primitive for behaviour whose only
// trace is a log line.
func (h *bridgeHarness) awaitLogged(t *testing.T, msg string, n int) {
	t.Helper()
	deadline := time.Now().Add(testTimeout)
	for {
		if got := h.logs.FilterMessage(msg).Len(); got >= n {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %d %q log entries, saw %d",
				n, msg, h.logs.FilterMessage(msg).Len())
		}
		time.Sleep(time.Millisecond)
	}
}

// pppdSends writes a raw PPP frame to the bridge the way pppd would: HDLC-framed.
func (h *bridgeHarness) pppdSends(t *testing.T, rawPPP []byte) {
	t.Helper()
	_, err := h.toBridge.Write(EncodeHDLC(rawPPP))
	require.NoError(t, err)
}

// nextSent returns the next frame the bridge handed to PPPDataIO.
func (h *bridgeHarness) nextSent(t *testing.T) []byte {
	t.Helper()
	select {
	case f := <-h.data.sent:
		return f
	case <-time.After(testTimeout):
		t.Fatal("timed out waiting for a frame on the data transport")
		return nil
	}
}

// nextNonProbeSent is nextSent, skipping MTU probes. Tests about payload frames
// need it because the probe loop shares the transport.
func (h *bridgeHarness) nextNonProbeSent(t *testing.T) []byte {
	t.Helper()
	deadline := time.After(testTimeout)
	for {
		select {
		case f := <-h.data.sent:
			if _, _, ok := parseMTUProbe(f); ok {
				continue
			}
			return f
		case <-deadline:
			t.Fatal("timed out waiting for a non-probe frame on the data transport")
			return nil
		}
	}
}

// establish brings the session up and waits for it, by sending the one frame
// that triggers the dial and seeing it arrive on the transport. Frames written
// during the dial are not lost -- see TestBridgeDeliversFramesWrittenWhileDialing
// -- but they do not appear until it completes, so tests that want to reason
// about what is on the transport get past this point first.
func (h *bridgeHarness) establish(t *testing.T) {
	t.Helper()
	h.pppdSends(t, frameLCPConfReq)
	require.Equal(t, frameLCPConfReq, h.nextSent(t),
		"the frame that triggered the dial should be carried into the session")
}

// Representative frames spanning both sides of the old >= 0x4000 split. Under
// the current design none of this matters, which is exactly what we assert.
var (
	frameLCPConfReq = []byte{0xFF, 0x03, 0xC0, 0x21, 0x01, 0x01, 0x00, 0x04}
	frameLCPEchoReq = []byte{0xFF, 0x03, 0xC0, 0x21, 0x09, 0x02, 0x00, 0x08, 0xDE, 0xAD, 0xBE, 0xEF}
	frameCHAP       = []byte{0xFF, 0x03, 0xC2, 0x23, 0x01, 0x01, 0x00, 0x05, 0x00}
	frameIPCP       = []byte{0xFF, 0x03, 0x80, 0x21, 0x01, 0x01, 0x00, 0x04}
	frameIPv4       = []byte{0xFF, 0x03, 0x00, 0x21, 0x45, 0x00, 0x00, 0x14, 0xAA, 0xBB}
	frameIPv6       = []byte{0xFF, 0x03, 0x00, 0x57, 0x60, 0x00, 0x00, 0x00, 0xCC, 0xDD}
	frameMP         = []byte{0xFF, 0x03, 0x00, 0x3D, 0xC0, 0x01, 0x00, 0x21, 0x45, 0x00}
)

// Every frame class takes the data path, in order, regardless of its protocol
// field. Before the transport was unified, the first four of these went to the
// control stream instead.
func TestBridgeSendsEveryProtocolOverDataIO(t *testing.T) {
	h := newBridgeHarness(t)
	h.establish(t)

	frames := [][]byte{
		frameLCPConfReq,
		frameCHAP,
		frameIPCP,
		frameIPv4,
		frameIPv6,
		frameMP,
		frameLCPEchoReq,
	}
	for _, f := range frames {
		h.pppdSends(t, f)
	}

	for i, want := range frames {
		got := h.nextSent(t)
		assert.Equal(t, want, got, "frame %d took the wrong path or was reordered", i)
	}
}

// LCP Echo is the keepalive. It has to share the data path, otherwise it reports
// a healthy link while user traffic is being dropped.
func TestBridgeKeepaliveSharesTheDataPath(t *testing.T) {
	h := newBridgeHarness(t)

	h.pppdSends(t, frameIPv4)
	require.Equal(t, frameIPv4, h.nextSent(t))

	h.pppdSends(t, frameLCPEchoReq)
	assert.Equal(t, frameLCPEchoReq, h.nextSent(t),
		"LCP Echo must traverse the same transport as user data")
}

// The dial is triggered by the first frame of any kind, not by sniffing for an
// LCP Configure-Request.
func TestBridgeDialsOnFirstFrameOfAnyKind(t *testing.T) {
	h := newBridgeHarness(t)

	h.pppdSends(t, frameIPv4)
	assert.Equal(t, frameIPv4, h.nextSent(t))
}

// Frames emitted while the dial is still in flight are not lost. The bridge
// reads exactly one frame before dialling -- the one that triggers it -- and the
// relay starts reading from the same endpoint afterwards, so the rest of the
// burst is still sitting in the child's stream and arrives in order.
//
// This is a change from the old design, where anything beyond the single dial
// slot was dropped outright and recovered only by PPP's Restart timer. Nothing
// depends on frames being dropped here, and the first exchange no longer costs a
// retransmission on a slow dial.
//
// The dial is held open for the whole burst on purpose: without it, whether the
// dial completes before or after the burst is a scheduling accident, and the
// test would be asserting nothing in particular.
func TestBridgeDeliversFramesWrittenWhileDialing(t *testing.T) {
	h := newBridgeHarness(t, withGatedDial())

	burst := [][]byte{frameLCPConfReq, frameCHAP, frameIPCP, frameIPv4, frameIPv6}
	for _, f := range burst {
		h.pppdSends(t, f)
	}

	// Nothing can have gone out yet: there is no transport to put it on.
	select {
	case early := <-h.data.sent:
		t.Fatalf("a frame reached the transport before the dial completed: %x", early)
	case <-time.After(200 * time.Millisecond):
	}

	h.releaseDial()

	for i, want := range burst {
		assert.Equalf(t, want, h.nextSent(t),
			"burst frame %d was dropped or reordered across the dial", i)
	}

	// And the session carries on normally afterwards.
	h.pppdSends(t, frameMP)
	assert.Equal(t, frameMP, h.nextSent(t))
}

// Nothing is written to the control stream after the handshake.
func TestBridgeWritesNothingToControlStream(t *testing.T) {
	h := newBridgeHarness(t)
	h.establish(t)

	for _, f := range [][]byte{frameLCPConfReq, frameCHAP, frameIPCP, frameIPv4} {
		h.pppdSends(t, f)
		require.Equal(t, f, h.nextSent(t))
	}

	require.NoError(t, h.control.SetReadDeadline(time.Now().Add(200*time.Millisecond)))
	buf := make([]byte, 64)
	n, err := h.control.Read(buf)
	assert.Zero(t, n, "control stream received %d bytes: %x", n, buf[:n])
	var ne net.Error
	require.True(t, errors.As(err, &ne) && ne.Timeout(),
		"expected the control stream to stay idle, got n=%d err=%v", n, err)
}

// Frames arriving from the network are re-framed as HDLC before reaching pppd.
func TestBridgeReframesReceivedFramesToChild(t *testing.T) {
	h := newBridgeHarness(t)

	// Establish the session first; the RX pump only runs once a session exists.
	h.pppdSends(t, frameLCPConfReq)
	require.Equal(t, frameLCPConfReq, h.nextSent(t))

	for _, want := range [][]byte{frameLCPConfReq, frameIPv4, frameMP} {
		h.data.recv <- append([]byte(nil), want...)

		require.NoError(t, h.fromBridge.SetReadDeadline(time.Now().Add(testTimeout)))
		buf := make([]byte, 512)
		n, err := h.fromBridge.Read(buf)
		require.NoError(t, err)

		decoded, err := DecodeHDLC(buf[:n])
		require.NoError(t, err, "bridge must emit a well-formed HDLC frame, got %x", buf[:n])
		assert.Equal(t, want, decoded)
	}
}

// A frame the transport cannot make sense of is still forwarded untouched: the
// bridge has no opinion about frame contents. This is the property that lets
// non-PPP payloads, compressed frames (CCP) and future protocols pass through.
func TestBridgeForwardsOpaquePayloads(t *testing.T) {
	h := newBridgeHarness(t)
	h.establish(t)

	opaque := [][]byte{
		{0xFF, 0x03, 0x00, 0x21},                   // header only, no payload
		{0x00, 0x21, 0x45},                         // no ACFC prefix
		{0x21, 0x45, 0x00},                         // PFC, single-octet protocol
		{0xFF, 0x03, 0x00, 0xFD, 0x01, 0x02, 0x03}, // CCP-compressed: inner protocol unknowable
		{0x42},                   // not PPP at all
		{0xFF, 0x03, 0xFF, 0xFF}, // reserved protocol
	}
	for _, f := range opaque {
		h.pppdSends(t, f)
	}
	for i, want := range opaque {
		assert.Equal(t, want, h.nextSent(t), "opaque frame %d was altered or dropped", i)
	}
}
