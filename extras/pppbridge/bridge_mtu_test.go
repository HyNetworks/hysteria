package pppbridge

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/apernet/hysteria/core/v2/ppp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// The MTU-related behaviour of the bridge, driven through the harness in
// bridge_transport_test.go.
//
// Two things are being pinned here. First, MTU probes share the data path with
// real PPP frames but must be invisible to pppd in both directions -- they are
// the one exception to "the bridge forwards everything untouched", so the
// exception has to be exact. Second, a frame that does not fit is a packet to
// drop, not a session to kill: a single oversized IP packet must cost that
// packet and nothing else.

// ---------------------------------------------------------------------------
// harness plumbing
// ---------------------------------------------------------------------------

// withTransportWrapper decorates the harness's fake transport. The wrapper is
// what the bridge talks to; whatever it forwards is still observable through
// bridgeHarness.nextSent.
func withTransportWrapper(wrap func(*fakeDataIO) ppp.PPPDataIO) harnessOption {
	return func(c *harnessCfg) { c.wrap = wrap }
}

// limitedDataIO refuses frames above a ceiling the way the datagram transport
// does once quic-go reports a smaller budget than the negotiated MTU.
type limitedDataIO struct {
	*fakeDataIO
	limit   int
	sendErr error // when set, oversize frames fail with this instead
}

func (d *limitedDataIO) SendData(frame []byte) error {
	if len(frame) > d.limit {
		if d.sendErr != nil {
			return d.sendErr
		}
		return &ppp.FrameTooLargeError{FrameSize: len(frame), MaxSize: d.limit}
	}
	return d.fakeDataIO.SendData(frame)
}

func (d *limitedDataIO) MaxFrameSize() int { return d.limit }

// breakableDataIO starts healthy and can be made to fail the way a dead QUIC
// connection does: every send errors and the receive side reports the transport
// gone.
type breakableDataIO struct {
	*fakeDataIO
	mu      sync.Mutex
	sendErr error
	broken  chan struct{}
	once    sync.Once
}

func newBreakableDataIO(f *fakeDataIO) *breakableDataIO {
	return &breakableDataIO{fakeDataIO: f, broken: make(chan struct{})}
}

func (d *breakableDataIO) failSends(err error) {
	d.mu.Lock()
	d.sendErr = err
	d.mu.Unlock()
}

func (d *breakableDataIO) breakReceive() {
	d.once.Do(func() { close(d.broken) })
}

func (d *breakableDataIO) SendData(frame []byte) error {
	d.mu.Lock()
	err := d.sendErr
	d.mu.Unlock()
	if err != nil {
		return err
	}
	return d.fakeDataIO.SendData(frame)
}

func (d *breakableDataIO) ReceiveData() ([]byte, error) {
	select {
	case f := <-d.recv:
		return f, nil
	case <-d.broken:
		return nil, errTransportGone
	case <-d.closed:
		return nil, io.EOF
	}
}

var errTransportGone = errors.New("test: transport gone")

// assertNothingReachesChild fails if the bridge writes anything toward pppd
// within the grace period.
func (h *bridgeHarness) assertNothingReachesChild(t *testing.T, why string) {
	t.Helper()
	require.NoError(t, h.fromBridge.SetReadDeadline(time.Now().Add(200*time.Millisecond)))
	buf := make([]byte, 4096)
	n, err := h.fromBridge.Read(buf)
	assert.Zerof(t, n, "%s, but %d bytes were written to pppd: %x", why, n, buf[:n])
	var ne interface{ Timeout() bool }
	assert.Truef(t, errors.As(err, &ne) && ne.Timeout(),
		"%s: expected the child pipe to stay idle, got n=%d err=%v", why, n, err)
	// Clear the deadline so later reads in the same test are not affected.
	require.NoError(t, h.fromBridge.SetReadDeadline(time.Time{}))
}

// waitRunReturned waits for Bridge.Run to return and reports its error. The
// result is recorded rather than consumed, so the harness cleanup can wait on
// the same signal.
func (h *bridgeHarness) waitRunReturned(t *testing.T) error {
	t.Helper()
	select {
	case <-h.runDone:
		return h.runErrVal
	case <-time.After(testTimeout):
		t.Fatal("Bridge.Run did not return")
		return nil
	}
}

// requireRunStillGoing fails if Bridge.Run has already returned.
func (h *bridgeHarness) requireRunStillGoing(t *testing.T, why string) {
	t.Helper()
	select {
	case <-h.runDone:
		t.Fatalf("%s, but Bridge.Run returned: %v", why, h.runErrVal)
	case <-time.After(200 * time.Millisecond):
	}
}

// readFromChild returns the next raw PPP frame the bridge wrote toward pppd.
func (h *bridgeHarness) readFromChild(t *testing.T) []byte {
	t.Helper()
	require.NoError(t, h.fromBridge.SetReadDeadline(time.Now().Add(testTimeout)))
	buf := make([]byte, 8192)
	n, err := h.fromBridge.Read(buf)
	require.NoError(t, err)
	raw, err := DecodeHDLC(buf[:n])
	require.NoError(t, err, "bridge must emit a well-formed HDLC frame, got %x", buf[:n])
	return raw
}

// ---------------------------------------------------------------------------
// Probes never reach the child
// ---------------------------------------------------------------------------

// An inbound probe request is answered by the bridge itself. pppd must never see
// it: protocol 0x4001 is not something pppd understands, and a full-size frame of
// padding delivered as PPP would at best be rejected and at worst counted as a
// protocol error against the link.
func TestBridgeAnswersProbeRequestsWithoutInvolvingTheChild(t *testing.T) {
	tests := []struct {
		name string
		seq  uint32
		size int
	}{
		{"first probe of a session", 1, 1404},
		{"sequence zero", 0, 1200},
		{"a header-sized request", 42, mtuProbeHeaderLen},
		{"the sequence number at its ceiling", ^uint32(0), 1404},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newBridgeHarness(t)
			h.establish(t)

			h.data.recv <- buildMTUProbe(mtuProbeRequest, tt.seq, tt.size)

			reply := h.nextSent(t)
			kind, seq, ok := parseMTUProbe(reply)
			require.True(t, ok, "the bridge must answer with a probe frame, got %x", reply)
			assert.Equal(t, mtuProbeReply, kind)
			assert.Equal(t, tt.seq, seq, "the reply must carry the sequence it answers")

			// Small, but not a fixed small. The reply exists to say the big one
			// arrived, so its length is free -- and a constant 9 octets one round
			// trip behind a full-size frame is a pairing that survives any timing
			// jitter, which is why it is padded. What it must never do is grow
			// into something the transport could refuse: relay.run drops an
			// oversize reply silently and the far end scores the probe it was
			// answering as unanswered.
			assert.GreaterOrEqual(t, len(reply), mtuProbeHeaderLen)
			assert.LessOrEqual(t, len(reply), mtuProbeReplyPadMax,
				"the reply must stay far below anything the transport could refuse")

			h.assertNothingReachesChild(t, "a probe request is consumed by the bridge")
		})
	}
}

// The reply half of the exchange is bookkeeping only. Nothing goes out, nothing
// goes down to pppd.
func TestBridgeConsumesProbeRepliesSilently(t *testing.T) {
	h := newBridgeHarness(t)
	h.establish(t)

	h.data.recv <- buildMTUProbe(mtuProbeReply, 7, mtuProbeHeaderLen)

	h.assertNothingReachesChild(t, "a probe reply is bookkeeping, not traffic")
	select {
	case f := <-h.data.sent:
		t.Fatalf("a probe reply must not be answered, but %x went out", f)
	case <-time.After(200 * time.Millisecond):
	}
}

// Probe handling must not disturb the frames around it: real traffic arriving
// before and after a probe still reaches pppd, in order.
func TestBridgeKeepsForwardingAroundProbes(t *testing.T) {
	h := newBridgeHarness(t)
	h.establish(t)

	h.data.recv <- append([]byte(nil), frameIPv4...)
	assert.Equal(t, frameIPv4, h.readFromChild(t))

	h.data.recv <- buildMTUProbe(mtuProbeRequest, 3, 1404)
	reply := h.nextSent(t)
	_, seq, ok := parseMTUProbe(reply)
	require.True(t, ok)
	require.Equal(t, uint32(3), seq)

	h.data.recv <- buildMTUProbe(mtuProbeReply, 3, mtuProbeHeaderLen)

	h.data.recv <- append([]byte(nil), frameIPv6...)
	assert.Equal(t, frameIPv6, h.readFromChild(t),
		"traffic after a probe must still reach pppd")
}

// A frame that merely looks probe-adjacent is ordinary traffic and belongs to
// pppd. This is the false-positive half of the contract: eating one of these
// would silently drop a user's packet.
func TestBridgeForwardsFramesThatAreNotProbes(t *testing.T) {
	almost := [][]byte{
		{0xFF, 0x03, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // neighbouring private protocol
		{0xFF, 0x03, 0x40, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00}, // the other neighbour
		{0xFF, 0x03, 0x40, 0x01, 0x00, 0x00, 0x00, 0x00},       // one octet short of the header
		{0x40, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // right protocol, no FF 03
	}

	h := newBridgeHarness(t)
	h.establish(t)

	for i, f := range almost {
		h.data.recv <- append([]byte(nil), f...)
		assert.Equalf(t, f, h.readFromChild(t), "frame %d was swallowed as a probe", i)
	}
}

// ---------------------------------------------------------------------------
// relay.probeLoop
// ---------------------------------------------------------------------------

// The refactor gave the probe schedule real seams -- relay.ProbeInterval,
// ProbeGrace and ProbeFailures, plumbed through from Bridge and from the L2TP
// handler -- so a teardown no longer costs grace + failures*interval = ~73
// seconds of wall clock to observe. bridge_teardown_test.go and e2e_test.go
// drive the whole decision in milliseconds through those fields. What is left
// here is the loop's exit condition, which does not need them.

// The loop is a goroutine per session; it must not outlive the session it was
// started for, whether the session ends during the grace period or later.
func TestProbeLoopStopsWhenTheSessionEnds(t *testing.T) {
	tests := []struct {
		name       string
		closeAfter time.Duration
	}{
		{"session already over when the loop starts", 0},
		{"session ends during the grace period", 50 * time.Millisecond},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := &limitedDataIO{fakeDataIO: newFakeDataIO(), limit: 1404}
			defer data.Close()
			r := newRelay(data, nil, zap.NewNop(), nil)
			// A grace period far longer than the test, so a probe can only escape
			// if the loop ignored the session ending.
			r.ProbeGrace = time.Minute
			errCh := make(chan error, 2)

			returned := make(chan struct{})
			go func() {
				r.probeLoop(errCh)
				close(returned)
			}()

			time.AfterFunc(tt.closeAfter, func() { close(r.done) })

			select {
			case <-returned:
			case <-time.After(testTimeout):
				t.Fatal("probeLoop did not return after the session ended")
			}
			assert.Empty(t, errCh, "a session that ended on its own is not a narrowed path")
			select {
			case f := <-data.sent:
				t.Fatalf("no probe may be sent before the grace period elapses, got %x", f)
			default:
			}
		})
	}
}

// errPathNarrowed is a session-level failure, not a droppable frame. If it were
// ever mistaken for one the teardown would be swallowed by the relay's oversize
// branch and the black hole would persist.
//
// The two directions are both worth pinning: errPathNarrowed must not classify
// as FrameTooLarge, and it must survive the wrapping that any real error picks
// up on its way out of the probe loop.
func TestErrPathNarrowedIsASessionFailure(t *testing.T) {
	assert.False(t, ppp.IsFrameTooLarge(errPathNarrowed),
		"a narrowed path is a session to rebuild, not a packet to drop")
	assert.False(t, ppp.IsFrameTooLarge(fmt.Errorf("probe loop: %w", errPathNarrowed)),
		"wrapping must not turn it into a droppable frame either")
	assert.True(t, errors.Is(fmt.Errorf("probe loop: %w", errPathNarrowed), errPathNarrowed),
		"callers have to be able to recognise it through a wrap")

	// The converse: the error the relay *does* swallow must not be mistaken for a
	// session failure, or one oversized IP packet would cost a re-negotiation.
	tooLarge := &ppp.FrameTooLargeError{FrameSize: 1500, MaxSize: 1404}
	assert.True(t, ppp.IsFrameTooLarge(tooLarge))
	assert.False(t, errors.Is(tooLarge, errPathNarrowed))
}

// DELETED: TestBridgeSessionErrorTearsDownAndRedials. It killed the session by
// closing the control stream, which no longer has that effect -- the control
// stream is not part of the relay at all now, it only carries the handshake and
// the closing SessionReason, so closing it just means no reason arrives. The
// teardown paths it stood in for are covered directly:
// TestBridgeTransportFailureEndsTheSession below (a dead transport) and
// TestBridgeTearsDownWhenFullSizeProbesGoUnanswered in bridge_teardown_test.go
// (errPathNarrowed out of the probe loop).

// ---------------------------------------------------------------------------
// Oversize frames on the way to the transport
// ---------------------------------------------------------------------------

// A frame refused for being too large is a packet to drop. The link is fine:
// smaller frames still go through, and the session must survive -- tearing it
// down would turn one oversized IP packet into a full PPP re-negotiation.
func TestBridgeOversizeFramesAreDroppedNotFatal(t *testing.T) {
	const limit = 64
	h := newBridgeHarness(t, withTransportWrapper(func(f *fakeDataIO) ppp.PPPDataIO {
		return &limitedDataIO{fakeDataIO: f, limit: limit}
	}))
	h.establish(t)
	require.Zero(t, h.bridge.OversizeDropped())

	big := append([]byte{0xFF, 0x03, 0x00, 0x21}, bytes.Repeat([]byte{0xAB}, 200)...)

	// Interleave oversized frames with frames that fit. The relay's endpoint pump
	// is sequential, so once a small frame arrives every frame before it is
	// decided.
	for round := 1; round <= 3; round++ {
		h.pppdSends(t, big)
		h.pppdSends(t, frameIPv4)
		assert.Equalf(t, frameIPv4, h.nextSent(t),
			"round %d: a frame that fits must still get through after an oversized one", round)
		assert.Equalf(t, uint64(round), h.bridge.OversizeDropped(),
			"round %d: the oversized frame must be counted", round)
	}

	// The oversized frames themselves never reached the transport.
	select {
	case f := <-h.data.sent:
		t.Fatalf("an oversized frame was forwarded after all: %x", f)
	case <-time.After(200 * time.Millisecond):
	}

	// And the session is still up.
	h.requireRunStillGoing(t, "oversized frames must not end the session")

	// Traffic in the other direction is unaffected too.
	h.data.recv <- append([]byte(nil), frameIPv6...)
	assert.Equal(t, frameIPv6, h.readFromChild(t))
}

// The counter is what makes an over-large negotiated MTU visible at all, so it
// has to count every drop rather than just latching.
func TestBridgeOversizeDroppedCountsEveryDrop(t *testing.T) {
	const (
		limit = 64
		drops = 25
	)
	h := newBridgeHarness(t, withTransportWrapper(func(f *fakeDataIO) ppp.PPPDataIO {
		return &limitedDataIO{fakeDataIO: f, limit: limit}
	}))
	h.establish(t)

	big := append([]byte{0xFF, 0x03, 0x00, 0x21}, bytes.Repeat([]byte{0xCD}, 100)...)
	for i := 0; i < drops; i++ {
		h.pppdSends(t, big)
	}
	h.pppdSends(t, frameIPv4)
	require.Equal(t, frameIPv4, h.nextSent(t), "the small frame flushes the ones before it")

	assert.Equal(t, uint64(drops), h.bridge.OversizeDropped())
}

// A frame exactly at the ceiling fits; one octet more does not. The boundary is
// where a negotiated MTU that is one byte too large lives.
func TestBridgeOversizeBoundary(t *testing.T) {
	const limit = 128
	h := newBridgeHarness(t, withTransportWrapper(func(f *fakeDataIO) ppp.PPPDataIO {
		return &limitedDataIO{fakeDataIO: f, limit: limit}
	}))
	h.establish(t)

	atLimit := append([]byte{0xFF, 0x03, 0x00, 0x21}, bytes.Repeat([]byte{0x11}, limit-4)...)
	require.Len(t, atLimit, limit)
	h.pppdSends(t, atLimit)
	assert.Equal(t, atLimit, h.nextSent(t), "a frame of exactly the ceiling must be carried")
	assert.Zero(t, h.bridge.OversizeDropped())

	overLimit := append(append([]byte(nil), atLimit...), 0x22)
	h.pppdSends(t, overLimit)
	h.pppdSends(t, frameIPv4)
	require.Equal(t, frameIPv4, h.nextSent(t))
	assert.Equal(t, uint64(1), h.bridge.OversizeDropped(),
		"one octet over the ceiling is a drop")
}

// A send failure that is not "this frame did not fit" is a different thing
// entirely: it ends the session, and it must not be filed under the MTU counter.
//
// This is a deliberate change from the pre-refactor bridge, whose tx loop logged
// every send error and carried on. Only ppp.FrameTooLargeError means "the peer
// sent something bigger than this path carries"; anything else means the path
// itself is in trouble, and continuing to feed a transport that cannot write
// leaves a session that looks alive and moves nothing.
func TestBridgeGenericSendErrorEndsTheSessionAndIsNotCountedAsOversize(t *testing.T) {
	const limit = 64
	h := newBridgeHarness(t, withTransportWrapper(func(f *fakeDataIO) ppp.PPPDataIO {
		return &limitedDataIO{fakeDataIO: f, limit: limit, sendErr: errors.New("write: broken pipe")}
	}))
	h.establish(t)

	big := append([]byte{0xFF, 0x03, 0x00, 0x21}, bytes.Repeat([]byte{0xEF}, 200)...)
	h.pppdSends(t, big)

	h.waitRunReturned(t)
	assert.Zero(t, h.bridge.OversizeDropped(),
		"only ppp.FrameTooLargeError means the negotiated MTU is wrong")
}

// When the transport is gone the session ends, which is the difference between
// a dropped packet and a dead link. Either direction failing is enough: the
// relay's two pumps both report into the same error channel, and the first one
// to speak ends the run.
func TestBridgeTransportFailureEndsTheSession(t *testing.T) {
	tests := []struct {
		name  string
		fail  func(*breakableDataIO)
		nudge bool // whether a frame from pppd is needed to provoke the failure
	}{
		{"the send side fails", func(b *breakableDataIO) { b.failSends(errTransportGone) }, true},
		{"the receive side reports the transport gone", (*breakableDataIO).breakReceive, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var broken *breakableDataIO
			h := newBridgeHarness(t, withTransportWrapper(func(f *fakeDataIO) ppp.PPPDataIO {
				broken = newBreakableDataIO(f)
				return broken
			}))
			require.NotNil(t, broken)
			h.establish(t)

			tt.fail(broken)
			if tt.nudge {
				h.pppdSends(t, frameIPv4)
			}

			h.waitRunReturned(t)
			assert.Zero(t, h.bridge.OversizeDropped(),
				"a transport error is not an MTU problem")
		})
	}
}
