package pppbridge

import (
	"context"
	"errors"
	"io"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apernet/hysteria/core/v2/ppp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// A transport with a datagram-shaped ceiling, so mtuProbeWorthwhile says yes and
// the probe loop starts. answer controls whether probe requests get a reply.
type probeTransport struct {
	*fakeDataIO
	ceiling int
	answer  bool
}

func (p *probeTransport) MaxFrameSize() int { return p.ceiling }

func (p *probeTransport) SendData(frame []byte) error {
	if err := p.fakeDataIO.SendData(frame); err != nil {
		return err
	}
	if kind, seq, ok := parseMTUProbe(frame); ok && kind == mtuProbeRequest && p.answer {
		select {
		case p.fakeDataIO.recv <- buildMTUProbe(mtuProbeReply, seq, mtuProbeHeaderLen):
		default:
		}
	}
	return nil
}

func withProbeTransport(ceiling int, answer bool) harnessOption {
	return withTransportWrapper(func(f *fakeDataIO) ppp.PPPDataIO {
		return &probeTransport{fakeDataIO: f, ceiling: ceiling, answer: answer}
	})
}

// A path that stops carrying full-size frames is invisible to everything else in
// the stack: quic-go never lowers its MTU estimate, and LCP Echo is small enough
// to keep getting through. The probe loop is the only thing that notices, and
// tearing the session down is what lets a fresh connection re-discover the
// smaller path. This is the most consequential decision in the feature.
func TestBridgeTearsDownWhenFullSizeProbesGoUnanswered(t *testing.T) {
	h := newBridgeHarness(t,
		withProbeTransport(1400, false),
		withProbeTimings(40*time.Millisecond, 10*time.Millisecond, 2))
	h.establish(t)

	// The teardown decision is only observable in the log, because Run discards
	// what it decided: it would have mapped errPathNarrowed to ReasonPathNarrowed
	// and returned a *LinkDownError, but it returns nil instead. See
	// TestBridgeRunSwallowsTheSessionReasonInsteadOfReturningLinkDownError, and
	// TestBlackHoledProbesEndTheSessionEndToEnd for the same decision driven
	// through a whole session.
	h.awaitLogged(t, "path no longer carries the negotiated MTU, tearing down the session "+
		"so it can be rebuilt at the smaller size", 1)

	// The session really is over, and the caller is told why: this is the one
	// reason that means "rebuild at a smaller size" rather than "retry as-is".
	var linkDown *LinkDownError
	err := h.waitRunReturned(t)
	require.ErrorAs(t, err, &linkDown)
	assert.Equal(t, ReasonPathNarrowed, linkDown.Reason.Code)
	assert.False(t, linkDown.Reason.Code.Permanent(),
		"a narrowed path is worth rebuilding into, not a hard stop")
}

// When the MTU was not this process's to choose, the same evidence must not end
// the session. That is nospawn: pppd is the parent, its MRU came from its own
// configuration, and a rebuilt session would negotiate the identical value -- so
// tearing down would fail again, tear down again, and go on doing so for as long
// as the path stayed narrow. The operator set the number and owns the outcome;
// what is owed them is a clear statement of it, not an interface that flaps.
func TestBridgeReportsRatherThanRebuildsWhenTheMTUIsNotItsToChoose(t *testing.T) {
	h := newBridgeHarness(t,
		withFixedMTU(),
		withProbeTransport(1400, false),
		withProbeTimings(40*time.Millisecond, 10*time.Millisecond, 2))
	h.establish(t)

	h.awaitLogged(t, "path no longer carries the configured MTU; full-size packets "+
		"are being lost. Lower the mtu option for this interface", 1)

	// Said, and then carried on: the link still works for everything that fits,
	// which is the whole point of not tearing it down.
	h.requireRunStillGoing(t, "a narrowed path must not end a session whose MTU is fixed")
	h.pppdSends(t, frameIPv4)
	assert.Equal(t, frameIPv4, h.nextNonProbeSent(t))
}

// It keeps saying so, rather than latching once and going quiet -- and it stays
// able to notice the path widening again, since an answered probe resets the
// count.
func TestFixedMTUNarrowingIsReportedRepeatedly(t *testing.T) {
	h := newBridgeHarness(t,
		withFixedMTU(),
		withProbeTransport(1400, false),
		withProbeTimings(30*time.Millisecond, 8*time.Millisecond, 1))
	h.establish(t)

	h.awaitLogged(t, "path no longer carries the configured MTU; full-size packets "+
		"are being lost. Lower the mtu option for this interface", 3)
	h.requireRunStillGoing(t, "repeated reports must still not end the session")
}

// The mirror image: a path that still carries full-size frames must not be torn
// down, however long the session runs.
func TestBridgeKeepsRunningWhileProbesAreAnswered(t *testing.T) {
	h := newBridgeHarness(t,
		withProbeTransport(1400, true),
		withProbeTimings(20*time.Millisecond, 5*time.Millisecond, 2))
	h.establish(t)

	// Long enough for many probe rounds to come and go.
	time.Sleep(500 * time.Millisecond)
	h.requireRunStillGoing(t, "probes were answered")

	// And it is still carrying traffic.
	h.pppdSends(t, frameIPv4)
	assert.Equal(t, frameIPv4, h.nextNonProbeSent(t))
}

// Probes are sized to the transport's current ceiling, since a smaller probe
// would not test the size that actually matters.
func TestBridgeProbesAtTheTransportCeiling(t *testing.T) {
	const ceiling = 1234
	h := newBridgeHarness(t,
		withProbeTransport(ceiling, true),
		withProbeTimings(30*time.Millisecond, 5*time.Millisecond, 3))
	h.establish(t)

	deadline := time.After(3 * time.Second)
	for {
		select {
		case frame := <-h.data.sent:
			if _, _, ok := parseMTUProbe(frame); ok {
				assert.Len(t, frame, ceiling, "probe must be padded to the ceiling")
				return
			}
		case <-deadline:
			t.Fatal("no MTU probe was ever sent")
		}
	}
}

// A transport with no per-frame ceiling worth worrying about -- a reliable
// stream -- must not be probed at all.
func TestBridgeDoesNotProbeStreamShapedTransports(t *testing.T) {
	h := newBridgeHarness(t,
		withProbeTransport(65535, false),
		withProbeTimings(20*time.Millisecond, 5*time.Millisecond, 2))
	h.establish(t)

	deadline := time.After(500 * time.Millisecond)
	for {
		select {
		case frame := <-h.data.sent:
			_, _, ok := parseMTUProbe(frame)
			require.False(t, ok, "a stream-shaped transport must never be probed")
		case <-h.runDone:
			t.Fatalf("session ended unexpectedly: %v", h.runErrVal)
		case <-deadline:
			return
		}
	}
}

// The link model: losing the Hysteria2 connection ends the PPP session, and Run
// returns rather than quietly re-dialling underneath a live pppd. Carrying PPP
// state across a reconnect would leave the client holding an address the server
// released the moment the connection dropped.
func TestBridgeReturnsWhenTheLinkDropsRatherThanRedialling(t *testing.T) {
	h := newBridgeHarness(t)
	h.establish(t)

	// Kill the transport out from under the session, as a dead QUIC connection
	// would: the receive side errors and the session ends.
	h.data.Close()

	h.waitRunReturned(t)

	// Exactly one dial happened: no attempt was made to rebuild underneath pppd.
	assert.Zero(t, h.logs.FilterMessage("session lost, proactively re-dialing").Len(),
		"the bridge must not re-dial under a live child")

	// The child is released too: Run's cleanup closes the pipe, which is what
	// gives a real pppd its SIGHUP instead of leaving it attached to a dead link.
	_, err := h.toBridge.Write(EncodeHDLC(frameIPv4))
	assert.Error(t, err, "the bridge must have closed its side of the child pipe")
}

// DEFECT (bridge.go:154-175, 219-225): Run classifies every ended session as
// "the child went first" and returns nil, so *LinkDownError is unreachable and
// the SessionReason the server sent is discarded -- along with the "PPP link
// down" log line that would have reported it.
//
// childDone is closed by the goroutine that reads the FIRST frame out of pppd,
// immediately after handing that frame over -- not when the child exits. By the
// time the relay returns it is therefore always closed, so the
//
//	select { case <-childDone: return nil; default: }
//
// guard after the relay always takes the first branch and returns before the
// reason is ever consulted.
//
// The cost is the whole point of reason.go: the caller cannot distinguish a
// refused credential from a flapping uplink, so ReasonCode.Permanent() never
// reaches anyone and netifd retries a password that can never work. The fix is
// to close childDone when the child actually goes away -- keep reading in that
// goroutine, or take the signal from waitFn -- not when its first frame lands.
//
// Regression test. Run used to close childDone as soon as pppd's first frame
// arrived rather than when pppd exited, so the "did the child go first?" check
// after the relay was always true and Run returned nil -- the reason the server
// had just written was read and thrown away, and *LinkDownError never escaped.
// Which side failed is now decided by relayError.fromEndpoint instead.
func TestBridgeReturnsLinkDownErrorCarryingTheServersReason(t *testing.T) {
	h := newBridgeHarness(t)
	h.establish(t)

	// The server's side of the bargain, verbatim from L2TPPPPHandler.rejectAuth.
	want := SessionReason{Code: ReasonAuthFailed, Result: 2, Error: 6, Message: "bad password"}
	writeSessionReason(h.control, want)
	require.True(t, want.Code.Permanent(), "the reason carried is a permanent one")

	// Kill the transport, as a dead QUIC connection would.
	h.data.Close()
	err := h.waitRunReturned(t)

	var linkDown *LinkDownError
	require.ErrorAs(t, err, &linkDown, "a lost link must surface as *LinkDownError")
	require.ErrorIs(t, err, errLinkDown)
	assert.Equal(t, want, linkDown.Reason,
		"the reason must reach the caller intact, result and message included")
	assert.True(t, linkDown.Reason.Code.Permanent(),
		"which is what stops netifd retrying a credential that cannot work")
}

// The dial retry loop must survive a transient failure. It used to die on its
// first retry, because the same childDone defect meant the backoff select saw an
// already-closed channel and reported a live child as having exited.
func TestBridgeRetriesATransientDialFailureAgainstALiveChild(t *testing.T) {
	childR, testW, err := os.Pipe()
	require.NoError(t, err)
	defer testW.Close()
	testR, childW, err := os.Pipe()
	require.NoError(t, err)
	defer testR.Close()

	b := &Bridge{NoSpawn: true, Logger: zap.NewNop(), In: childR, Out: childW}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var attempts atomic.Int32
	dialFn := func() (io.ReadWriteCloser, ppp.PPPDataIO, func(), error) {
		if attempts.Add(1) >= 2 {
			cancel() // stop the loop once we have proved it came back round
		}
		return nil, nil, nil, errors.New("connection refused")
	}

	runErr := make(chan error, 1)
	go func() { runErr <- b.Run(ctx, dialFn) }()

	// pppd's first frame: the link is not up, nothing is negotiated, and the child
	// is very much still there.
	_, err = testW.Write(EncodeHDLC(frameLCPConfReq))
	require.NoError(t, err)

	select {
	case err := <-runErr:
		require.Error(t, err)
		assert.NotContains(t, err.Error(), "child exited",
			"a live child must not be reported as having exited")
	case <-time.After(5 * time.Second):
		t.Fatal("Bridge.Run did not return")
	}

	assert.GreaterOrEqual(t, attempts.Load(), int32(2),
		"the backoff must actually wait and retry")
}

// A PPP-layer event is not a link event. Terminate-Request is just another frame
// to the bridge, so it reaches the peer and leaves the connection alone.
func TestBridgePPPTerminateDoesNotDropTheLink(t *testing.T) {
	h := newBridgeHarness(t)
	h.establish(t)

	// LCP Terminate-Request.
	terminate := []byte{0xFF, 0x03, 0xC0, 0x21, 0x05, 0x02, 0x00, 0x04}
	h.pppdSends(t, terminate)
	assert.Equal(t, terminate, h.nextNonProbeSent(t), "terminate is relayed like any frame")

	h.requireRunStillGoing(t, "PPP terminate is not a link event")

	// Still carrying traffic afterwards.
	h.pppdSends(t, frameIPv4)
	assert.Equal(t, frameIPv4, h.nextNonProbeSent(t))
}

// A bridge that does not read reasons must not wait for one.
//
// Only the client listens on the control stream; the server writes there and
// never reads. Run used to wait out its one-second grace regardless, on a
// channel nothing would ever send to -- so every server-side session sat for a
// second after its link dropped before Run returned, and only then did
// ServerPPPHandler release the client's IP and reap its pppd. On a server
// cycling sessions that is a second of held address per teardown, for nothing.
func TestBridgeThatDoesNotReadReasonsReturnsImmediately(t *testing.T) {
	h := newBridgeHarness(t, withoutReasonReader())
	h.establish(t)

	start := time.Now()
	h.data.Close() // the transport dies, as a dropped QUIC connection would
	err := h.waitRunReturned(t)
	elapsed := time.Since(start)

	// It still reports the link loss -- promptness must not cost the answer.
	var linkDown *LinkDownError
	require.ErrorAs(t, err, &linkDown)
	assert.Equal(t, ReasonLinkDown, linkDown.Reason.Code)

	assert.Less(t, elapsed, 500*time.Millisecond,
		"a bridge with no reason reader waited %s for a reason that cannot arrive", elapsed)
}

// And a bridge that does read them still waits, because the reason is worth the
// wait: it is what tells a refused credential from a flapping uplink.
func TestBridgeThatReadsReasonsStillWaitsForOne(t *testing.T) {
	h := newBridgeHarness(t)
	h.establish(t)

	want := SessionReason{Code: ReasonAuthFailed, Result: 2, Error: 6, Message: "bad password"}
	go func() {
		// Arrives after the drop, which is the case the grace period exists for.
		time.Sleep(80 * time.Millisecond)
		writeSessionReason(h.control, want)
	}()

	h.data.Close()
	err := h.waitRunReturned(t)

	var linkDown *LinkDownError
	require.ErrorAs(t, err, &linkDown)
	assert.Equal(t, want, linkDown.Reason,
		"a reason that arrives inside the grace period must still be picked up")
}
