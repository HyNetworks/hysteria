package pppbridge

import (
	"bytes"
	"testing"
	"time"

	"github.com/apernet/hysteria/core/v2/ppp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// withCounters attaches a caller-owned counter set, the way the OpenWrt client
// does so it can publish what this link carried.
func withCounters(c *Counters) harnessOption {
	return func(cfg *harnessCfg) { cfg.counters = c }
}

// establishTx is what bringing a session up leaves on the counters before a test
// sends anything of its own: harness.establish pushes the frame that triggers the
// dial, and Run carries it onto the transport and counts it.
var establishTx = Snapshot{TxBytes: uint64(len(frameLCPConfReq)), TxFrames: 1}

// awaitCounters waits for the counters to reach a reading, and fails with the
// last one it saw if they never do.
//
// Polling rather than reading once, and this is not belt-and-braces. The TX tap
// runs *after* r.data.SendData returns, while nextSent observes the frame from
// *inside* SendData -- the fake's channel send is what wakes the test goroutine.
// So the test can be running its assertion, on another P, before the relay
// goroutine has reached the increment. Both sides are atomics, so the race
// detector cannot see it, and it surfaces only as an intermittent failure in this
// file on a change that never touched this package.
//
// The RX assertions do not need this -- addRx precedes ep.SendPPP, so a frame
// arriving out of the child orders the increment before it -- but they go through
// here anyway, because a reader cannot tell which assertions are safe by looking
// and the next person to add one should not have to know.
func awaitCounters(t *testing.T, c *Counters, want Snapshot) {
	t.Helper()

	var got Snapshot
	deadline := time.Now().Add(testTimeout)
	for time.Now().Before(deadline) {
		got = c.Read()
		if got == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("counters never reached %+v; last reading was %+v", want, got)
}

// The plain case: what goes each way is counted each way, in bytes and frames.
func TestCountersCountBothDirections(t *testing.T) {
	c := new(Counters)
	h := newBridgeHarness(t, withCounters(c))
	h.establish(t)

	h.pppdSends(t, frameIPv4)
	require.Equal(t, frameIPv4, h.nextSent(t))

	h.data.recv <- append([]byte(nil), frameIPv6...)
	require.Equal(t, frameIPv6, h.readFromChild(t))

	awaitCounters(t, c, Snapshot{
		// What pppd sent is TX -- the frame above, and the one establish pushed.
		TxBytes:  establishTx.TxBytes + uint64(len(frameIPv4)),
		TxFrames: establishTx.TxFrames + 1,
		// What the server sent is RX.
		RxBytes:  uint64(len(frameIPv6)),
		RxFrames: 1,
	})
}

// The relay's own MTU probes must not appear as the server's traffic.
//
// This is the difference between an idle link reading zero and an idle link
// reading a steady trickle nobody sent. The probe is a full-size frame, so at a
// 1400-byte MTU it would dwarf the LCP echoes around it and read as real load.
func TestCountersExcludeMTUProbes(t *testing.T) {
	c := new(Counters)
	h := newBridgeHarness(t, withCounters(c))
	h.establish(t)

	// A probe request from the far end: the relay answers it and must not file
	// either half under this link's traffic. Nothing is asserted yet -- the pump
	// runs on its own goroutine, so a zero here would pass for the wrong reason.
	// The frame round-tripped below is what orders this test.
	h.data.recv <- buildMTUProbe(mtuProbeRequest, 1, 64)

	// The reply the relay generates goes out on the transport; drain it so the
	// assertion below is about the counter and not about ordering.
	sent := h.nextSent(t)
	_, _, isProbe := parseMTUProbe(sent)
	require.True(t, isProbe, "the relay answers a probe with a probe")

	h.data.recv <- buildMTUProbe(mtuProbeReply, 1, 64)

	// A real frame afterwards, so we know the pump is still running and the
	// zeroes above are not just "nothing has been processed yet".
	h.data.recv <- append([]byte(nil), frameIPv4...)
	require.Equal(t, frameIPv4, h.readFromChild(t))

	// TX is the establish frame and nothing else: the probe reply this relay
	// generated went out on the transport between them and was not counted.
	awaitCounters(t, c, Snapshot{
		RxBytes:  uint64(len(frameIPv4)),
		RxFrames: 1,
		TxBytes:  establishTx.TxBytes,
		TxFrames: establishTx.TxFrames,
	})
}

// A frame the transport refused for being too large was not carried, and must
// not be counted as though it had been.
//
// Getting this backwards would make a link look busiest exactly when its path
// had narrowed and it had stopped delivering anything -- the one moment the
// figure is being read to diagnose something.
func TestCountersExcludeOversizeDrops(t *testing.T) {
	const limit = 64

	c := new(Counters)
	h := newBridgeHarness(t,
		withCounters(c),
		withTransportWrapper(func(f *fakeDataIO) ppp.PPPDataIO {
			return &limitedDataIO{fakeDataIO: f, limit: limit}
		}))
	h.establish(t)

	big := append([]byte{0xFF, 0x03, 0x00, 0x21}, bytes.Repeat([]byte{0xCD}, 100)...)
	h.pppdSends(t, big)
	h.pppdSends(t, frameIPv4)
	require.Equal(t, frameIPv4, h.nextSent(t), "the small frame flushes the one before it")

	// Only the frames that fit were carried; the oversize one is absent from both
	// the byte and the frame count.
	awaitCounters(t, c, Snapshot{
		TxBytes:  establishTx.TxBytes + uint64(len(frameIPv4)),
		TxFrames: establishTx.TxFrames + 1,
	})
	assert.Equal(t, uint64(1), h.bridge.OversizeDropped(), "and the drop is still counted as a drop")
}

// A bridge with no counters attached must behave exactly as it did before they
// existed. Every server-side relay and every test but this file's runs that way.
func TestCountersOptionalCostsNothing(t *testing.T) {
	h := newBridgeHarness(t)
	h.establish(t)

	h.pppdSends(t, frameIPv4)
	assert.Equal(t, frameIPv4, h.nextSent(t))

	h.data.recv <- append([]byte(nil), frameIPv6...)
	assert.Equal(t, frameIPv6, h.readFromChild(t))
}

// Counters outlive the Bridge that fills them.
//
// Spawn mode calls Run again after every link failure, and the OpenWrt status
// page reads one figure per server across all of it. A counter that reset with
// each rebuild would report a link that had just reconnected as having carried
// nothing, which is indistinguishable from the link that really is idle.
func TestCountersSurviveABridgeRebuild(t *testing.T) {
	c := new(Counters)

	first := newBridgeHarness(t, withCounters(c))
	first.establish(t)
	first.pppdSends(t, frameIPv4)
	require.Equal(t, frameIPv4, first.nextSent(t))
	awaitCounters(t, c, Snapshot{
		TxBytes:  establishTx.TxBytes + uint64(len(frameIPv4)),
		TxFrames: establishTx.TxFrames + 1,
	})

	first.cancel()
	_ = first.waitRunReturned(t)

	second := newBridgeHarness(t, withCounters(c))
	second.establish(t)
	second.pppdSends(t, frameIPv6)
	require.Equal(t, frameIPv6, second.nextSent(t))

	// The second bridge adds to the first bridge's total rather than restarting
	// it: two sessions, each of an establish frame and one frame of traffic.
	awaitCounters(t, c, Snapshot{
		TxBytes:  2*establishTx.TxBytes + uint64(len(frameIPv4)+len(frameIPv6)),
		TxFrames: 2*establishTx.TxFrames + 2,
	})
}

// Read on a nil receiver is zero rather than a panic: the publisher reads the
// counters on a schedule and must not be the thing that kills a working link.
func TestCountersNilReadIsZero(t *testing.T) {
	var c *Counters
	assert.Equal(t, Snapshot{}, c.Read())
}

// Frames counted under concurrent pumps add up exactly. The two directions run
// on separate goroutines against the same struct, which is the whole reason
// these are atomics.
func TestCountersConcurrentAddsAreExact(t *testing.T) {
	const each = 500

	c := new(Counters)
	done := make(chan struct{}, 2)

	go func() {
		for i := 0; i < each; i++ {
			c.addRx(10)
		}
		done <- struct{}{}
	}()
	go func() {
		for i := 0; i < each; i++ {
			c.addTx(7)
		}
		done <- struct{}{}
	}()

	for i := 0; i < 2; i++ {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("counter goroutines did not finish")
		}
	}

	s := c.Read()
	assert.Equal(t, uint64(each*10), s.RxBytes)
	assert.Equal(t, uint64(each), s.RxFrames)
	assert.Equal(t, uint64(each*7), s.TxBytes)
	assert.Equal(t, uint64(each), s.TxFrames)
}
