package ppp

import (
	"errors"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The datagram budget is whatever quic-go will currently accept in one DATAGRAM
// frame. On a loopback path quic-go starts from its initial packet size (which
// leaves 1243 octets of payload) and Path MTU discovery walks it up towards
// MaxPacketBufferSize (1452); the rungs measured here are 1243, 1329, 1372,
// 1393 and finally 1404. These bounds are deliberately loose: the point is that
// the number is a real per-packet ceiling and not a hard-coded constant that
// will drift with quic-go.
const (
	minPlausibleBudget = 1000
	maxPlausibleBudget = 1500
)

func datagramConfig() *quic.Config {
	return &quic.Config{EnableDatagrams: true}
}

// TestDatagramBudgetReportsAPlausibleCeilingOnALiveConnection checks both ends
// of a real connection, because client and server run Path MTU discovery
// independently and the handshake sizes the PPP link against both.
func TestDatagramBudgetReportsAPlausibleCeilingOnALiveConnection(t *testing.T) {
	p := newQUICPair(t, datagramConfig())

	for _, tt := range []struct {
		name string
		conn *quic.Conn
	}{
		{"client side", p.client},
		{"server side", p.server},
	} {
		t.Run(tt.name, func(t *testing.T) {
			budget := DatagramBudget(tt.conn)
			assert.Greater(t, budget, minPlausibleBudget,
				"a live loopback connection should carry more than %d octets per datagram", minPlausibleBudget)
			assert.Less(t, budget, maxPlausibleBudget,
				"a QUIC datagram payload can never reach the %d-octet Ethernet MTU", maxPlausibleBudget)

			// A frame of exactly the reported size must be accepted: that is what
			// makes the number a measurement rather than a guess.
			assert.NoError(t, tt.conn.SendDatagram(make([]byte, budget)))

			// And one octet more must not fit -- with the caveat that this is a
			// live connection whose Path MTU discovery is still searching upward
			// between these two calls. If the ceiling rose in between, the larger
			// frame is legitimately accepted, and what has to hold is that the
			// ceiling really did rise. Asserting a fixed equality here instead
			// makes the test fail whenever a probe lands mid-assertion.
			err := tt.conn.SendDatagram(make([]byte, budget+1))
			var tooLarge *quic.DatagramTooLargeError
			if !errors.As(err, &tooLarge) {
				require.NoError(t, err, "an over-budget datagram failed for some other reason")
				assert.Greater(t, DatagramBudget(tt.conn), budget,
					"a datagram above the budget was accepted without the ceiling moving, "+
						"so the budget was not a ceiling")
				return
			}
			assert.GreaterOrEqual(t, tooLarge.MaxDatagramPayloadSize, int64(budget),
				"quic-go's own limit must never be below what DatagramBudget reported")
		})
	}
}

// TestDatagramBudgetIsZeroWithoutDatagramSupport pins the "unknown" answer.
// SendDatagram fails with a plain error rather than DatagramTooLargeError when
// datagrams are off, and the budget has to read as 0 so EffectiveMTU treats the
// side as having reported nothing.
func TestDatagramBudgetIsZeroWithoutDatagramSupport(t *testing.T) {
	tests := []struct {
		name string
		conf *quic.Config
	}{
		{"default config", nil},
		{"datagrams explicitly disabled", &quic.Config{EnableDatagrams: false}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newQUICPair(t, tt.conf)
			assert.Equal(t, 0, DatagramBudget(p.client))
			assert.Equal(t, 0, DatagramBudget(p.server))
		})
	}
}

// TestStableDatagramBudgetSettlesAndReturnsBeforeItsTimeout is the property
// that keeps the handshake cheap: once Path MTU discovery stops moving,
// StableDatagramBudget must come back after roughly the settle window, not
// after the whole timeout.
func TestStableDatagramBudgetSettlesAndReturnsBeforeItsTimeout(t *testing.T) {
	const (
		settle  = 200 * time.Millisecond
		timeout = 5 * time.Second
	)
	p := newQUICPair(t, datagramConfig())

	// First call absorbs the discovery ramp.
	initial := DatagramBudget(p.client)
	settled := StableDatagramBudget(p.client, settle, timeout)
	assert.GreaterOrEqual(t, settled, initial, "the budget only ever grows during discovery")
	assert.Greater(t, settled, minPlausibleBudget)
	assert.Less(t, settled, maxPlausibleBudget)

	// Second call runs against an already-stable value, so it must return
	// promptly instead of burning the timeout.
	start := time.Now()
	again := StableDatagramBudget(p.client, settle, timeout)
	elapsed := time.Since(start)

	assert.GreaterOrEqual(t, again, settled, "the budget only ever grows")
	assert.GreaterOrEqual(t, elapsed, settle, "it still has to observe the value holding still")

	// The promptness claim is about a budget that has stopped moving, so it can
	// only be made once one has. Settling is a heuristic -- a scheduling stall
	// long enough to span the settle window makes a still-climbing budget look
	// still -- and on a loaded machine that is exactly what happens. Taking
	// longer while the value is genuinely still rising is the correct behaviour,
	// not the regression this is looking for.
	if again == settled {
		assert.Less(t, elapsed, timeout/2,
			"StableDatagramBudget burned %s of its %s timeout on an already-settled budget",
			elapsed, timeout)
	} else {
		t.Logf("discovery was still climbing (%d -> %d), so the promptness check does not apply",
			settled, again)
	}
}

// TestStableDatagramBudgetReturnsZeroPromptlyWithoutDatagramSupport: 0 is
// stable from the first poll, so a connection that will never carry datagrams
// must not stall the handshake for the full timeout either.
func TestStableDatagramBudgetReturnsZeroPromptlyWithoutDatagramSupport(t *testing.T) {
	const (
		settle  = 100 * time.Millisecond
		timeout = 3 * time.Second
	)
	p := newQUICPair(t, nil)

	start := time.Now()
	budget := StableDatagramBudget(p.client, settle, timeout)
	elapsed := time.Since(start)

	assert.Equal(t, 0, budget)
	assert.Less(t, elapsed, timeout/2,
		"StableDatagramBudget took %s to conclude that datagrams are unavailable", elapsed)
}

// StableDatagramBudget documents that it "returns the last observed value even
// if it never settles within timeout". A settle window longer than the timeout
// makes that the only reachable exit, so this pins the give-up path rather than
// the converged one: it must still hand back a usable figure, promptly, instead
// of 0 or a block until the settle window elapses.
func TestStableDatagramBudgetReturnsTheLastValueWhenItCannotSettle(t *testing.T) {
	const (
		settle  = 10 * time.Second // deliberately unreachable
		timeout = 150 * time.Millisecond
	)
	p := newQUICPair(t, datagramConfig())

	start := time.Now()
	budget := StableDatagramBudget(p.client, settle, timeout)
	elapsed := time.Since(start)

	assert.Less(t, elapsed, settle/2,
		"it must give up at its timeout (%s), not wait out the settle window", timeout)
	assert.Greater(t, budget, minPlausibleBudget,
		"giving up must still report the last measurement, not 0")
	assert.Less(t, budget, maxPlausibleBudget)

	// And what it reported is a figure the connection really accepts.
	assert.NoError(t, p.client.SendDatagram(make([]byte, budget)))
}

// TestPreDiscoveryBudgetMatchesWhatDiscoveryStartsFrom pins the arithmetic that
// preDiscoveryBudget mirrors out of quic-go.
//
// quic-go's estimateMaxPayloadSize is unexported, so the 37 octets it subtracts
// are copied rather than called. A quic-go bump that changes them would leave
// preDiscoveryBudget just beside the real floor -- and "just beside" is the one
// answer that breaks StableDatagramBudget quietly, because a floor one octet low
// never matches and the wait it guards stops happening.
//
// Path MTU discovery is off here on purpose: with it on, the budget starts at the
// floor and leaves within a few round trips, which on loopback is too soon to
// sample reliably. Off, the floor is the only value the connection will ever
// report, and the comparison is exact instead of racing.
func TestPreDiscoveryBudgetMatchesWhatDiscoveryStartsFrom(t *testing.T) {
	for _, tt := range []struct {
		name          string
		initialPacket uint16
	}{
		{"quic-go's default initial packet size", 0},
		{"a connection configured to start smaller", 1300},
	} {
		t.Run(tt.name, func(t *testing.T) {
			conf := &quic.Config{
				EnableDatagrams:         true,
				DisablePathMTUDiscovery: true,
				InitialPacketSize:       tt.initialPacket,
			}
			p := newQUICPair(t, conf)

			floor := preDiscoveryBudget(p.client)
			require.Greater(t, floor, 0, "the floor must be determinable from the connection")
			assert.Equal(t, floor, DatagramBudget(p.client),
				"with discovery disabled the budget can only ever be the floor, "+
					"so preDiscoveryBudget's %d-octet overhead is what quic-go really subtracts",
				quicPayloadEstimateOverhead)
		})
	}
}

// TestStableDatagramBudgetWaitsOutDiscoveryOnALatentPath checks the whole thing
// end to end on a path with a real round trip: given the arguments the server
// actually passes, a link on a latent path must come up sized to something
// discovery measured rather than to the value it started from.
//
// This is a confirmation, not the regression guard -- that is
// TestStableDatagramBudgetReportsTheFloorOnAPathThatCannotExceedIt. The bug this
// came from was a race and cannot be pinned by real timing: the first rung of
// the ladder lands at 6.1 smoothed round trips and the old settle window closed
// at 6.0, so the whole defect lived in a tenth of a round trip, and which side a
// run fell on was decided by where the 20ms poll grid happened to tick. Against
// the old code this test fails roughly one run in three at 250ms and two in five
// at 120ms -- enough to have caught it eventually, nowhere near enough to be the
// thing relied on.
//
// What it does pin deterministically is the other half of the fix: that the
// extended timeout is long enough for a latent path to reach a measured value at
// all. The assertion is only that the budget left the floor, which the first rung
// achieves at about a fifth of the available time, so a loaded machine makes this
// slower rather than flaky.
func TestStableDatagramBudgetWaitsOutDiscoveryOnALatentPath(t *testing.T) {
	// Far enough past the 400ms settle floor that every window in play is derived
	// from the round trip rather than clamped to a constant, which is the regime
	// the bug lived in, and close to a real intercontinental path. Kept no higher
	// than that because the ladder costs 21 round trips and this test waits out
	// all of them.
	const rtt = 150 * time.Millisecond
	p := newDelayedQUICPair(t, datagramConfig(), rtt)

	floor := preDiscoveryBudget(p.server)
	require.Greater(t, floor, 0)
	require.Equal(t, floor, DatagramBudget(p.server),
		"discovery should not have moved yet, so this measures from the same "+
			"starting point the server does at the PPP handshake")

	// Exactly the arguments core/server passes when it sizes a PPP session.
	start := time.Now()
	budget := StableDatagramBudget(p.server, 400*time.Millisecond, 3*time.Second)
	elapsed := time.Since(start)

	assert.Greater(t, budget, floor,
		"returned the %d-octet pre-discovery floor after %s: that is the value the "+
			"discoverer was initialised with, not one the path was measured at",
		floor, elapsed)
	assert.Less(t, budget, maxPlausibleBudget)
	assert.NoError(t, p.server.SendDatagram(make([]byte, budget)),
		"whatever it reports must be a size the connection really accepts")
}

// TestStableDatagramBudgetReportsTheFloorOnAPathThatCannotExceedIt is the
// regression guard, and it is deterministic where a timing test cannot be.
//
// It states the rule the old code broke, directly and without a race: a budget
// sitting on its pre-discovery floor is not a measurement, so it must never be
// returned as settled -- only as a deadline expiring. With discovery disabled the
// budget is pinned to the floor for the life of the connection, which is both how
// a genuinely narrow path looks and how a path looks before discovery has run.
// The old code broke out after the settle window on either; this asserts it takes
// the full timeout, which is what makes returning the floor evidence rather than
// an accident of when the observation started.
//
// The second half matters as much as the first. A path that really cannot exceed
// the floor has to be reported as such: refusing to settle on the floor must not
// become refusing to return it.
func TestStableDatagramBudgetReportsTheFloorOnAPathThatCannotExceedIt(t *testing.T) {
	const timeout = 400 * time.Millisecond
	p := newQUICPair(t, &quic.Config{EnableDatagrams: true, DisablePathMTUDiscovery: true})

	floor := preDiscoveryBudget(p.client)
	require.Greater(t, floor, 0)

	start := time.Now()
	budget := StableDatagramBudget(p.client, 100*time.Millisecond, timeout)
	elapsed := time.Since(start)

	assert.Equal(t, floor, budget,
		"a path that cannot carry more than the floor must still be reported as such")
	assert.GreaterOrEqual(t, elapsed, timeout,
		"the floor is only an answer once enough time has passed for probes to have "+
			"been sent and lost, so it must be reached at the deadline and not before")
	assert.Less(t, elapsed, 3*timeout, "and it must not overrun that deadline either")
}
