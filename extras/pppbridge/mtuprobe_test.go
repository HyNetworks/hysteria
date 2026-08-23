package pppbridge

import (
	"encoding/binary"
	"math"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/apernet/hysteria/core/v2/ppp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// Unit coverage for mtuprobe.go: the probe wire format, the predicate that
// decides whether probing is worth doing at all, and the high-water mark that
// records which probes came back.
//
// The probe frame is the one thing in this package that shares the PPP data path
// with real traffic while never being PPP, so the two properties that matter are
// symmetric: a probe must always be recognised as a probe, and nothing that is
// not a probe may ever be mistaken for one. A false positive here silently eats a
// user's packet.

// ---------------------------------------------------------------------------
// buildMTUProbe / parseMTUProbe
// ---------------------------------------------------------------------------

func TestBuildMTUProbeRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		kind uint8
		seq  uint32
		size int
	}{
		{"request, first sequence number", mtuProbeRequest, 0, 1400},
		{"reply, first sequence number", mtuProbeReply, 0, mtuProbeHeaderLen},
		{"request, sequence 1", mtuProbeRequest, 1, 1200},
		{"reply carries the sequence it answers", mtuProbeReply, 12345, mtuProbeHeaderLen},
		{"sequence number at the uint32 ceiling", mtuProbeRequest, math.MaxUint32, 1500},
		{"one below the uint32 ceiling", mtuProbeReply, math.MaxUint32 - 1, mtuProbeHeaderLen},
		{"high bit set in the sequence", mtuProbeRequest, 0x80000000, 576},
		{"probe at the minimum PPP MTU", mtuProbeRequest, 7, minPPPMTU},
		{"probe at the maximum PPP MTU", mtuProbeRequest, 8, maxPPPMTU},
		{"kind values are carried verbatim", 0xFE, 9, mtuProbeHeaderLen + 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := buildMTUProbe(tt.kind, tt.seq, tt.size)

			require.Len(t, f, tt.size, "probe must be padded to exactly the requested size")
			assert.Equal(t, byte(0xFF), f[0], "HDLC address octet")
			assert.Equal(t, byte(0x03), f[1], "HDLC control octet")
			assert.Equal(t, pppProtoMTUProbe, binary.BigEndian.Uint16(f[2:4]),
				"probes ride a private protocol number so pppd never sees them")

			kind, seq, ok := parseMTUProbe(f)
			require.True(t, ok, "a frame built by buildMTUProbe must parse as a probe")
			assert.Equal(t, tt.kind, kind)
			assert.Equal(t, tt.seq, seq)

			// The padding is what gives the probe its size; it must not carry
			// anything that could be read as data.
			for i := mtuProbeHeaderLen; i < len(f); i++ {
				require.Zerof(t, f[i], "padding octet %d is not zero", i)
			}
		})
	}
}

// A probe smaller than its own header is not representable, so buildMTUProbe
// grows it rather than truncating the sequence number it has to carry.
func TestBuildMTUProbeFloorsAtHeaderLength(t *testing.T) {
	for _, size := range []int{math.MinInt32, -1, 0, 1, mtuProbeHeaderLen - 1, mtuProbeHeaderLen} {
		f := buildMTUProbe(mtuProbeReply, 0xAABBCCDD, size)
		require.Len(t, f, mtuProbeHeaderLen, "size %d must be raised to the header length", size)

		kind, seq, ok := parseMTUProbe(f)
		require.True(t, ok)
		assert.Equal(t, mtuProbeReply, kind)
		assert.Equal(t, uint32(0xAABBCCDD), seq, "the sequence number survives the floor")
	}
}

// The probe is a fixed prefix followed by padding: the same kind and sequence
// must produce the same header no matter how big the frame is.
func TestBuildMTUProbeHeaderIsIndependentOfSize(t *testing.T) {
	small := buildMTUProbe(mtuProbeRequest, 424242, mtuProbeHeaderLen)
	large := buildMTUProbe(mtuProbeRequest, 424242, 1400)
	assert.Equal(t, small, large[:mtuProbeHeaderLen])
}

// Everything that is not a probe must be handed on untouched. These are the
// frames that actually travel the data path.
func TestParseMTUProbeRejectsNonProbes(t *testing.T) {
	valid := buildMTUProbe(mtuProbeRequest, 0x01020304, 64)

	tests := []struct {
		name string
		raw  []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"one octet", []byte{0xFF}},
		{"address and control only", []byte{0xFF, 0x03}},
		{"header truncated by one octet", valid[:mtuProbeHeaderLen-1]},
		{"header truncated to the protocol field", valid[:4]},
		{"header truncated after the kind", valid[:5]},

		{"missing the address octet", func() []byte {
			b := append([]byte(nil), valid...)
			b[0] = 0x00
			return b
		}()},
		{"missing the control octet", func() []byte {
			b := append([]byte(nil), valid...)
			b[1] = 0x00
			return b
		}()},
		{"protocol-field compressed (no FF 03)", append([]byte{0x40, 0x01, 0x00}, make([]byte, 16)...)},

		{"neighbouring private protocol 0x4000", func() []byte {
			b := append([]byte(nil), valid...)
			binary.BigEndian.PutUint16(b[2:4], 0x4000)
			return b
		}()},
		{"neighbouring private protocol 0x4002", func() []byte {
			b := append([]byte(nil), valid...)
			binary.BigEndian.PutUint16(b[2:4], 0x4002)
			return b
		}()},
		{"byte-swapped protocol number", func() []byte {
			b := append([]byte(nil), valid...)
			binary.BigEndian.PutUint16(b[2:4], 0x0140)
			return b
		}()},

		{"a real LCP Configure-Request", frameLCPConfReq},
		{"a real LCP Echo-Request", frameLCPEchoReq},
		{"a real CHAP frame", frameCHAP},
		{"a real IPCP frame", frameIPCP},
		{"a real IPv4 packet", frameIPv4},
		{"a real IPv6 packet", frameIPv6},
		{"a real multilink fragment", frameMP},
		// A full-size IPv4 packet whose payload happens to contain the probe
		// header further in: only the frame's own header may be consulted.
		{
			"an IPv4 packet containing the probe header as payload",
			append([]byte{0xFF, 0x03, 0x00, 0x21}, buildMTUProbe(mtuProbeRequest, 1, 32)...),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kind, seq, ok := parseMTUProbe(tt.raw)
			assert.False(t, ok, "%x must not be taken for an MTU probe", tt.raw)
			assert.Zero(t, kind)
			assert.Zero(t, seq)
		})
	}
}

// Padding beyond the header is ignored: a probe stays a probe whatever the peer
// put in the pad, which is what lets the size be chosen freely.
func TestParseMTUProbeIgnoresPadding(t *testing.T) {
	f := buildMTUProbe(mtuProbeReply, 99, 128)
	for i := mtuProbeHeaderLen; i < len(f); i++ {
		f[i] = 0xA5
	}
	kind, seq, ok := parseMTUProbe(f)
	require.True(t, ok)
	assert.Equal(t, mtuProbeReply, kind)
	assert.Equal(t, uint32(99), seq)
}

func FuzzParseMTUProbe(f *testing.F) {
	f.Add(buildMTUProbe(mtuProbeRequest, 0, 1400))
	f.Add(buildMTUProbe(mtuProbeReply, math.MaxUint32, mtuProbeHeaderLen))
	f.Add(buildMTUProbe(0xFF, 7, 32))
	f.Add(frameLCPConfReq)
	f.Add(frameIPv4)
	f.Add([]byte{0xFF, 0x03, 0x40, 0x01})
	f.Add([]byte{0xFF, 0x03})
	f.Add([]byte(nil))

	f.Fuzz(func(t *testing.T, raw []byte) {
		kind, seq, ok := parseMTUProbe(raw)
		if !ok {
			if kind != 0 || seq != 0 {
				t.Fatalf("rejected frame reported kind=%d seq=%d for %x", kind, seq, raw)
			}
			return
		}
		// Anything shorter than the header cannot carry a sequence number, so
		// it must never be accepted -- accepting it would mean eating a frame
		// that belongs to pppd.
		if len(raw) < mtuProbeHeaderLen {
			t.Fatalf("frame of %d bytes accepted as a probe: %x", len(raw), raw)
		}
		if raw[0] != 0xFF || raw[1] != 0x03 {
			t.Fatalf("accepted a frame without FF 03: %x", raw)
		}
		if got := binary.BigEndian.Uint16(raw[2:4]); got != pppProtoMTUProbe {
			t.Fatalf("accepted protocol %04X as a probe: %x", got, raw)
		}
		// Accepting implies the header round trips.
		if want := buildMTUProbe(kind, seq, len(raw)); !equalPrefix(want, raw, mtuProbeHeaderLen) {
			t.Fatalf("parse/build disagree: %x vs %x", want[:mtuProbeHeaderLen], raw[:mtuProbeHeaderLen])
		}
	})
}

func equalPrefix(a, b []byte, n int) bool {
	if len(a) < n || len(b) < n {
		return false
	}
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// transportMaxFrame / mtuProbeWorthwhile
// ---------------------------------------------------------------------------

// limitedDataIO (bridge_mtu_test.go) is the transport that reports a ceiling.
var _ ppp.MaxFrameSizer = (*limitedDataIO)(nil)

func TestTransportMaxFrame(t *testing.T) {
	t.Run("a transport that cannot report one", func(t *testing.T) {
		// The plain fake deliberately does not implement MaxFrameSizer, which is
		// the case a stream transport presents.
		var io ppp.PPPDataIO = newFakeDataIO()
		_, isSizer := io.(ppp.MaxFrameSizer)
		require.False(t, isSizer, "the plain fake must not report a ceiling")
		assert.Equal(t, 0, transportMaxFrame(io))
	})
	t.Run("a transport that reports one", func(t *testing.T) {
		assert.Equal(t, 1404, transportMaxFrame(&limitedDataIO{fakeDataIO: newFakeDataIO(), limit: 1404}))
	})
}

// Probing costs a full-size frame every interval, so it only pays for itself
// where a narrowing path is invisible: datagrams. Reliable streams are segmented
// by QUIC and report the 64KiB stream ceiling instead, where a smaller path MTU
// is not a black hole.
func TestMTUProbeWorthwhile(t *testing.T) {
	tests := []struct {
		name string
		max  int
		want bool
	}{
		{"no ceiling reported", 0, false},
		{"a nonsensical negative ceiling", -1, false},
		{"a datagram ceiling measured at handshake", 1243, true},
		{"a datagram ceiling after PMTU discovery settles", 1404, true},
		{"a datagram ceiling on a narrow path", minPPPMTU, true},
		{"a ceiling of exactly one octet", 1, true},
		{"a datagram ceiling at the largest PPP frame", maxPPPMTU, true},
		{"one octet above the largest PPP frame", maxPPPMTU + 1, false},
		{"the stream-shaped ceiling", 65535, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := &limitedDataIO{fakeDataIO: newFakeDataIO(), limit: tt.max}
			assert.Equal(t, tt.want, mtuProbeWorthwhile(data))
		})
	}

	t.Run("a transport with no ceiling to report", func(t *testing.T) {
		assert.False(t, mtuProbeWorthwhile(newFakeDataIO()),
			"a transport that cannot report a ceiling must not be probed")
	})
}

// ---------------------------------------------------------------------------
// noteProbeReply
// ---------------------------------------------------------------------------

// probeLoop compares lastProbeSeq against the sequence it just sent, so the
// field has to be a high-water mark: a late reply to an older probe must never pull it
// back down and make a live path look dead.
func TestNoteProbeReplyIsMonotonic(t *testing.T) {
	tests := []struct {
		name string
		seqs []uint32
		want uint32
	}{
		{"nothing noted yet", nil, 0},
		{"in order", []uint32{1, 2, 3, 4}, 4},
		{"a stale reply arriving late", []uint32{5, 2, 1, 3}, 5},
		{"the same sequence twice", []uint32{7, 7, 7}, 7},
		{"zero never lowers the mark", []uint32{9, 0, 0}, 9},
		{"the uint32 ceiling", []uint32{math.MaxUint32, 1}, math.MaxUint32},
		{"one below the ceiling then the ceiling", []uint32{math.MaxUint32 - 1, math.MaxUint32}, math.MaxUint32},
		{"strictly decreasing", []uint32{4, 3, 2, 1}, 4},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &relay{}
			for _, seq := range tt.seqs {
				s.noteProbeReply(seq)
			}
			assert.Equal(t, tt.want, s.lastProbeSeq.Load())
		})
	}
}

// relay's receive pump calls noteProbeReply while the probe loop reads the same
// field, and
// a multi-stream transport can deliver replies out of order across streams. Run
// it under -race with concurrent writers and an interleaved reader.
func TestNoteProbeReplyUnderConcurrency(t *testing.T) {
	const (
		writers  = 8
		perRound = 250
	)
	s := &relay{}

	stop := make(chan struct{})
	var readerWG sync.WaitGroup
	readerWG.Add(1)
	go func() {
		defer readerWG.Done()
		var prev uint32
		for {
			select {
			case <-stop:
				return
			default:
			}
			// A concurrent observer must never see the mark go backwards.
			cur := s.lastProbeSeq.Load()
			if cur < prev {
				t.Errorf("high-water mark went backwards: %d -> %d", prev, cur)
				return
			}
			prev = cur
			// Yield, so this loop still interleaves with the writers when the
			// suite is run with GOMAXPROCS=1 instead of monopolising the P.
			runtime.Gosched()
		}
	}()

	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			// Each writer walks its own range in a different direction so the
			// sequences interleave out of order.
			for i := 0; i < perRound; i++ {
				seq := uint32(w*perRound + i)
				if w%2 == 1 {
					seq = uint32(w*perRound + (perRound - 1 - i))
				}
				s.noteProbeReply(seq)
			}
		}(w)
	}
	wg.Wait()
	close(stop)
	readerWG.Wait()

	assert.Equal(t, uint32(writers*perRound-1), s.lastProbeSeq.Load(),
		"the mark must settle on the highest sequence any goroutine noted")
}

// ---------------------------------------------------------------------------
// Probe timing constants
// ---------------------------------------------------------------------------

// relay.probeLoop's schedule comes from these package constants unless a caller
// overrides it through ProbeInterval/ProbeGrace/ProbeFailures, which is how the
// teardown tests reach the decision in milliseconds instead of the ~73 seconds
// the defaults would cost. The defaults themselves are still the production
// policy, and the policy is the part that decides whether a healthy session gets
// killed, so it is worth checking directly.
func TestMTUProbeTimingConstants(t *testing.T) {
	assert.Greater(t, maxMTUProbeFailures, 1,
		"a single lost probe must never tear down a session; datagrams are lossy by design")
	assert.Positive(t, mtuProbeInterval)

	// The grace period no longer has to cover a probe interval -- it did when the
	// two were seconds apart, and an interval of minutes would now mean a session
	// spending its first minutes unprobed for no reason. What its floor has to
	// cover is the link coming up and quic-go's own path discovery converging,
	// which is a handful of round trips; what its width has to do is stop the
	// first probe of every session landing at the same offset from the handshake.
	assert.GreaterOrEqual(t, mtuProbeGraceMin, 20*time.Second,
		"a session must be given time to converge before full-size frames are demanded")
	assert.Greater(t, mtuProbeGraceMax, 2*mtuProbeGraceMin,
		"a narrow grace range is barely better than a constant offset")

	// The reply window is a fixed budget, so it has to be long enough for a round
	// trip on a bad link and short enough that the failures the teardown counts
	// are consecutive in any meaningful sense.
	assert.Positive(t, mtuProbeTimeout)
	assert.Less(t, mtuProbeTimeout, mtuProbeRetryInterval,
		"a reply window longer than the retry cadence would overlap the next probe")
	assert.Less(t, mtuProbeRetryInterval, mtuProbeInterval,
		"confirming a suspected narrowing must be quicker than noticing one")

	// How long a mid-session narrowing takes to be declared. Only the first miss
	// waits an interval; the rest go at the retry cadence, which is what keeps a
	// four minute interval affordable. Two figures, because they are bounded by
	// different things: noticing at all is bounded by the interval and its jitter
	// tail, and the verdict after that has to be quick regardless.
	maxJitter := float64(mtuProbeJitterMax) / mtuProbeJitterMean
	notice := time.Duration(maxJitter*float64(mtuProbeInterval)) + mtuProbeTimeout
	rounds := time.Duration(maxMTUProbeFailures - 1)
	confirm := rounds * (mtuProbeRetryInterval + mtuProbeRetrySpread + mtuProbeTimeout)
	assert.Less(t, notice+confirm, 6*time.Minute,
		"a black-holed path must be found in minutes, not in whatever the QUIC idle "+
			"timeout happens to be; currently %s", notice+confirm)
	assert.Less(t, confirm, time.Minute,
		"once a probe goes unanswered the verdict must be quick; currently %s", confirm)

	// The average case is what an operator actually lives with, and it is the
	// number the interval was chosen against: half an interval to notice, plus
	// the confirmation burst.
	assert.Less(t, mtuProbeInterval/2+confirm, 3*time.Minute,
		"the typical time from a narrowing to a rebuild; currently %s",
		mtuProbeInterval/2+confirm)

	// The confirmation burst must never outrun pppd's own verdict on a link that
	// has gone silent entirely. Both ends run it with lcp-echo-interval 5 and
	// lcp-echo-failure 3 (extras/pppbridge/handler.go, app/cmd/client_ppp.go), so
	// LCP condemns a dead link at roughly 15-20 seconds. This prober exists for
	// what LCP cannot see -- small frames arriving while large ones vanish -- and
	// a burst that can finish sooner would make it the first responder to every
	// wifi roam and LTE handover instead.
	const lcpVerdict = 20 * time.Second
	shortestBurst := mtuProbeTimeout + rounds*(mtuProbeRetryInterval+mtuProbeTimeout)
	assert.Greater(t, shortestBurst, lcpVerdict,
		"the fastest possible teardown must still be slower than LCP's; currently %s",
		shortestBurst)

	// Which is also why the confirmation wait is bounded from below rather than
	// scaled: a multiplicative jitter has no floor to reason about.
	assert.Positive(t, mtuProbeRetrySpread)
	assert.LessOrEqual(t, mtuProbeRetrySpread, mtuProbeRetryInterval,
		"the spread must not dominate the floor it is protecting")

	// The whole point of the interval being long. Rate is the load-bearing part
	// of this: an idle flow carries nothing but LCP echoes and QUIC keepalives,
	// so every probe is a uniquely large packet whatever its timing, and the only
	// real defence is that there are very few of them. Both ends probe
	// independently, so the figure on the wire is twice this one.
	const wasInterval = 15 * time.Second // the fixed schedule this replaced
	assert.GreaterOrEqual(t, mtuProbeInterval/wasInterval, time.Duration(8),
		"the rate cut is what defeats the signature; jitter alone would not")
	assert.LessOrEqual(t, int(time.Hour/mtuProbeInterval), 30,
		"the steady-state probe rate is a signature; keep it rare")

	// Jitter wide enough that the interval is not recoverable from the extremes
	// of a few samples, and bounded tightly enough that the tail above does not
	// run away.
	assert.LessOrEqual(t, mtuProbeJitterMin, 0.5)
	assert.GreaterOrEqual(t, mtuProbeJitterMax, 2.0)
	assert.Less(t, mtuProbeJitterMax, 3.0)

	// The mean correction is what keeps the drawn interval centred on the
	// constant above; get it wrong and every latency figure here is wrong too.
	// It is the conditional mean of Exp(1) on the truncation range.
	lo, hi := math.Exp(-mtuProbeJitterMin), math.Exp(-mtuProbeJitterMax)
	want := ((mtuProbeJitterMin+1)*lo - (mtuProbeJitterMax+1)*hi) / (lo - hi)
	assert.InDelta(t, want, mtuProbeJitterMean, 1e-4,
		"mtuProbeJitterMean must be the conditional mean of Exp(1) on [min, max]")

	// A padded reply must stay clear of anything a transport could refuse: a
	// reply lost for being too large is scored as an unanswered probe at the far
	// end, which is a teardown for a healthy link.
	assert.Greater(t, mtuProbeReplyPadMin, mtuProbeHeaderLen)
	assert.Greater(t, mtuProbeReplyPadMax, mtuProbeReplyPadMin)
	assert.Less(t, mtuProbeReplyPadMax, maxPPPMTU/2)

	assert.Equal(t, 4+1+4, mtuProbeHeaderLen,
		"FF 03 + protocol(2) + kind(1) + sequence(4)")

	// RFC 1661 s2 assigns PPP Protocol field values 4xxx-7xxx to "low volume
	// traffic with no associated NCP", which is exactly what a probe is. Staying
	// inside it means a peer that does not know the number answers with a
	// Protocol-Reject rather than mis-parsing the frame.
	assert.GreaterOrEqual(t, pppProtoMTUProbe, uint16(0x4000))
	assert.LessOrEqual(t, pppProtoMTUProbe, uint16(0x7FFF))

	// The probe frame carries the HDLC address and control octets, so it is not
	// distinguishable from real traffic by shape alone -- only by protocol number.
	// If it ever collided with a protocol pppd uses, the responder in relay.run
	// would start eating that protocol's frames.
	for _, used := range []uint16{pppProtoLCP, pppProtoPAP, pppProtoCHAP, 0x0021, 0x0057, 0x003D, 0x8021} {
		assert.NotEqual(t, used, pppProtoMTUProbe,
			"the probe protocol must not collide with a protocol pppd speaks")
	}
}

// The jitter is the whole anti-signature mechanism, so the two things it has to
// do -- stay in a bounded range, and actually vary -- are worth pinning. A
// jitter that silently returned its argument would leave the probe as periodic
// as it ever was, and nothing else in the package would notice.
func TestJitterProbeWait(t *testing.T) {
	d := time.Minute
	lo := time.Duration(float64(mtuProbeJitterMin) / mtuProbeJitterMean * float64(d))
	hi := time.Duration(float64(mtuProbeJitterMax) / mtuProbeJitterMean * float64(d))

	const samples = 20000
	seen := make(map[time.Duration]struct{}, samples)
	var total time.Duration
	var short, long int
	for range samples {
		got := jitterProbeWait(d)
		require.GreaterOrEqual(t, got, lo, "a jittered wait must stay inside the truncation range")
		require.LessOrEqual(t, got, hi, "a jittered wait must stay inside the truncation range")
		seen[got] = struct{}{}
		total += got
		switch {
		case got < d:
			short++
		case got > d:
			long++
		}
	}

	assert.Greater(t, len(seen), samples/2,
		"the wait must actually vary; a constant would be no jitter at all")
	assert.Positive(t, short, "waits shorter than the interval must occur")
	assert.Positive(t, long, "waits longer than the interval must occur")

	// Centred on the interval, which is what mtuProbeJitterMean is for. Getting
	// this wrong would silently move the probe rate away from the constant the
	// latency and signature arguments were both made about. 2% over 20k samples
	// of a distribution with a standard deviation below the mean is loose enough
	// never to flake and tight enough to catch a missing correction, which would
	// show up as a 1.5% shift or worse.
	assert.InEpsilon(t, d, total/samples, 0.02, "the jittered wait must average to the interval")

	// An exponential puts most of its mass below its mean, unlike the symmetric
	// distribution this replaced -- that asymmetry is the point, and a uniform
	// draw slipping back in would show up here as a near-even split.
	assert.Greater(t, short, long, "the distribution must be right-skewed, not symmetric")

	// A non-positive wait is the caller saying "no wait", and must survive being
	// scaled by a fraction rather than becoming one.
	assert.Zero(t, jitterProbeWait(0))
	assert.Equal(t, -time.Second, jitterProbeWait(-time.Second))
	assert.Positive(t, jitterProbeWait(1), "the smallest positive wait must stay positive")
}

// The reply window and the retry cadence are capped by the interval, which is
// what lets one set of constants serve both a four minute production schedule
// and the millisecond ones every teardown test drives. Getting the cap wrong is
// invisible in production and turns every one of those tests into a timeout.
func TestProbeScheduleCapsTheDerivedWaitsToTheInterval(t *testing.T) {
	tests := []struct {
		name                              string
		interval, grace                   time.Duration
		failures                          int
		wantInterval, wantRetry, wantWait time.Duration
		wantSpread                        time.Duration
		wantAllowed                       int
	}{
		{
			name:         "no overrides is the production policy",
			wantInterval: mtuProbeInterval,
			wantRetry:    mtuProbeRetryInterval,
			wantSpread:   mtuProbeRetrySpread,
			wantWait:     mtuProbeTimeout,
			wantAllowed:  maxMTUProbeFailures,
		},
		{
			name:     "a millisecond interval scales the whole schedule down",
			interval: 40 * time.Millisecond,
			grace:    10 * time.Millisecond,
			failures: 2,
			// Not mtuProbeRetryInterval and not mtuProbeTimeout: a retry cadence
			// slower than the interval, or a reply window of three seconds, would
			// mean the test waiting on constants it explicitly overrode.
			wantInterval: 40 * time.Millisecond,
			wantRetry:    40 * time.Millisecond,
			wantSpread:   40 * time.Millisecond,
			wantWait:     20 * time.Millisecond,
			wantAllowed:  2,
		},
		{
			name:         "an interval between the two is capped only where it bites",
			interval:     8 * time.Second,
			wantInterval: 8 * time.Second,
			wantRetry:    8 * time.Second,
			wantSpread:   mtuProbeRetrySpread,
			wantWait:     mtuProbeTimeout,
			wantAllowed:  maxMTUProbeFailures,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &relay{ProbeInterval: tt.interval, ProbeGrace: tt.grace, ProbeFailures: tt.failures}
			s := r.probeSchedule()
			assert.Equal(t, tt.wantInterval, s.interval)
			assert.Equal(t, tt.wantRetry, s.retry)
			assert.Equal(t, tt.wantSpread, s.retrySpread)
			assert.Equal(t, tt.wantWait, s.timeout)
			assert.Equal(t, tt.wantAllowed, s.allowed)

			if tt.grace > 0 {
				// A named grace is used verbatim. Every test names one, and a
				// randomised delay before a test's first probe is only flake.
				assert.Equal(t, tt.grace, s.grace)
			} else {
				assert.GreaterOrEqual(t, s.grace, mtuProbeGraceMin)
				assert.LessOrEqual(t, s.grace, mtuProbeGraceMax)
			}

			assert.LessOrEqual(t, s.retry, s.interval,
				"confirming a miss must never be slower than noticing one")
			assert.LessOrEqual(t, s.timeout, s.interval,
				"a reply window wider than the interval would never close")
		})
	}

	// The unnamed grace is drawn per session, not once per process: two sessions
	// starting together must not probe together.
	var graces []time.Duration
	for range 200 {
		graces = append(graces, (&relay{}).probeSchedule().grace)
	}
	assert.Greater(t, len(unique(graces)), 100,
		"the first probe of a session must not land at a fixed offset")
}

// The reply's length is the one dimension of the probe exchange that timing
// jitter cannot touch, so it is padded. The cap is what makes the padding safe:
// relay.run treats a reply refused for being too large as nothing at all, and
// the far end then scores the probe it was answering as unanswered, so a reply
// that outgrows the transport is three rounds away from tearing down a session
// whose path is fine.
func TestProbeReplySizeIsPaddedButNeverRefusable(t *testing.T) {
	tests := []struct {
		name    string
		ceiling int
		wantMin int
		wantMax int
	}{
		{"a normal transport pads into the configured range", 1399, mtuProbeReplyPadMin, mtuProbeReplyPadMax},
		{"an unknown ceiling means no padding at all", 0, mtuProbeHeaderLen, mtuProbeHeaderLen},
		{"a ceiling too small to pad within falls back to the header", 16, mtuProbeHeaderLen, mtuProbeHeaderLen},
		{"a narrow ceiling pads only as far as half of it", 400, mtuProbeReplyPadMin, 200},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := &limitedDataIO{fakeDataIO: newFakeDataIO(), limit: tt.ceiling}
			defer data.Close()
			r := newRelay(data, nil, zap.NewNop(), nil)

			var sizes []int
			for range 500 {
				got := r.probeReplySize()
				require.GreaterOrEqual(t, got, tt.wantMin)
				require.LessOrEqual(t, got, tt.wantMax)
				if tt.ceiling > 0 {
					require.LessOrEqual(t, got, tt.ceiling,
						"a reply the transport would refuse is a reply that never goes out")
					// Half the ceiling, except that a header is the smallest frame
					// there is: a transport too narrow to hold one is not a case the
					// padding can do anything about, and no real one is -- a relay
					// only probes at all when the ceiling is a PPP MTU.
					require.LessOrEqual(t, got, max(tt.ceiling/2, mtuProbeHeaderLen),
						"padding must stay well clear of the ceiling, not merely under it")
				}
				sizes = append(sizes, got)
			}
			if tt.wantMin == tt.wantMax {
				return
			}
			assert.Greater(t, len(unique(sizes)), 50,
				"a padded reply must vary in length; one constant traded for another is no gain")
		})
	}
}

func unique[T comparable](in []T) []T {
	seen := make(map[T]struct{}, len(in))
	var out []T
	for _, v := range in {
		if _, dup := seen[v]; !dup {
			seen[v] = struct{}{}
			out = append(out, v)
		}
	}
	return out
}
