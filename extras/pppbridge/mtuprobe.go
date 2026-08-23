package pppbridge

import (
	"encoding/binary"
	"errors"
	"math/rand"
	"time"

	"github.com/apernet/hysteria/core/v2/ppp"
)

// Detecting a path that narrows after the MTU was already agreed.
//
// Nothing else in the stack notices this. quic-go's Path MTU discovery only ever
// searches upward -- CurrentSize() returns the confirmed minimum, which is raised
// on a successful probe and never lowered -- so once the estimate is set it stays
// set. SendDatagram keeps succeeding because quic-go still believes the larger
// size works, and the packets are simply lost on the wire with no ICMP. LCP Echo
// does not help either: echo frames are a few dozen octets and sail through a
// path that only drops large packets.
//
// Measured: on a connection converged at a 1500-byte path, narrowing the path to
// 1300 left the connection healthy and the budget unchanged for over 75 seconds
// while every full-size frame vanished (TestMTUSimulationPathShrinksMidConnection).
//
// So the only way to see it is to probe at the size that actually matters. These
// probes are full-size frames the peer echoes back; losing several in a row means
// the path no longer carries what the PPP link was sized for. The session is then
// torn down so it can be rebuilt -- a fresh QUIC connection restarts discovery
// from the initial packet size and re-converges on the narrower path.
const (
	// A private protocol number in RFC 1661's 0x4000-0x7FFF range, which is
	// reserved for low-volume traffic with no associated NCP. Frames carrying it
	// are consumed by the peer bridge and never reach pppd.
	pppProtoMTUProbe uint16 = 0x4001

	mtuProbeRequest uint8 = 0
	mtuProbeReply   uint8 = 1

	// probe header: FF 03 <proto:2> <kind:1> <seq:4>
	mtuProbeHeaderLen = 4 + 1 + 4

	// The steady-state cadence, and never used as written: every wait is drawn
	// around it by jitterProbeWait.
	//
	// A probe is the most conspicuous thing this transport emits. It is a
	// maximum-size datagram answered a moment later by a small one, on a link
	// that is very often otherwise idle -- and an idle PPP-over-Hysteria2 flow is
	// nothing but LCP echoes and QUIC keepalives, so a full-size packet is not
	// merely periodic, it is the only large packet there is. At the fixed 15
	// seconds this started at, that pair appeared 240 times an hour, at each end
	// independently, on a schedule accurate to the millisecond. What the probe
	// detects is a path narrowing mid-session, which is rare and does not become
	// more likely by being looked for more often, so the cadence was paying a
	// permanent, perfectly periodic cost for it.
	//
	// Rate is the load-bearing fix and jitter is the insurance: at two minutes
	// this is 30 an hour per direction against 240 before, and the marginal
	// concealment above this flattens out fast while the marginal cost does not.
	// Five and ten minute intervals were both considered and rejected on that
	// basis: they hide no better in any realistic observation window and they
	// stretch the tail below into a quarter of an hour.
	//
	// What the interval costs is time-to-notice, and less than it looks -- see
	// mtuProbeRetryInterval. The failure it delays noticing is not a slow link
	// but a hang: OpenWrt leaves tcp_mtu_probing at 0, so during a black hole
	// DNS resolves and TCP connects while every page stalls on the first
	// full-size response, for every host behind the router at once.
	mtuProbeInterval = 2 * time.Minute

	// The cadence after a probe goes unanswered, which is what makes an interval
	// this long affordable. Only the *first* miss waits an interval; once there
	// is something to confirm, confirming it is quick, so the wait for a verdict
	// is one interval rather than maxMTUProbeFailures of them.
	//
	// Jittered additively over a floor, and this is the one wait that must not
	// use the multiplicative jitter above. What bounds it from below is not
	// concealment, it is layering: pppd is run with lcp-echo-interval 5 and
	// lcp-echo-failure 3, so it declares a silent link dead in 15-20 seconds. A
	// burst that can complete faster than that would make this the first
	// responder to an ordinary total outage -- a wifi roam, an LTE handover, a
	// route flap -- and tear the session down for a reason it is not the judge
	// of. This prober exists for what LCP cannot see: small frames arriving
	// while large ones vanish. A multiplicative jitter with a 0.25x floor put
	// the fastest possible burst at 11 seconds, inside LCP's own window.
	//
	// Floor plus spread gives a burst spanning
	// timeout + 2*(retry+timeout) = 33 to 45 seconds: above LCP's verdict either
	// way, and close to the 37.5 second span the fixed schedule had. That span
	// also has to stay long enough that a single congestion episode cannot cover
	// the whole burst, because datagrams are never retransmitted and ordinary
	// loss already costs a probe.
	//
	// It is also the only burst this ever emits, it lasts three frames, and it
	// happens only on a path that has already stopped carrying full-size traffic
	// -- which is a louder signal to any observer than the probe ever was.
	mtuProbeRetryInterval = 12 * time.Second
	mtuProbeRetrySpread   = 6 * time.Second

	// How long a probe has to be echoed back. An absolute budget rather than a
	// fraction of the interval: the two answer different questions -- how often
	// to ask, and how long an answer may take -- and deriving the second from the
	// first meant that making the probe rarer also made every reply window
	// minutes long. A datagram is never retransmitted, so the reply arrives in
	// about a round trip or it never arrives; waiting two minutes for it would
	// only mean the "consecutive" failures being counted spanned a period in
	// which the path could narrow and recover several times over.
	//
	// Capped by the interval in probeSchedule, because every test drives this
	// decision in milliseconds and a fixed three seconds there would be the whole
	// test.
	mtuProbeTimeout = 3 * time.Second

	// The first probe of a session is drawn uniformly from this range instead of
	// landing at a fixed offset from the handshake. A constant offset identifies
	// the protocol from a single session, without an observer ever needing to see
	// a second probe -- and unlike the interval there is no cadence here to hide
	// in, so the offset has to carry its own randomness.
	//
	// The floor is what the link needs to come up and quic-go's own path
	// discovery to converge; below it a probe measures a ceiling that is still
	// being searched for.
	mtuProbeGraceMin = 20 * time.Second
	mtuProbeGraceMax = 90 * time.Second

	// A reply says only "the large one arrived", so its length carries no
	// information and is free to vary. That matters more than it looks: a
	// 1452-byte packet answered one round trip later by a 9-byte one is a pairing
	// with a ~150:1 size ratio and a fixed direction order, and no amount of
	// timing jitter touches it. Padding to a random length in this range breaks
	// the ratio while staying far below any plausible reverse ceiling -- see
	// probeReplySize for why that bound is not optional.
	//
	// Wire-compatible in both directions: parseMTUProbe reads the first nine
	// octets and ignores everything after them, and buildMTUProbe already pads to
	// any requested length, so a peer running the old code answers and is
	// answered correctly. Same treatment the control-stream response already gets
	// in pppproto.go.
	mtuProbeReplyPadMin = 64
	mtuProbeReplyPadMax = 512

	maxMTUProbeFailures = 3
)

// Jitter bounds, as multiples of an Exp(1) draw, and the conditional mean that
// normalises them back to the interval.
//
// A truncated exponential rather than the obvious uniform +/-X%. The gaps of a
// jittered probe form a renewal process, whose Bartlett spectrum is
// (1-|phi|^2)/|1-phi|^2 for phi the characteristic function of the gap
// distribution -- and for uniform +/-X that is |sinc(2*pi*X)| at the fundamental.
// Small X barely helps: +/-10% still leaves a 30x spectral peak at 1/interval.
// The tempting answer is +/-50%, because sinc(pi) is exactly zero and the peak
// vanishes at every harmonic -- but it substitutes a 4.5x spectral *deficit* at
// half the rate, and a hole is as findable as a peak. Worse, bounded uniform
// jitter leaves hard edges: no gap is ever below half the interval or above one
// and a half times it, so "smallest gap seen" and "largest gap seen" converge on
// the interval from both sides.
//
// An exponential is flat at every frequency by construction and has no support
// edges. Truncating it keeps the tail finite so the worst-case time-to-notice
// stays bounded, at the price of a little flatness: on [0.25, 2.0] the spectrum
// is 0.53 / 0.61 / 0.89 / 1.15 at half, one, two and three times the rate --
// within about 2x of flat, with no line and no hole.
//
// The upper bound is the load-bearing half and it is chosen against latency, not
// concealment: it caps the longest a black hole can go unnoticed at 2.27
// intervals. Untruncated, or truncated at 3x, the tail is what decides the
// worst case, and no observer is any better off for it.
const (
	mtuProbeJitterMin = 0.25
	mtuProbeJitterMax = 2.0
	// Conditional mean of Exp(1) on [min, max]:
	// ((lo+1)e^-lo - (hi+1)e^-hi) / (e^-lo - e^-hi).
	mtuProbeJitterMean = 0.88194
)

// jitterProbeWait returns d scaled by a truncated-exponential factor with mean
// one, never returning a non-positive duration for a positive d.
//
// math/rand rather than crypto/rand, matching the rest of the tree (obfs,
// udphop, pppproto): the sequence is not a secret and nothing is derived from
// it. What matters is that it is seeded per process -- Go's global source has
// been randomly seeded since 1.20 -- so two routers on one uplink do not probe
// in lockstep.
func jitterProbeWait(d time.Duration) time.Duration {
	if d <= 0 {
		return d
	}
	// Rejection rather than an inverse-CDF draw over the truncated range: it is
	// the same distribution, it is obvious by inspection that it is, and it runs
	// once every few minutes -- the acceptance rate is e^-0.25 - e^-2 = 64%.
	var f float64
	for {
		if f = rand.ExpFloat64(); f > mtuProbeJitterMin && f < mtuProbeJitterMax {
			break
		}
	}
	scaled := time.Duration(float64(d) * f / mtuProbeJitterMean)
	if scaled <= 0 {
		return 1
	}
	return scaled
}

// probeReplySize returns the length to pad a probe reply out to.
//
// The cap is the part that matters. relay.run deliberately ignores a reply
// refused for being too large -- it is a bookkeeping frame, not traffic -- so an
// oversize reply is not an error anywhere; it is simply never sent, and the far
// end scores the probe it was answering as unanswered. Three of those tear down
// a session whose path was never narrow. Half the ceiling leaves that impossible
// with room to spare, and an unknown ceiling means no padding at all.
func (r *relay) probeReplySize() int {
	max := transportMaxFrame(r.data)
	if max <= 0 {
		return mtuProbeHeaderLen
	}
	hi := min(max/2, mtuProbeReplyPadMax)
	lo := min(mtuProbeReplyPadMin, hi)
	if lo <= mtuProbeHeaderLen {
		return mtuProbeHeaderLen
	}
	return lo + rand.Intn(hi-lo+1)
}

// probeSchedule is the resolved schedule one probeLoop runs on: the package
// constants unless the caller overrode them.
type probeSchedule struct {
	grace    time.Duration
	interval time.Duration
	// retry is the floor of the confirmation cadence and retrySpread its width;
	// see mtuProbeRetryInterval for why this one is bounded from below rather
	// than scaled.
	retry       time.Duration
	retrySpread time.Duration
	timeout     time.Duration
	allowed     int
}

// retryWait returns the next confirmation wait, drawn uniformly from
// [retry, retry+retrySpread].
func (s probeSchedule) retryWait() time.Duration {
	if s.retrySpread <= 0 {
		return s.retry
	}
	return s.retry + time.Duration(rand.Int63n(int64(s.retrySpread)+1))
}

// probeSchedule resolves the relay's overrides against the package defaults.
//
// Split out of probeLoop because the interesting part is not the loop, it is
// that the reply window and the retry cadence are capped by the interval: a
// caller asking for a probe every 40ms -- which is every test that drives the
// teardown decision -- must not inherit a five second reply window and a twenty
// second retry from constants written for a four minute one. That cap is worth a
// test that does not have to run a session to reach it.
func (r *relay) probeSchedule() probeSchedule {
	s := probeSchedule{
		interval: mtuProbeInterval,
		allowed:  maxMTUProbeFailures,
		// Drawn here rather than jittered at the point of use, so that a caller
		// that names a grace gets exactly the one it named. Every test does, and a
		// randomised delay before a test's first probe would buy nothing but flake.
		grace: mtuProbeGraceMin + time.Duration(rand.Int63n(int64(mtuProbeGraceMax-mtuProbeGraceMin)+1)),
	}
	if r.ProbeInterval > 0 {
		s.interval = r.ProbeInterval
	}
	if r.ProbeGrace > 0 {
		s.grace = r.ProbeGrace
	}
	if r.ProbeFailures > 0 {
		s.allowed = r.ProbeFailures
	}
	s.timeout = min(mtuProbeTimeout, s.interval/2)
	s.retry = min(mtuProbeRetryInterval, s.interval)
	s.retrySpread = min(mtuProbeRetrySpread, s.retry)
	return s
}

// errPathNarrowed reports that full-size frames stopped getting through.
var errPathNarrowed = errors.New("ppp: path no longer carries the negotiated MTU")

// buildMTUProbe returns a probe frame padded out to size total octets.
func buildMTUProbe(kind uint8, seq uint32, total int) []byte {
	if total < mtuProbeHeaderLen {
		total = mtuProbeHeaderLen
	}
	f := make([]byte, total)
	f[0] = 0xFF
	f[1] = 0x03
	binary.BigEndian.PutUint16(f[2:4], pppProtoMTUProbe)
	f[4] = kind
	binary.BigEndian.PutUint32(f[5:9], seq)
	return f
}

// parseMTUProbe reports whether raw is a probe frame, and if so its kind and
// sequence number.
func parseMTUProbe(raw []byte) (kind uint8, seq uint32, ok bool) {
	if len(raw) < mtuProbeHeaderLen {
		return 0, 0, false
	}
	if raw[0] != 0xFF || raw[1] != 0x03 {
		return 0, 0, false
	}
	if binary.BigEndian.Uint16(raw[2:4]) != pppProtoMTUProbe {
		return 0, 0, false
	}
	return raw[4], binary.BigEndian.Uint32(raw[5:9]), true
}

// transportMaxFrame reports the data transport's current per-frame ceiling, or 0
// when it does not have one to report.
func transportMaxFrame(data ppp.PPPDataIO) int {
	if s, ok := data.(ppp.MaxFrameSizer); ok {
		return s.MaxFrameSize()
	}
	return 0
}

// mtuProbeWorthwhile reports whether the transport has a per-frame ceiling small
// enough for a shrinking path to matter. Reliable streams do not.
func mtuProbeWorthwhile(data ppp.PPPDataIO) bool {
	max := transportMaxFrame(data)
	return max > 0 && max <= maxPPPMTU
}
