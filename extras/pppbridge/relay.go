package pppbridge

import (
	"context"
	"encoding/hex"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/apernet/hysteria/core/v2/ppp"
	"go.uber.org/zap"
)

const hexHeadMax = 64

// hexHead renders the head of a frame for debug logging, appending a total when
// it truncates. Frames are only ever logged, never inspected.
func hexHead(b []byte) string {
	if len(b) <= hexHeadMax {
		return hex.EncodeToString(b)
	}
	return fmt.Sprintf("%s...(%d total)", hex.EncodeToString(b[:hexHeadMax]), len(b))
}

// relayError says which side of the relay failed. The distinction matters to the
// caller: a dead endpoint means the PPP daemon went away and the whole thing
// should be rebuilt quietly, while a dead transport means the link dropped and
// there may be a reason worth reporting.
type relayError struct {
	fromEndpoint bool
	err          error
}

func (e *relayError) Error() string { return e.err.Error() }
func (e *relayError) Unwrap() error { return e.err }

// relay pumps raw PPP frames between the Hysteria2 transport and an Endpoint.
//
// Both server modes and the client bridge use this: the local mode's Endpoint is
// a pppd over a pty, the LAC's is an L2TP session to an LNS, and the client's is
// its own pppd. Everything that is not "which endpoint" lives here exactly once
// -- the MTU probe protocol, oversize accounting, and the rule that a frame which
// does not fit is a dropped packet while a dead transport ends the session.
type relay struct {
	data ppp.PPPDataIO
	ep   Endpoint

	Logger *zap.Logger

	// ProbeInterval, ProbeGrace and ProbeFailures override the MTU probe
	// schedule; zero selects the package defaults.
	ProbeInterval time.Duration
	ProbeGrace    time.Duration
	ProbeFailures int

	// MTUFixed suppresses the teardown when the probe stops getting answers.
	//
	// Tearing down is only useful if the rebuild can come back smaller, and that
	// needs this process to be the one choosing the MTU. In nospawn mode it is
	// not: pppd is the parent and its MRU came from its own configuration, so a
	// rebuilt session negotiates the identical value and the teardown buys
	// nothing -- while costing a full interface rebuild, which under a multilink
	// bundle takes every other link with it.
	//
	// Not because the probe would fail again. The probe is sized from the
	// transport's live datagram budget, not from the configured MRU, and a fresh
	// QUIC connection restarts path discovery and re-converges on the narrower
	// path -- so its probes would be answered. The point is that pppd would still
	// be framing to the old number. Frames that no longer fit land in the
	// non-fatal oversize branch above, which is where they belong: the operator
	// set the number and owns the consequence, and what is owed them is a clear
	// statement of it rather than a link that will not stay up.
	MTUFixed bool

	// oversizeDropped counts frames the transport refused for being too large.
	// Non-zero means the negotiated PPP MTU exceeds what the path carries, which
	// is otherwise invisible.
	oversizeDropped *atomic.Uint64

	// counters accumulate what this link carried, for the status surface that
	// reports each server's share of a bundle. Never nil: newRelay allocates a
	// throwaway when the caller wants no reading, so the pumps below can add
	// unconditionally rather than branching once per frame.
	counters *Counters

	lastProbeSeq atomic.Uint32
	done         chan struct{}
}

func newRelay(data ppp.PPPDataIO, ep Endpoint, logger *zap.Logger, dropped *atomic.Uint64) *relay {
	if dropped == nil {
		dropped = new(atomic.Uint64)
	}
	return &relay{
		data:            data,
		ep:              ep,
		Logger:          logger,
		oversizeDropped: dropped,
		counters:        new(Counters),
		done:            make(chan struct{}),
	}
}

// wait sleeps for d, reporting false if the session ended first. Every sleep in
// probeLoop goes through it, because a probe schedule measured in minutes must
// not keep a goroutine alive for minutes after the session it belongs to is
// gone.
func (r *relay) wait(d time.Duration) bool {
	if d <= 0 {
		select {
		case <-r.done:
			return false
		default:
			return true
		}
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-r.done:
		return false
	}
}

func (r *relay) noteProbeReply(seq uint32) {
	for {
		cur := r.lastProbeSeq.Load()
		if seq <= cur || r.lastProbeSeq.CompareAndSwap(cur, seq) {
			return
		}
	}
}

// run pumps in both directions until one side fails, and returns that error.
// A frame refused for being too large never ends the relay.
func (r *relay) run(ctx context.Context) error {
	errCh := make(chan error, 3)
	defer close(r.done)

	// Transport -> endpoint. MTU probes terminate here rather than reaching the
	// endpoint, which neither pppd nor an LNS would know what to do with.
	go func() {
		for {
			frame, err := r.data.ReceiveData()
			if err != nil {
				errCh <- &relayError{err: err}
				return
			}
			if kind, seq, ok := parseMTUProbe(frame); ok {
				switch kind {
				case mtuProbeRequest:
					// The reply is small on purpose -- what is being established is
					// that the large one arrived -- but not the same small every
					// time. A constant 9 octets a round trip behind a full-size
					// frame is a pairing no amount of timing jitter hides.
					if serr := r.data.SendData(buildMTUProbe(mtuProbeReply, seq, r.probeReplySize())); serr != nil &&
						!ppp.IsFrameTooLarge(serr) {
						errCh <- &relayError{err: serr}
						return
					}
				case mtuProbeReply:
					r.noteProbeReply(seq)
				}
				continue
			}
			// Past the probe filter above, so the synthetic frames this relay
			// generates for its own MTU measurement are not reported as the
			// server's traffic. An idle link would otherwise show a slow trickle
			// that no subscriber sent and no operator can explain.
			r.counters.addRx(len(frame))
			if ce := r.Logger.Check(zap.DebugLevel, "relay: transport -> endpoint"); ce != nil {
				ce.Write(zap.Int("bytes", len(frame)), zap.String("hex", hexHead(frame)))
			}
			if err := r.ep.SendPPP(frame); err != nil {
				errCh <- &relayError{fromEndpoint: true, err: err}
				return
			}
		}
	}()

	// Endpoint -> transport.
	go func() {
		var oversize uint64
		for {
			frame, err := r.ep.RecvPPP()
			if err != nil {
				errCh <- &relayError{fromEndpoint: true, err: err}
				return
			}
			if ce := r.Logger.Check(zap.DebugLevel, "relay: endpoint -> transport"); ce != nil {
				ce.Write(zap.Int("bytes", len(frame)), zap.String("hex", hexHead(frame)))
			}
			if err := r.data.SendData(frame); err != nil {
				if ppp.IsFrameTooLarge(err) {
					// A packet to drop, not a session to end. The peer is entitled
					// to send up to the MRU it was given, which it may not have
					// honoured, and tearing down on the first full-size download
					// would make the link flap instead of degrade.
					r.oversizeDropped.Add(1)
					if oversize == 0 {
						r.Logger.Warn("PPP frame exceeds the transport limit, dropping; "+
							"the negotiated MTU is too large for this path",
							zap.Error(err), zap.Int("bytes", len(frame)))
					} else if ce := r.Logger.Check(zap.DebugLevel, "oversize frame dropped"); ce != nil {
						ce.Write(zap.Error(err), zap.Uint64("count", oversize))
					}
					oversize++
					continue
				}
				errCh <- &relayError{err: err}
				return
			}
			// After the send rather than before it, so the oversize branch above
			// is excluded: those frames were dropped, and counting a drop as
			// carried traffic would make a link look healthiest exactly when its
			// path had narrowed.
			r.counters.addTx(len(frame))
		}
	}()

	if mtuProbeWorthwhile(r.data) {
		go r.probeLoop(errCh)
	}

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// probeLoop sends a full-size frame occasionally and requires the peer to echo
// it. Several unanswered in a row means the path stopped carrying what the PPP
// link was negotiated for -- which nothing else in the stack can see, because
// quic-go never lowers its MTU estimate and LCP Echo is small enough to pass a
// path that only drops large packets.
//
// Every wait is jittered and the steady-state one is long, because a probe is a
// max-size frame answered by a tiny one and nothing else on an idle link looks
// like that; see the constants in mtuprobe.go. The schedule has two speeds. In
// the ordinary case it waits an interval, and having seen a probe go unanswered
// it drops to the retry cadence until the question is settled either way -- so
// the long interval costs latency only up to the first miss, not once per
// failure the teardown requires.
func (r *relay) probeLoop(errCh chan<- error) {
	s := r.probeSchedule()

	// Not jittered here: probeSchedule already drew it across the grace range,
	// and a caller that named one meant it.
	if !r.wait(s.grace) {
		return
	}

	var seq uint32
	var failures int
	for {
		// Drawn per round rather than once, so the schedule has no period to
		// average out over a long observation. The two speeds draw differently on
		// purpose -- the steady-state wait is scaled to hide a cadence, the
		// confirmation wait is bounded from below to stay out of LCP's way.
		next := jitterProbeWait(s.interval)
		if failures > 0 {
			next = s.retryWait()
		}
		if !r.wait(next) {
			return
		}

		size := transportMaxFrame(r.data)
		if size <= 0 || size > maxPPPMTU {
			continue
		}
		seq++
		if err := r.data.SendData(buildMTUProbe(mtuProbeRequest, seq, size)); err != nil {
			// Inconclusive, not fatal: a refusal means the transport already knows
			// the size does not fit, and any other error may be momentary. Giving
			// up would leave the session running with black-hole detection off.
			if ce := r.Logger.Check(zap.DebugLevel, "MTU probe send failed"); ce != nil {
				ce.Write(zap.Error(err), zap.Uint32("seq", seq))
			}
			continue
		}

		if !r.wait(s.timeout) {
			return
		}

		if r.lastProbeSeq.Load() >= seq {
			failures = 0
			continue
		}
		failures++
		r.Logger.Warn("full-size MTU probe unanswered",
			zap.Uint32("seq", seq), zap.Int("size", size), zap.Int("consecutive", failures))
		if failures >= s.allowed {
			if r.MTUFixed {
				// Said once, then the probe keeps running: the path may widen
				// again, and if it does the next answered probe resets failures
				// and this goes quiet without anyone intervening.
				r.Logger.Error("path no longer carries the configured MTU; full-size packets "+
					"are being lost. Lower the mtu option for this interface",
					zap.Int("probeSize", size))
				failures = 0
				continue
			}
			r.Logger.Error("path no longer carries the negotiated MTU, tearing down the session "+
				"so it can be rebuilt at the smaller size",
				zap.Int("probeSize", size))
			select {
			case errCh <- &relayError{err: errPathNarrowed}:
			default:
			}
			return
		}
	}
}
