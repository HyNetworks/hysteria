// Reno and hybrid slow start adapted from github.com/apernet/quic-go's
// internal/congestion implementation (MIT license). Used only to restore Reno
// when a masquerade BBR connection subsequently authenticates as a Reno proxy.
package reno

import (
	"time"

	"github.com/apernet/hysteria/core/v2/internal/congestion/common"
	"github.com/apernet/quic-go/congestion"
	"github.com/apernet/quic-go/monotime"
)

type Sender struct {
	rtt                                congestion.RTTStatsProvider
	pacer                              *common.Pacer
	size                               congestion.ByteCount
	cwnd                               congestion.ByteCount
	threshold                          congestion.ByteCount
	largestSent, largestAcked, cutback congestion.PacketNumber
	acked                              uint64
	slowStart                          hybridSlowStart
}

var _ congestion.CongestionControl = (*Sender)(nil)

func NewSender(size congestion.ByteCount) *Sender {
	s := &Sender{
		size: size, cwnd: 32 * size, threshold: 1<<62 - 1,
		largestSent: -1, largestAcked: -1, cutback: -1,
	}
	s.pacer = common.NewPacer(func() congestion.ByteCount {
		rtt := s.rtt.SmoothedRTT()
		if rtt <= 0 {
			rtt = time.Millisecond
		}
		// Match quic-go's pacing rate (1.25 times the window / RTT).
		return congestion.ByteCount(float64(s.cwnd) * float64(time.Second) / float64(rtt) * 1.25)
	})
	s.pacer.SetMaxDatagramSize(size)
	return s
}

func (s *Sender) SetRTTStatsProvider(rtt congestion.RTTStatsProvider) { s.rtt = rtt }
func (s *Sender) TimeUntilSend(_ congestion.ByteCount) monotime.Time  { return s.pacer.TimeUntilSend() }
func (s *Sender) HasPacingBudget(now monotime.Time) bool              { return s.pacer.Budget(now) >= s.size }
func (s *Sender) CanSend(inFlight congestion.ByteCount) bool          { return inFlight < s.cwnd }
func (s *Sender) GetCongestionWindow() congestion.ByteCount           { return s.cwnd }
func (s *Sender) InSlowStart() bool                                   { return s.cwnd < s.threshold }
func (s *Sender) InRecovery() bool                                    { return s.largestAcked != -1 && s.largestAcked <= s.cutback }

func (s *Sender) OnPacketSent(now monotime.Time, _ congestion.ByteCount, pn congestion.PacketNumber, bytes congestion.ByteCount, retransmittable bool) {
	s.pacer.SentPacket(now, bytes)
	if retransmittable {
		s.largestSent = pn
		s.slowStart.lastSent = pn
	}
}

func (s *Sender) MaybeExitSlowStart() {
	if s.InSlowStart() && s.slowStart.shouldExit(s.rtt.LatestRTT(), s.rtt.MinRTT(), s.cwnd/s.size) {
		s.threshold = s.cwnd
	}
}

func (s *Sender) OnPacketAcked(pn congestion.PacketNumber, _ congestion.ByteCount, inFlight congestion.ByteCount, _ monotime.Time) {
	s.largestAcked = max(s.largestAcked, pn)
	if s.InRecovery() {
		return
	}
	limited := inFlight >= s.cwnd || (s.InSlowStart() && inFlight > s.cwnd/2) || s.cwnd-inFlight <= 3*s.size
	if limited && s.cwnd < congestion.MaxCongestionWindowPackets*s.size {
		if s.InSlowStart() {
			s.cwnd += s.size
		} else {
			s.acked++
			if s.acked >= uint64(s.cwnd/s.size) {
				s.cwnd += s.size
				s.acked = 0
			}
		}
	}
	if s.InSlowStart() && pn > s.slowStart.endPacket {
		s.slowStart.started = false
	}
}

func (s *Sender) OnCongestionEvent(pn congestion.PacketNumber, _, _ congestion.ByteCount) {
	if pn <= s.cutback {
		return
	}
	s.cwnd = max(2*s.size, congestion.ByteCount(float64(s.cwnd)*0.7))
	s.threshold = s.cwnd
	s.cutback = s.largestSent
	s.acked = 0
}

func (s *Sender) OnRetransmissionTimeout(retransmitted bool) {
	s.cutback = -1
	if retransmitted {
		s.slowStart.started = false
		s.slowStart.found = false
		s.threshold = s.cwnd / 2
		s.cwnd = 2 * s.size
	}
}

func (s *Sender) SetMaxDatagramSize(size congestion.ByteCount) {
	if size < s.size {
		panic("reno: decreased max datagram size")
	}
	if s.cwnd == 2*s.size {
		s.cwnd = 2 * size
	}
	s.size = size
	s.pacer.SetMaxDatagramSize(size)
}

type hybridSlowStart struct {
	lastSent, endPacket congestion.PacketNumber
	started, found      bool
	minRTT              time.Duration
	samples             uint32
}

func (s *hybridSlowStart) shouldExit(latest, minimum time.Duration, window congestion.ByteCount) bool {
	if !s.started {
		s.endPacket = s.lastSent
		s.minRTT = 0
		s.samples = 0
		s.started = true
	}
	if s.found {
		return true
	}
	s.samples++
	if s.samples <= 8 && (s.minRTT == 0 || latest < s.minRTT) {
		s.minRTT = latest
	}
	if s.samples == 8 {
		threshold := min(16*time.Millisecond, max(4*time.Millisecond, minimum/8))
		s.found = s.minRTT > minimum+threshold
	}
	return window >= 16 && s.found
}
