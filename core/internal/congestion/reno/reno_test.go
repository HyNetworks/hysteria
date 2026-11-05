package reno

import (
	"testing"
	"time"

	"github.com/apernet/quic-go/congestion"
	"github.com/apernet/quic-go/monotime"
	"github.com/stretchr/testify/require"
)

type testRTT struct{ congestion.RTTStatsProvider }

func (testRTT) SmoothedRTT() time.Duration { return 100 * time.Millisecond }
func (testRTT) LatestRTT() time.Duration   { return 100 * time.Millisecond }
func (testRTT) MinRTT() time.Duration      { return 80 * time.Millisecond }

func TestRenoGrowthLossAndRecovery(t *testing.T) {
	s := NewSender(1200)
	s.SetRTTStatsProvider(testRTT{})
	require.EqualValues(t, 32*1200, s.GetCongestionWindow())
	require.True(t, s.CanSend(0))
	require.False(t, s.CanSend(s.cwnd))
	now := monotime.Now()
	s.OnPacketSent(now, 0, 10, 1200, true)
	s.OnPacketAcked(1, 1200, s.cwnd, now)
	require.EqualValues(t, 33*1200, s.cwnd)
	s.OnCongestionEvent(2, 1200, s.cwnd)
	cut := s.cwnd
	require.EqualValues(t, float64(33*1200)*0.7, cut)
	require.True(t, s.InRecovery())
	s.OnCongestionEvent(3, 1200, s.cwnd)
	s.OnPacketAcked(4, 1200, s.cwnd, now)
	require.Equal(t, cut, s.cwnd, "one cutback per recovery epoch")
	s.OnPacketAcked(11, 1200, s.cwnd, now)
	require.False(t, s.InRecovery())
	for i := congestion.PacketNumber(12); i < 12+congestion.PacketNumber(cut/1200)-1; i++ {
		s.OnPacketAcked(i, 1200, s.cwnd, now)
	}
	require.Equal(t, cut+1200, s.cwnd, "Reno increases by one packet per window")
	s.OnRetransmissionTimeout(true)
	require.EqualValues(t, 2400, s.cwnd)
	s.SetMaxDatagramSize(1400)
	require.EqualValues(t, 2800, s.cwnd)
	require.Panics(t, func() { s.SetMaxDatagramSize(1200) })
}

func TestRenoApplicationLimitedAndPacing(t *testing.T) {
	s := NewSender(1200)
	s.SetRTTStatsProvider(testRTT{})
	now := monotime.Now()
	before := s.cwnd
	s.OnPacketAcked(1, 1200, 1200, now)
	require.Equal(t, before, s.cwnd)
	for range 10 {
		s.OnPacketSent(now, 0, 2, 1200, true)
	}
	require.False(t, s.HasPacingBudget(now))
	require.True(t, s.TimeUntilSend(0).After(now))
	require.True(t, s.HasPacingBudget(now.Add(time.Second)))
}

func TestHybridSlowStart(t *testing.T) {
	var s hybridSlowStart
	for range 8 {
		s.shouldExit(120*time.Millisecond, 80*time.Millisecond, 32)
	}
	require.True(t, s.found)
	require.True(t, s.shouldExit(100*time.Millisecond, 80*time.Millisecond, 32))
}
