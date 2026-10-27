// Package l3frag reassembles L3 IP packets from interleaved QUIC datagram fragments.
// Unlike frag.Defragger, several packets may be in flight at once.
package l3frag

import "time"

const (
	slotCount       = 64
	assembleTimeout = 200 * time.Millisecond
	maxPacketSize   = 1600
)

type slot struct {
	id        uint32
	fragCount uint8
	got       []bool
	data      [][]byte
	received  int
	total     int
	started   time.Time
	active    bool
}

// Assembler keeps a small ring of in-progress packets, keyed by PacketID % 64.
type Assembler struct {
	slots [slotCount]slot
	now   func() time.Time
}

func (a *Assembler) clock() time.Time {
	if a.now != nil {
		return a.now()
	}
	return time.Now()
}

// Feed adds one fragment. It returns the IP packet when this fragment completes it.
// A fragment that does not belong to a valid in-progress packet is discarded.
func (a *Assembler) Feed(packetID uint32, fragID, fragCount uint8, payload []byte) []byte {
	if fragCount == 0 || fragID >= fragCount || len(payload) == 0 || len(payload) > maxPacketSize {
		return nil
	}
	if fragCount == 1 {
		return append([]byte(nil), payload...)
	}
	now := a.clock()
	s := &a.slots[packetID%slotCount]
	if !s.active || s.id != packetID || now.Sub(s.started) > assembleTimeout {
		s.reset(packetID, fragCount, now)
	} else if s.fragCount != fragCount {
		return nil
	}
	if s.got[fragID] {
		return nil
	}
	if s.total+len(payload) > maxPacketSize {
		s.active = false
		return nil
	}
	s.got[fragID] = true
	// The slot keeps its buffers; the packet returned below is a fresh copy.
	s.data[fragID] = append(s.data[fragID][:0], payload...)
	s.total += len(payload)
	s.received++
	if s.received != int(s.fragCount) {
		return nil
	}
	out := make([]byte, 0, s.total)
	for i := uint8(0); i < s.fragCount; i++ {
		out = append(out, s.data[i]...)
	}
	s.active = false
	return out
}

// reset starts a new packet in s and reuses the slices of the previous one,
// so a steady stream of split packets does not allocate per fragment.
func (s *slot) reset(id uint32, fragCount uint8, now time.Time) {
	n := int(fragCount)
	if cap(s.got) < n {
		s.got = make([]bool, n)
		s.data = make([][]byte, n)
	} else {
		s.got = s.got[:n]
		clear(s.got)
		s.data = s.data[:n]
	}
	s.id = id
	s.fragCount = fragCount
	s.received = 0
	s.total = 0
	s.started = now
	s.active = true
}
