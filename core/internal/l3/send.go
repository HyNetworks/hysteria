package l3

import (
	"errors"
	"sync"
	"sync/atomic"

	"github.com/apernet/quic-go"

	"github.com/apernet/hysteria/core/v2/internal/protocol"
)

// probeEvery is how often a packet that the cached limit would split is tried
// whole anyway, so a path MTU that grew is noticed.
const probeEvery = 256

// fragPool holds datagram buffers. SendDatagram copies its argument, so a
// buffer goes back to the pool as soon as the call returns.
var fragPool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, protocol.L3HeaderSize+protocol.L3MaxPacketSize)
		return &b
	},
}

// Sender carries IP packets as QUIC datagrams for one connection.
// It numbers the packets and remembers the largest datagram the path took,
// so a packet that will not fit is split without a failed attempt first.
type Sender struct {
	next   atomic.Uint32
	max    atomic.Int64 // 0 until a datagram was too large
	splits atomic.Uint32
}

// Send carries one IP packet as one or more QUIC datagrams.
// An empty packet or one larger than the L3 maximum is dropped.
// A packet that does not fit the path is split into even pieces.
// ip is not kept after Send returns.
func (s *Sender) Send(sendDatagram func([]byte) error, ip []byte) error {
	if len(ip) == 0 || len(ip) > protocol.L3MaxPacketSize {
		return nil
	}
	id := s.next.Add(1)
	size := protocol.L3HeaderSize + len(ip)
	limit := int(s.max.Load())
	if limit > 0 && size > limit && s.splits.Add(1)%probeEvery != 0 {
		return sendParts(sendDatagram, id, ip, limit)
	}
	err := sendFragment(sendDatagram, id, 0, 1, ip)
	var tooLarge *quic.DatagramTooLargeError
	if !errors.As(err, &tooLarge) {
		if err == nil && limit > 0 && size > limit {
			// The probe went through. Forget the limit until the next failure.
			s.max.CompareAndSwap(int64(limit), 0)
		}
		return err
	}
	s.max.Store(tooLarge.MaxDatagramPayloadSize)
	if perr := sendParts(sendDatagram, id, ip, int(tooLarge.MaxDatagramPayloadSize)); perr != nil {
		if perr == errCannotSplit {
			return err
		}
		return perr
	}
	return nil
}

var errCannotSplit = errors.New("l3 packet cannot be split to fit the path")

func sendParts(sendDatagram func([]byte) error, id uint32, ip []byte, maxDatagram int) error {
	count := protocol.L3FragmentCount(len(ip), maxDatagram)
	if count == 0 {
		return errCannotSplit
	}
	base := len(ip) / count
	extra := len(ip) % count
	off := 0
	for i := 0; i < count; i++ {
		n := base
		if i < extra {
			n++
		}
		if err := sendFragment(sendDatagram, id, uint8(i), uint8(count), ip[off:off+n]); err != nil {
			return err
		}
		off += n
	}
	return nil
}

func sendFragment(sendDatagram func([]byte) error, id uint32, fragID, fragCount uint8, data []byte) error {
	bp := fragPool.Get().(*[]byte)
	b := protocol.AppendL3Fragment((*bp)[:0], id, fragID, fragCount, data)
	err := sendDatagram(b)
	*bp = b[:0]
	fragPool.Put(bp)
	return err
}
