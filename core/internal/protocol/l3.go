package protocol

import "encoding/binary"

const (
	// L3HeaderSize is the fixed prefix of an L3 datagram.
	//
	//	SessionID u32 = 0 | PacketID low 16 | FragID u8 | FragCount u8 | 0x00 | PacketID high 16 | IP packet
	//
	// SessionID 0 and the zero address-length byte keep this distinct from UDPMessage.
	// ParseUDPMessage rejects a zero address length, so an old peer drops the datagram.
	L3HeaderSize    = 11
	L3MaxPacketSize = 1600
)

// L3Fragment is one piece of an IP packet carried in a QUIC datagram.
type L3Fragment struct {
	PacketID  uint32
	FragID    uint8
	FragCount uint8
	Data      []byte
}

// ParseL3Fragment reports whether msg is an L3 datagram and, when it is, the fragment.
// A datagram that merely shares the UDPMessage prefix but is not valid L3 returns false
// so the caller can try ParseUDPMessage.
func ParseL3Fragment(msg []byte) (L3Fragment, bool) {
	if len(msg) <= L3HeaderSize || binary.BigEndian.Uint32(msg[0:4]) != 0 || msg[8] != 0 {
		return L3Fragment{}, false
	}
	fragCount := msg[7]
	fragID := msg[6]
	if fragCount == 0 || fragID >= fragCount {
		return L3Fragment{}, false
	}
	lo := binary.BigEndian.Uint16(msg[4:6])
	hi := binary.BigEndian.Uint16(msg[9:11])
	return L3Fragment{
		PacketID:  uint32(hi)<<16 | uint32(lo),
		FragID:    fragID,
		FragCount: fragCount,
		Data:      msg[L3HeaderSize:],
	}, true
}

// L3FragmentCount is how many even pieces an IP packet of size n needs so each
// fits in maxDatagram. It returns 0 when the packet cannot be carried.
func L3FragmentCount(n, maxDatagram int) int {
	if n <= 0 || n > L3MaxPacketSize || maxDatagram <= L3HeaderSize {
		return 0
	}
	maxPayload := maxDatagram - L3HeaderSize
	count := (n + maxPayload - 1) / maxPayload
	if count > 255 {
		return 0
	}
	return count
}

// AppendL3Fragment appends one L3 datagram to dst.
func AppendL3Fragment(dst []byte, packetID uint32, fragID, fragCount uint8, data []byte) []byte {
	var hdr [L3HeaderSize]byte
	binary.BigEndian.PutUint16(hdr[4:6], uint16(packetID))
	hdr[6] = fragID
	hdr[7] = fragCount
	binary.BigEndian.PutUint16(hdr[9:11], uint16(packetID>>16))
	dst = append(dst, hdr[:]...)
	dst = append(dst, data...)
	return dst
}

// SplitL3 splits an IP packet into evenly sized L3 datagrams that each fit in maxDatagram.
// maxDatagram is the largest QUIC datagram payload the peer currently accepts.
// It returns nil when the packet cannot be carried.
func SplitL3(packetID uint32, ip []byte, maxDatagram int) [][]byte {
	count := L3FragmentCount(len(ip), maxDatagram)
	if count == 0 {
		return nil
	}
	base := len(ip) / count
	extra := len(ip) % count
	out := make([][]byte, 0, count)
	off := 0
	for i := 0; i < count; i++ {
		n := base
		if i < extra {
			n++
		}
		out = append(out, AppendL3Fragment(nil, packetID, uint8(i), uint8(count), ip[off:off+n]))
		off += n
	}
	return out
}
