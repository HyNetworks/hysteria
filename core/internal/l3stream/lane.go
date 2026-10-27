package l3stream

import "encoding/binary"

// Lane picks a stream for an IP packet on hytun0.
// VXLAN's outer header is UDP, and Linux fills the source port from the inner flow.
// Packets of one inner flow stay on one lane. Anything else uses lane 0.
func Lane(ip []byte, n int) int {
	if n <= 1 {
		return 0
	}
	port, ok := udpSourcePort(ip)
	if !ok {
		return 0
	}
	return int(port) % n
}

func udpSourcePort(ip []byte) (uint16, bool) {
	if len(ip) < 1 {
		return 0, false
	}
	switch ip[0] >> 4 {
	case 4:
		ihl := int(ip[0]&0x0f) * 4
		if ihl < 20 || len(ip) < ihl+4 || ip[9] != 17 {
			return 0, false
		}
		return binary.BigEndian.Uint16(ip[ihl : ihl+2]), true
	case 6:
		if len(ip) < 40+4 || ip[6] != 17 {
			return 0, false
		}
		return binary.BigEndian.Uint16(ip[40 : 40+2]), true
	default:
		return 0, false
	}
}
