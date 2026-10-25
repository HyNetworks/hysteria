package l3stream

import "encoding/binary"

// pureACKMax is the largest outer packet sent as one unreliable datagram.
// A pure ACK is far smaller than this. Anything bigger stays on a reliable stream
// so it is never split across datagrams.
const pureACKMax = 512

const (
	vxlanPort = 4789
	vxlanIBit = 0x08
)

// PureACK reports whether pkt is one VXLAN frame whose inner TCP segment is
// only an acknowledgement: no payload, ACK set, and no SYN, FIN, or RST.
// The packet must also fit in a single datagram. Anything else returns false
// and keeps the reliable stream path.
func PureACK(pkt []byte) bool {
	if len(pkt) == 0 || len(pkt) > pureACKMax {
		return false
	}
	inner, ok := vxlanInner(pkt)
	if !ok {
		return false
	}
	return tcpACKOnly(inner)
}

// Datagram reports whether hybrid mode sends pkt as an unreliable datagram.
// Inner TCP stays on its reliable stream, except a pure ACK. Everything else,
// such as UDP, ICMP and ARP, goes as a datagram: a lost packet costs only
// itself, and a later one is not held behind its retransmission.
// A packet that is not VXLAN is judged by its own protocol.
func Datagram(pkt []byte) bool {
	inner, ok := vxlanInner(pkt)
	if !ok {
		inner = pkt
	}
	if _, isTCP := tcpSegment(inner); !isTCP {
		return true
	}
	return len(pkt) <= pureACKMax && tcpACKOnly(inner)
}

func vxlanInner(pkt []byte) ([]byte, bool) {
	udp, ok := udpHeader(pkt)
	if !ok || len(udp) < 8+8+14 {
		return nil, false
	}
	if binary.BigEndian.Uint16(udp[2:4]) != vxlanPort || udp[8]&vxlanIBit == 0 {
		return nil, false
	}
	frame := udp[16:]
	off := 12
	if len(frame) < 14 {
		return nil, false
	}
	ether := binary.BigEndian.Uint16(frame[off : off+2])
	off += 2
	if ether == 0x8100 || ether == 0x88a8 {
		if len(frame) < off+4 {
			return nil, false
		}
		ether = binary.BigEndian.Uint16(frame[off+2 : off+4])
		off += 4
	}
	if ether != 0x0800 && ether != 0x86dd {
		return nil, false
	}
	if off > len(frame) {
		return nil, false
	}
	return frame[off:], true
}

func udpHeader(ip []byte) ([]byte, bool) {
	if len(ip) < 1 {
		return nil, false
	}
	switch ip[0] >> 4 {
	case 4:
		ihl := int(ip[0]&0x0f) * 4
		if ihl < 20 || len(ip) < ihl+8 || ip[9] != 17 {
			return nil, false
		}
		return ip[ihl:], true
	case 6:
		if len(ip) < 40+8 || ip[6] != 17 {
			return nil, false
		}
		return ip[40:], true
	default:
		return nil, false
	}
}

func tcpACKOnly(ip []byte) bool {
	tcp, ok := tcpSegment(ip)
	if !ok {
		return false
	}
	dataOff := int(tcp[12]>>4) * 4
	if dataOff < 20 || len(tcp) < dataOff || len(tcp) != dataOff {
		return false
	}
	const (
		fin = 0x01
		syn = 0x02
		rst = 0x04
		ack = 0x10
	)
	flags := tcp[13]
	return flags&ack != 0 && flags&(syn|fin|rst) == 0
}

func tcpSegment(ip []byte) ([]byte, bool) {
	if len(ip) < 1 {
		return nil, false
	}
	switch ip[0] >> 4 {
	case 4:
		ihl := int(ip[0]&0x0f) * 4
		if ihl < 20 || len(ip) < ihl+20 || ip[9] != 6 {
			return nil, false
		}
		total := int(binary.BigEndian.Uint16(ip[2:4]))
		if total < ihl+20 || total > len(ip) {
			return nil, false
		}
		return ip[ihl:total], true
	case 6:
		if len(ip) < 40+20 || ip[6] != 6 {
			return nil, false
		}
		payloadLen := int(binary.BigEndian.Uint16(ip[4:6]))
		if payloadLen < 20 || 40+payloadLen > len(ip) {
			return nil, false
		}
		return ip[40 : 40+payloadLen], true
	default:
		return nil, false
	}
}
