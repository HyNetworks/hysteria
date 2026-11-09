package vxrelay

import (
	"encoding/binary"
	"net/netip"
)

const (
	vxlanPort = 4789
	vxlanIBit = 0x08
	// maxPacket matches the L3 tunnel ceiling. A larger datagram cannot be carried.
	maxPacket = 1600

	ipv4Header = 20
	ipv6Header = 40
	udpHeader  = 8
)

// Wrap builds an outer IP/UDP packet whose payload is one VXLAN datagram.
// Over IPv4 the UDP checksum is left at zero, as RFC 7348 recommends: QUIC
// already authenticates every byte, and summing 1.5 KB per packet buys nothing.
// IPv6 requires a checksum, so it is computed there.
// The UDP destination port is always 4789, which is what a kernel VTEP listens on.
// sport selects the QUIC stream lane. The result is nil when it would exceed
// the tunnel ceiling or the addresses are not a matching pair.
func Wrap(src, dst netip.Addr, sport uint16, vxlan []byte) []byte {
	src = src.Unmap()
	dst = dst.Unmap()
	if !src.IsValid() || !dst.IsValid() || src.Is4() != dst.Is4() || len(vxlan) == 0 {
		return nil
	}
	if sport == 0 {
		sport = 1
	}
	if src.Is4() {
		return wrap4(src, dst, sport, vxlan)
	}
	return wrap6(src, dst, sport, vxlan)
}

func wrap4(src, dst netip.Addr, sport uint16, vxlan []byte) []byte {
	total := ipv4Header + udpHeader + len(vxlan)
	if total > maxPacket {
		return nil
	}
	pkt := make([]byte, total)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(total))
	pkt[8] = 64
	pkt[9] = 17
	src4, dst4 := src.As4(), dst.As4()
	copy(pkt[12:16], src4[:])
	copy(pkt[16:20], dst4[:])
	binary.BigEndian.PutUint16(pkt[10:12], checksum(sumBytes(0, pkt[:ipv4Header])))
	putUDP(pkt[ipv4Header:], sport, vxlan)
	return pkt
}

func wrap6(src, dst netip.Addr, sport uint16, vxlan []byte) []byte {
	total := ipv6Header + udpHeader + len(vxlan)
	if total > maxPacket {
		return nil
	}
	pkt := make([]byte, total)
	pkt[0] = 0x60
	binary.BigEndian.PutUint16(pkt[4:6], uint16(udpHeader+len(vxlan)))
	pkt[6] = 17
	pkt[7] = 64
	src6, dst6 := src.As16(), dst.As16()
	copy(pkt[8:24], src6[:])
	copy(pkt[24:40], dst6[:])
	udp := pkt[ipv6Header:]
	putUDP(udp, sport, vxlan)
	binary.BigEndian.PutUint16(udp[6:8], udpChecksum(src, dst, udp))
	return pkt
}

// putUDP writes the UDP header with a zero checksum, then the payload.
func putUDP(udp []byte, sport uint16, payload []byte) {
	binary.BigEndian.PutUint16(udp[0:2], sport)
	binary.BigEndian.PutUint16(udp[2:4], vxlanPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpHeader+len(payload)))
	copy(udp[udpHeader:], payload)
}

// Unwrap checks that pkt is a UDP datagram for this relay: the source is peer,
// the destination is local, the destination port is 4789, and the payload is
// VXLAN with the I bit set. payload aliases pkt. The UDP checksum is not
// verified: the packet came out of an authenticated QUIC connection.
func Unwrap(pkt []byte, local, peer netip.Addr) (payload []byte, vni uint32, ok bool) {
	udp, ok := udpPayload(pkt, local.Unmap(), peer.Unmap())
	if !ok {
		return nil, 0, false
	}
	vni, ok = parseVNI(udp)
	if !ok {
		return nil, 0, false
	}
	return udp, vni, true
}

// parseVNI reads the network identifier from a VXLAN datagram.
// The I bit must be set. Anything shorter is rejected.
func parseVNI(vxlan []byte) (uint32, bool) {
	if len(vxlan) < udpHeader || vxlan[0]&vxlanIBit == 0 {
		return 0, false
	}
	return uint32(vxlan[4])<<16 | uint32(vxlan[5])<<8 | uint32(vxlan[6]), true
}

// FlowPort is the outer UDP source port used to spread inner flows across
// QUIC streams. A VTEP such as RouterOS may send every flow from one fixed
// port, so the original port is only a fallback for frames that are not IP.
func FlowPort(vxlan []byte, fallback uint16) uint16 {
	if port, ok := innerFlowPort(vxlan); ok {
		return port
	}
	if fallback == 0 {
		return 1
	}
	return fallback
}

func udpPayload(pkt []byte, local, peer netip.Addr) ([]byte, bool) {
	if len(pkt) < 1 || !local.IsValid() || !peer.IsValid() {
		return nil, false
	}
	var udp []byte
	switch pkt[0] >> 4 {
	case 4:
		if !local.Is4() || !peer.Is4() || len(pkt) < ipv4Header {
			return nil, false
		}
		ihl := int(pkt[0]&0x0f) * 4
		if ihl < ipv4Header || len(pkt) < ihl+udpHeader {
			return nil, false
		}
		total := int(binary.BigEndian.Uint16(pkt[2:4]))
		if total < ihl+udpHeader || total > len(pkt) {
			return nil, false
		}
		if pkt[9] != 17 || pkt[6]&0x3f != 0 || pkt[7] != 0 {
			return nil, false
		}
		if !headerChecksumOK(pkt[:ihl]) {
			return nil, false
		}
		if netip.AddrFrom4(([4]byte)(pkt[12:16])) != peer || netip.AddrFrom4(([4]byte)(pkt[16:20])) != local {
			return nil, false
		}
		udp = pkt[ihl:total]
	case 6:
		if local.Is4() || peer.Is4() || len(pkt) < ipv6Header+udpHeader {
			return nil, false
		}
		if pkt[6] != 17 {
			return nil, false
		}
		payloadLen := int(binary.BigEndian.Uint16(pkt[4:6]))
		if payloadLen < udpHeader || ipv6Header+payloadLen > len(pkt) {
			return nil, false
		}
		if netip.AddrFrom16(([16]byte)(pkt[8:24])) != peer || netip.AddrFrom16(([16]byte)(pkt[24:40])) != local {
			return nil, false
		}
		udp = pkt[ipv6Header : ipv6Header+payloadLen]
	default:
		return nil, false
	}
	length := int(binary.BigEndian.Uint16(udp[4:6]))
	if length < udpHeader || length > len(udp) {
		return nil, false
	}
	if binary.BigEndian.Uint16(udp[2:4]) != vxlanPort {
		return nil, false
	}
	return udp[udpHeader:length], true
}

func headerChecksumOK(hdr []byte) bool {
	return checksum(sumBytes(0, hdr)) == 0
}

func udpChecksum(src, dst netip.Addr, udp []byte) uint16 {
	saved := binary.BigEndian.Uint16(udp[6:8])
	udp[6], udp[7] = 0, 0
	var sum uint32
	if src.Is4() {
		s, d := src.As4(), dst.As4()
		sum = sumBytes(0, s[:])
		sum = sumBytes(sum, d[:])
		sum += 17
		sum += uint32(len(udp))
	} else {
		s, d := src.As16(), dst.As16()
		sum = sumBytes(0, s[:])
		sum = sumBytes(sum, d[:])
		sum += uint32(len(udp) >> 16)
		sum += uint32(len(udp) & 0xffff)
		sum += 17
	}
	sum = sumBytes(sum, udp)
	binary.BigEndian.PutUint16(udp[6:8], saved)
	c := checksum(sum)
	if c == 0 {
		// A computed zero is transmitted as 0xffff. Zero itself means "absent".
		return 0xffff
	}
	return c
}

func checksum(sum uint32) uint16 {
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func sumBytes(sum uint32, b []byte) uint32 {
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	return sum
}

func innerFlowPort(vxlan []byte) (uint16, bool) {
	ip, ok := innerIP(vxlan)
	if !ok || len(ip) < 1 {
		return 0, false
	}
	var h uint32
	switch ip[0] >> 4 {
	case 4:
		ihl := int(ip[0]&0x0f) * 4
		if ihl < ipv4Header || len(ip) < ihl {
			return 0, false
		}
		frag := binary.BigEndian.Uint16(ip[6:8])
		h = hashParts(ip[12:16], ip[16:20], []byte{ip[9]})
		if frag&0x3fff != 0 {
			h = hashParts(ip[12:16], ip[16:20], ip[4:6], []byte{ip[9]})
		} else if portBytes, ok := transportPorts(ip[ihl:], ip[9]); ok {
			h = hashParts(ip[12:16], ip[16:20], []byte{ip[9]}, portBytes)
		}
	case 6:
		if len(ip) < ipv6Header {
			return 0, false
		}
		h = hashParts(ip[8:24], ip[24:40], []byte{ip[6]})
		if portBytes, ok := transportPorts(ip[ipv6Header:], ip[6]); ok {
			h = hashParts(ip[8:24], ip[24:40], []byte{ip[6]}, portBytes)
		}
	default:
		return 0, false
	}
	return uint16(h%65535) + 1, true
}

func transportPorts(seg []byte, proto byte) ([]byte, bool) {
	if proto != 6 && proto != 17 || len(seg) < 4 {
		return nil, false
	}
	return seg[:4], true
}

func innerIP(vxlan []byte) ([]byte, bool) {
	if len(vxlan) < 8+14 || vxlan[0]&vxlanIBit == 0 {
		return nil, false
	}
	frame := vxlan[8:]
	off := 12
	if len(frame) < 14 {
		return nil, false
	}
	ether := binary.BigEndian.Uint16(frame[off : off+2])
	off += 2
	for n := 0; n < 2 && (ether == 0x8100 || ether == 0x88a8); n++ {
		if len(frame) < off+4 {
			return nil, false
		}
		ether = binary.BigEndian.Uint16(frame[off+2 : off+4])
		off += 4
	}
	if ether != 0x0800 && ether != 0x86dd || off > len(frame) {
		return nil, false
	}
	return frame[off:], true
}

func hashParts(parts ...[]byte) uint32 {
	h := uint32(2166136261)
	for _, p := range parts {
		for _, b := range p {
			h ^= uint32(b)
			h *= 16777619
		}
	}
	return h
}
