package vxrelay

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func TestWrapKnownChecksum(t *testing.T) {
	src := netip.MustParseAddr("10.200.0.2")
	dst := netip.MustParseAddr("10.200.0.1")
	vxlan := []byte{0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0xf4, 0x00}
	pkt := Wrap(src, dst, 12345, vxlan)
	if pkt == nil {
		t.Fatal("wrap returned nil")
	}
	if got := binary.BigEndian.Uint16(pkt[10:12]); got != 0x6537 {
		t.Fatalf("ipv4 checksum = %04x, want 6537", got)
	}
	if got := binary.BigEndian.Uint16(pkt[26:28]); got != 0 {
		t.Fatalf("udp checksum = %04x, want 0 over ipv4", got)
	}
	payload, vni, ok := Unwrap(pkt, dst, src)
	if !ok || vni != 500 || string(payload) != string(vxlan) {
		t.Fatalf("unwrap = %x vni %d ok %v", payload, vni, ok)
	}
}

func TestWrapIPv6RoundTrip(t *testing.T) {
	src := netip.MustParseAddr("2001:db8::2")
	dst := netip.MustParseAddr("2001:db8::1")
	vxlan := testVXLAN(7, ethernet(0x0800, ipv4UDP(1)))
	pkt := Wrap(src, dst, 40000, vxlan)
	if pkt == nil || pkt[0]>>4 != 6 {
		t.Fatalf("wrap = %x", pkt)
	}
	if binary.BigEndian.Uint16(pkt[46:48]) == 0 {
		t.Fatal("ipv6 udp checksum is zero")
	}
	payload, vni, ok := Unwrap(pkt, dst, src)
	if !ok || vni != 7 || string(payload) != string(vxlan) {
		t.Fatalf("unwrap = vni %d ok %v", vni, ok)
	}
	pkt[20] ^= 0xff
	if _, _, ok := Unwrap(pkt, dst, src); ok {
		t.Fatal("corrupted packet was accepted")
	}
}

func TestUnwrapRejectsWrongPeer(t *testing.T) {
	src := netip.MustParseAddr("10.200.0.2")
	dst := netip.MustParseAddr("10.200.0.1")
	pkt := Wrap(src, dst, 9, testVXLAN(1, nil))
	if _, _, ok := Unwrap(pkt, dst, netip.MustParseAddr("10.200.0.3")); ok {
		t.Fatal("wrong peer was accepted")
	}
	if _, _, ok := Unwrap(pkt, netip.MustParseAddr("10.200.0.3"), src); ok {
		t.Fatal("wrong local address was accepted")
	}
}

func TestWrapDropsOversized(t *testing.T) {
	src := netip.MustParseAddr("10.200.0.2")
	dst := netip.MustParseAddr("10.200.0.1")
	if Wrap(src, dst, 1, make([]byte, maxPacket)) != nil {
		t.Fatal("oversized packet was wrapped")
	}
}

func TestFlowPortSeparatesFlows(t *testing.T) {
	base := innerFrame(10, 20)
	first := FlowPort(testVXLAN(100, base), 4789)
	again := FlowPort(testVXLAN(100, base), 1)
	if first != again || first == 4789 {
		t.Fatalf("port = %d, again %d", first, again)
	}
	other := FlowPort(testVXLAN(100, innerFrame(10, 21)), 4789)
	if first == other {
		t.Fatalf("different flows share port %d", first)
	}
	seen := map[int]struct{}{}
	for dport := uint16(1); dport <= 64; dport++ {
		seen[int(FlowPort(testVXLAN(100, innerFrame(10, dport)), 1))%32] = struct{}{}
	}
	if len(seen) < 8 {
		t.Fatalf("only %d lanes out of 64 flows", len(seen))
	}
	const arp = 0x0806
	if got := FlowPort(testVXLAN(100, ethernet(arp, []byte{1, 2, 3, 4})), 3333); got != 3333 {
		t.Fatalf("non-ip fallback = %d", got)
	}
	vlan := ethernet(0x8100, append([]byte{0x00, 0x64, 0x08, 0x00}, ipv4UDP(9)...))
	if FlowPort(testVXLAN(100, vlan), 1) == 1 {
		t.Fatal("vlan frame did not yield a flow port")
	}
}

func testVXLAN(vni uint32, frame []byte) []byte {
	buf := make([]byte, 8+len(frame))
	buf[0] = vxlanIBit
	buf[4] = byte(vni >> 16)
	buf[5] = byte(vni >> 8)
	buf[6] = byte(vni)
	copy(buf[8:], frame)
	return buf
}

func innerFrame(sport, dport uint16) []byte {
	return ethernet(0x0800, ipv4UDPPorts(sport, dport))
}

func ethernet(ether uint16, payload []byte) []byte {
	frame := make([]byte, 14+len(payload))
	frame[5] = 2
	frame[11] = 1
	binary.BigEndian.PutUint16(frame[12:14], ether)
	copy(frame[14:], payload)
	return frame
}

func ipv4UDP(dport byte) []byte {
	return ipv4UDPPorts(1000, uint16(dport))
}

func ipv4UDPPorts(sport, dport uint16) []byte {
	ip := make([]byte, 20+8)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(ip)))
	ip[8] = 64
	ip[9] = 17
	ip[12], ip[15] = 10, 1
	ip[16], ip[19] = 10, 2
	binary.BigEndian.PutUint16(ip[20:22], sport)
	binary.BigEndian.PutUint16(ip[22:24], dport)
	return ip
}
