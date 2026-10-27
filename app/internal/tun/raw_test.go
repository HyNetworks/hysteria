package tun

import (
	"net/netip"
	"testing"
)

func TestPacketSource(t *testing.T) {
	v4 := make([]byte, 20)
	v4[0] = 0x45
	copy(v4[12:16], []byte{10, 200, 0, 2})
	got, ok := packetSource(v4)
	if !ok || got != netip.MustParseAddr("10.200.0.2") {
		t.Fatalf("v4 source = %v %v", got, ok)
	}
	v6 := make([]byte, 40)
	v6[0] = 0x60
	addr := netip.MustParseAddr("2001:db8::1").As16()
	copy(v6[8:24], addr[:])
	got, ok = packetSource(v6)
	if !ok || got != netip.MustParseAddr("2001:db8::1") {
		t.Fatalf("v6 source = %v %v", got, ok)
	}
	if _, ok := packetSource([]byte{0x45, 0x00}); ok {
		t.Fatal("short ipv4 accepted")
	}
}

func TestNewRawRejectsBadPeer(t *testing.T) {
	_, err := NewRaw("hytun0", 1600, netip.MustParsePrefix("10.200.0.1/30"), netip.MustParseAddr("2001:db8::1"))
	if err == nil {
		t.Fatal("mixed IP versions were accepted")
	}
}

func udp4(src, dst string, dport uint16, fragOff uint16) []byte {
	pkt := make([]byte, 20+8)
	pkt[0] = 0x45
	pkt[6], pkt[7] = byte(fragOff>>8), byte(fragOff)
	pkt[9] = 17
	s, d := netip.MustParseAddr(src).As4(), netip.MustParseAddr(dst).As4()
	copy(pkt[12:16], s[:])
	copy(pkt[16:20], d[:])
	pkt[22], pkt[23] = byte(dport>>8), byte(dport)
	return pkt
}

func TestRawAcceptsOnlyVXLANToSelf(t *testing.T) {
	r, err := NewRaw("hytun0", 1600, netip.MustParsePrefix("10.200.0.1/30"), netip.MustParseAddr("10.200.0.2"))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		pkt  []byte
		want bool
	}{
		{"vxlan", udp4("10.200.0.2", "10.200.0.1", 4789, 0), true},
		{"later fragment", udp4("10.200.0.2", "10.200.0.1", 0, 185), true},
		{"other port", udp4("10.200.0.2", "10.200.0.1", 53, 0), false},
		{"other destination", udp4("10.200.0.2", "169.254.169.254", 4789, 0), false},
		{"spoofed source", udp4("10.200.0.3", "10.200.0.1", 4789, 0), false},
	}
	tcp := udp4("10.200.0.2", "10.200.0.1", 4789, 0)
	tcp[9] = 6
	cases = append(cases, struct {
		name string
		pkt  []byte
		want bool
	}{"tcp", tcp, false})
	for _, c := range cases {
		if got := r.accepts(c.pkt); got != c.want {
			t.Errorf("%s: accepts = %v, want %v", c.name, got, c.want)
		}
	}
	r.VXLANOnly = false
	if !r.accepts(udp4("10.200.0.2", "169.254.169.254", 53, 0)) {
		t.Fatal("filter none still checked the destination")
	}
}

func TestIsVXLANTo6(t *testing.T) {
	local := netip.MustParseAddr("fd00::1")
	pkt := make([]byte, 40+8)
	pkt[0] = 0x60
	pkt[6] = 17
	d := local.As16()
	copy(pkt[24:40], d[:])
	pkt[42], pkt[43] = 0x12, 0xb5
	if !isVXLANTo(pkt, local) {
		t.Fatal("ipv6 vxlan rejected")
	}
	pkt[6] = 44
	if isVXLANTo(pkt, local) {
		t.Fatal("ipv6 fragment accepted")
	}
}
