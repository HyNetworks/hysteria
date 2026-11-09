package l3stream

import (
	"encoding/binary"
	"testing"
)

func TestPureACK(t *testing.T) {
	cases := []struct {
		name string
		pkt  []byte
		want bool
	}{
		{"ack", wrapVXLAN(tcp4(0x10, 0, 0), 0x0800), true},
		{"ack with sack", wrapVXLAN(tcp4(0x10, 0, 12), 0x0800), true},
		{"ack psh empty", wrapVXLAN(tcp4(0x18, 0, 0), 0x0800), true},
		{"payload", wrapVXLAN(tcp4(0x10, 1, 0), 0x0800), false},
		{"synack", wrapVXLAN(tcp4(0x12, 0, 0), 0x0800), false},
		{"finack", wrapVXLAN(tcp4(0x11, 0, 0), 0x0800), false},
		{"rst", wrapVXLAN(tcp4(0x04, 0, 0), 0x0800), false},
		{"ipv6 ack", wrapVXLAN(tcp6(0x10, 0), 0x86dd), true},
		{"ipv6 payload", wrapVXLAN(tcp6(0x10, 8), 0x86dd), false},
		{"inner udp", wrapVXLAN(innerUDP(), 0x0800), false},
		{"not vxlan", tcp4(0x10, 0, 0), false},
		{"padded ack", wrapVXLAN(pad(tcp4(0x10, 0, 0), 20), 0x0800), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := PureACK(tc.pkt); got != tc.want {
				t.Fatalf("PureACK = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestPureACKRejectsOversized(t *testing.T) {
	pkt := wrapVXLAN(tcp4(0x10, 0, 0), 0x0800)
	pkt = append(pkt, make([]byte, pureACKMax)...)
	if PureACK(pkt) {
		t.Fatal("oversized packet classified as a pure ACK")
	}
}

func TestPureACKRejectsMissingIBit(t *testing.T) {
	pkt := wrapVXLAN(tcp4(0x10, 0, 0), 0x0800)
	pkt[28] = 0
	if PureACK(pkt) {
		t.Fatal("VXLAN without the I bit classified as a pure ACK")
	}
}

func wrapVXLAN(inner []byte, ether uint16) []byte {
	frame := make([]byte, 14+len(inner))
	binary.BigEndian.PutUint16(frame[12:14], ether)
	copy(frame[14:], inner)
	vxlan := make([]byte, 8+len(frame))
	vxlan[0] = vxlanIBit
	copy(vxlan[8:], frame)
	udpLen := 8 + len(vxlan)
	ip := make([]byte, 20+udpLen)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(ip)))
	ip[9] = 17
	binary.BigEndian.PutUint16(ip[20:22], 40000)
	binary.BigEndian.PutUint16(ip[22:24], vxlanPort)
	binary.BigEndian.PutUint16(ip[24:26], uint16(udpLen))
	copy(ip[28:], vxlan)
	return ip
}

func tcp4(flags byte, payload, opt int) []byte {
	tcpLen := 20 + opt
	total := 20 + tcpLen + payload
	ip := make([]byte, total)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(total))
	ip[9] = 6
	ip[20+12] = byte((tcpLen / 4) << 4)
	ip[20+13] = flags
	return ip
}

func tcp6(flags byte, payload int) []byte {
	ip := make([]byte, 40+20+payload)
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:6], uint16(20+payload))
	ip[6] = 6
	ip[40+12] = 5 << 4
	ip[40+13] = flags
	return ip
}

func innerUDP() []byte {
	ip := make([]byte, 28)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], 28)
	ip[9] = 17
	return ip
}

func pad(pkt []byte, n int) []byte {
	return append(pkt, make([]byte, n)...)
}

func TestDatagram(t *testing.T) {
	cases := []struct {
		name string
		pkt  []byte
		want bool
	}{
		{"inner tcp data", wrapVXLAN(tcp4(0x10, 1, 0), 0x0800), false},
		{"inner synack", wrapVXLAN(tcp4(0x12, 0, 0), 0x0800), false},
		{"inner pure ack", wrapVXLAN(tcp4(0x10, 0, 0), 0x0800), true},
		{"inner udp", wrapVXLAN(innerUDP(), 0x0800), true},
		{"inner arp", wrapVXLAN(make([]byte, 28), 0x0806), true},
		{"ipv6 tcp data", wrapVXLAN(tcp6(0x10, 8), 0x86dd), false},
		{"bare tcp", tcp4(0x10, 1, 0), false},
		{"bare udp", innerUDP(), true},
	}
	for _, tc := range cases {
		if got := Datagram(tc.pkt); got != tc.want {
			t.Errorf("%s: Datagram = %v, want %v", tc.name, got, tc.want)
		}
	}
}
