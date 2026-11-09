package l3stream

import (
	"encoding/binary"
	"testing"
)

func TestLaneUsesUDPSourcePort(t *testing.T) {
	a := udp4(1000, 8)
	b := udp4(1001, 8)
	if Lane(a, 8) == Lane(b, 8) {
		t.Fatalf("ports 1000 and 1001 share lane %d", Lane(a, 8))
	}
	if Lane(a, 8) != Lane(udp4(1000, 20), 8) {
		t.Fatal("same source port moved lanes")
	}
	tcp := udp4(1000, 8)
	tcp[9] = 6
	if Lane(tcp, 8) != 0 {
		t.Fatalf("tcp lane = %d", Lane(tcp, 8))
	}
	v6 := make([]byte, 48)
	v6[0] = 0x60
	v6[6] = 17
	binary.BigEndian.PutUint16(v6[40:42], 1000)
	if Lane(v6, 8) != int(1000%8) {
		t.Fatalf("ipv6 lane = %d", Lane(v6, 8))
	}
}

func udp4(src uint16, payload int) []byte {
	ip := make([]byte, 20+8+payload)
	ip[0] = 0x45
	ip[9] = 17
	binary.BigEndian.PutUint16(ip[20:22], src)
	binary.BigEndian.PutUint16(ip[22:24], 4789)
	return ip
}
