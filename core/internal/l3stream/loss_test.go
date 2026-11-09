package l3stream

import (
	"net"
	"testing"
	"time"

	"github.com/apernet/quic-go"

	"github.com/apernet/hysteria/core/v2/internal/l3frag"
	"github.com/apernet/hysteria/core/v2/internal/protocol"
)

// Datagram fragments are not retransmitted, so a missing piece drops the IP packet.
// The same packets on a stream all arrive.
func TestStreamKeepsPacketsDatagramDrops(t *testing.T) {
	var packets [][]byte
	for i := 0; i < 20; i++ {
		packets = append(packets, udp4(uint16(1000+i), 1400))
	}

	asm := l3frag.Assembler{}
	var dgramGot int
	var seq uint32
	for _, pkt := range packets {
		seq++
		parts := protocol.SplitL3(seq, pkt, 800)
		for i, part := range parts {
			if (int(seq)+i)%10 == 0 {
				continue
			}
			frag, ok := protocol.ParseL3Fragment(part)
			if !ok {
				t.Fatal("fragment did not parse")
			}
			if asm.Feed(frag.PacketID, frag.FragID, frag.FragCount, frag.Data) != nil {
				dgramGot++
			}
		}
	}
	if dgramGot >= len(packets) {
		t.Fatalf("datagram path delivered %d/%d with loss", dgramGot, len(packets))
	}

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	g := NewLaneGroup(4)
	got := make(chan []byte, len(packets))
	if !g.Attach(0, pipeLane{client}, func(pkt []byte) {
		got <- pkt
	}) {
		t.Fatal("attach rejected")
	}
	for _, pkt := range packets {
		if err := protocol.WriteL3Frame(server, pkt); err != nil {
			t.Fatal(err)
		}
	}
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	for n := 0; n < len(packets); n++ {
		select {
		case <-got:
		case <-timer.C:
			t.Fatalf("stream delivered %d/%d", n, len(packets))
		}
	}
}

type pipeLane struct{ net.Conn }

func (p pipeLane) CancelRead(quic.StreamErrorCode)  { p.Close() }
func (p pipeLane) CancelWrite(quic.StreamErrorCode) { p.Close() }
