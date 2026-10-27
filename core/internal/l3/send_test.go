package l3

import (
	"bytes"
	"testing"

	"github.com/apernet/quic-go"

	"github.com/apernet/hysteria/core/v2/internal/l3frag"
	"github.com/apernet/hysteria/core/v2/internal/protocol"
)

func TestSendEvenSplitAndInterleavedReassembly(t *testing.T) {
	var s Sender
	var datagrams [][]byte
	send := func(b []byte) error {
		if len(b) > 1200 {
			return &quic.DatagramTooLargeError{MaxDatagramPayloadSize: 1200}
		}
		datagrams = append(datagrams, append([]byte(nil), b...))
		return nil
	}
	pktA := bytes.Repeat([]byte{0x45}, 1600)
	pktB := bytes.Repeat([]byte{0x60}, 1500)
	if err := s.Send(send, pktA); err != nil {
		t.Fatal(err)
	}
	if err := s.Send(send, pktB); err != nil {
		t.Fatal(err)
	}
	if len(datagrams) != 4 {
		t.Fatalf("datagrams = %d, want 4", len(datagrams))
	}
	// 1600 bytes, payload budget 1189, two equal pieces of 800.
	f0, ok := protocol.ParseL3Fragment(datagrams[0])
	if !ok || len(f0.Data) != 800 || f0.FragCount != 2 {
		t.Fatalf("first fragment = %+v len %d", f0, len(f0.Data))
	}
	if _, err := protocol.ParseUDPMessage(datagrams[0]); err == nil {
		t.Fatal("UDP parser accepted an L3 datagram")
	}

	asm := &l3frag.Assembler{}
	// A0, B0, B1, A1 — the two packets are in flight together.
	order := []int{0, 2, 3, 1}
	var gotA, gotB []byte
	for _, i := range order {
		f, ok := protocol.ParseL3Fragment(datagrams[i])
		if !ok {
			t.Fatalf("datagram %d is not L3", i)
		}
		got := asm.Feed(f.PacketID, f.FragID, f.FragCount, f.Data)
		if got == nil {
			continue
		}
		switch got[0] {
		case 0x45:
			gotA = got
		case 0x60:
			gotB = got
		}
	}
	if !bytes.Equal(gotA, pktA) || !bytes.Equal(gotB, pktB) {
		t.Fatalf("reassembly A=%d B=%d", len(gotA), len(gotB))
	}
}

func TestSenderRemembersPathLimit(t *testing.T) {
	var s Sender
	var calls, whole int
	send := func(b []byte) error {
		calls++
		if len(b) > 1200 {
			whole++
			return &quic.DatagramTooLargeError{MaxDatagramPayloadSize: 1200}
		}
		return nil
	}
	pkt := bytes.Repeat([]byte{0x45}, 1500)
	for i := 0; i < 3; i++ {
		if err := s.Send(send, pkt); err != nil {
			t.Fatal(err)
		}
	}
	// One failed whole attempt, then two pieces per packet.
	if whole != 1 || calls != 1+3*2 {
		t.Fatalf("whole = %d calls = %d", whole, calls)
	}
	if err := s.Send(send, []byte{0x45, 0x00}); err != nil || calls != 8 {
		t.Fatalf("small packet: err %v calls %d", err, calls)
	}
}

func TestSenderProbesForLargerPath(t *testing.T) {
	var s Sender
	limit := 1200
	var whole int
	send := func(b []byte) error {
		if len(b) > limit {
			return &quic.DatagramTooLargeError{MaxDatagramPayloadSize: int64(limit)}
		}
		if len(b) > 1200 {
			whole++
		}
		return nil
	}
	pkt := bytes.Repeat([]byte{0x45}, 1500)
	_ = s.Send(send, pkt)
	limit = 1600 // the path MTU grew
	for i := 0; i < probeEvery; i++ {
		_ = s.Send(send, pkt)
	}
	if whole != 1 {
		t.Fatalf("whole sends after growth = %d, want the probe", whole)
	}
	_ = s.Send(send, pkt)
	if whole != 2 {
		t.Fatal("limit was not forgotten after a successful probe")
	}
}
