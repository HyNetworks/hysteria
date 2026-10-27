package l3frag

import (
	"bytes"
	"testing"
	"time"
)

func frag(payload []byte, n int) [][]byte {
	base := len(payload) / n
	extra := len(payload) % n
	out := make([][]byte, n)
	off := 0
	for i := 0; i < n; i++ {
		sz := base
		if i < extra {
			sz++
		}
		out[i] = payload[off : off+sz]
		off += sz
	}
	return out
}

func TestInterleavedAndReordered(t *testing.T) {
	a := &Assembler{}
	aPkt := bytes.Repeat([]byte{0x45}, 1550)
	bPkt := bytes.Repeat([]byte{0x46}, 1600)
	af := frag(aPkt, 2)
	bf := frag(bPkt, 2)

	if got := a.Feed(1, 0, 2, af[0]); got != nil {
		t.Fatal("packet A completed too early")
	}
	if got := a.Feed(2, 1, 2, bf[1]); got != nil {
		t.Fatal("packet B completed too early")
	}
	gotA := a.Feed(1, 1, 2, af[1])
	gotB := a.Feed(2, 0, 2, bf[0])
	if !bytes.Equal(gotA, aPkt) || !bytes.Equal(gotB, bPkt) {
		t.Fatalf("reassembly mismatch %d %d", len(gotA), len(gotB))
	}
}

func TestLostFragmentDoesNotComplete(t *testing.T) {
	now := time.Unix(0, 0)
	a := &Assembler{now: func() time.Time { return now }}
	pkt := bytes.Repeat([]byte{0x45}, 100)
	parts := frag(pkt, 2)
	if got := a.Feed(7, 0, 2, parts[0]); got != nil {
		t.Fatal("completed with a missing fragment")
	}
	now = now.Add(assembleTimeout + time.Millisecond)
	// The timed-out packet is discarded. A later fragment does not finish it.
	if got := a.Feed(7, 1, 2, parts[1]); got != nil {
		t.Fatal("completed a timed-out packet")
	}
}

func TestSlotOverwriteAndWrap(t *testing.T) {
	a := &Assembler{}
	first := bytes.Repeat([]byte{0x45}, 80)
	second := bytes.Repeat([]byte{0x60}, 90)
	// 1 and 65 share a slot (mod 64). The newer id replaces the unfinished packet.
	parts := frag(first, 2)
	if got := a.Feed(1, 0, 2, parts[0]); got != nil {
		t.Fatal("unexpected completion")
	}
	sp := frag(second, 2)
	if got := a.Feed(65, 0, 2, sp[0]); got != nil {
		t.Fatal("unexpected completion")
	}
	// A mismatched id overwrites the slot, so the old fragment neither
	// completes packet 65 nor leaves that packet's pieces in place.
	if got := a.Feed(1, 1, 2, parts[1]); got != nil {
		t.Fatal("old packet id completed after overwrite")
	}
	if got := a.Feed(65, 1, 2, sp[1]); got != nil {
		t.Fatal("completed packet 65 from a single fragment after overwrite")
	}
	got := a.Feed(65, 0, 2, sp[0])
	if !bytes.Equal(got, second) {
		t.Fatalf("wrapped slot packet = %d bytes", len(got))
	}

	// uint32 wrap: 0xFFFFFFFF and 64 share no slot with each other, but the id
	// itself must survive as a full 32-bit value (high bits included).
	wide := bytes.Repeat([]byte{0x45}, 40)
	wp := frag(wide, 2)
	const id = uint32(0xFFFFFFFF)
	if got := a.Feed(id, 1, 2, wp[1]); got != nil {
		t.Fatal("unexpected completion")
	}
	got = a.Feed(id, 0, 2, wp[0])
	if !bytes.Equal(got, wide) {
		t.Fatal("32-bit wrapped packet id failed to reassemble")
	}
}

func TestRejectsOversizedAndBadCount(t *testing.T) {
	a := &Assembler{}
	if got := a.Feed(3, 0, 2, bytes.Repeat([]byte{1}, 1500)); got != nil {
		t.Fatal("completed from the first fragment")
	}
	if got := a.Feed(3, 1, 2, bytes.Repeat([]byte{1}, 200)); got != nil {
		t.Fatal("completed a packet larger than 1600")
	}
	if got := a.Feed(4, 0, 1, bytes.Repeat([]byte{1}, maxPacketSize+1)); got != nil {
		t.Fatal("accepted an oversized single fragment")
	}
	if got := a.Feed(5, 0, 2, []byte{1}); got != nil {
		t.Fatal("unexpected")
	}
	if got := a.Feed(5, 1, 3, []byte{1}); got != nil {
		t.Fatal("accepted a mismatched fragment count")
	}
}

func TestSlotReuseKeepsPacketsApart(t *testing.T) {
	var a Assembler
	pktA := bytes.Repeat([]byte{0xaa}, 1500)
	pktB := bytes.Repeat([]byte{0xbb}, 900)
	var gotA []byte
	for i, f := range frag(pktA, 2) {
		if out := a.Feed(1, uint8(i), 2, f); out != nil {
			gotA = out
		}
	}
	// Packet 65 lands in the same slot with a different fragment count.
	var gotB []byte
	for i, f := range frag(pktB, 3) {
		if out := a.Feed(65, uint8(i), 3, f); out != nil {
			gotB = out
		}
	}
	if !bytes.Equal(gotA, pktA) || !bytes.Equal(gotB, pktB) {
		t.Fatalf("A ok %v, B ok %v", bytes.Equal(gotA, pktA), bytes.Equal(gotB, pktB))
	}
}
