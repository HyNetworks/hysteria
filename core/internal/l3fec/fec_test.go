package l3fec

import (
	"bytes"
	"math/rand"
	"testing"
	"time"
)

func TestGFInv(t *testing.T) {
	if mul(1, 1) != 1 || mul(0, 7) != 0 {
		t.Fatal("mul identity")
	}
	for a := 1; a < 256; a++ {
		if mul(byte(a), inv(byte(a))) != 1 {
			t.Fatalf("inv %d", a)
		}
	}
}

func TestEncodeRecoverMixed(t *testing.T) {
	pkts := [][]byte{
		bytes.Repeat([]byte{0x45}, 40),
		bytes.Repeat([]byte{0x60}, 100),
		bytes.Repeat([]byte{0xab}, 1500),
		{0x01, 0x02, 0x03},
	}
	blobs := Encode(7, pkts)
	if len(blobs) != len(pkts)+ParityCount(len(pkts)) {
		t.Fatalf("blobs %d", len(blobs))
	}
	data := map[int][]byte{}
	par := map[int][]byte{}
	for _, b := range blobs {
		c, ok := Unpack(b)
		if !ok {
			t.Fatal("unpack")
		}
		if c.Index < c.K {
			data[c.Index] = c.Payload
		} else {
			par[c.Index-c.K] = c.Payload
		}
	}
	delete(data, 1)
	delete(data, 2)
	got, ok := Recover(len(pkts), data, par)
	if !ok {
		t.Fatal("recover")
	}
	for i := range pkts {
		if !bytes.Equal(got[i], pkts[i]) {
			t.Fatalf("pkt %d got %d want %d", i, len(got[i]), len(pkts[i]))
		}
	}
}

func TestLossyGroups(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	out := make(chan []byte, 64)
	asm := NewAssembler(out)
	var got [][]byte
	done := make(chan struct{})
	go func() {
		for p := range out {
			got = append(got, p)
		}
		close(done)
	}()
	var want [][]byte
	now := time.Now()
	const groups = 80
	for g := 0; g < groups; g++ {
		k := 32
		if g%11 == 0 {
			k = 1 + rng.Intn(7)
		}
		pkts := make([][]byte, k)
		for i := 0; i < k; i++ {
			n := 20 + rng.Intn(1400)
			pkts[i] = make([]byte, n)
			pkts[i][0] = byte(g)
			pkts[i][1] = byte(i)
			want = append(want, pkts[i])
		}
		blobs := Encode(uint32(g), pkts)
		rng.Shuffle(len(blobs), func(i, j int) { blobs[i], blobs[j] = blobs[j], blobs[i] })
		for _, b := range blobs {
			if rng.Float64() < 0.10 {
				continue
			}
			asm.Push(b, now)
		}
		now = now.Add(time.Millisecond)
	}
	close(out)
	<-done
	if len(got) != len(want) {
		t.Fatalf("got %d want %d", len(got), len(want))
	}
	for i := range want {
		if !bytes.Equal(got[i], want[i]) {
			t.Fatalf("mismatch at %d", i)
		}
	}
}
