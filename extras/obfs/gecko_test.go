package obfs

import (
	"bytes"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/ipv4"
)

// --- in-memory packet pipe ---

// memEnd is one side of a bidirectional, lossy in-memory packet pipe.
type memEnd struct {
	addr  net.Addr
	other *memEnd

	mu     sync.Mutex
	closed bool
	done   chan struct{}
	inbox  chan memPacket

	writeCount atomic.Int64
	dropFn     func(idx int) bool // optional: return true to drop the n-th outgoing packet
}

type memPacket struct {
	src  net.Addr
	data []byte
}

func newMemPipe(aAddr, bAddr net.Addr) (*memEnd, *memEnd) {
	a := &memEnd{addr: aAddr, inbox: make(chan memPacket, 1024), done: make(chan struct{})}
	b := &memEnd{addr: bAddr, inbox: make(chan memPacket, 1024), done: make(chan struct{})}
	a.other = b
	b.other = a
	return a, b
}

func (e *memEnd) WriteTo(p []byte, _ net.Addr) (int, error) {
	idx := int(e.writeCount.Add(1) - 1)
	if e.dropFn != nil && e.dropFn(idx) {
		return len(p), nil
	}
	cp := make([]byte, len(p))
	copy(cp, p)
	select {
	case e.other.inbox <- memPacket{src: e.addr, data: cp}:
	case <-e.other.done:
	}
	return len(p), nil
}

func (e *memEnd) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case pkt := <-e.inbox:
		return copy(p, pkt.data), pkt.src, nil
	case <-e.done:
		return 0, nil, net.ErrClosed
	}
}

func (e *memEnd) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return nil
	}
	e.closed = true
	close(e.done)
	return nil
}

func (e *memEnd) LocalAddr() net.Addr              { return e.addr }
func (e *memEnd) SetDeadline(time.Time) error      { return nil }
func (e *memEnd) SetReadDeadline(time.Time) error  { return nil }
func (e *memEnd) SetWriteDeadline(time.Time) error { return nil }

// pendingInbox returns the count of buffered, undelivered packets on this end.
func (e *memEnd) pendingInbox() int { return len(e.inbox) }

// --- helpers ---

func mustWrapGecko(t *testing.T, conn net.PacketConn, password string) net.PacketConn {
	t.Helper()
	g, err := WrapPacketConnGecko(conn, GeckoOptions{Password: []byte(password)})
	if err != nil {
		t.Fatalf("WrapPacketConnGecko: %v", err)
	}
	return g
}

func makeAddrs() (a, b net.Addr) {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1111},
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2222}
}

// quicLong / quicShort produce realistic-looking QUIC payloads of n bytes
// with the appropriate top-bit on byte 0 to trigger / avoid fragmentation.
func quicLong(n int) []byte {
	p := make([]byte, n)
	rand.New(rand.NewSource(1)).Read(p)
	p[0] = 0xc0
	return p
}

func quicShort(n int) []byte {
	p := make([]byte, n)
	rand.New(rand.NewSource(2)).Read(p)
	p[0] = 0x40
	return p
}

// --- tests ---

func TestGeckoRoundTripShortHeader(t *testing.T) {
	aAddr, bAddr := makeAddrs()
	a, b := newMemPipe(aAddr, bAddr)
	defer a.Close()
	defer b.Close()

	ga := mustWrapGecko(t, a, "test")
	gb := mustWrapGecko(t, b, "test")
	defer ga.Close()
	defer gb.Close()

	payload := quicShort(400)
	if _, err := ga.WriteTo(payload, bAddr); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	// Short-header packets should produce exactly one wire datagram.
	if got := a.writeCount.Load(); got != 1 {
		t.Fatalf("inner writes = %d, want 1", got)
	}

	buf := make([]byte, 4096)
	n, src, err := gb.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if !bytes.Equal(buf[:n], payload) {
		t.Fatalf("payload mismatch")
	}
	if src.String() != aAddr.String() {
		t.Fatalf("src = %v, want %v", src, aAddr)
	}
}

func TestGeckoRoundTripLongHeader(t *testing.T) {
	aAddr, bAddr := makeAddrs()
	a, b := newMemPipe(aAddr, bAddr)
	defer a.Close()
	defer b.Close()

	ga := mustWrapGecko(t, a, "test")
	gb := mustWrapGecko(t, b, "test")
	defer ga.Close()
	defer gb.Close()

	payload := quicLong(1200)
	if _, err := ga.WriteTo(payload, bAddr); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	chunks := a.writeCount.Load()
	if chunks < geckoMinFragmentChunks || chunks > geckoMaxFragmentChunks {
		t.Fatalf("inner writes = %d, want in [%d,%d]", chunks, geckoMinFragmentChunks, geckoMaxFragmentChunks)
	}

	buf := make([]byte, 4096)
	n, _, err := gb.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if !bytes.Equal(buf[:n], payload) {
		t.Fatalf("payload mismatch")
	}
}

func TestGeckoRoundTripSmallLongHeader(t *testing.T) {
	for _, size := range []int{1, 2, 5, 10, 15, 20, 25, 27, 30, 40, 64, 128} {
		t.Run(fmt.Sprintf("size=%d", size), func(t *testing.T) {
			aAddr, bAddr := makeAddrs()
			a, b := newMemPipe(aAddr, bAddr)
			defer a.Close()
			defer b.Close()

			ga := mustWrapGecko(t, a, "test")
			gb := mustWrapGecko(t, b, "test")
			defer ga.Close()
			defer gb.Close()

			payload := quicLong(size)
			if _, err := ga.WriteTo(payload, bAddr); err != nil {
				t.Fatalf("WriteTo: %v", err)
			}

			buf := make([]byte, 4096)
			n, _, err := gb.ReadFrom(buf)
			if err != nil {
				t.Fatalf("ReadFrom: %v", err)
			}
			if !bytes.Equal(buf[:n], payload) {
				t.Fatalf("payload mismatch: got %d bytes, want %d", n, size)
			}
		})
	}
}

func TestGeckoWriteFragmentedNeverPanics(t *testing.T) {
	aAddr, bAddr := makeAddrs()
	a, b := newMemPipe(aAddr, bAddr)
	defer a.Close()
	defer b.Close()
	stop := make(chan struct{})
	defer close(stop)
	drainInbox(b, stop)

	g := mustWrapGecko(t, a, "test").(*geckoPacketConn)
	defer g.Close()

	for size := 1; size <= 64; size++ {
		payload := quicLong(size)
		if _, err := g.WriteTo(payload, bAddr); err != nil {
			t.Fatalf("size=%d: WriteTo: %v", size, err)
		}
	}
}

func TestGeckoReassemblesOutOfOrder(t *testing.T) {
	aAddr, bAddr := makeAddrs()
	a, b := newMemPipe(aAddr, bAddr)
	defer a.Close()
	defer b.Close()

	// We need exclusive access to b's inbox to reorder. Wrap a side directly,
	// receive raw datagrams from b, shuffle them into a private pipe that
	// feeds the receiver gecko.
	ga := mustWrapGecko(t, a, "test")
	defer ga.Close()

	payload := quicLong(900)
	if _, err := ga.WriteTo(payload, bAddr); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}

	// Drain b's inbox.
	var pkts []memPacket
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) && a.writeCount.Load() > int64(len(pkts)) {
		select {
		case pkt := <-b.inbox:
			pkts = append(pkts, pkt)
		case <-time.After(50 * time.Millisecond):
		}
	}
	if int64(len(pkts)) != a.writeCount.Load() {
		t.Fatalf("captured %d/%d", len(pkts), a.writeCount.Load())
	}

	// Build a private pipe and feed packets in reverse order.
	c, d := newMemPipe(aAddr, bAddr)
	gd := mustWrapGecko(t, d, "test")
	defer gd.Close()
	defer c.Close()
	go func() {
		for i := len(pkts) - 1; i >= 0; i-- {
			d.inbox <- pkts[i]
		}
	}()

	buf := make([]byte, 4096)
	n, _, err := gd.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if !bytes.Equal(buf[:n], payload) {
		t.Fatalf("payload mismatch after reorder")
	}
}

func TestGeckoExpiresIncompleteFragment(t *testing.T) {
	aAddr, bAddr := makeAddrs()
	a, b := newMemPipe(aAddr, bAddr)
	defer a.Close()
	defer b.Close()

	// Drop the first chunk so reassembly can never complete.
	a.dropFn = func(idx int) bool { return idx == 0 }

	ga := mustWrapGecko(t, a, "test")
	gb := mustWrapGecko(t, b, "test").(*geckoPacketConn)
	defer ga.Close()
	defer gb.Close()

	payload := quicLong(900)
	if _, err := ga.WriteTo(payload, bAddr); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}

	// Read all incoming packets in a goroutine; ReadFrom should never return
	// because no message is complete.
	done := make(chan struct{})
	go func() {
		buf := make([]byte, 4096)
		gb.ReadFrom(buf)
		close(done)
	}()

	// Wait until the reassembly entry exists, then fast-forward time.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		gb.mu.Lock()
		n := len(gb.reassembly)
		gb.mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	gb.mu.Lock()
	if len(gb.reassembly) == 0 {
		gb.mu.Unlock()
		t.Fatal("expected at least one reassembly entry")
	}
	gb.mu.Unlock()

	gb.gcExpired(time.Now().Add(geckoReassemblyTTL + time.Second))

	gb.mu.Lock()
	if len(gb.reassembly) != 0 {
		gb.mu.Unlock()
		t.Fatalf("reassembly map not empty after gc")
	}
	if len(gb.perSource) != 0 {
		gb.mu.Unlock()
		t.Fatalf("perSource map not empty after gc")
	}
	gb.mu.Unlock()

	// Cleanup: closing gb unblocks the reader goroutine.
	gb.Close()
	<-done
}

func TestGeckoEnforcesPerSourceCap(t *testing.T) {
	aAddr, bAddr := makeAddrs()
	a, b := newMemPipe(aAddr, bAddr)
	defer a.Close()
	defer b.Close()

	// Drop every second chunk onward so reassembly never completes; the
	// receiver accumulates partial entries.
	a.dropFn = func(idx int) bool { return idx > 0 && idx%2 == 0 }

	ga := mustWrapGecko(t, a, "test")
	gb := mustWrapGecko(t, b, "test").(*geckoPacketConn)
	defer ga.Close()
	defer gb.Close()

	go func() {
		buf := make([]byte, 4096)
		for {
			if _, _, err := gb.ReadFrom(buf); err != nil {
				return
			}
		}
	}()

	for i := 0; i < geckoMaxPerSource+5; i++ {
		if _, err := ga.WriteTo(quicLong(1200), bAddr); err != nil {
			t.Fatalf("WriteTo %d: %v", i, err)
		}
	}

	// Wait for the receiver to settle.
	time.Sleep(100 * time.Millisecond)

	gb.mu.Lock()
	defer gb.mu.Unlock()
	count := gb.perSource[aAddr.String()]
	if count > geckoMaxPerSource {
		t.Fatalf("perSource = %d, want <= %d", count, geckoMaxPerSource)
	}
}

func TestGeckoEvictsOldestOnGlobalCap(t *testing.T) {
	g := newGeckoPacketConn(nil, geckoDefaultMinPacket, geckoDefaultMaxPacket) // not actually used for I/O
	defer close(g.closeCh)

	// Manually fill the reassembly map past the cap with entries from
	// distinct sources (so the per-source cap doesn't trigger first).
	now := time.Now()
	for i := 0; i < geckoMaxReassembly; i++ {
		key := reassemblyKey{addr: fmt.Sprintf("src-%d", i), msgID: 1}
		g.reassembly[key] = &reassemblyEntry{
			chunks:   make([][]byte, 4),
			total:    4,
			deadline: now.Add(time.Duration(i) * time.Millisecond),
		}
		g.perSource[key.addr]++
	}

	// Trigger eviction.
	g.mu.Lock()
	g.evictOldestLocked()
	g.mu.Unlock()

	if len(g.reassembly) != geckoMaxReassembly-1 {
		t.Fatalf("after evict len = %d, want %d", len(g.reassembly), geckoMaxReassembly-1)
	}
	// The "oldest" was the one with the smallest deadline → src-0.
	if _, ok := g.reassembly[reassemblyKey{addr: "src-0", msgID: 1}]; ok {
		t.Fatal("oldest entry not evicted")
	}
	if g.perSource["src-0"] != 0 {
		t.Fatalf("perSource[src-0] = %d after eviction, want 0", g.perSource["src-0"])
	}
}

func TestGeckoBoundedUnderGarbageFlood(t *testing.T) {
	aAddr, bAddr := makeAddrs()
	a, b := newMemPipe(aAddr, bAddr)
	defer a.Close()
	defer b.Close()

	gb := mustWrapGecko(t, b, "test").(*geckoPacketConn)
	defer gb.Close()

	go func() {
		buf := make([]byte, 4096)
		for {
			if _, _, err := gb.ReadFrom(buf); err != nil {
				return
			}
		}
	}()

	// Inject 50k random datagrams from a moderate number of distinct sources.
	rng := rand.New(rand.NewSource(42))
	for i := 0; i < 50_000; i++ {
		size := 16 + rng.Intn(200)
		junk := make([]byte, size)
		rng.Read(junk)
		src := &net.UDPAddr{IP: net.IPv4(10, 0, 0, byte(i%256)), Port: 1024 + i%4096}
		select {
		case b.inbox <- memPacket{src: src, data: junk}:
		case <-time.After(time.Second):
			t.Fatal("inbox blocked")
		}
	}

	// Let the receiver drain.
	for i := 0; i < 50; i++ {
		if a.pendingInbox() == 0 && b.pendingInbox() == 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	gb.mu.Lock()
	defer gb.mu.Unlock()
	if len(gb.reassembly) > geckoMaxReassembly {
		t.Fatalf("reassembly map size = %d, exceeds cap %d", len(gb.reassembly), geckoMaxReassembly)
	}
}

func TestGeckoUDPPassthrough(t *testing.T) {
	udp, err := net.ListenUDP("udp", &net.UDPAddr{})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()

	g, err := WrapPacketConnGecko(udp, GeckoOptions{Password: []byte("test")})
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()

	type udpLike interface {
		SyscallConn() (syscall.RawConn, error)
		SetReadBuffer(int) error
		SetWriteBuffer(int) error
		ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr *net.UDPAddr, err error)
		WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error)
		ReadBatch([]ipv4.Message, int) (int, error)
	}
	u, ok := g.(udpLike)
	if !ok {
		t.Fatal("gecko conn does not expose UDP-flavor methods")
	}
	if rc, err := u.SyscallConn(); err != nil || rc == nil {
		t.Fatalf("SyscallConn: %v %v", rc, err)
	}
	if err := u.SetReadBuffer(1 << 20); err != nil {
		t.Fatalf("SetReadBuffer: %v", err)
	}
	if err := u.SetWriteBuffer(1 << 20); err != nil {
		t.Fatalf("SetWriteBuffer: %v", err)
	}
}

func TestGeckoRequiresPassword(t *testing.T) {
	if _, err := WrapPacketConnGecko(nil, GeckoOptions{}); err == nil {
		t.Fatal("expected error for missing password")
	}
}

func TestGeckoRejectsInvalidPacketSize(t *testing.T) {
	cases := []GeckoOptions{
		{Password: []byte("x"), MinPacketSize: 1000, MaxPacketSize: 500}, // min > max
		{Password: []byte("x"), MinPacketSize: -1},                       // min <= 0
		{Password: []byte("x"), MaxPacketSize: geckoBufferSize + 1},      // max too large
	}
	for i, opt := range cases {
		if _, err := WrapPacketConnGecko(nil, opt); err == nil {
			t.Fatalf("case %d: expected error", i)
		}
	}
}

// TestGeckoPaddingWithinBounds verifies every fragmented wire datagram is
// padded into the configured [min, max] size band.
func TestGeckoPaddingWithinBounds(t *testing.T) {
	const minSize, maxSize = 400, 900
	aAddr, bAddr := makeAddrs()
	a, b := newMemPipe(aAddr, bAddr)
	defer a.Close()
	defer b.Close()

	ga, err := WrapPacketConnGecko(a, GeckoOptions{
		Password:      []byte("test"),
		MinPacketSize: minSize,
		MaxPacketSize: maxSize,
	})
	if err != nil {
		t.Fatalf("WrapPacketConnGecko: %v", err)
	}
	defer ga.Close()

	for _, size := range []int{1, 50, 200, 600, 1200} {
		if _, err := ga.WriteTo(quicLong(size), bAddr); err != nil {
			t.Fatalf("WriteTo size=%d: %v", size, err)
		}
	}
	for {
		select {
		case pkt := <-b.inbox:
			if len(pkt.data) < minSize || len(pkt.data) > maxSize {
				t.Fatalf("datagram size %d outside [%d, %d]", len(pkt.data), minSize, maxSize)
			}
		default:
			return
		}
	}
}

// Compile-time interface assertions.
var (
	_ net.PacketConn    = (*geckoPacketConn)(nil)
	_ udpLikePacketConn = (*geckoPacketConn)(nil)
	_ interface {
		oobCapablePacketConn
		ReadBatch([]ipv4.Message, int) (int, error)
	} = (*geckoPacketConnOOB)(nil)
)

// Sanity: errors.ErrUnsupported is what we return when inner isn't UDP-like.
func TestGeckoNonUDPInnerReturnsUnsupported(t *testing.T) {
	aAddr, bAddr := makeAddrs()
	a, _ := newMemPipe(aAddr, bAddr)
	defer a.Close()

	g := mustWrapGecko(t, a, "test").(*geckoPacketConn)
	defer g.Close()

	if _, err := g.SyscallConn(); !errors.Is(err, errors.ErrUnsupported) {
		t.Fatalf("SyscallConn err = %v, want ErrUnsupported", err)
	}
	if err := g.SetReadBuffer(1 << 20); !errors.Is(err, errors.ErrUnsupported) {
		t.Fatalf("SetReadBuffer err = %v, want ErrUnsupported", err)
	}
	if err := g.SetWriteBuffer(1 << 20); !errors.Is(err, errors.ErrUnsupported) {
		t.Fatalf("SetWriteBuffer err = %v, want ErrUnsupported", err)
	}
}

// --- benchmarks ---

// drainInbox empties an inbox in a goroutine until done is closed; used in
// benchmarks so a full memEnd.inbox never blocks WriteTo.
func drainInbox(end *memEnd, done <-chan struct{}) {
	go func() {
		for {
			select {
			case <-done:
				return
			case <-end.inbox:
			}
		}
	}()
}

func BenchmarkGeckoWriteShortHeader(b *testing.B) {
	aAddr, bAddr := makeAddrs()
	a, bEnd := newMemPipe(aAddr, bAddr)
	defer a.Close()
	defer bEnd.Close()
	stop := make(chan struct{})
	defer close(stop)
	drainInbox(bEnd, stop)

	g, _ := WrapPacketConnGecko(a, GeckoOptions{Password: []byte("bench")})
	defer g.Close()

	payload := quicShort(400)
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := g.WriteTo(payload, bAddr); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkGeckoWriteLongHeader(b *testing.B) {
	aAddr, bAddr := makeAddrs()
	a, bEnd := newMemPipe(aAddr, bAddr)
	defer a.Close()
	defer bEnd.Close()
	stop := make(chan struct{})
	defer close(stop)
	drainInbox(bEnd, stop)

	g, _ := WrapPacketConnGecko(a, GeckoOptions{Password: []byte("bench")})
	defer g.Close()

	payload := quicLong(1200)
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := g.WriteTo(payload, bAddr); err != nil {
			b.Fatal(err)
		}
	}
}

// captureGeckoWire fragments payload through a sender Gecko conn and returns
// the resulting wire datagrams, for use as fixed input to read benchmarks.
func captureGeckoWire(b *testing.B, payload []byte) []memPacket {
	b.Helper()
	aAddr, bAddr := makeAddrs()
	a, bEnd := newMemPipe(aAddr, bAddr)
	defer a.Close()
	defer bEnd.Close()

	ga, err := WrapPacketConnGecko(a, GeckoOptions{Password: []byte("bench")})
	if err != nil {
		b.Fatal(err)
	}
	defer ga.Close()
	if _, err := ga.WriteTo(payload, bAddr); err != nil {
		b.Fatal(err)
	}

	var wire []memPacket
	for {
		select {
		case pkt := <-bEnd.inbox:
			wire = append(wire, pkt)
		default:
			return wire
		}
	}
}

func BenchmarkGeckoReadShortHeader(b *testing.B) {
	wire := captureGeckoWire(b, quicShort(400))

	_, recv := newMemPipe(makeAddrs())
	gb, err := WrapPacketConnGecko(recv, GeckoOptions{Password: []byte("bench")})
	if err != nil {
		b.Fatal(err)
	}
	defer gb.Close()

	buf := make([]byte, 4096)
	b.SetBytes(400)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, pkt := range wire {
			recv.inbox <- pkt
		}
		if _, _, err := gb.ReadFrom(buf); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkGeckoReadLongHeader(b *testing.B) {
	wire := captureGeckoWire(b, quicLong(1200))

	_, recv := newMemPipe(makeAddrs())
	gb, err := WrapPacketConnGecko(recv, GeckoOptions{Password: []byte("bench")})
	if err != nil {
		b.Fatal(err)
	}
	defer gb.Close()

	buf := make([]byte, 4096)
	b.SetBytes(1200)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, pkt := range wire {
			recv.inbox <- pkt
		}
		if _, _, err := gb.ReadFrom(buf); err != nil {
			b.Fatal(err)
		}
	}
}
