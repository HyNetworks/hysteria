package obfs

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/net/ipv4"
)

// Gecko adds shape obfuscation on top of Salamander: QUIC long-header
// (handshake) packets are fragmented into randomly-sized, randomly-padded
// chunks; short-header packets pass through untouched.
const (
	geckoReassemblyTTL = 8 * time.Second
	geckoMaxReassembly = 4096
	geckoMaxPerSource  = 8

	geckoBufferSize = 2048

	geckoDefaultMinPacket = 512
	geckoDefaultMaxPacket = 1200
)

type GeckoOptions struct {
	Password      []byte
	MinPacketSize int
	MaxPacketSize int
}

func WrapPacketConnGecko(conn net.PacketConn, opts GeckoOptions) (net.PacketConn, error) {
	if len(opts.Password) == 0 {
		return nil, errors.New("gecko: password is required")
	}
	minPkt, maxPkt := opts.MinPacketSize, opts.MaxPacketSize
	if minPkt == 0 {
		minPkt = geckoDefaultMinPacket
	}
	if maxPkt == 0 {
		maxPkt = geckoDefaultMaxPacket
	}
	if minPkt <= 0 || minPkt > maxPkt || maxPkt > geckoBufferSize {
		return nil, errors.New("gecko: invalid min/max packet size")
	}
	inner, err := WrapPacketConnSalamander(conn, opts.Password)
	if err != nil {
		return nil, err
	}
	g := newGeckoPacketConn(inner, minPkt, maxPkt)
	if oobConn, ok := inner.(oobCapablePacketConn); ok {
		return &geckoPacketConnOOB{
			geckoPacketConn: g,
			innerOOB:        oobConn,
		}, nil
	}
	return g, nil
}

type reassemblyKey struct {
	addr  string
	msgID uint8
}

type reassemblyEntry struct {
	chunks   [][]byte
	received int
	total    uint8
	deadline time.Time
}

type geckoPacketConn struct {
	inner          net.PacketConn
	minPkt, maxPkt int

	msgID atomic.Uint32

	readMu  sync.Mutex
	readBuf []byte

	mu         sync.Mutex
	reassembly map[reassemblyKey]*reassemblyEntry
	perSource  map[string]int

	closeCh   chan struct{}
	closeOnce sync.Once
}

type geckoPacketConnOOB struct {
	*geckoPacketConn
	innerOOB oobCapablePacketConn
}

func newGeckoPacketConn(inner net.PacketConn, minPkt, maxPkt int) *geckoPacketConn {
	g := &geckoPacketConn{
		inner:      inner,
		minPkt:     minPkt,
		maxPkt:     maxPkt,
		readBuf:    make([]byte, geckoBufferSize),
		reassembly: make(map[reassemblyKey]*reassemblyEntry),
		perSource:  make(map[string]int),
		closeCh:    make(chan struct{}),
	}
	go g.gcLoop()
	return g
}

// --- Send path ---

func (g *geckoPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if p[0]&0x80 != 0 {
		// QUIC long header, do fragmentation.
		return g.writeFragmented(p, addr)
	}
	// QUIC short header (data), pass through.
	return g.inner.WriteTo(p, addr)
}

func (g *geckoPacketConn) writeFragmented(p []byte, addr net.Addr) (int, error) {
	return g.writeFragmentedWith(p, func(buf []byte) error {
		_, err := g.inner.WriteTo(buf, addr)
		return err
	})
}

func (g *geckoPacketConn) writeFragmentedWith(p []byte, write func([]byte) error) (int, error) {
	chunks := randomFragmentChunks()
	chunkSize := len(p) / chunks
	msgID := uint8(g.msgID.Add(1))
	for i := range chunks {
		start := i * chunkSize
		end := len(p)
		if i < chunks-1 {
			end = start + chunkSize
		}
		chunk := p[start:end]
		padLen := g.randomPadLen(len(chunk))
		buf := make([]byte, geckoHeaderSize+int(padLen)+len(chunk))
		n, err := encodeFrame(frameHeader{
			padLen:      padLen,
			msgID:       msgID,
			chunkIdx:    uint8(i),
			totalChunks: uint8(chunks),
		}, chunk, buf)
		if err != nil {
			return 0, err
		}
		if err := write(buf[:n]); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

// randomPadLen picks padding so the final UDP datagram (Salamander salt +
// header + padding + chunk) falls within [minPkt, maxPkt]. If the chunk alone
// already exceeds maxPkt, no padding is added.
func (g *geckoPacketConn) randomPadLen(chunkLen int) uint16 {
	base := smSaltLen + geckoHeaderSize + chunkLen
	lo := max(g.minPkt, base)
	if lo > g.maxPkt {
		return 0
	}
	return uint16(lo - base + randIntn(g.maxPkt-lo+1))
}

func randomFragmentChunks() int {
	return geckoMinFragmentChunks + randIntn(geckoMaxFragmentChunks-geckoMinFragmentChunks+1)
}

// randIntn returns a uniform random int in [0, n).
func randIntn(n int) int {
	if n <= 1 {
		return 0
	}
	var b [4]byte
	_, _ = rand.Read(b[:])
	return int(binary.BigEndian.Uint32(b[:]) % uint32(n))
}

// --- Receive path ---

func (g *geckoPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	g.readMu.Lock()
	defer g.readMu.Unlock()
	buf := g.readBuf
	for {
		n, addr, err := g.inner.ReadFrom(buf)
		if err != nil {
			return 0, addr, err
		}
		if n <= 0 {
			continue
		}
		// Top bit set → Gecko fragment frame; clear → short-header packet
		// or garbage, passed through for QUIC to handle.
		if buf[0]&0x80 == 0 {
			return copy(p, buf[:n]), addr, nil
		}
		h, payload, decErr := decodeFrame(buf[:n])
		if decErr != nil {
			// Malformed frame; drop silently.
			continue
		}
		out, ready := g.acceptChunk(addr, h, payload)
		if !ready {
			continue
		}
		return copy(p, out), addr, nil
	}
}

func (g *geckoPacketConn) acceptChunk(addr net.Addr, h frameHeader, payload []byte) ([]byte, bool) {
	key := reassemblyKey{addr: addr.String(), msgID: h.msgID}

	g.mu.Lock()
	defer g.mu.Unlock()

	e, exists := g.reassembly[key]
	if !exists {
		// Per-source cap.
		if g.perSource[key.addr] >= geckoMaxPerSource {
			return nil, false
		}
		// Global cap with eviction.
		if len(g.reassembly) >= geckoMaxReassembly {
			g.evictOldestLocked()
		}
		e = &reassemblyEntry{
			chunks:   make([][]byte, h.totalChunks),
			total:    h.totalChunks,
			deadline: time.Now().Add(geckoReassemblyTTL),
		}
		g.reassembly[key] = e
		g.perSource[key.addr]++
	} else if e.total != h.totalChunks {
		// Inconsistent chunk count; drop.
		return nil, false
	}
	if int(h.chunkIdx) >= len(e.chunks) || e.chunks[h.chunkIdx] != nil {
		// Bad index or duplicate; drop.
		return nil, false
	}
	cp := make([]byte, len(payload))
	copy(cp, payload)
	e.chunks[h.chunkIdx] = cp
	e.received++
	if e.received < int(e.total) {
		return nil, false
	}

	total := 0
	for _, c := range e.chunks {
		total += len(c)
	}
	out := make([]byte, total)
	off := 0
	for _, c := range e.chunks {
		off += copy(out[off:], c)
	}
	g.dropEntryLocked(key)
	return out, true
}

// --- Maintenance ---

func (g *geckoPacketConn) gcLoop() {
	t := time.NewTicker(geckoReassemblyTTL / 2)
	defer t.Stop()
	for {
		select {
		case <-g.closeCh:
			return
		case now := <-t.C:
			g.gcExpired(now)
		}
	}
}

func (g *geckoPacketConn) gcExpired(now time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for k, e := range g.reassembly {
		if now.After(e.deadline) {
			g.dropEntryLocked(k)
		}
	}
}

// dropEntryLocked must be called with mu held.
func (g *geckoPacketConn) dropEntryLocked(k reassemblyKey) {
	if _, ok := g.reassembly[k]; !ok {
		return
	}
	delete(g.reassembly, k)
	g.perSource[k.addr]--
	if g.perSource[k.addr] <= 0 {
		delete(g.perSource, k.addr)
	}
}

// evictOldestLocked must be called with mu held. O(n) over the map; n is
// bounded by geckoMaxReassembly.
func (g *geckoPacketConn) evictOldestLocked() {
	var oldestKey reassemblyKey
	var oldestDeadline time.Time
	first := true
	for k, e := range g.reassembly {
		if first || e.deadline.Before(oldestDeadline) {
			oldestKey = k
			oldestDeadline = e.deadline
			first = false
		}
	}
	if !first {
		g.dropEntryLocked(oldestKey)
	}
}

// --- net.PacketConn boilerplate ---

func (g *geckoPacketConn) Close() error {
	g.closeOnce.Do(func() { close(g.closeCh) })
	return g.inner.Close()
}

func (g *geckoPacketConn) LocalAddr() net.Addr               { return g.inner.LocalAddr() }
func (g *geckoPacketConn) SetDeadline(t time.Time) error     { return g.inner.SetDeadline(t) }
func (g *geckoPacketConn) SetReadDeadline(t time.Time) error { return g.inner.SetReadDeadline(t) }
func (g *geckoPacketConn) SetWriteDeadline(t time.Time) error {
	return g.inner.SetWriteDeadline(t)
}

// --- UDP-flavor passthrough ---

func (g *geckoPacketConn) SyscallConn() (syscall.RawConn, error) {
	if u, ok := g.inner.(udpLikePacketConn); ok {
		return u.SyscallConn()
	}
	return nil, errors.ErrUnsupported
}

func (g *geckoPacketConn) SetReadBuffer(bytes int) error {
	if u, ok := g.inner.(udpLikePacketConn); ok {
		return u.SetReadBuffer(bytes)
	}
	return errors.ErrUnsupported
}

func (g *geckoPacketConn) SetWriteBuffer(bytes int) error {
	if u, ok := g.inner.(udpLikePacketConn); ok {
		return u.SetWriteBuffer(bytes)
	}
	return errors.ErrUnsupported
}

func (g *geckoPacketConnOOB) ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr *net.UDPAddr, err error) {
	g.readMu.Lock()
	defer g.readMu.Unlock()
	buf := g.readBuf
	for {
		n, oobn, flags, addr, err = g.innerOOB.ReadMsgUDP(buf, oob)
		if err != nil {
			return 0, oobn, flags, addr, err
		}
		if n <= 0 {
			continue
		}
		// Top bit set means Gecko fragment frame; clear means short-header
		// packet or garbage, passed through for QUIC to handle.
		if buf[0]&0x80 == 0 {
			return copy(b, buf[:n]), oobn, flags, addr, nil
		}
		h, payload, decErr := decodeFrame(buf[:n])
		if decErr != nil {
			// Malformed frame; drop silently.
			continue
		}
		out, ready := g.acceptChunk(addr, h, payload)
		if !ready {
			continue
		}
		return copy(b, out), oobn, flags, addr, nil
	}
}

func (g *geckoPacketConnOOB) WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error) {
	if len(b) == 0 {
		return 0, 0, nil
	}
	if b[0]&0x80 != 0 {
		return g.writeFragmentedMsg(b, oob, addr)
	}
	n, oobn, err = g.innerOOB.WriteMsgUDP(b, oob, addr)
	if err == nil {
		n = len(b)
	}
	return n, oobn, err
}

func (g *geckoPacketConnOOB) writeFragmentedMsg(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error) {
	n, err = g.writeFragmentedWith(b, func(buf []byte) error {
		var writeErr error
		_, oobn, writeErr = g.innerOOB.WriteMsgUDP(buf, oob, addr)
		return writeErr
	})
	return n, oobn, err
}

func (g *geckoPacketConnOOB) ReadBatch(ms []ipv4.Message, flags int) (int, error) {
	return readBatchOne(g, ms, flags)
}
