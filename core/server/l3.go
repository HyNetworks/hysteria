package server

import (
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/apernet/quic-go"

	coreErrs "github.com/apernet/hysteria/core/v2/errors"
	"github.com/apernet/hysteria/core/v2/internal/l3"
	"github.com/apernet/hysteria/core/v2/internal/l3frag"
	"github.com/apernet/hysteria/core/v2/internal/l3stream"
	"github.com/apernet/hysteria/core/v2/internal/protocol"
)

const l3RecvQueue = 2048

// HyL3Conn is the single L3 peer binding for this server.
// Send drops the packet when no client is bound. Receive waits for the next
// reassembled IP packet from the current peer.
type HyL3Conn interface {
	Send(ipPkt []byte) error
	Receive() ([]byte, error)
}

type l3Hub struct {
	mu     sync.Mutex
	cur    *l3Peer
	recv   chan []byte
	done   chan struct{}
	once   sync.Once
	closed bool
}

func newL3Hub() *l3Hub {
	return &l3Hub{
		recv: make(chan []byte, l3RecvQueue),
		done: make(chan struct{}),
	}
}

// adopt binds conn as the L3 peer. stream adds the downlink lane writers.
// A live peer with another auth ID keeps the binding and adopt returns nil,
// so one user cannot take over another user's tunnel. A peer with the same
// auth ID is replaced and its connection is closed, so a stale client notices.
func (h *l3Hub) adopt(conn *quic.Conn, authID string, tl TrafficLogger, stream bool) *l3Peer {
	p := &l3Peer{
		hub:    h,
		conn:   conn,
		authID: authID,
		tl:     tl,
		alive: func() bool {
			return conn != nil && conn.Context().Err() == nil
		},
	}
	if stream {
		p.down = newDownLink()
	}
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		p.release()
		return nil
	}
	old := h.cur
	if old != nil && old.authID != authID && old.alive() {
		h.mu.Unlock()
		p.release()
		return nil
	}
	h.cur = p
	h.mu.Unlock()
	if old != nil {
		old.evict()
	}
	return p
}

func (h *l3Hub) clear(p *l3Peer) {
	if p == nil {
		return
	}
	if p.down != nil {
		p.down.close()
	}
	h.mu.Lock()
	if h.cur == p {
		h.cur = nil
	}
	h.mu.Unlock()
}

func (h *l3Hub) current() *l3Peer {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.cur
}

func (h *l3Hub) push(pkt []byte) {
	select {
	case <-h.done:
		return
	default:
	}
	select {
	case <-h.done:
	case h.recv <- pkt:
	default:
	}
}

// pushBlock waits until the TUN reader takes the packet.
// A full queue stops this stream only, so QUIC flow control slows that flow.
func (h *l3Hub) pushBlock(pkt []byte) {
	select {
	case <-h.done:
	case h.recv <- pkt:
	}
}

func (h *l3Hub) Send(ipPkt []byte) error {
	select {
	case <-h.done:
		return coreErrs.ClosedError{}
	default:
	}
	p := h.current()
	if p == nil {
		return nil
	}
	if p.tl != nil && len(ipPkt) > 0 && len(ipPkt) <= protocol.L3MaxPacketSize {
		if !p.tl.LogTraffic(p.authID, 0, uint64(len(ipPkt))) {
			_ = p.conn.CloseWithError(closeErrCodeTrafficLimitReached, "")
			h.clear(p)
			return nil
		}
	}
	if err := p.send(ipPkt); err != nil {
		// A gone client must not tear down the local TUN. Drop the packet.
		if p.conn.Context().Err() != nil {
			h.clear(p)
		}
		return nil
	}
	return nil
}

func (h *l3Hub) Receive() ([]byte, error) {
	select {
	case <-h.done:
		return nil, coreErrs.ClosedError{}
	case pkt := <-h.recv:
		return pkt, nil
	}
}

func (h *l3Hub) close() {
	h.once.Do(func() {
		h.mu.Lock()
		h.closed = true
		h.cur = nil
		h.mu.Unlock()
		close(h.done)
	})
}

type l3Peer struct {
	hub    *l3Hub
	conn   *quic.Conn
	authID string
	tl     TrafficLogger
	alive  func() bool
	asm    l3frag.Assembler
	next   atomic.Uint32
	down   *downLink // set before the peer is published, never changed
}

// release stops the downlink writers of a peer that was never bound.
func (p *l3Peer) release() {
	if p.down != nil {
		p.down.close()
	}
}

// evict closes a peer that a newer connection replaced.
func (p *l3Peer) evict() {
	p.release()
	if p.conn != nil {
		_ = p.conn.CloseWithError(closeErrCodeL3Replaced, "l3 tunnel taken over by a newer connection")
	}
}

func (p *l3Peer) send(ip []byte) error {
	if p.down != nil {
		// Upload ACKs travel the lossy downlink. A reliable stream would hold
		// every later ACK behind one retransmission. A pure ACK is cumulative,
		// so losing it is harmless and it goes out as a datagram instead.
		if l3stream.PureACK(ip) {
			if err := l3.Send(p.conn.SendDatagram, &p.next, ip); err != nil {
				return nil
			}
			if l3AckDup {
				_ = l3.Send(p.conn.SendDatagram, &p.next, ip)
			}
			p.down.acks.Add(1)
			return nil
		}
		p.down.send(ip)
		return nil
	}
	return l3.Send(p.conn.SendDatagram, &p.next, ip)
}

var l3AckDup = os.Getenv("HYSTERIA_L3_ACK_DUP") == "1"

func (p *l3Peer) deliverUplink(pkt []byte) {
	if p.hub.current() != p {
		return
	}
	if p.tl != nil && !p.tl.LogTraffic(p.authID, uint64(len(pkt)), 0) {
		_ = p.conn.CloseWithError(closeErrCodeTrafficLimitReached, "")
		return
	}
	p.hub.pushBlock(pkt)
}

// pipeQueue is the backlog of one lane. A full lane drops the packet instead
// of stalling the reader that feeds every lane, and the inner TCP recovers.
// 128 full-size packets are about 200 KB, a bounded delay on a slow link.
const pipeQueue = 128

// downLink writes each inner flow to the client-opened stream selected by
// its VXLAN source port. QUIC retransmits a lost packet on that stream.
type downLink struct {
	lanes []chan []byte
	gen   []atomic.Uint64
	done  chan struct{}
	once  sync.Once
	debug bool
	sent  atomic.Uint64
	acks  atomic.Uint64
	errs  atomic.Uint64
	drops atomic.Uint64
}

func newDownLink() *downLink {
	d := &downLink{
		lanes: make([]chan []byte, protocol.L3PipeLanes),
		gen:   make([]atomic.Uint64, protocol.L3PipeLanes),
		done:  make(chan struct{}),
		debug: os.Getenv("HYSTERIA_L3_DEBUG") == "1",
	}
	for i := range d.lanes {
		d.lanes[i] = make(chan []byte, pipeQueue)
	}
	if d.debug {
		go d.debugLoop()
	}
	return d
}

func (d *downLink) debugLoop() {
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-d.done:
			return
		case <-tick.C:
			fmt.Fprintf(os.Stderr, "l3dbg server sent=%d acks=%d errs=%d drops=%d\n", d.sent.Load(), d.acks.Load(), d.errs.Load(), d.drops.Load())
		}
	}
}

func (d *downLink) send(pkt []byte) {
	if len(pkt) == 0 || len(pkt) > protocol.L3MaxPacketSize {
		return
	}
	cp := append([]byte(nil), pkt...)
	lane := l3stream.Lane(cp, protocol.L3PipeLanes)
	select {
	case <-d.done:
	case d.lanes[lane] <- cp:
	default:
		d.drops.Add(1)
	}
}

func (d *downLink) add(idx int, stream *quic.Stream) {
	if idx < 0 || idx >= len(d.lanes) {
		stream.CancelRead(0)
		stream.CancelWrite(0)
		return
	}
	select {
	case <-d.done:
		stream.CancelRead(0)
		stream.CancelWrite(0)
		return
	default:
	}
	gen := d.gen[idx].Add(1)
	go d.writeLane(idx, gen, stream)
}

func (d *downLink) writeLane(idx int, gen uint64, stream *quic.Stream) {
	defer func() {
		stream.CancelRead(0)
		stream.CancelWrite(0)
	}()
	q := d.lanes[idx]
	var pending []byte
	for d.gen[idx].Load() == gen {
		if pending == nil {
			select {
			case <-d.done:
				return
			case pending = <-q:
			}
		}
		if d.gen[idx].Load() != gen {
			d.returnPkt(q, pending)
			return
		}
		if err := protocol.WriteL3Frame(stream, pending); err != nil {
			d.errs.Add(1)
			return
		}
		d.sent.Add(1)
		pending = nil
	}
}

// returnPkt hands a packet back to the lane for the replacing writer.
// A lane that filled up meanwhile drops it, like a new packet would be.
func (d *downLink) returnPkt(q chan []byte, pkt []byte) {
	select {
	case <-d.done:
	case q <- pkt:
	default:
		d.drops.Add(1)
	}
}

func (d *downLink) close() {
	d.once.Do(func() { close(d.done) })
}

func (p *l3Peer) accept(frag protocol.L3Fragment) {
	if p.hub.current() != p {
		return
	}
	pkt := p.asm.Feed(frag.PacketID, frag.FragID, frag.FragCount, frag.Data)
	if pkt == nil {
		return
	}
	if p.tl != nil {
		if !p.tl.LogTraffic(p.authID, uint64(len(pkt)), 0) {
			_ = p.conn.CloseWithError(closeErrCodeTrafficLimitReached, "")
			return
		}
	}
	p.hub.push(pkt)
}
