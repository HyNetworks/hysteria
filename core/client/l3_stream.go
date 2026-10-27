package client

import (
	"context"
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

// pipeQueue is the backlog of one lane. A full lane drops the packet instead
// of stalling the TUN reader that feeds every lane, and the inner TCP recovers.
// 128 full-size packets are about 200 KB, a bounded delay on a slow link.
const pipeQueue = 128

// l3StreamEndpoint carries each inner flow on its own reliable QUIC stream.
// The lane is the VXLAN source port, which Linux derives from the inner flow.
// A lost packet is retransmitted by QUIC before the next packet of that flow
// is delivered. Other flows keep moving.
type l3StreamEndpoint struct {
	conn   *quic.Conn
	asm    l3frag.Assembler
	dg     l3.Sender
	hybrid bool // inner TCP on the lanes, everything else as datagrams
	recv   chan []byte
	up     []chan []byte
	done   chan struct{}
	once   sync.Once

	debug    bool
	upSent   atomic.Uint64
	downSent atomic.Uint64
	ackIn    atomic.Uint64
	upErr    atomic.Uint64
	downErr  atomic.Uint64
	drops    atomic.Uint64
	dgrams   atomic.Uint64
}

func openL3Streams(conn *quic.Conn, hybrid bool) (*l3StreamEndpoint, error) {
	ep := &l3StreamEndpoint{
		conn:   conn,
		hybrid: hybrid,
		recv:   make(chan []byte, pipeQueue),
		up:     make([]chan []byte, protocol.L3PipeLanes),
		done:   make(chan struct{}),
		debug:  os.Getenv("HYSTERIA_L3_DEBUG") == "1",
	}
	for i := range ep.up {
		ep.up[i] = make(chan []byte, pipeQueue)
		go ep.uplinkLane(i)
		go ep.downlinkLane(i)
	}
	if ep.debug {
		go ep.debugLoop()
	}
	return ep, nil
}

func (e *l3StreamEndpoint) Send(ipPkt []byte) error {
	select {
	case <-e.done:
		return coreErrs.ClosedError{}
	default:
	}
	if len(ipPkt) == 0 || len(ipPkt) > protocol.L3MaxPacketSize {
		return nil
	}
	if e.sendsDatagram(ipPkt) {
		// A failure here is a dropped packet. A dead connection ends the
		// datagram loop, which closes this endpoint.
		if e.dg.Send(e.conn.SendDatagram, ipPkt) == nil {
			e.dgrams.Add(1)
		}
		return nil
	}
	pkt := append([]byte(nil), ipPkt...)
	lane := l3stream.Lane(pkt, protocol.L3PipeLanes)
	select {
	case <-e.done:
		return coreErrs.ClosedError{}
	case e.up[lane] <- pkt:
		return nil
	default:
		e.drops.Add(1)
		return nil
	}
}

// sendsDatagram picks the unreliable path. Download ACKs ride the lossy
// uplink, so a pure ACK always goes as a datagram, like the server does for
// upload ACKs. Hybrid sends everything but inner TCP data that way too.
func (e *l3StreamEndpoint) sendsDatagram(pkt []byte) bool {
	if e.hybrid {
		return l3stream.Datagram(pkt)
	}
	return l3stream.PureACK(pkt)
}

func (e *l3StreamEndpoint) Receive() ([]byte, error) {
	select {
	case <-e.done:
		return nil, coreErrs.ClosedError{}
	case pkt := <-e.recv:
		return pkt, nil
	}
}

func (e *l3StreamEndpoint) debugLoop() {
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-e.done:
			return
		case <-tick.C:
			fmt.Fprintf(os.Stderr, "l3dbg client up=%d down=%d ack=%d upErr=%d downErr=%d drops=%d dgrams=%d\n",
				e.upSent.Load(), e.downSent.Load(), e.ackIn.Load(), e.upErr.Load(), e.downErr.Load(), e.drops.Load(), e.dgrams.Load())
		}
	}
}

// feedDatagram reassembles a packet the server sent as a datagram and
// delivers it on the same path as stream packets. It runs on the datagram
// reader shared with UDP sessions, so a full queue drops the packet.
func (e *l3StreamEndpoint) feedDatagram(frag protocol.L3Fragment) {
	pkt := e.asm.Feed(frag.PacketID, frag.FragID, frag.FragCount, frag.Data)
	if pkt == nil {
		return
	}
	select {
	case <-e.done:
	case e.recv <- pkt:
		e.ackIn.Add(1)
	default:
		e.drops.Add(1)
	}
}

func (e *l3StreamEndpoint) close() {
	e.once.Do(func() { close(e.done) })
}

func (e *l3StreamEndpoint) uplinkLane(i int) {
	var fw protocol.L3FrameWriter
	var pending []byte
	for {
		stream, stop := e.openLane(protocol.L3StreamUplink, uint8(i))
		if stop {
			return
		}
		if stream == nil {
			continue
		}
		var closed bool
		pending, closed = e.writeLane(stream, e.up[i], pending, &fw)
		stream.CancelWrite(0)
		stream.CancelRead(0)
		if closed {
			return
		}
		e.upErr.Add(1)
	}
}

func (e *l3StreamEndpoint) writeLane(stream *quic.Stream, q chan []byte, pending []byte, fw *protocol.L3FrameWriter) ([]byte, bool) {
	for {
		if pending == nil {
			select {
			case <-e.done:
				return nil, true
			case pending = <-q:
			}
		}
		if err := fw.Write(stream, pending); err != nil {
			return pending, false
		}
		e.upSent.Add(1)
		pending = nil
	}
}

func (e *l3StreamEndpoint) downlinkLane(i int) {
	for {
		select {
		case <-e.done:
			return
		default:
		}
		if !e.readLane(uint8(i)) {
			return
		}
		e.downErr.Add(1)
	}
}

func (e *l3StreamEndpoint) readLane(lane uint8) bool {
	stream, stop := e.openLane(protocol.L3StreamDownlink, lane)
	if stop {
		return false
	}
	if stream == nil {
		return true
	}
	defer func() {
		stream.CancelRead(0)
		stream.CancelWrite(0)
	}()
	for {
		pkt, err := protocol.ReadL3Frame(stream)
		if err != nil {
			return true
		}
		select {
		case <-e.done:
			return false
		case e.recv <- pkt:
			e.downSent.Add(1)
		}
	}
}

func (e *l3StreamEndpoint) openLane(dir, lane uint8) (*quic.Stream, bool) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		select {
		case <-e.done:
			cancel()
		case <-ctx.Done():
		}
	}()
	stream, err := e.conn.OpenStreamSync(ctx)
	if err != nil {
		e.close()
		return nil, true
	}
	if err := protocol.WriteL3StreamHello(stream, dir, lane); err != nil {
		stream.CancelWrite(0)
		stream.CancelRead(0)
		select {
		case <-e.done:
			return nil, true
		case <-time.After(20 * time.Millisecond):
			return nil, false
		}
	}
	return stream, false
}
