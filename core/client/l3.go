package client

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
)

const l3RecvQueue = 128

type l3Endpoint struct {
	conn *quic.Conn
	asm  l3frag.Assembler
	dg   l3.Sender

	recv chan []byte
	done chan struct{}
	once sync.Once

	in    atomic.Uint64
	drops atomic.Uint64
}

func newL3Endpoint(conn *quic.Conn) *l3Endpoint {
	e := &l3Endpoint{
		conn: conn,
		recv: make(chan []byte, l3RecvQueue),
		done: make(chan struct{}),
	}
	if os.Getenv("HYSTERIA_L3_DEBUG") == "1" {
		go e.debugLoop()
	}
	return e
}

func (e *l3Endpoint) debugLoop() {
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-e.done:
			return
		case <-tick.C:
			fmt.Fprintf(os.Stderr, "l3dbg client datagram in=%d drops=%d\n", e.in.Load(), e.drops.Load())
		}
	}
}

func (e *l3Endpoint) Send(ipPkt []byte) error {
	select {
	case <-e.done:
		return coreErrs.ClosedError{}
	default:
	}
	if err := e.dg.Send(e.conn.SendDatagram, ipPkt); err != nil {
		return wrapIfConnectionClosed(err)
	}
	return nil
}

func (e *l3Endpoint) Receive() ([]byte, error) {
	select {
	case <-e.done:
		return nil, coreErrs.ClosedError{}
	case pkt := <-e.recv:
		return pkt, nil
	}
}

func (e *l3Endpoint) push(pkt []byte) {
	select {
	case <-e.done:
		return
	default:
	}
	select {
	case <-e.done:
	case e.recv <- pkt:
		e.in.Add(1)
	default:
		// The QUIC receive queue is small. Drop rather than stall the reader.
		e.drops.Add(1)
	}
}

func (e *l3Endpoint) close() {
	e.once.Do(func() { close(e.done) })
}
