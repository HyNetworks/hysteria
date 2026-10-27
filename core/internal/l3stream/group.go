package l3stream

import (
	"io"
	"sync"

	"github.com/apernet/quic-go"

	"github.com/apernet/hysteria/core/v2/internal/protocol"
)

const sendQueue = 256

// laneIO is a QUIC stream used as one reliable L3 lane.
type laneIO interface {
	io.ReadWriteCloser
	CancelRead(quic.StreamErrorCode)
	CancelWrite(quic.StreamErrorCode)
}

// LaneGroup fans IP packets out to N QUIC streams and reads them back.
// A full lane queue drops the packet. A stream error closes the group.
type LaneGroup struct {
	n        int
	qs       []chan []byte
	attached []bool
	closers  []laneIO
	done     chan struct{}
	once     sync.Once
	mu       sync.Mutex
	onFail   func()
}

func NewLaneGroup(n int) *LaneGroup {
	n = protocol.NormalizeL3Lanes(n)
	g := &LaneGroup{
		n:        n,
		qs:       make([]chan []byte, n),
		attached: make([]bool, n),
		done:     make(chan struct{}),
	}
	for i := range g.qs {
		g.qs[i] = make(chan []byte, sendQueue)
	}
	return g
}

func (g *LaneGroup) OnFail(fn func()) {
	g.mu.Lock()
	g.onFail = fn
	g.mu.Unlock()
}

// Send queues one packet. A closed group returns an error. A full queue drops it.
func (g *LaneGroup) Send(pkt []byte) error {
	select {
	case <-g.done:
		return io.ErrClosedPipe
	default:
	}
	if len(pkt) == 0 || len(pkt) > protocol.L3MaxPacketSize {
		return nil
	}
	lane := Lane(pkt, g.n)
	cp := append([]byte(nil), pkt...)
	select {
	case <-g.done:
		return io.ErrClosedPipe
	case g.qs[lane] <- cp:
		return nil
	default:
		return nil
	}
}

// Attach starts the read and write loops for one lane. A second attach is rejected.
func (g *LaneGroup) Attach(lane int, rw laneIO, onPacket func([]byte)) bool {
	if rw == nil || lane < 0 || lane >= g.n {
		return false
	}
	g.mu.Lock()
	if g.attached[lane] {
		g.mu.Unlock()
		return false
	}
	g.attached[lane] = true
	g.closers = append(g.closers, rw)
	g.mu.Unlock()
	go g.writeLoop(lane, rw)
	go g.readLoop(rw, onPacket)
	return true
}

func (g *LaneGroup) writeLoop(lane int, w io.Writer) {
	for {
		select {
		case <-g.done:
			return
		case pkt := <-g.qs[lane]:
			if err := protocol.WriteL3Frame(w, pkt); err != nil {
				g.fail()
				return
			}
		}
	}
}

func (g *LaneGroup) readLoop(r io.Reader, onPacket func([]byte)) {
	for {
		pkt, err := protocol.ReadL3Frame(r)
		if err != nil {
			g.fail()
			return
		}
		select {
		case <-g.done:
			return
		default:
		}
		if onPacket != nil {
			onPacket(pkt)
		}
	}
}

// Fail closes every lane. It is safe to call more than once.
func (g *LaneGroup) Fail() {
	g.fail()
}

func (g *LaneGroup) fail() {
	g.once.Do(func() {
		close(g.done)
		g.mu.Lock()
		closers := append([]laneIO(nil), g.closers...)
		fn := g.onFail
		g.mu.Unlock()
		for _, c := range closers {
			c.CancelRead(0)
			c.CancelWrite(0)
		}
		if fn != nil {
			fn()
		}
	})
}
