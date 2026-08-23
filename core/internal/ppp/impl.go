package ppp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"sync"
	"sync/atomic"
	"time"

	corePPP "github.com/apernet/hysteria/core/v2/ppp"

	"github.com/apernet/quic-go"
)

// DebugLogFunc is an optional callback for debug-level logging.
// If nil, no debug logging is performed.
type DebugLogFunc func(msg string, fields ...any)

// DatagramIO implements PPPDataIO using QUIC datagrams.
// Used on both server and client side (with a dispatcher channel).
type DatagramIO struct {
	conn   *quic.Conn
	recvCh <-chan []byte
	done   chan struct{}
	once   sync.Once
}

func NewDatagramIO(conn *quic.Conn, recvCh <-chan []byte) corePPP.PPPDataIO {
	return &DatagramIO{conn: conn, recvCh: recvCh, done: make(chan struct{})}
}

func (d *DatagramIO) SendData(frame []byte) error {
	err := d.conn.SendDatagram(frame)
	var tooLarge *quic.DatagramTooLargeError
	if errors.As(err, &tooLarge) {
		return &corePPP.FrameTooLargeError{
			FrameSize: len(frame),
			MaxSize:   int(tooLarge.MaxDatagramPayloadSize),
		}
	}
	return err
}

// sizeProbe is larger than any QUIC packet can ever be (MaxPacketBufferSize is
// 1452), so SendDatagram always rejects it and reports the current ceiling
// instead of queueing anything. It returns before copying the payload, so this
// costs nothing beyond the shared buffer.
var sizeProbe = make([]byte, 2048)

// MaxFrameSize reports the largest frame that would be accepted right now. The
// value grows as Path MTU discovery probes the path, so callers that need a
// stable answer should poll until it stops changing.
func (d *DatagramIO) MaxFrameSize() int {
	err := d.conn.SendDatagram(sizeProbe)
	var tooLarge *quic.DatagramTooLargeError
	if errors.As(err, &tooLarge) {
		return int(tooLarge.MaxDatagramPayloadSize)
	}
	return 0
}

func (d *DatagramIO) ReceiveData() ([]byte, error) {
	select {
	case msg, ok := <-d.recvCh:
		if !ok {
			return nil, io.EOF
		}
		return msg, nil
	case <-d.done:
		return nil, io.EOF
	}
}

func (d *DatagramIO) Close() error {
	d.once.Do(func() { close(d.done) })
	return nil
}

// MultiStreamIO implements PPPDataIO using N parallel QUIC streams
// with length-prefix framing and per-flow hashing.
type MultiStreamIO struct {
	streams []*quic.Stream
	// writeMu[i] guards streams[i]. A frame goes out as a length prefix followed
	// by the payload, so two senders interleaving on one stream would leave the
	// receiver parsing payload octets as a length -- unrecoverable for the life of
	// the stream. The bridge has several concurrent senders, so this is reachable.
	writeMu       []sync.Mutex
	recvCh        chan []byte
	debugLog      DebugLogFunc
	once          sync.Once
	done          chan struct{}
	activeReaders atomic.Int32
}

func NewMultiStreamIO(streams []*quic.Stream, debugLog DebugLogFunc) corePPP.PPPDataIO {
	m := &MultiStreamIO{
		streams:  streams,
		writeMu:  make([]sync.Mutex, len(streams)),
		recvCh:   make(chan []byte, 256),
		debugLog: debugLog,
		done:     make(chan struct{}),
	}
	m.activeReaders.Store(int32(len(streams)))
	for i, s := range streams {
		go m.readLoop(i, s)
	}
	return m
}

func (m *MultiStreamIO) readLoop(idx int, s *quic.Stream) {
	defer func() {
		if m.activeReaders.Add(-1) == 0 {
			m.Close()
		}
	}()
	hdr := make([]byte, 2)
	for {
		if _, err := io.ReadFull(s, hdr); err != nil {
			return
		}
		frameLen := int(binary.BigEndian.Uint16(hdr))
		frame := make([]byte, frameLen)
		if _, err := io.ReadFull(s, frame); err != nil {
			return
		}
		select {
		case m.recvCh <- frame:
		case <-m.done:
			return
		}
	}
}

// MaxFrameSize reports the ceiling imposed by the 16-bit length prefix. A
// reliable stream has no per-frame limit of its own.
func (m *MultiStreamIO) MaxFrameSize() int { return math.MaxUint16 }

func (m *MultiStreamIO) SendData(frame []byte) error {
	// The length prefix is 16 bits. Without this guard the cast below truncates
	// silently and the receiver desynchronises for the life of the stream.
	if len(frame) > math.MaxUint16 {
		return &corePPP.FrameTooLargeError{FrameSize: len(frame), MaxSize: math.MaxUint16}
	}
	idx := flowHash(frame, len(m.streams), m.debugLog)
	hdr := [2]byte{}
	binary.BigEndian.PutUint16(hdr[:], uint16(len(frame)))
	m.writeMu[idx].Lock()
	defer m.writeMu[idx].Unlock()
	if _, err := m.streams[idx].Write(hdr[:]); err != nil {
		return err
	}
	_, err := m.streams[idx].Write(frame)
	return err
}

func (m *MultiStreamIO) ReceiveData() ([]byte, error) {
	select {
	case frame, ok := <-m.recvCh:
		if !ok {
			return nil, io.EOF
		}
		return frame, nil
	case <-m.done:
		return nil, io.EOF
	}
}

func (m *MultiStreamIO) Close() error {
	m.once.Do(func() {
		select {
		case <-m.done:
		default:
			close(m.done)
		}
	})
	for _, s := range m.streams {
		_ = s.Close()
	}
	return nil
}

// CollectDataStreams waits for N data streams to arrive on the channel
// and returns a MultiStreamIO wrapping them.
func CollectDataStreams(ch <-chan *quic.Stream, n int, timeout time.Duration, debugLog DebugLogFunc) (corePPP.PPPDataIO, error) {
	streams := make([]*quic.Stream, 0, n)
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for len(streams) < n {
		select {
		case s, ok := <-ch:
			if !ok {
				return nil, fmt.Errorf("data stream channel closed, got %d/%d", len(streams), n)
			}
			streams = append(streams, s)
		case <-timer.C:
			for _, s := range streams {
				_ = s.Close()
			}
			return nil, fmt.Errorf("timed out waiting for data streams, got %d/%d", len(streams), n)
		}
	}
	return NewMultiStreamIO(streams, debugLog), nil
}

// DatagramBudget reports the largest datagram payload conn will accept right
// now, or 0 if datagrams are unavailable. The value tracks Path MTU discovery,
// which starts at quic-go's initial packet size and grows as the path is probed.
func DatagramBudget(conn *quic.Conn) int {
	err := conn.SendDatagram(sizeProbe)
	var tooLarge *quic.DatagramTooLargeError
	if errors.As(err, &tooLarge) {
		return int(tooLarge.MaxDatagramPayloadSize)
	}
	return 0
}

// quicPayloadEstimateOverhead is what quic-go subtracts from the current packet
// size to get the largest datagram payload it will accept:
//
//	estimateMaxPayloadSize(mtu) = mtu - 1 - 20 - 16
//
// a type byte, the maximum connection ID length rather than the one in use, and
// the AEAD tag. Mirrored here because it is unexported, and pinned by
// TestPreDiscoveryBudgetMatchesWhatDiscoveryStartsFrom, which fails if a quic-go bump
// moves it -- silently drifting would put preDiscoveryBudget just off the real
// floor and quietly restore the bug it exists to prevent.
const quicPayloadEstimateOverhead = 37

// preDiscoveryBudget is the datagram budget a connection reports before Path
// MTU discovery has raised it a single rung, or 0 when it cannot be determined.
//
// This is the one budget value that is not a measurement. quic-go seeds the
// discoverer at InitialPacketSize -- 1280, the smallest packet every path is
// required to carry -- and raises it only when a larger probe is acknowledged.
// Until that happens the budget is the initialisation value, and it says
// nothing at all about the path.
func preDiscoveryBudget(conn *quic.Conn) int {
	initial := int(conn.InitialPacketSize())
	if initial <= quicPayloadEstimateOverhead {
		return 0
	}
	return initial - quicPayloadEstimateOverhead
}

// StableDatagramBudget waits for Path MTU discovery to finish and returns the
// datagram budget it settled on.
//
// Discovery probes for a larger packet every mtuProbeDelay -- five -- smoothed
// round trips, and the budget moves only when a probe is acknowledged, one round
// trip later. Sizing PPP against the early value wastes the path permanently;
// sizing it against an assumed final value drops every full-size frame until
// discovery catches up. Waiting is the way out, and it is nearly free here: pppd
// is retransmitting its Configure-Request on a 3s restart timer with ten
// attempts, so several seconds is invisible to it.
//
// Two things have to hold before the budget is believed, and the first is the
// one this used to get wrong:
//
//   - It must have left its pre-discovery floor. The floor is the value the
//     discoverer is initialised with, not something measured, and it is present
//     from the instant the connection exists. Treating "it has not moved" as
//     convergence therefore reports the floor as the answer whenever the
//     observation starts before the first probe is acknowledged -- which is
//     always, because the observation starts at the PPP handshake and the first
//     acknowledgement cannot arrive for six round trips. On any path with a real
//     round trip that produced a 1239-octet link on a path carrying 1390, for the
//     life of every session, and no configuration could raise it: the figure is
//     the smaller half of a min() with what the client asked for, so lowering the
//     client's request only ever moved the number that lost.
//
//   - It must then hold still for settle. This is what spots the top of the
//     ladder, and it is why settle has to be wider than one probe interval:
//     narrower and the pause between two rungs reads as convergence.
//
// A path that genuinely carries no more than the initial size is the case where
// those two rules disagree, and it is why the wait has a real deadline rather
// than only a settle window. There the probes are lost rather than never sent,
// the budget stays on the floor legitimately, and no amount of waiting will move
// it. Returning the floor is then the correct answer -- but only once enough
// time has passed for the probes to have been sent and lost, which is what
// timeout is sized for. Before that, the same value means the opposite thing.
//
// Returns the last observed value whichever exit is taken, so a caller always
// gets a figure the connection really accepts.
func StableDatagramBudget(conn *quic.Conn, settle, timeout time.Duration) int {
	// Slightly more than one probe interval, so that the pause between two rungs
	// cannot be mistaken for the top of the ladder.
	const settleRTTs = 6
	// Long enough for the whole ladder: four rungs at five round trips each plus
	// the acknowledgement that moves the last one is twenty-one, and the settle
	// window that confirms it is six more. Below this a slow path returns a rung
	// partway up -- which is at least a measurement, unlike the floor -- and
	// above maxTimeout it would stall link setup for longer than the answer is
	// worth.
	const (
		timeoutRTTs = 30
		maxTimeout  = 8 * time.Second
	)
	if rtt := conn.ConnectionStats().SmoothedRTT; rtt > 0 {
		if want := settleRTTs * rtt; want > settle {
			settle = want
		}
		// The caller's timeout is a floor rather than the answer. It is chosen
		// without knowing the round trip, and the thing being waited for is
		// measured entirely in round trips: at 150ms the ladder needs four
		// seconds, and every timeout short of it returns early with whatever rung
		// discovery had reached. Capped because this blocks a link coming up.
		if want := min(timeoutRTTs*rtt, maxTimeout); want > timeout {
			timeout = want
		}
	}
	// A settle window wider than the timeout simply means this returns the best
	// figure it saw rather than a converged one, which is the honest answer.
	if settle > timeout {
		settle = timeout
	}

	// Zero when it cannot be determined, which disables the floor rule rather
	// than guessing at it: a budget is then believed as soon as it holds still,
	// exactly as it was before.
	floor := preDiscoveryBudget(conn)

	deadline := time.Now().Add(timeout)
	poll := 20 * time.Millisecond
	last := DatagramBudget(conn)
	stableSince := time.Now()
	keepalive := make([]byte, 16)
	for time.Now().Before(deadline) {
		// Discovery only advances when packets are acknowledged: probes go out
		// every few round trips and a probe that is never ACKed teaches it
		// nothing. On an otherwise idle connection the budget therefore stalls
		// partway up the ramp and looks settled. Keep a trickle of traffic going
		// so what we observe is convergence rather than silence.
		_ = conn.SendDatagram(keepalive)
		time.Sleep(poll)
		cur := DatagramBudget(conn)
		if cur != last {
			last = cur
			stableSince = time.Now()
			continue
		}
		// Still on the floor, so discovery has not produced a result yet and
		// there is nothing here to call settled. Wait for the deadline instead,
		// which is sized so that arriving there still on the floor is itself the
		// finding: the probes went out and were lost, and the path really does
		// carry no more than this.
		//
		// Guarded on last > 0 because a connection without datagram support
		// reports 0 forever, and that is settled from the first poll -- it must
		// not be made to wait out a timeout to conclude something it already
		// knows.
		if last > 0 && last <= floor {
			continue
		}
		if time.Since(stableSince) >= settle {
			break
		}
	}
	return last
}
