package pppbridge

import (
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/apernet/hysteria/core/v2/ppp"
	"github.com/apernet/quic-go/quicvarint"
)

// Shared plumbing for tests that work at the frame level.
//
// After the refactor there is exactly one currency between the pieces of this
// package: a raw PPP frame. ppp.PPPDataIO carries them, Endpoint carries them,
// and FrameRW is the two-method subset both satisfy. So the fakes live here once
// rather than being re-invented per file.

// ---------------------------------------------------------------------------
// FrameRW
// ---------------------------------------------------------------------------

// frameRWSpy is a FrameRW under test control. Everything the code under test
// sends is recorded on sent, and RecvPPP returns whatever the test queued,
// blocking until it does -- which is what lets a negotiation be driven one step
// at a time instead of by sleeping.
type frameRWSpy struct {
	sent   chan []byte
	recv   chan []byte
	closed chan struct{}
	once   sync.Once

	mu      sync.Mutex
	sendErr error
}

func newFrameRWSpy() *frameRWSpy {
	return &frameRWSpy{
		sent:   make(chan []byte, 256),
		recv:   make(chan []byte, 256),
		closed: make(chan struct{}),
	}
}

func (f *frameRWSpy) SendPPP(rawPPP []byte) error {
	f.mu.Lock()
	err := f.sendErr
	f.mu.Unlock()
	if err != nil {
		return err
	}
	select {
	case f.sent <- append([]byte(nil), rawPPP...):
		return nil
	case <-f.closed:
		return io.ErrClosedPipe
	}
}

func (f *frameRWSpy) RecvPPP() ([]byte, error) {
	select {
	case b := <-f.recv:
		return b, nil
	case <-f.closed:
		return nil, io.EOF
	}
}

// failSends makes every later SendPPP return err.
func (f *frameRWSpy) failSends(err error) {
	f.mu.Lock()
	f.sendErr = err
	f.mu.Unlock()
}

// queue hands the code under test a frame built from a protocol and payload.
func (f *frameRWSpy) queue(proto uint16, payload []byte) {
	f.recv <- buildPPPFrame(proto, payload)
}

// queueRaw hands over a frame verbatim, for inputs that are not well-formed PPP.
func (f *frameRWSpy) queueRaw(raw []byte) { f.recv <- raw }

func (f *frameRWSpy) close() { f.once.Do(func() { close(f.closed) }) }

// nextFrame returns the next frame the code under test sent, as a protocol and
// payload pair.
func (f *frameRWSpy) nextFrame(t *testing.T) (uint16, []byte) {
	t.Helper()
	select {
	case raw := <-f.sent:
		return parsePPPFrame(raw)
	case <-time.After(testTimeout):
		t.Fatal("timed out waiting for a frame from the code under test")
		return 0, nil
	}
}

// nextRawFrame is nextFrame without the parse, for assertions about the frame
// itself rather than its contents.
func (f *frameRWSpy) nextRawFrame(t *testing.T) []byte {
	t.Helper()
	select {
	case raw := <-f.sent:
		return raw
	case <-time.After(testTimeout):
		t.Fatal("timed out waiting for a frame from the code under test")
		return nil
	}
}

// assertSilent fails if anything is sent within a short window.
func (f *frameRWSpy) assertSilent(t *testing.T, why string) {
	t.Helper()
	select {
	case raw := <-f.sent:
		t.Fatalf("%s, but %x was sent", why, raw)
	case <-time.After(200 * time.Millisecond):
	}
}

// drainSent returns every frame sent so far, without blocking.
func (f *frameRWSpy) drainSent() [][]byte {
	var out [][]byte
	for {
		select {
		case raw := <-f.sent:
			out = append(out, raw)
		default:
			return out
		}
	}
}

// ---------------------------------------------------------------------------
// A paired ppp.PPPDataIO
// ---------------------------------------------------------------------------

// framePair is a bidirectional in-memory frame channel: what one end sends is
// byte-for-byte what the other end receives, with nothing in between. It stands
// in for the Hysteria2 data transport, which is frame-shaped for the same
// reason.
type framePair struct {
	ab, ba chan []byte
	closed chan struct{}
	once   sync.Once
}

func newFramePair(depth int) *framePair {
	return &framePair{
		ab:     make(chan []byte, depth),
		ba:     make(chan []byte, depth),
		closed: make(chan struct{}),
	}
}

func (p *framePair) shutdown() { p.once.Do(func() { close(p.closed) }) }

// ends returns the two halves: whatever a sends, b receives.
func (p *framePair) ends() (a, b *pairedDataIO) {
	return &pairedDataIO{pair: p, out: p.ab, in: p.ba},
		&pairedDataIO{pair: p, out: p.ba, in: p.ab}
}

// pairedDataIO is one end of a framePair presented as a ppp.PPPDataIO. It
// deliberately does NOT implement ppp.MaxFrameSizer, so mtuProbeWorthwhile says
// no and a test that does not care about probes is not perturbed by them.
type pairedDataIO struct {
	pair *framePair
	out  chan []byte
	in   chan []byte

	// limit, when positive, is the per-frame ceiling. A larger frame is refused
	// with ppp.FrameTooLargeError, exactly as the datagram transport does once
	// quic-go reports a smaller budget than the negotiated PPP MTU.
	limit int

	// tap, when set, sees every frame this end accepts for sending.
	tap func([]byte)

	// dropProbeRequests makes this end swallow inbound MTU probe requests before
	// anything can answer them, which is what a path that has stopped carrying
	// full-size frames looks like from the other side.
	dropProbeRequests bool
}

func (d *pairedDataIO) SendData(frame []byte) error {
	// A shut-down pair fails the send even when the channel still has room, so a
	// dead transport is a dead transport rather than a scheduling coin flip.
	select {
	case <-d.pair.closed:
		return io.ErrClosedPipe
	default:
	}
	if d.limit > 0 && len(frame) > d.limit {
		return &ppp.FrameTooLargeError{FrameSize: len(frame), MaxSize: d.limit}
	}
	cp := append([]byte(nil), frame...)
	if d.tap != nil {
		d.tap(cp)
	}
	select {
	case d.out <- cp:
		return nil
	case <-d.pair.closed:
		return io.ErrClosedPipe
	}
}

func (d *pairedDataIO) ReceiveData() ([]byte, error) {
	for {
		select {
		case f := <-d.in:
			if d.dropProbeRequests {
				if kind, _, ok := parseMTUProbe(f); ok && kind == mtuProbeRequest {
					continue
				}
			}
			return f, nil
		case <-d.pair.closed:
			return nil, io.EOF
		}
	}
}

func (d *pairedDataIO) Close() error {
	d.pair.shutdown()
	return nil
}

// sizedDataIO is a pairedDataIO that reports its ceiling, so the MTU probe loop
// considers the transport worth probing.
type sizedDataIO struct{ *pairedDataIO }

func (d sizedDataIO) MaxFrameSize() int { return d.limit }

// ---------------------------------------------------------------------------
// A control stream that records what was written to it
// ---------------------------------------------------------------------------

// writeCountingConn counts what its owner wrote. Reading the far end of a
// net.Pipe is not an option for this: Bridge.Run keeps a ReadSessionReason
// goroutine on the control stream for the whole session, so a test that read the
// same pipe would be competing with it. Counting at the writer is the only place
// the question "did anything go out on the control stream" can be asked.
type writeCountingConn struct {
	net.Conn
	mu      sync.Mutex
	written []byte
}

func (c *writeCountingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.mu.Lock()
		c.written = append(c.written, p[:n]...)
		c.mu.Unlock()
	}
	return n, err
}

func (c *writeCountingConn) wrote() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.written...)
}

// ---------------------------------------------------------------------------
// The PPP handshake response
// ---------------------------------------------------------------------------

// readPPPResponse consumes the response writePPPResponse emits. The real client
// does this in its dialer, before the control stream is handed to Bridge.Run, so
// a test that drives a server handler directly has to do the same or the bridge
// would read the handshake as a session reason.
//
// It returns an error rather than taking a *testing.T because it runs on the
// dialer's goroutine, which is Bridge.Run's, not the test's.
func readPPPResponse(r io.Reader) (ok bool, msg string, dataStreams, mtu int, err error) {
	br := quicvarint.NewReader(r)
	status, err := br.ReadByte()
	if err != nil {
		return false, "", 0, 0, err
	}

	readBytes := func() (string, error) {
		n, err := quicvarint.Read(br)
		if err != nil {
			return "", err
		}
		if n == 0 {
			return "", nil
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", err
		}
		return string(buf), nil
	}

	if msg, err = readBytes(); err != nil {
		return false, "", 0, 0, err
	}
	ds, err := quicvarint.Read(br)
	if err != nil {
		return false, "", 0, 0, err
	}
	m, err := quicvarint.Read(br)
	if err != nil {
		return false, "", 0, 0, err
	}
	if _, err := readBytes(); err != nil { // padding
		return false, "", 0, 0, err
	}
	return status == 0, msg, int(ds), int(m), nil
}
