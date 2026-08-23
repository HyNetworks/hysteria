package pppbridge

import (
	"fmt"
	"io"
	"sync"

	"github.com/apernet/hysteria/extras/v2/l2tp"
)

// Endpoint is whatever sits at the far end of a PPP frame relay: a local pppd,
// or an L2TP session to an LNS. Frames are raw PPP -- address, control, protocol
// and payload -- with no HDLC framing, which is the same shape the Hysteria2
// transport carries.
//
// Having both server modes meet this one interface is what lets the relay, the
// MTU probe protocol and the oversize accounting exist once instead of twice.
// Closing is deliberately not part of this interface. Whoever built the endpoint
// tears it down, because only they know what else has to happen and in what
// order: the Bridge closes the pty and then waits for the child to exit, and the
// L2TP handler closes the session so a CDN reaches the LNS. A Close here would
// suggest the relay owns that, which it does not.
type Endpoint interface {
	// SendPPP hands a frame from the Hysteria2 client to the endpoint.
	SendPPP(rawPPP []byte) error
	// RecvPPP returns the next frame from the endpoint, bound for the client.
	RecvPPP() ([]byte, error)
}

// FrameRW is the subset of a transport needed to exchange raw PPP frames. Both
// ppp.PPPDataIO and an Endpoint satisfy the same shape, which is what lets LCP
// negotiation run over either without knowing which it has.
type FrameRW interface {
	SendPPP(rawPPP []byte) error
	RecvPPP() ([]byte, error)
}

// maxHDLCAccumulate bounds the bytes an endpoint will buffer while looking for a
// frame. A 1500-octet frame cannot exceed ~3KB even if every octet needs
// escaping, so anything past this without a flag octet is not a frame in
// progress.
const maxHDLCAccumulate = 16384

// hdlcEndpoint is a pppd reached over a byte stream -- a pty, a pipe, or this
// process's own stdio. It is the only place HDLC framing happens: pppd speaks it,
// the Hysteria2 transport does not, and both the client bridge and the local
// server mode use this same adapter.
type hdlcEndpoint struct {
	r io.Reader
	w io.Writer

	// writeMu serialises writes toward pppd. Frames reach it from the relay's
	// receive pump and, historically, from more than one place; one writer at a
	// time is what keeps the HDLC stream intelligible.
	writeMu sync.Mutex
	encBuf  []byte

	// accumulated HDLC bytes not yet forming a complete frame
	buf []byte
	// readBuf is reused across calls. RecvPPP is called once per PPP frame, so
	// allocating here would put a fresh 16KB buffer through the garbage collector
	// for every frame the link carries. Only the relay's endpoint pump reads.
	readBuf []byte
}

func newHDLCEndpoint(r io.Reader, w io.Writer) *hdlcEndpoint {
	return &hdlcEndpoint{
		r:       r,
		w:       w,
		encBuf:  make([]byte, 0, 4096),
		readBuf: make([]byte, 16384),
	}
}

func (e *hdlcEndpoint) SendPPP(rawPPP []byte) error {
	e.writeMu.Lock()
	defer e.writeMu.Unlock()
	e.encBuf = EncodeHDLCTo(rawPPP, e.encBuf)
	_, err := e.w.Write(e.encBuf)
	return err
}

// RecvPPP returns the next complete PPP frame from the byte stream, skipping
// frames whose FCS does not check out.
func (e *hdlcEndpoint) RecvPPP() ([]byte, error) {
	for {
		for {
			frame, rest, ok := extractHDLCFrame(e.buf)
			if !ok {
				break
			}
			e.buf = rest
			rawPPP, err := DecodeHDLC(frame)
			if err != nil {
				// A corrupt frame is discarded and reception resumes at the next
				// flag, per RFC 1662 s4.3.
				continue
			}
			return rawPPP, nil
		}
		n, err := e.r.Read(e.readBuf)
		if n > 0 {
			e.buf = append(e.buf, e.readBuf[:n]...)
			// extractHDLCFrame hands the buffer straight back when it cannot find
			// a frame, so a peer that never sends a flag octet would otherwise
			// grow this without bound.
			if len(e.buf) > maxHDLCAccumulate {
				return nil, fmt.Errorf("ppp: no HDLC frame in %d buffered bytes", len(e.buf))
			}
			continue
		}
		if err != nil {
			return nil, err
		}
	}
}

// l2tpEndpoint is an L2TP session to an LNS.
//
// There is nothing to adapt. RFC 2661 s4.1 makes the information field of an
// L2TP data message the PPP frame with its HDLC framing removed, which is
// exactly what the relay carries, so a frame crosses the LAC as the bytes it
// arrived as.
//
// It used to split the protocol field out on the way in and glue it back on the
// way out. Nothing in between ever read it -- the L2TP session ID does all the
// routing -- and the round trip was a liability rather than a cost. The
// subscriber's pppd negotiates Protocol-Field-Compression and address/control
// compression with the LNS directly, through this tunnel and without telling the
// LAC, so any reading of those fields here was a guess about an agreement
// between two other parties. Passing the bytes through cannot be wrong about it.
type l2tpEndpoint struct {
	session *l2tp.Session
}

func newL2TPEndpoint(s *l2tp.Session) *l2tpEndpoint { return &l2tpEndpoint{session: s} }

func (e *l2tpEndpoint) SendPPP(rawPPP []byte) error { return e.session.SendPPP(rawPPP) }

func (e *l2tpEndpoint) RecvPPP() ([]byte, error) { return e.session.RecvPPP() }

// dataIOFrameRW presents a ppp.PPPDataIO as a FrameRW so LCP negotiation can run
// over the Hysteria2 transport directly, with no HDLC in between.
type dataIOFrameRW struct {
	send func([]byte) error
	recv func() ([]byte, error)
}

func (d dataIOFrameRW) SendPPP(rawPPP []byte) error { return d.send(rawPPP) }
func (d dataIOFrameRW) RecvPPP() ([]byte, error)    { return d.recv() }
