package protocol

import (
	"encoding/binary"
	"io"

	"github.com/apernet/quic-go/quicvarint"

	"github.com/apernet/hysteria/core/v2/errors"
)

const (
	FrameTypeL3Stream = 0x402

	// L3StreamUplink means the client writes IP packets after the hello.
	L3StreamUplink = 0
	// L3StreamDownlink means the server writes IP packets after the hello.
	L3StreamDownlink = 1

	// L3PipeLanes is the fixed stream pool for one direction.
	// The client opens every stream. A VXLAN source port stays on one lane,
	// so one inner flow is not split and is not blocked by another flow.
	L3PipeLanes = 32

	// L3StreamPayloadMax is one IP packet plus a little headroom.
	L3StreamPayloadMax = 2048
)

// WriteL3StreamHello writes the stream frame type, the direction, and the lane.
// The server peeks the frame type, then reads the two bytes.
func WriteL3StreamHello(w io.Writer, dir, lane uint8) error {
	buf := make([]byte, quicvarint.Len(FrameTypeL3Stream)+2)
	n := varintPut(buf, FrameTypeL3Stream)
	buf[n] = dir
	buf[n+1] = lane
	return writeFull(w, buf[:n+2])
}

// WriteL3Frame writes one length-prefixed IP packet.
func WriteL3Frame(w io.Writer, pkt []byte) error {
	buf, err := AppendL3Frame(nil, pkt)
	if err != nil {
		return err
	}
	return writeFull(w, buf)
}

// L3FrameWriter writes length-prefixed IP packets through one reused buffer.
// A lane writer owns one, so a packet costs no allocation.
type L3FrameWriter struct {
	buf []byte
}

// Write writes one length-prefixed IP packet to w.
func (fw *L3FrameWriter) Write(w io.Writer, pkt []byte) error {
	buf, err := AppendL3Frame(fw.buf[:0], pkt)
	if err != nil {
		return err
	}
	fw.buf = buf
	return writeFull(w, buf)
}

// AppendL3Frame appends one length-prefixed IP packet to dst.
func AppendL3Frame(dst []byte, pkt []byte) ([]byte, error) {
	if len(pkt) == 0 || len(pkt) > L3StreamPayloadMax {
		return dst, errors.ProtocolError{Message: "invalid l3 frame"}
	}
	dst = binary.BigEndian.AppendUint16(dst, uint16(len(pkt)))
	return append(dst, pkt...), nil
}

// ReadL3Frame reads one length-prefixed IP packet.
func ReadL3Frame(r io.Reader) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	if n == 0 || n > L3StreamPayloadMax {
		return nil, errors.ProtocolError{Message: "invalid l3 frame length"}
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func writeFull(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}
