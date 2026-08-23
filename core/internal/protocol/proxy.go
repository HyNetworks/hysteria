package protocol

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/apernet/hysteria/core/v2/errors"

	"github.com/apernet/quic-go/quicvarint"
)

const (
	FrameTypeTCPRequest = 0x401
	FrameTypePPPRequest = 0x402
	FrameTypePPPData    = 0x403

	// Max length values are for preventing DoS attacks

	MaxAddressLength = 2048
	MaxMessageLength = 2048
	MaxPaddingLength = 4096

	MaxPPPDataStreams = 256

	MaxDatagramFrameSize = 65535
	// MaxPPPFrameSize bounds the advertised per-frame ceiling in the PPP handshake.
	MaxPPPFrameSize = 65535
	MaxUDPSize      = 4096

	maxVarInt1 = 63
	maxVarInt2 = 16383
	maxVarInt4 = 1073741823
	maxVarInt8 = 4611686018427387903
)

// TCPRequest format:
// 0x401 (QUIC varint)
// Address length (QUIC varint)
// Address (bytes)
// Padding length (QUIC varint)
// Padding (bytes)

func ReadTCPRequest(r io.Reader) (string, error) {
	bReader := quicvarint.NewReader(r)
	addrLen, err := quicvarint.Read(bReader)
	if err != nil {
		return "", err
	}
	if addrLen == 0 || addrLen > MaxAddressLength {
		return "", errors.ProtocolError{Message: "invalid address length"}
	}
	addrBuf := make([]byte, addrLen)
	_, err = io.ReadFull(r, addrBuf)
	if err != nil {
		return "", err
	}
	paddingLen, err := quicvarint.Read(bReader)
	if err != nil {
		return "", err
	}
	if paddingLen > MaxPaddingLength {
		return "", errors.ProtocolError{Message: "invalid padding length"}
	}
	if paddingLen > 0 {
		_, err = io.CopyN(io.Discard, r, int64(paddingLen))
		if err != nil {
			return "", err
		}
	}
	return string(addrBuf), nil
}

func WriteTCPRequest(w io.Writer, addr string) error {
	padding := tcpRequestPadding.String()
	paddingLen := len(padding)
	addrLen := len(addr)
	sz := int(quicvarint.Len(FrameTypeTCPRequest)) +
		int(quicvarint.Len(uint64(addrLen))) + addrLen +
		int(quicvarint.Len(uint64(paddingLen))) + paddingLen
	buf := make([]byte, sz)
	i := varintPut(buf, FrameTypeTCPRequest)
	i += varintPut(buf[i:], uint64(addrLen))
	i += copy(buf[i:], addr)
	i += varintPut(buf[i:], uint64(paddingLen))
	copy(buf[i:], padding)
	_, err := w.Write(buf)
	return err
}

// TCPResponse format:
// Status (byte, 0=ok, 1=error)
// Message length (QUIC varint)
// Message (bytes)
// Padding length (QUIC varint)
// Padding (bytes)

func ReadTCPResponse(r io.Reader) (bool, string, error) {
	var status [1]byte
	if _, err := io.ReadFull(r, status[:]); err != nil {
		return false, "", err
	}
	bReader := quicvarint.NewReader(r)
	msgLen, err := quicvarint.Read(bReader)
	if err != nil {
		return false, "", err
	}
	if msgLen > MaxMessageLength {
		return false, "", errors.ProtocolError{Message: "invalid message length"}
	}
	var msgBuf []byte
	// No message is fine
	if msgLen > 0 {
		msgBuf = make([]byte, msgLen)
		_, err = io.ReadFull(r, msgBuf)
		if err != nil {
			return false, "", err
		}
	}
	paddingLen, err := quicvarint.Read(bReader)
	if err != nil {
		return false, "", err
	}
	if paddingLen > MaxPaddingLength {
		return false, "", errors.ProtocolError{Message: "invalid padding length"}
	}
	if paddingLen > 0 {
		_, err = io.CopyN(io.Discard, r, int64(paddingLen))
		if err != nil {
			return false, "", err
		}
	}
	return status[0] == 0, string(msgBuf), nil
}

func WriteTCPResponse(w io.Writer, ok bool, msg string) error {
	padding := tcpResponsePadding.String()
	paddingLen := len(padding)
	msgLen := len(msg)
	sz := 1 + int(quicvarint.Len(uint64(msgLen))) + msgLen +
		int(quicvarint.Len(uint64(paddingLen))) + paddingLen
	buf := make([]byte, sz)
	if ok {
		buf[0] = 0
	} else {
		buf[0] = 1
	}
	i := varintPut(buf[1:], uint64(msgLen))
	i += copy(buf[1+i:], msg)
	i += varintPut(buf[1+i:], uint64(paddingLen))
	copy(buf[1+i:], padding)
	_, err := w.Write(buf)
	return err
}

// PPPRequest format:
// 0x402 (QUIC varint)
// DataStreams (QUIC varint)
// Padding length (QUIC varint)
// Padding (bytes)

// ReadPPPRequest returns the requested data stream count and the largest frame
// the client's transport will carry. A zero maxFrameSize means the client did
// not measure one.
func ReadPPPRequest(r io.Reader) (dataStreams, maxFrameSize int, err error) {
	bReader := quicvarint.NewReader(r)
	ds, err := quicvarint.Read(bReader)
	if err != nil {
		return 0, 0, err
	}
	if ds > MaxPPPDataStreams {
		return 0, 0, errors.ProtocolError{Message: "invalid dataStreams value"}
	}
	mfs, err := quicvarint.Read(bReader)
	if err != nil {
		return 0, 0, err
	}
	if mfs > MaxPPPFrameSize {
		return 0, 0, errors.ProtocolError{Message: "invalid maxFrameSize value"}
	}
	paddingLen, err := quicvarint.Read(bReader)
	if err != nil {
		return 0, 0, err
	}
	if paddingLen > MaxPaddingLength {
		return 0, 0, errors.ProtocolError{Message: "invalid padding length"}
	}
	if paddingLen > 0 {
		if _, err = io.CopyN(io.Discard, r, int64(paddingLen)); err != nil {
			return 0, 0, err
		}
	}
	return int(ds), int(mfs), nil
}

// WritePPPRequest announces the data stream count and the client's measured
// per-frame transport ceiling, so the server can size the PPP link to the
// smaller of the two directions. Pass 0 if it is unknown.
func WritePPPRequest(w io.Writer, dataStreams, maxFrameSize int) error {
	padding := pppRequestPadding.String()
	paddingLen := len(padding)
	sz := int(quicvarint.Len(FrameTypePPPRequest)) +
		int(quicvarint.Len(uint64(dataStreams))) +
		int(quicvarint.Len(uint64(maxFrameSize))) +
		int(quicvarint.Len(uint64(paddingLen))) + paddingLen
	buf := make([]byte, sz)
	i := varintPut(buf, FrameTypePPPRequest)
	i += varintPut(buf[i:], uint64(dataStreams))
	i += varintPut(buf[i:], uint64(maxFrameSize))
	i += varintPut(buf[i:], uint64(paddingLen))
	copy(buf[i:], padding)
	_, err := w.Write(buf)
	return err
}

// PPPResponse format:
// Status (byte, 0=ok, 1=error)
// Message length (QUIC varint)
// Message (bytes)
// DataStreams (QUIC varint)
// Padding length (QUIC varint)
// Padding (bytes)

// ReadPPPResponse also returns the PPP MTU the server settled on, or 0 if it
// did not pick one.
func ReadPPPResponse(r io.Reader) (ok bool, msg string, dataStreams, mtu int, err error) {
	var status [1]byte
	if _, err := io.ReadFull(r, status[:]); err != nil {
		return false, "", 0, 0, err
	}
	bReader := quicvarint.NewReader(r)
	msgLen, err := quicvarint.Read(bReader)
	if err != nil {
		return false, "", 0, 0, err
	}
	if msgLen > MaxMessageLength {
		return false, "", 0, 0, errors.ProtocolError{Message: "invalid message length"}
	}
	var msgBuf []byte
	if msgLen > 0 {
		msgBuf = make([]byte, msgLen)
		if _, err = io.ReadFull(r, msgBuf); err != nil {
			return false, "", 0, 0, err
		}
	}
	ds, err := quicvarint.Read(bReader)
	if err != nil {
		return false, "", 0, 0, err
	}
	if ds > MaxPPPDataStreams {
		return false, "", 0, 0, errors.ProtocolError{Message: "invalid dataStreams value"}
	}
	rawMTU, err := quicvarint.Read(bReader)
	if err != nil {
		return false, "", 0, 0, err
	}
	if rawMTU > MaxPPPFrameSize {
		return false, "", 0, 0, errors.ProtocolError{Message: "invalid mtu value"}
	}
	paddingLen, err := quicvarint.Read(bReader)
	if err != nil {
		return false, "", 0, 0, err
	}
	if paddingLen > MaxPaddingLength {
		return false, "", 0, 0, errors.ProtocolError{Message: "invalid padding length"}
	}
	if paddingLen > 0 {
		if _, err = io.CopyN(io.Discard, r, int64(paddingLen)); err != nil {
			return false, "", 0, 0, err
		}
	}
	return status[0] == 0, string(msgBuf), int(ds), int(rawMTU), nil
}

// WritePPPResponse reports the negotiated PPP MTU back to the client so it can
// be logged and surfaced; pass 0 when none was computed.
func WritePPPResponse(w io.Writer, ok bool, msg string, dataStreams, mtu int) error {
	padding := pppResponsePadding.String()
	paddingLen := len(padding)
	msgLen := len(msg)
	sz := 1 + int(quicvarint.Len(uint64(msgLen))) + msgLen +
		int(quicvarint.Len(uint64(dataStreams))) +
		int(quicvarint.Len(uint64(mtu))) +
		int(quicvarint.Len(uint64(paddingLen))) + paddingLen
	buf := make([]byte, sz)
	if ok {
		buf[0] = 0
	} else {
		buf[0] = 1
	}
	i := varintPut(buf[1:], uint64(msgLen))
	i += copy(buf[1+i:], msg)
	i += varintPut(buf[1+i:], uint64(dataStreams))
	i += varintPut(buf[1+i:], uint64(mtu))
	i += varintPut(buf[1+i:], uint64(paddingLen))
	copy(buf[1+i:], padding)
	_, err := w.Write(buf)
	return err
}

// UDPMessage format:
// Session ID (uint32 BE)
// Packet ID (uint16 BE)
// Fragment ID (uint8)
// Fragment count (uint8)
// Address length (QUIC varint)
// Address (bytes)
// Data...

type UDPMessage struct {
	SessionID uint32 // 4
	PacketID  uint16 // 2
	FragID    uint8  // 1
	FragCount uint8  // 1
	Addr      string // varint + bytes
	Data      []byte
}

func (m *UDPMessage) HeaderSize() int {
	lAddr := len(m.Addr)
	return 4 + 2 + 1 + 1 + int(quicvarint.Len(uint64(lAddr))) + lAddr
}

func (m *UDPMessage) Size() int {
	return m.HeaderSize() + len(m.Data)
}

func (m *UDPMessage) Serialize(buf []byte) int {
	// Make sure the buffer is big enough
	if len(buf) < m.Size() {
		return -1
	}
	binary.BigEndian.PutUint32(buf, m.SessionID)
	binary.BigEndian.PutUint16(buf[4:], m.PacketID)
	buf[6] = m.FragID
	buf[7] = m.FragCount
	i := varintPut(buf[8:], uint64(len(m.Addr)))
	i += copy(buf[8+i:], m.Addr)
	i += copy(buf[8+i:], m.Data)
	return 8 + i
}

func ParseUDPMessage(msg []byte) (*UDPMessage, error) {
	m := &UDPMessage{}
	buf := bytes.NewBuffer(msg)
	if err := binary.Read(buf, binary.BigEndian, &m.SessionID); err != nil {
		return nil, err
	}
	if err := binary.Read(buf, binary.BigEndian, &m.PacketID); err != nil {
		return nil, err
	}
	if err := binary.Read(buf, binary.BigEndian, &m.FragID); err != nil {
		return nil, err
	}
	if err := binary.Read(buf, binary.BigEndian, &m.FragCount); err != nil {
		return nil, err
	}
	lAddr, err := quicvarint.Read(buf)
	if err != nil {
		return nil, err
	}
	if lAddr == 0 || lAddr > MaxMessageLength {
		return nil, errors.ProtocolError{Message: "invalid address length"}
	}
	bs := buf.Bytes()
	if len(bs) <= int(lAddr) {
		// We use <= instead of < here as we expect at least one byte of data after the address
		return nil, errors.ProtocolError{Message: "invalid message length"}
	}
	m.Addr = string(bs[:lAddr])
	m.Data = bs[lAddr:]
	return m, nil
}

// varintPut is like quicvarint.Append, but instead of appending to a slice,
// it writes to a fixed-size buffer. Returns the number of bytes written.
func varintPut(b []byte, i uint64) int {
	if i <= maxVarInt1 {
		b[0] = uint8(i)
		return 1
	}
	if i <= maxVarInt2 {
		b[0] = uint8(i>>8) | 0x40
		b[1] = uint8(i)
		return 2
	}
	if i <= maxVarInt4 {
		b[0] = uint8(i>>24) | 0x80
		b[1] = uint8(i >> 16)
		b[2] = uint8(i >> 8)
		b[3] = uint8(i)
		return 4
	}
	if i <= maxVarInt8 {
		b[0] = uint8(i>>56) | 0xc0
		b[1] = uint8(i >> 48)
		b[2] = uint8(i >> 40)
		b[3] = uint8(i >> 32)
		b[4] = uint8(i >> 24)
		b[5] = uint8(i >> 16)
		b[6] = uint8(i >> 8)
		b[7] = uint8(i)
		return 8
	}
	panic(fmt.Sprintf("%#x doesn't fit into 62 bits", i))
}
