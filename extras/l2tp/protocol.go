package l2tp

import (
	"crypto/md5"
	"encoding/binary"
	"errors"
	"fmt"
)

// L2TP message types (AVP type 0)
const (
	MsgTypeSCCRQ   uint16 = 1  // Start-Control-Connection-Request
	MsgTypeSCCRP   uint16 = 2  // Start-Control-Connection-Reply
	MsgTypeSCCCN   uint16 = 3  // Start-Control-Connection-Connected
	MsgTypeStopCCN uint16 = 4  // Stop-Control-Connection-Notification
	MsgTypeHello   uint16 = 6  // Hello
	MsgTypeICRQ    uint16 = 10 // Incoming-Call-Request
	MsgTypeICRP    uint16 = 11 // Incoming-Call-Reply
	MsgTypeICCN    uint16 = 12 // Incoming-Call-Connected
	MsgTypeCDN     uint16 = 14 // Call-Disconnect-Notify
)

// AVP attribute types (IETF, Vendor ID 0)
const (
	AVPMessageType               uint16 = 0
	AVPResultCode                uint16 = 1
	AVPProtocolVersion           uint16 = 2
	AVPFramingCapabilities       uint16 = 3
	AVPHostName                  uint16 = 7
	AVPAssignedTunnelID          uint16 = 9
	AVPReceiveWindowSize         uint16 = 10
	AVPChallenge                 uint16 = 11
	AVPChallengeResponse         uint16 = 13
	AVPAssignedSessionID         uint16 = 14
	AVPCallSerialNumber          uint16 = 15
	AVPFramingType               uint16 = 19
	AVPCallingNumber             uint16 = 22
	AVPConnectSpeed              uint16 = 24
	AVPInitialReceivedLCPCONFREQ uint16 = 26
	AVPLastSentLCPCONFREQ        uint16 = 27
	AVPLastReceivedLCPCONFREQ    uint16 = 28
	AVPProxyAuthenType           uint16 = 29
	AVPProxyAuthenName           uint16 = 30
	AVPProxyAuthenChallenge      uint16 = 31
	AVPProxyAuthenID             uint16 = 32
	AVPProxyAuthenResponse       uint16 = 33
)

// Proxy Authen Type values (RFC 2661 Section 4.4.5)
const (
	ProxyAuthenCHAP uint16 = 2
	ProxyAuthenPAP  uint16 = 3
)

// Framing capabilities/type bits
const (
	FramingAsync uint32 = 0x00000002
	FramingSync  uint32 = 0x00000001
)

// L2TP protocol version
const (
	ProtocolVersion  uint8 = 1
	ProtocolRevision uint8 = 0
)

var (
	ErrShortPacket = errors.New("l2tp: packet too short")
	ErrBadHeader   = errors.New("l2tp: invalid header")
	ErrBadAVP      = errors.New("l2tp: invalid AVP")
	ErrMissingAVP  = errors.New("l2tp: required AVP missing")
)

// Header represents a decoded L2TP header.
type Header struct {
	IsControl bool
	HasLength bool
	Tunnel    uint16
	Session   uint16
	Ns        uint16
	Nr        uint16
	Length    uint16 // total packet length (only if HasLength)
}

// DecodeHeader decodes an L2TP header from raw bytes.
// Returns the header and the offset to the payload, which is always within
// data: every optional field is bounds-checked as it is consumed, so a caller
// may slice data[off:] without checking again.
//
// The checks are written the same way whether or not the six-octet minimum
// already covers the field -- the first one cannot fire today, and is kept in
// step with the rest rather than left as the one place a future change to the
// minimum would have to remember to fix.
func DecodeHeader(data []byte) (Header, int, error) {
	if len(data) < 6 {
		return Header{}, 0, ErrShortPacket
	}
	flags := binary.BigEndian.Uint16(data[0:2])
	isControl := flags&0x8000 != 0
	hasLength := flags&0x4000 != 0
	hasSeq := flags&0x0800 != 0
	ver := flags & 0x000F
	if ver != 2 {
		return Header{}, 0, fmt.Errorf("%w: version %d", ErrBadHeader, ver)
	}

	off := 2
	var h Header
	h.IsControl = isControl
	h.HasLength = hasLength

	if hasLength {
		if off+2 > len(data) {
			return Header{}, 0, ErrShortPacket
		}
		h.Length = binary.BigEndian.Uint16(data[off : off+2])
		off += 2
	}

	if off+4 > len(data) {
		return Header{}, 0, ErrShortPacket
	}
	h.Tunnel = binary.BigEndian.Uint16(data[off : off+2])
	h.Session = binary.BigEndian.Uint16(data[off+2 : off+4])
	off += 4

	if hasSeq {
		if off+4 > len(data) {
			return Header{}, 0, ErrShortPacket
		}
		h.Ns = binary.BigEndian.Uint16(data[off : off+2])
		h.Nr = binary.BigEndian.Uint16(data[off+2 : off+4])
		off += 4
	}

	// Skip offset field if present (O bit)
	if flags&0x0200 != 0 {
		if off+2 > len(data) {
			return Header{}, 0, ErrShortPacket
		}
		oSize := binary.BigEndian.Uint16(data[off : off+2])
		off += 2 + int(oSize)
		if off > len(data) {
			return Header{}, 0, ErrShortPacket
		}
	}

	return h, off, nil
}

// EncodeControlHeader builds an L2TP control message header.
// Control messages always have Length, Sequence, and T bit set.
func EncodeControlHeader(tunnel, session, ns, nr uint16, payloadLen int) []byte {
	totalLen := 12 + payloadLen // flags(2) + length(2) + tunnelID(2) + sessionID(2) + Ns(2) + Nr(2) + payload
	buf := make([]byte, 12)
	// T=1, L=1, S=1, version=2
	binary.BigEndian.PutUint16(buf[0:2], 0xC802)
	binary.BigEndian.PutUint16(buf[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(buf[4:6], tunnel)
	binary.BigEndian.PutUint16(buf[6:8], session)
	binary.BigEndian.PutUint16(buf[8:10], ns)
	binary.BigEndian.PutUint16(buf[10:12], nr)
	return buf
}

// EncodeDataHeader builds an L2TP data message header (no Length, no Sequence).
func EncodeDataHeader(tunnel, session uint16) []byte {
	buf := make([]byte, 6)
	// T=0, L=0, S=0, version=2
	binary.BigEndian.PutUint16(buf[0:2], 0x0002)
	binary.BigEndian.PutUint16(buf[2:4], tunnel)
	binary.BigEndian.PutUint16(buf[4:6], session)
	return buf
}

// AVP represents a decoded Attribute-Value Pair.
type AVP struct {
	Mandatory bool
	VendorID  uint16
	Type      uint16
	Value     []byte
}

// DecodeAVPs parses all AVPs from control message payload.
func DecodeAVPs(data []byte) ([]AVP, error) {
	var avps []AVP
	off := 0
	for off < len(data) {
		if off+6 > len(data) {
			return nil, ErrBadAVP
		}
		flags := binary.BigEndian.Uint16(data[off : off+2])
		avpLen := int(flags & 0x03FF)
		mandatory := flags&0x8000 != 0

		if avpLen < 6 || off+avpLen > len(data) {
			return nil, ErrBadAVP
		}

		vendorID := binary.BigEndian.Uint16(data[off+2 : off+4])
		attrType := binary.BigEndian.Uint16(data[off+4 : off+6])
		value := make([]byte, avpLen-6)
		copy(value, data[off+6:off+avpLen])

		avps = append(avps, AVP{
			Mandatory: mandatory,
			VendorID:  vendorID,
			Type:      attrType,
			Value:     value,
		})
		off += avpLen
	}
	return avps, nil
}

// EncodeAVPWithFlags encodes a single AVP with the provided Mandatory bit and Vendor ID 0.
// AVPMaxValue is the largest value an AVP can carry. RFC 2661 s4.1 gives the
// Length field 10 bits, so an AVP is at most 1023 octets including its 6-octet
// header.
const (
	avpMaxLen   = 1023
	AVPMaxValue = avpMaxLen - 6
)

// EncodeAVPWithFlags encodes one AVP, truncating a value that cannot fit.
//
// The truncation is not politeness, it is a security boundary. The Length field
// is 10 bits, so a value of 1018 octets or more makes the length wrap: at 1024 it
// becomes 0 and spills into the reserved bits, and at 1030 it becomes 6 -- which
// means the peer stops reading the value where we thought it began and starts
// parsing the rest of it as further AVPs. Anyone able to influence the length of
// an encoded value would therefore get to inject AVPs of their choosing into a
// message the LNS trusts, which is far worse than a field arriving short.
//
// Callers for whom a truncated value would be wrong rather than merely lossy
// must bound their input themselves; BuildICRQ does this for the calling number.
func EncodeAVPWithFlags(attrType uint16, value []byte, mandatory bool) []byte {
	if len(value) > AVPMaxValue {
		value = value[:AVPMaxValue]
	}
	avpLen := 6 + len(value)
	buf := make([]byte, avpLen)
	flags := uint16(avpLen)
	if mandatory {
		flags |= 0x8000
	}
	// Hidden=0, length in lower 10 bits
	binary.BigEndian.PutUint16(buf[0:2], flags)
	binary.BigEndian.PutUint16(buf[2:4], 0) // Vendor ID
	binary.BigEndian.PutUint16(buf[4:6], attrType)
	copy(buf[6:], value)
	return buf
}

// EncodeAVP encodes a single AVP with the Mandatory bit set, Vendor ID 0.
func EncodeAVP(attrType uint16, value []byte) []byte {
	return EncodeAVPWithFlags(attrType, value, true)
}

// Helper functions for encoding common AVP value types.

func EncodeUint16AVP(attrType, val uint16) []byte {
	return EncodeUint16AVPWithFlags(attrType, val, true)
}

func EncodeUint16AVPWithFlags(attrType, val uint16, mandatory bool) []byte {
	v := make([]byte, 2)
	binary.BigEndian.PutUint16(v, val)
	return EncodeAVPWithFlags(attrType, v, mandatory)
}

func EncodeUint32AVP(attrType uint16, val uint32) []byte {
	return EncodeUint32AVPWithFlags(attrType, val, true)
}

func EncodeUint32AVPWithFlags(attrType uint16, val uint32, mandatory bool) []byte {
	v := make([]byte, 4)
	binary.BigEndian.PutUint32(v, val)
	return EncodeAVPWithFlags(attrType, v, mandatory)
}

func EncodeStringAVP(attrType uint16, val string) []byte {
	return EncodeStringAVPWithFlags(attrType, val, true)
}

func EncodeStringAVPWithFlags(attrType uint16, val string, mandatory bool) []byte {
	return EncodeAVPWithFlags(attrType, []byte(val), mandatory)
}

func EncodeBytesAVP(attrType uint16, val []byte) []byte {
	return EncodeBytesAVPWithFlags(attrType, val, true)
}

func EncodeBytesAVPWithFlags(attrType uint16, val []byte, mandatory bool) []byte {
	return EncodeAVPWithFlags(attrType, val, mandatory)
}

// FindAVP searches for an AVP by vendor ID and type in a list.
func FindAVP(avps []AVP, vendorID, attrType uint16) *AVP {
	for i := range avps {
		if avps[i].VendorID == vendorID && avps[i].Type == attrType {
			return &avps[i]
		}
	}
	return nil
}

// AVPUint16 extracts a uint16 value from an AVP.
func AVPUint16(avp *AVP) (uint16, error) {
	if len(avp.Value) < 2 {
		return 0, fmt.Errorf("%w: expected 2 bytes for uint16 AVP", ErrBadAVP)
	}
	return binary.BigEndian.Uint16(avp.Value), nil
}

// AVPUint32 extracts a uint32 value from an AVP.
func AVPUint32(avp *AVP) (uint32, error) {
	if len(avp.Value) < 4 {
		return 0, fmt.Errorf("%w: expected 4 bytes for uint32 AVP", ErrBadAVP)
	}
	return binary.BigEndian.Uint32(avp.Value), nil
}

// BuildSCCRQ builds a Start-Control-Connection-Request message payload (AVPs only).
func BuildSCCRQ(hostname string, tunnelID, recvWindowSize uint16, challenge []byte) []byte {
	var buf []byte
	buf = append(buf, EncodeUint16AVP(AVPMessageType, MsgTypeSCCRQ)...)
	// Protocol Version: 1.0
	ver := []byte{ProtocolVersion, ProtocolRevision}
	buf = append(buf, EncodeAVP(AVPProtocolVersion, ver)...)
	buf = append(buf, EncodeStringAVP(AVPHostName, hostname)...)
	buf = append(buf, EncodeUint32AVP(AVPFramingCapabilities, FramingAsync|FramingSync)...)
	buf = append(buf, EncodeUint16AVP(AVPAssignedTunnelID, tunnelID)...)
	buf = append(buf, EncodeUint16AVP(AVPReceiveWindowSize, recvWindowSize)...)
	if len(challenge) > 0 {
		buf = append(buf, EncodeBytesAVP(AVPChallenge, challenge)...)
	}
	return buf
}

// BuildSCCCN builds a Start-Control-Connection-Connected message payload.
func BuildSCCCN(challengeResponse []byte) []byte {
	var buf []byte
	buf = append(buf, EncodeUint16AVP(AVPMessageType, MsgTypeSCCCN)...)
	if len(challengeResponse) > 0 {
		buf = append(buf, EncodeBytesAVP(AVPChallengeResponse, challengeResponse)...)
	}
	return buf
}

// BuildICRQ builds an Incoming-Call-Request message payload.
// maxCallingNumber bounds the Calling Number AVP. See BuildICRQ.
const maxCallingNumber = 255

func BuildICRQ(sessionID uint16, callSerial uint32, callingNumber string) []byte {
	var buf []byte
	buf = append(buf, EncodeUint16AVP(AVPMessageType, MsgTypeICRQ)...)
	buf = append(buf, EncodeUint16AVP(AVPAssignedSessionID, sessionID)...)
	buf = append(buf, EncodeUint32AVP(AVPCallSerialNumber, callSerial)...)
	// The calling number is the subscriber's Hysteria2 identity, which with an
	// external authenticator is a string this LAC does not choose. Bound it here
	// rather than rely on the encoder's own clamp, so what reaches the LNS is a
	// deliberate length and not a side effect. 255 is generous for an identity and
	// is what most LNS implementations record as the Calling-Station-Id.
	if callingNumber != "" {
		if len(callingNumber) > maxCallingNumber {
			callingNumber = callingNumber[:maxCallingNumber]
		}
		buf = append(buf, EncodeStringAVP(AVPCallingNumber, callingNumber)...)
	}
	return buf
}

// BuildICCN builds an Incoming-Call-Connected message payload with proxy AVPs.
// BuildICCN builds an Incoming-Call-Connected message payload.
//
// RFC 2661 s6.8 makes exactly three AVPs mandatory here -- Message Type, (Tx)
// Connect Speed and Framing Type -- and every proxy LCP/authentication AVP
// optional. This LAC sends none of them: it never runs LCP or authentication
// with the subscriber, so it has nothing to proxy and nothing to lie about.
//
// Omitting Proxy Authen Type is not a gap, it is the signal. RFC 2661 s4.4.5:
// "If it is not present, then it is assumed that this peer cannot perform proxy
// authentication, requiring a restart of the authentication phase at the LNS".
// The LNS therefore runs LCP and authentication directly with the subscriber,
// end to end through the tunnel, which is what we want.
func BuildICCN() []byte {
	var buf []byte
	buf = append(buf, EncodeUint16AVP(AVPMessageType, MsgTypeICCN)...)
	buf = append(buf, EncodeUint32AVP(AVPConnectSpeed, 100000000)...) // 100 Mbps nominal
	buf = append(buf, EncodeUint32AVP(AVPFramingType, FramingSync)...)
	return buf
}

// BuildStopCCN builds a Stop-Control-Connection-Notification message payload.
func BuildStopCCN(tunnelID, resultCode, errorCode uint16, errMsg string) []byte {
	var buf []byte
	buf = append(buf, EncodeUint16AVP(AVPMessageType, MsgTypeStopCCN)...)
	buf = append(buf, EncodeUint16AVP(AVPAssignedTunnelID, tunnelID)...)

	// Result Code AVP: result(2) + error(2) + optional message
	rc := make([]byte, 4+len(errMsg))
	binary.BigEndian.PutUint16(rc[0:2], resultCode)
	binary.BigEndian.PutUint16(rc[2:4], errorCode)
	copy(rc[4:], errMsg)
	buf = append(buf, EncodeAVP(AVPResultCode, rc)...)
	return buf
}

// BuildCDN builds a Call-Disconnect-Notify message payload.
func BuildCDN(sessionID, resultCode, errorCode uint16, errMsg string) []byte {
	var buf []byte
	buf = append(buf, EncodeUint16AVP(AVPMessageType, MsgTypeCDN)...)
	buf = append(buf, EncodeUint16AVP(AVPAssignedSessionID, sessionID)...)

	rc := make([]byte, 4+len(errMsg))
	binary.BigEndian.PutUint16(rc[0:2], resultCode)
	binary.BigEndian.PutUint16(rc[2:4], errorCode)
	copy(rc[4:], errMsg)
	buf = append(buf, EncodeAVP(AVPResultCode, rc)...)
	return buf
}

// BuildHello builds a Hello message payload.
func BuildHello() []byte {
	return EncodeUint16AVP(AVPMessageType, MsgTypeHello)
}

// GetMessageType extracts the Message Type from a list of AVPs.
func GetMessageType(avps []AVP) (uint16, error) {
	avp := FindAVP(avps, 0, AVPMessageType)
	if avp == nil {
		return 0, fmt.Errorf("%w: Message Type", ErrMissingAVP)
	}
	return AVPUint16(avp)
}

// ComputeChallengeResponse computes the CHAP-style challenge response
// for L2TP tunnel authentication per RFC 2661 Section 5.1.1.
// response = MD5(msgType + secret + challenge)
func ComputeChallengeResponse(msgType uint8, secret, challenge []byte) []byte {
	h := md5.New()
	h.Write([]byte{msgType})
	h.Write(secret)
	h.Write(challenge)
	return h.Sum(nil)
}
