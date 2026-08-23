package l2tp

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncodeDecodeControlHeader(t *testing.T) {
	payload := []byte{0x01, 0x02, 0x03}
	hdr := EncodeControlHeader(100, 200, 5, 3, len(payload))
	pkt := append(hdr, payload...)

	decoded, off, err := DecodeHeader(pkt)
	require.NoError(t, err)
	assert.True(t, decoded.IsControl)
	assert.True(t, decoded.HasLength)
	assert.Equal(t, uint16(100), decoded.Tunnel)
	assert.Equal(t, uint16(200), decoded.Session)
	assert.Equal(t, uint16(5), decoded.Ns)
	assert.Equal(t, uint16(3), decoded.Nr)
	assert.Equal(t, uint16(len(pkt)), decoded.Length)
	assert.Equal(t, payload, pkt[off:])
}

func TestEncodeDecodeDataHeader(t *testing.T) {
	hdr := EncodeDataHeader(100, 200)
	payload := []byte{0xC0, 0x21, 0x01, 0x02}
	pkt := append(hdr, payload...)

	decoded, off, err := DecodeHeader(pkt)
	require.NoError(t, err)
	assert.False(t, decoded.IsControl)
	assert.False(t, decoded.HasLength)
	assert.Equal(t, uint16(100), decoded.Tunnel)
	assert.Equal(t, uint16(200), decoded.Session)
	assert.Equal(t, payload, pkt[off:])
}

func TestDecodeHeaderWithOffset(t *testing.T) {
	payload := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	pkt := make([]byte, 12+len(payload))
	binary.BigEndian.PutUint16(pkt[0:2], 0x4202) // L=1, O=1, version=2
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	binary.BigEndian.PutUint16(pkt[4:6], 10)
	binary.BigEndian.PutUint16(pkt[6:8], 20)
	binary.BigEndian.PutUint16(pkt[8:10], 2) // offset size
	pkt[10] = 0
	pkt[11] = 0
	copy(pkt[12:], payload)

	decoded, off, err := DecodeHeader(pkt)
	require.NoError(t, err)
	assert.True(t, decoded.HasLength)
	assert.Equal(t, 12, off)
	assert.Equal(t, payload, pkt[off:])
}

func TestDecodeHeaderRejectsBadOffset(t *testing.T) {
	pkt := []byte{
		0x42, 0x02, // L=1, O=1, version=2
		0x00, 0x0C, // length
		0x00, 0x01, // tunnel
		0x00, 0x02, // session
		0x00, 0x10, // offset size too large
	}

	_, _, err := DecodeHeader(pkt)
	require.ErrorIs(t, err, ErrShortPacket)
}

func TestEncodeDecodeAVPs(t *testing.T) {
	var buf []byte
	buf = append(buf, EncodeUint16AVP(AVPMessageType, MsgTypeSCCRQ)...)
	buf = append(buf, EncodeStringAVPWithFlags(AVPHostName, "test-lac", false)...)
	buf = append(buf, EncodeUint32AVP(AVPFramingCapabilities, FramingAsync|FramingSync)...)

	avps, err := DecodeAVPs(buf)
	require.NoError(t, err)
	require.Len(t, avps, 3)

	assert.Equal(t, AVPMessageType, avps[0].Type)
	assert.True(t, avps[0].Mandatory)
	mt, err := AVPUint16(&avps[0])
	require.NoError(t, err)
	assert.Equal(t, MsgTypeSCCRQ, mt)

	assert.Equal(t, AVPHostName, avps[1].Type)
	assert.False(t, avps[1].Mandatory)
	assert.Equal(t, "test-lac", string(avps[1].Value))

	assert.Equal(t, AVPFramingCapabilities, avps[2].Type)
	assert.True(t, avps[2].Mandatory)
	fc, err := AVPUint32(&avps[2])
	require.NoError(t, err)
	assert.Equal(t, FramingAsync|FramingSync, fc)
}

func TestDecodeAVPsRejectsMalformedLength(t *testing.T) {
	_, err := DecodeAVPs([]byte{
		0x80, 0x04, // declared length too short for an AVP
		0x00, 0x00,
		0x00, 0x01,
	})
	require.ErrorIs(t, err, ErrBadAVP)
}

func TestFindAVP(t *testing.T) {
	var buf []byte
	buf = append(buf, EncodeUint16AVP(AVPMessageType, MsgTypeICRQ)...)
	buf = append(buf, EncodeUint16AVP(AVPAssignedSessionID, 42)...)

	avps, err := DecodeAVPs(buf)
	require.NoError(t, err)

	found := FindAVP(avps, 0, AVPAssignedSessionID)
	require.NotNil(t, found)
	sid, err := AVPUint16(found)
	require.NoError(t, err)
	assert.Equal(t, uint16(42), sid)

	notFound := FindAVP(avps, 0, AVPHostName)
	assert.Nil(t, notFound)
}

func TestBuildSCCRQ(t *testing.T) {
	payload := BuildSCCRQ("my-lac", 1234, 4, []byte{1, 2, 3, 4})
	avps := decodeAVPs(t, payload)

	assertMessageType(t, avps, MsgTypeSCCRQ)
	assertAVPFlags(t, avps, AVPProtocolVersion, true)
	assertAVPFlags(t, avps, AVPHostName, true)
	assertAVPFlags(t, avps, AVPFramingCapabilities, true)
	assertAVPFlags(t, avps, AVPAssignedTunnelID, true)
	assertAVPFlags(t, avps, AVPReceiveWindowSize, true)
	assertAVPFlags(t, avps, AVPChallenge, true)

	hn := FindAVP(avps, 0, AVPHostName)
	require.NotNil(t, hn)
	assert.Equal(t, "my-lac", string(hn.Value))

	tid := FindAVP(avps, 0, AVPAssignedTunnelID)
	require.NotNil(t, tid)
	v, err := AVPUint16(tid)
	require.NoError(t, err)
	assert.Equal(t, uint16(1234), v)
}

func TestBuildSCCCN(t *testing.T) {
	payload := BuildSCCCN([]byte{0xAA, 0xBB})
	avps := decodeAVPs(t, payload)

	assertMessageType(t, avps, MsgTypeSCCCN)
	assertAVPFlags(t, avps, AVPChallengeResponse, true)
}

func TestBuildICRQ(t *testing.T) {
	payload := BuildICRQ(42, 123456, "bear")
	avps := decodeAVPs(t, payload)

	assertMessageType(t, avps, MsgTypeICRQ)
	assertAVPFlags(t, avps, AVPAssignedSessionID, true)
	assertAVPFlags(t, avps, AVPCallSerialNumber, true)
	assertAVPFlags(t, avps, AVPCallingNumber, true)

	sid := FindAVP(avps, 0, AVPAssignedSessionID)
	require.NotNil(t, sid)
	sidVal, err := AVPUint16(sid)
	require.NoError(t, err)
	assert.Equal(t, uint16(42), sidVal)
}

func TestBuildICCNAVPFlags(t *testing.T) {
	avps := decodeAVPs(t, BuildICCN())
	assertMessageType(t, avps, MsgTypeICCN)
	// RFC 2661 s6.8 mandatory AVPs carry the M bit; there is nothing else to send.
	assertAVPFlags(t, avps, AVPConnectSpeed, true)
	assertAVPFlags(t, avps, AVPFramingType, true)
}

func TestBuildStopCCNAndCDN(t *testing.T) {
	stop := decodeAVPs(t, BuildStopCCN(77, 2, 9, "boom"))
	assertMessageType(t, stop, MsgTypeStopCCN)
	assertAVPFlags(t, stop, AVPAssignedTunnelID, true)
	assertAVPFlags(t, stop, AVPResultCode, true)
	assertResultCodeAVP(t, FindAVP(stop, 0, AVPResultCode), 2, 9, "boom")

	cdn := decodeAVPs(t, BuildCDN(88, 3, 4, "bye"))
	assertMessageType(t, cdn, MsgTypeCDN)
	assertAVPFlags(t, cdn, AVPAssignedSessionID, true)
	assertAVPFlags(t, cdn, AVPResultCode, true)
	assertResultCodeAVP(t, FindAVP(cdn, 0, AVPResultCode), 3, 4, "bye")
}

func TestComputeChallengeResponse(t *testing.T) {
	secret := []byte("mysecret")
	challenge := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	resp := ComputeChallengeResponse(byte(MsgTypeSCCRP), secret, challenge)
	assert.Len(t, resp, 16)

	resp2 := ComputeChallengeResponse(byte(MsgTypeSCCRP), secret, challenge)
	assert.Equal(t, resp, resp2)

	resp3 := ComputeChallengeResponse(byte(MsgTypeSCCCN), secret, challenge)
	assert.NotEqual(t, resp, resp3)
}

func decodeAVPs(t *testing.T, payload []byte) []AVP {
	t.Helper()
	avps, err := DecodeAVPs(payload)
	require.NoError(t, err)
	return avps
}

func assertMessageType(t *testing.T, avps []AVP, want uint16) {
	t.Helper()
	mt, err := GetMessageType(avps)
	require.NoError(t, err)
	assert.Equal(t, want, mt)
}

func assertAVPFlags(t *testing.T, avps []AVP, attrType uint16, mandatory bool) {
	t.Helper()
	avp := FindAVP(avps, 0, attrType)
	require.NotNil(t, avp, "missing AVP %d", attrType)
	assert.Equal(t, mandatory, avp.Mandatory, "unexpected mandatory bit for AVP %d", attrType)
}

func assertResultCodeAVP(t *testing.T, avp *AVP, resultCode, errorCode uint16, msg string) {
	t.Helper()
	require.NotNil(t, avp)
	require.GreaterOrEqual(t, len(avp.Value), 4)
	assert.Equal(t, resultCode, binary.BigEndian.Uint16(avp.Value[0:2]))
	assert.Equal(t, errorCode, binary.BigEndian.Uint16(avp.Value[2:4]))
	assert.Equal(t, msg, string(avp.Value[4:]))
}
