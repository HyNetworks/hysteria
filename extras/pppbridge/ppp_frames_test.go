package pppbridge

import "encoding/binary"

// PPP vocabulary for the tests, and only for the tests.
//
// Nothing in this package parses PPP any more: the client bridge relays frames
// to the server, and the LAC relays them to the LNS, both without looking
// inside. These constants exist so the tests can still speak real PPP at the
// endpoints -- a test that relayed opaque random bytes would prove the relay
// moves bytes, but not that a genuine LCP or CHAP exchange survives the trip
// unaltered, which is the property that matters.
const (
	pppProtoLCP  uint16 = 0xC021
	pppProtoPAP  uint16 = 0xC023
	pppProtoCHAP uint16 = 0xC223
)

// LCP code values (RFC 1661 s5).
const (
	lcpConfigRequest uint8 = 1
	lcpConfigAck     uint8 = 2
	lcpConfigNak     uint8 = 3
	lcpConfigReject  uint8 = 4
	lcpTermRequest   uint8 = 5
	lcpTermAck       uint8 = 6
	lcpEchoRequest   uint8 = 9
	lcpEchoReply     uint8 = 10
)

// LCP option types (RFC 1661 s6, RFC 1990 for the multilink ones).
const (
	lcpOptMRU                   uint8 = 1
	lcpOptAuthProtocol          uint8 = 3
	lcpOptMagicNumber           uint8 = 5
	lcpOptMRRU                  uint8 = 17
	lcpOptShortSeqNum           uint8 = 18
	lcpOptEndpointDiscriminator uint8 = 19
)

// PAP code values (RFC 1334 s2.2).
const (
	papAuthRequest uint8 = 1
	papAuthAck     uint8 = 2
	papAuthNak     uint8 = 3
)

// CHAP code values (RFC 1994 s4).
const (
	chapChallenge uint8 = 1
	chapResponse  uint8 = 2
	chapSuccess   uint8 = 3
	chapFailure   uint8 = 4
)

// buildLCPPacket assembles a Code/Identifier/Length/Options packet, the shape
// LCP, PAP and CHAP all share.
func buildLCPPacket(code uint8, id byte, options []byte) []byte {
	pktLen := 4 + len(options)
	pkt := make([]byte, pktLen)
	pkt[0] = code
	pkt[1] = id
	binary.BigEndian.PutUint16(pkt[2:4], uint16(pktLen))
	copy(pkt[4:], options)
	return pkt
}

// ---------------------------------------------------------------------------
// Frames as (protocol, payload)
// ---------------------------------------------------------------------------
//
// These two used to live in endpoint.go, where the L2TP endpoint split every
// frame apart on the way in and rebuilt it on the way out. Nothing downstream
// ever used the protocol -- the L2TP session ID does the routing -- and the
// split was a guess about compression the subscriber and the LNS negotiated
// without telling the LAC, so the relay path stopped doing it and they are only
// test vocabulary now.
//
// They stay because plenty of tests are about which protocol went where, and
// being wrong about that in a test costs an assertion rather than a
// subscriber's traffic.

// parsePPPFrame reads a frame as RFC 1661 s2 describes it: an optional FF 03,
// then a protocol field that is one odd octet when compressed and an even-led
// pair when not.
func parsePPPFrame(rawPPP []byte) (proto uint16, payload []byte) {
	off := 0
	if len(rawPPP) >= 2 && rawPPP[0] == 0xFF && rawPPP[1] == 0x03 {
		off = 2
	}
	if off >= len(rawPPP) {
		return 0, nil
	}
	if rawPPP[off]&0x01 == 1 {
		return uint16(rawPPP[off]), rawPPP[off+1:]
	}
	if off+2 > len(rawPPP) {
		return 0, nil
	}
	return binary.BigEndian.Uint16(rawPPP[off : off+2]), rawPPP[off+2:]
}

// buildPPPFrame assembles the uncompressed form: address, control, a full
// protocol field, then the payload.
func buildPPPFrame(proto uint16, payload []byte) []byte {
	f := make([]byte, 4+len(payload))
	f[0] = 0xFF
	f[1] = 0x03
	binary.BigEndian.PutUint16(f[2:4], proto)
	copy(f[4:], payload)
	return f
}
