package l2tp

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// This file holds the RFC 2661 conformance and hostile-input layer for the
// L2TPv2 wire codec. protocol_test.go covers the happy path; everything here
// is about bit layout, truncation, malformed input and byte-level known
// answers.
//
// Header bit layout under test (RFC 2661 Section 3.1):
//
//	 0                   1
//	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|T|L|x|x|S|x|O|P|x|x|x|x|  Ver  |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
const (
	hdrBitT   uint16 = 0x8000
	hdrBitL   uint16 = 0x4000
	hdrBitS   uint16 = 0x0800
	hdrBitO   uint16 = 0x0200
	hdrBitP   uint16 = 0x0100
	hdrVerMsk uint16 = 0x000F
	// The x bits. RFC 2661 Section 3.1 says these MUST be 0 on send and are
	// ignored on receive, so ignoring them on receive is conformant.
	hdrRsvdMsk uint16 = 0x30F0 | 0x0400
)

// AVP flag layout under test (RFC 2661 Section 4.1):
//
//	|M|H| rsvd  |      Length       |
const (
	avpBitM    uint16 = 0x8000
	avpBitH    uint16 = 0x4000
	avpRsvdMsk uint16 = 0x3C00
	avpLenMsk  uint16 = 0x03FF
	// avpMaxLen and AVPMaxValue now live in protocol.go, where the encoder
	// enforces them. This alias keeps the shorter name readable here.
	avpMaxValue = AVPMaxValue
)

// ---------------------------------------------------------------------------
// Header: bit layout
// ---------------------------------------------------------------------------

func TestEncodeHeaderBitLayout(t *testing.T) {
	tests := []struct {
		name      string
		flags     uint16
		wantT     bool
		wantL     bool
		wantS     bool
		wantO     bool
		wantP     bool
		wantVer   uint16
		wantHdrSz int
	}{
		{
			name:      "control header sets T,L,S and version 2",
			flags:     binary.BigEndian.Uint16(EncodeControlHeader(1, 2, 3, 4, 0)),
			wantT:     true,
			wantL:     true,
			wantS:     true,
			wantVer:   2,
			wantHdrSz: 12,
		},
		{
			name:      "data header sets nothing but version 2",
			flags:     binary.BigEndian.Uint16(EncodeDataHeader(1, 2)),
			wantVer:   2,
			wantHdrSz: 6,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.wantT, tt.flags&hdrBitT != 0, "T bit")
			assert.Equal(t, tt.wantL, tt.flags&hdrBitL != 0, "L bit")
			assert.Equal(t, tt.wantS, tt.flags&hdrBitS != 0, "S bit")
			assert.Equal(t, tt.wantO, tt.flags&hdrBitO != 0, "O bit")
			assert.Equal(t, tt.wantP, tt.flags&hdrBitP != 0, "P bit")
			assert.Equal(t, tt.wantVer, tt.flags&hdrVerMsk, "Ver")
			assert.Zero(t, tt.flags&hdrRsvdMsk, "reserved bits must be zero on send")
		})
	}

	// The exact flag words are part of the wire contract.
	assert.Equal(t, uint16(0xC802), binary.BigEndian.Uint16(EncodeControlHeader(0, 0, 0, 0, 0)))
	assert.Equal(t, uint16(0x0002), binary.BigEndian.Uint16(EncodeDataHeader(0, 0)))
}

func TestEncodeControlHeaderRoundTrip(t *testing.T) {
	tests := []struct {
		name                    string
		tunnel, session, ns, nr uint16
		payload                 []byte
		wantOff, wantLen        int
	}{
		{"empty payload", 1, 0, 0, 0, nil, 12, 12},
		{"typical", 0x1234, 0x5678, 0x9ABC, 0xDEF0, []byte{1, 2, 3}, 12, 15},
		{"max ids", 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, bytes.Repeat([]byte{0xAA}, 64), 12, 76},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkt := append(EncodeControlHeader(tt.tunnel, tt.session, tt.ns, tt.nr, len(tt.payload)), tt.payload...)
			require.Len(t, pkt, tt.wantLen)

			h, off, err := DecodeHeader(pkt)
			require.NoError(t, err)
			assert.True(t, h.IsControl)
			assert.True(t, h.HasLength)
			assert.Equal(t, tt.tunnel, h.Tunnel)
			assert.Equal(t, tt.session, h.Session)
			assert.Equal(t, tt.ns, h.Ns)
			assert.Equal(t, tt.nr, h.Nr)
			assert.Equal(t, uint16(tt.wantLen), h.Length)
			assert.Equal(t, tt.wantOff, off)
			assert.True(t, bytes.Equal(tt.payload, pkt[off:]), "payload must survive round trip")
		})
	}
}

func TestEncodeDataHeaderRoundTrip(t *testing.T) {
	payload := []byte{0xC0, 0x21, 0x01}
	pkt := append(EncodeDataHeader(0x0A0B, 0x0C0D), payload...)

	h, off, err := DecodeHeader(pkt)
	require.NoError(t, err)
	assert.False(t, h.IsControl)
	assert.False(t, h.HasLength)
	assert.Zero(t, h.Length)
	assert.Zero(t, h.Ns)
	assert.Zero(t, h.Nr)
	assert.Equal(t, uint16(0x0A0B), h.Tunnel)
	assert.Equal(t, uint16(0x0C0D), h.Session)
	assert.Equal(t, 6, off)
	assert.Equal(t, payload, pkt[off:])
}

// ---------------------------------------------------------------------------
// Header: version
// ---------------------------------------------------------------------------

func TestDecodeHeaderRejectsNonVersion2(t *testing.T) {
	// RFC 2661 Section 3.1: "Ver MUST be 2, indicating the version of the L2TP
	// data message header described in this document." The value 1 is reserved
	// so that L2F packets can be detected if they arrive intermixed.
	for _, ver := range []uint16{0, 1, 3, 15} {
		for _, base := range []struct {
			name  string
			flags uint16
		}{
			{"control-shaped", hdrBitT | hdrBitL | hdrBitS},
			{"data-shaped", 0},
		} {
			t.Run(base.name, func(t *testing.T) {
				pkt := make([]byte, 12)
				binary.BigEndian.PutUint16(pkt[0:2], base.flags|ver)
				binary.BigEndian.PutUint16(pkt[2:4], 12)

				h, off, err := DecodeHeader(pkt)
				require.ErrorIs(t, err, ErrBadHeader, "version %d must be rejected", ver)
				assert.Contains(t, err.Error(), "version")
				assert.Zero(t, off)
				assert.Equal(t, Header{}, h, "no partial header on error")
			})
		}
	}
}

// ---------------------------------------------------------------------------
// Header: truncation at every boundary
// ---------------------------------------------------------------------------

func TestDecodeHeaderTruncationReturnsErrorNeverPanics(t *testing.T) {
	// Every case must return ErrShortPacket, not panic and not decode.
	tests := []struct {
		name string
		pkt  []byte
	}{
		{"0 bytes", []byte{}},
		{"1 byte", []byte{0xC8}},
		{"2 bytes: flags only", []byte{0xC8, 0x02}},
		// L is set but the 2-byte Length field is cut off. The len(data) < 6
		// guard fires before the L-specific bounds check.
		{"3 bytes: L set, Length truncated", []byte{0xC8, 0x02, 0x00}},
		{"4 bytes: L set, Length present but nothing else", []byte{0xC8, 0x02, 0x00, 0x0C}},
		{"5 bytes", []byte{0xC8, 0x02, 0x00, 0x0C, 0x00}},

		// L set, Tunnel/Session truncated.
		{"L set, 6 bytes (tunnel/session truncated)", []byte{0xC8, 0x02, 0x00, 0x0C, 0x00, 0x01}},
		{"L set, 7 bytes (tunnel/session truncated)", []byte{0xC8, 0x02, 0x00, 0x0C, 0x00, 0x01, 0x00}},

		// S set, Ns/Nr truncated at every offset.
		{"T|L|S, 8 bytes (Ns/Nr missing)", []byte{0xC8, 0x02, 0x00, 0x0C, 0x00, 0x01, 0x00, 0x02}},
		{"T|L|S, 9 bytes (Ns/Nr truncated)", []byte{0xC8, 0x02, 0x00, 0x0C, 0x00, 0x01, 0x00, 0x02, 0x00}},
		{"T|L|S, 10 bytes (Nr missing)", []byte{0xC8, 0x02, 0x00, 0x0C, 0x00, 0x01, 0x00, 0x02, 0x00, 0x05}},
		{"T|L|S, 11 bytes (Nr truncated)", []byte{0xC8, 0x02, 0x00, 0x0C, 0x00, 0x01, 0x00, 0x02, 0x00, 0x05, 0x00}},
		// S without L: Ns/Nr start right after Tunnel/Session.
		{"T|S no L, 6 bytes", []byte{0x88, 0x02, 0x00, 0x01, 0x00, 0x02}},
		{"T|S no L, 9 bytes", []byte{0x88, 0x02, 0x00, 0x01, 0x00, 0x02, 0x00, 0x05, 0x00}},

		// O set but the 2-byte Offset Size field itself is truncated.
		{"O set, 6 bytes (Offset Size missing)", []byte{0x02, 0x02, 0x00, 0x01, 0x00, 0x02}},
		{"O set, 7 bytes (Offset Size truncated)", []byte{0x02, 0x02, 0x00, 0x01, 0x00, 0x02, 0x00}},

		// O set with an Offset Size that runs past the end of the packet.
		{"O set, offset pad runs 1 past end", []byte{0x02, 0x02, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01}},
		{"O set, offset pad 16 past end", []byte{0x02, 0x02, 0x00, 0x01, 0x00, 0x02, 0x00, 0x10}},
		{"O set, offset pad 0xFFFF", []byte{0x02, 0x02, 0x00, 0x01, 0x00, 0x02, 0xFF, 0xFF}},
		{"T|L|S|O, offset pad past end", []byte{
			0xCA, 0x02, 0x00, 0x0E, 0x00, 0x01, 0x00, 0x02, 0x00, 0x05, 0x00, 0x04, 0x00, 0x08,
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.NotPanics(t, func() {
				h, off, err := DecodeHeader(tt.pkt)
				require.ErrorIs(t, err, ErrShortPacket)
				assert.Zero(t, off)
				assert.Equal(t, Header{}, h)
			})
		})
	}
}

func TestDecodeHeaderTruncationOfEveryPrefix(t *testing.T) {
	// Exhaustive: every strict prefix of a well-formed control packet must be
	// rejected, and the full packet accepted.
	full := append(EncodeControlHeader(0x1111, 0x2222, 0x3333, 0x4444, 2), 0xAB, 0xCD)
	// Every prefix shorter than the 12-octet control header must be rejected.
	for i := 0; i < 12; i++ {
		_, _, err := DecodeHeader(full[:i])
		require.ErrorIs(t, err, ErrShortPacket, "prefix of length %d must be rejected", i)
	}
	// From 12 octets on the header is complete and only the body is short --
	// which DecodeHeader does not police (see the Length-field gap below).
	for i := 12; i <= len(full); i++ {
		_, off, err := DecodeHeader(full[:i])
		require.NoError(t, err, "prefix of length %d", i)
		assert.Equal(t, 12, off)
	}
	h, off, err := DecodeHeader(full)
	require.NoError(t, err)
	assert.Equal(t, 12, off)
	assert.Equal(t, uint16(0x3333), h.Ns)
}

// ---------------------------------------------------------------------------
// Header: O bit / offset pad
// ---------------------------------------------------------------------------

func TestDecodeHeaderSkipsOffsetPad(t *testing.T) {
	tests := []struct {
		name    string
		flags   uint16
		oSize   int
		payload []byte
		wantOff int
	}{
		{"O with zero-size pad", hdrBitO | 2, 0, []byte{0xDE, 0xAD}, 8},
		{"O with 2-byte pad", hdrBitO | 2, 2, []byte{0xDE, 0xAD}, 10},
		{"O with 64-byte pad", hdrBitO | 2, 64, []byte{0xDE, 0xAD}, 72},
		{"O with 255-byte pad", hdrBitO | 2, 255, []byte{0x01}, 263},
		{"O with pad and no payload", hdrBitO | 2, 8, nil, 16},
		{"T|L|S|O with pad", hdrBitT | hdrBitL | hdrBitS | hdrBitO | 2, 4, []byte{0xBE, 0xEF}, 18},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var pkt []byte
			pkt = binary.BigEndian.AppendUint16(pkt, tt.flags)
			if tt.flags&hdrBitL != 0 {
				pkt = binary.BigEndian.AppendUint16(pkt, 0) // Length, patched below
			}
			pkt = binary.BigEndian.AppendUint16(pkt, 0x00AA) // Tunnel
			pkt = binary.BigEndian.AppendUint16(pkt, 0x00BB) // Session
			if tt.flags&hdrBitS != 0 {
				pkt = binary.BigEndian.AppendUint16(pkt, 7) // Ns
				pkt = binary.BigEndian.AppendUint16(pkt, 8) // Nr
			}
			pkt = binary.BigEndian.AppendUint16(pkt, uint16(tt.oSize))
			// The pad is deliberately non-zero garbage: it must be skipped, not parsed.
			pkt = append(pkt, bytes.Repeat([]byte{0x5A}, tt.oSize)...)
			pkt = append(pkt, tt.payload...)
			if tt.flags&hdrBitL != 0 {
				binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
			}

			h, off, err := DecodeHeader(pkt)
			require.NoError(t, err)
			assert.Equal(t, tt.wantOff, off, "payload offset must point past the offset pad")
			assert.Equal(t, uint16(0x00AA), h.Tunnel)
			assert.Equal(t, uint16(0x00BB), h.Session)
			if tt.payload == nil {
				assert.Empty(t, pkt[off:])
			} else {
				assert.Equal(t, tt.payload, pkt[off:])
			}
		})
	}
}

func TestDecodeHeaderIgnoresPriorityAndReservedBits(t *testing.T) {
	// RFC 2661 Section 3.1: the x bits MUST be 0 on send and are ignored on
	// receive, so accepting them set is conformant. The P bit does not change
	// the header layout either.
	base := EncodeDataHeader(0x1234, 0x5678)
	wantH, wantOff, err := DecodeHeader(base)
	require.NoError(t, err)

	for _, extra := range []uint16{hdrBitP, 0x2000, 0x1000, 0x0400, 0x00F0, hdrRsvdMsk | hdrBitP} {
		pkt := append([]byte(nil), base...)
		binary.BigEndian.PutUint16(pkt[0:2], binary.BigEndian.Uint16(pkt[0:2])|extra)
		h, off, err := DecodeHeader(pkt)
		require.NoError(t, err, "extra flags %#04x", extra)
		assert.Equal(t, wantH, h)
		assert.Equal(t, wantOff, off)
	}
}

// ---------------------------------------------------------------------------
// Header: the Length field is decoded but never enforced
// ---------------------------------------------------------------------------

// CONFORMANCE GAP (RFC 2661 s3.1): the Length field is defined as the "overall
// length of the message, including header, message type AVP, plus any
// additional AVPs associated with a given control message type" -- i.e. it is
// the only thing that says where the message ends. (The RFC does not spell out
// what a receiver must do when Length disagrees with the datagram it arrived
// in; treating Length as authoritative is the reading, not a literal quote.)
// DecodeHeader reads h.Length into the Header struct but
// never compares it to len(data), and no caller (Tunnel.recvControlDirect,
// Tunnel.recvLoop, Tunnel.handleControl, Tunnel.handleData) trims the payload
// to it. A datagram carrying trailing padding after the declared end of the
// message therefore has that padding fed to DecodeAVPs, which either rejects
// the whole message (dropping a perfectly good control message) or, if the
// padding happens to look like an AVP, silently accepts the extra AVPs.
// This test pins the current behaviour so a future fix is a deliberate change.
func TestDecodeHeaderDoesNotEnforceLengthShorterThanBuffer(t *testing.T) {
	tests := []struct {
		name           string
		trailing       []byte
		wantAVPsErr    bool
		wantAVPCount   int
		wantExtraTypes []uint16
	}{
		{
			name:        "trailing padding that is not a valid AVP kills the whole message",
			trailing:    []byte{0x00, 0x00, 0x00, 0x00},
			wantAVPsErr: true,
		},
		{
			name:           "trailing bytes that look like an AVP are silently accepted",
			trailing:       EncodeStringAVP(AVPHostName, "smuggled"),
			wantAVPCount:   2,
			wantExtraTypes: []uint16{AVPMessageType, AVPHostName},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := BuildHello() // 8 bytes: a single Message Type AVP
			pkt := append(EncodeControlHeader(1, 0, 0, 0, len(payload)), payload...)
			declared := binary.BigEndian.Uint16(pkt[2:4])
			require.Equal(t, uint16(20), declared)

			pkt = append(pkt, tt.trailing...)
			require.Greater(t, len(pkt), int(declared), "buffer must outrun the declared Length")

			h, off, err := DecodeHeader(pkt)
			require.NoError(t, err, "an under-declared Length is accepted without complaint")
			assert.Equal(t, declared, h.Length)
			assert.Less(t, int(h.Length), len(pkt))

			// The payload handed to DecodeAVPs is NOT trimmed to h.Length.
			assert.Len(t, pkt[off:], len(payload)+len(tt.trailing))

			avps, err := DecodeAVPs(pkt[off:])
			if tt.wantAVPsErr {
				require.ErrorIs(t, err, ErrBadAVP)
				assert.Nil(t, avps)
				return
			}
			require.NoError(t, err)
			require.Len(t, avps, tt.wantAVPCount)
			got := make([]uint16, 0, len(avps))
			for _, a := range avps {
				got = append(got, a.Type)
			}
			assert.Equal(t, tt.wantExtraTypes, got)

			// If the payload had been trimmed to h.Length, only the Hello AVP
			// would be visible.
			trimmed, err := DecodeAVPs(pkt[off:int(h.Length)])
			require.NoError(t, err)
			assert.Len(t, trimmed, 1)
		})
	}
}

// CONFORMANCE GAP (RFC 2661 s3.1): same root cause as above, opposite
// direction. A packet whose Length field claims more octets than the datagram
// actually contains is accepted silently; DecodeHeader never validates
// h.Length against len(data), so a receiver cannot tell a truncated datagram
// from a complete one. This test pins the current behaviour.
func TestDecodeHeaderAcceptsLengthLongerThanBuffer(t *testing.T) {
	for _, declared := range []uint16{21, 100, 4096, 0xFFFF} {
		payload := BuildHello()
		pkt := append(EncodeControlHeader(1, 0, 0, 0, len(payload)), payload...)
		binary.BigEndian.PutUint16(pkt[2:4], declared)

		h, off, err := DecodeHeader(pkt)
		require.NoError(t, err, "declared Length %d", declared)
		assert.Equal(t, declared, h.Length)
		assert.Greater(t, int(h.Length), len(pkt), "Length overruns the buffer but is not checked")
		assert.Equal(t, 12, off)

		// And the truncated body still decodes as if nothing were missing.
		avps, err := DecodeAVPs(pkt[off:])
		require.NoError(t, err)
		require.Len(t, avps, 1)
	}
}

// CONFORMANCE GAP (RFC 2661 s3.1): the L and S bits "MUST be set to 1 for
// control messages", and the O and P bits MUST be 0 on control messages.
// DecodeHeader applies no such check: it keys purely off the individual bits,
// so a control message with L or S clear is decoded happily and handed to
// Tunnel.handleControl with Ns and Nr silently defaulted to 0.
//
// Two things this comment deliberately does NOT claim. (1) RFC 2661 s3.1
// states the MUSTs on the sender; it does not spell out "discard on receive",
// so rejecting such a header is the natural hardening, not a literal
// requirement. (2) A forged S=0 datagram is not accepted at an arbitrary
// moment: handleControl only acts on it while t.nr happens to be 0, i.e.
// before the first inbound control message (or after Nr wraps), because the
// defaulted Ns=0 must equal the expected Nr. Everything else about it -- no
// Length, no sequence state, O/P set -- is accepted unconditionally.
// This test pins the current behaviour so a future fix is a deliberate change.
func TestDecodeHeaderAcceptsMalformedControlMessages(t *testing.T) {
	tests := []struct {
		name     string
		pkt      []byte
		wantOff  int
		wantLenB bool
		wantNs   uint16
		wantNr   uint16
	}{
		{
			name:    "control message with L and S clear",
			pkt:     []byte{0x80, 0x02, 0x00, 0x01, 0x00, 0x00},
			wantOff: 6,
		},
		{
			name:     "control message with S clear but L set",
			pkt:      []byte{0xC0, 0x02, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00},
			wantOff:  8,
			wantLenB: true,
		},
		{
			name:    "control message with L clear but S set",
			pkt:     []byte{0x88, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x09, 0x00, 0x07},
			wantOff: 10,
			wantNs:  9,
			wantNr:  7,
		},
		{
			name:     "control message with the O bit set",
			pkt:      []byte{0xCA, 0x02, 0x00, 0x0E, 0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 0x04, 0x00, 0x00},
			wantOff:  14,
			wantLenB: true,
			wantNs:   3,
			wantNr:   4,
		},
		{
			name:     "control message with the P bit set",
			pkt:      []byte{0xC9, 0x02, 0x00, 0x0C, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02},
			wantOff:  12,
			wantLenB: true,
			wantNs:   1,
			wantNr:   2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, off, err := DecodeHeader(tt.pkt)
			require.NoError(t, err, "malformed control headers are currently accepted")
			assert.True(t, h.IsControl)
			assert.Equal(t, tt.wantLenB, h.HasLength)
			assert.Equal(t, tt.wantOff, off)
			assert.Equal(t, tt.wantNs, h.Ns, "Ns silently defaults to 0 when S is clear")
			assert.Equal(t, tt.wantNr, h.Nr, "Nr silently defaults to 0 when S is clear")
		})
	}
}

// ---------------------------------------------------------------------------
// AVPs: flag layout
// ---------------------------------------------------------------------------

func TestEncodeAVPFlagLayout(t *testing.T) {
	tests := []struct {
		name      string
		attrType  uint16
		value     []byte
		mandatory bool
		wantFlags uint16
	}{
		{"mandatory empty value", AVPMessageType, nil, true, avpBitM | 6},
		{"optional empty value", AVPHostName, nil, false, 6},
		{"mandatory 2-byte value", AVPMessageType, []byte{0x00, 0x01}, true, avpBitM | 8},
		{"optional 4-byte value", AVPFramingType, []byte{0, 0, 0, 1}, false, 10},
		{"maximum length value", AVPChallenge, make([]byte, avpMaxValue), true, avpBitM | avpMaxLen},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enc := EncodeAVPWithFlags(tt.attrType, tt.value, tt.mandatory)
			require.Len(t, enc, 6+len(tt.value))

			flags := binary.BigEndian.Uint16(enc[0:2])
			assert.Equal(t, tt.wantFlags, flags)
			assert.Equal(t, tt.mandatory, flags&avpBitM != 0, "M bit")
			assert.Zero(t, flags&avpBitH, "encoder never sets the Hidden bit")
			assert.Zero(t, flags&avpRsvdMsk, "reserved bits must be zero on send")
			assert.Equal(t, uint16(6+len(tt.value)), flags&avpLenMsk, "Length is the low 10 bits")
			assert.Equal(t, uint16(0), binary.BigEndian.Uint16(enc[2:4]), "Vendor ID 0 (IETF)")
			assert.Equal(t, tt.attrType, binary.BigEndian.Uint16(enc[4:6]))
			assert.True(t, bytes.Equal(tt.value, enc[6:]), "value follows the 6-byte AVP header")
		})
	}
}

func TestDecodeAVPsFlagLayout(t *testing.T) {
	tests := []struct {
		name          string
		flags         uint16
		vendorID      uint16
		attrType      uint16
		value         []byte
		wantMandatory bool
	}{
		{"M clear", 8, 0, AVPHostName, []byte{1, 2}, false},
		{"M set", avpBitM | 8, 0, AVPHostName, []byte{1, 2}, true},
		{"non-zero vendor ID is preserved", avpBitM | 8, 0x1234, 9, []byte{1, 2}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var raw []byte
			raw = binary.BigEndian.AppendUint16(raw, tt.flags)
			raw = binary.BigEndian.AppendUint16(raw, tt.vendorID)
			raw = binary.BigEndian.AppendUint16(raw, tt.attrType)
			raw = append(raw, tt.value...)

			avps, err := DecodeAVPs(raw)
			require.NoError(t, err)
			require.Len(t, avps, 1)
			assert.Equal(t, tt.wantMandatory, avps[0].Mandatory)
			assert.Equal(t, tt.vendorID, avps[0].VendorID)
			assert.Equal(t, tt.attrType, avps[0].Type)
			assert.Equal(t, tt.value, avps[0].Value)
		})
	}
}

func TestDecodeAVPsCopiesValueOutOfTheInputBuffer(t *testing.T) {
	raw := append([]byte(nil), EncodeStringAVP(AVPHostName, "lac")...)
	avps, err := DecodeAVPs(raw)
	require.NoError(t, err)
	require.Len(t, avps, 1)

	// Scribble on the receive buffer; the decoded AVP must not change.
	for i := range raw {
		raw[i] = 0xFF
	}
	assert.Equal(t, "lac", string(avps[0].Value))
}

// CONFORMANCE GAP (RFC 2661 s4.1/s4.3): the H (Hidden) bit says the AVP's
// Attribute Value is encrypted with the shared secret (the "Hiding AVP
// Attribute Values" mechanism used for e.g. the Proxy Authen Secret AVP).
// DecodeAVPs never looks at bit 0x4000: the AVP struct has no Hidden field,
// nothing decrypts the value, and the still-encrypted ciphertext -- which per
// s4.3 is actually a 2-byte length prefix, the plaintext, and random padding,
// not the value at all -- is returned to callers as if it were plaintext. Any
// LNS that hides an AVP will silently feed this code garbage. This test pins
// the current behaviour so a future fix is a deliberate change.
func TestDecodeAVPsIgnoresHiddenBit(t *testing.T) {
	ciphertext := []byte{0xDE, 0xAD, 0xBE, 0xEF}

	var hidden []byte
	hidden = binary.BigEndian.AppendUint16(hidden, avpBitM|avpBitH|uint16(6+len(ciphertext)))
	hidden = binary.BigEndian.AppendUint16(hidden, 0)
	hidden = binary.BigEndian.AppendUint16(hidden, AVPChallenge)
	hidden = append(hidden, ciphertext...)

	avps, err := DecodeAVPs(hidden)
	require.NoError(t, err, "a hidden AVP is not rejected")
	require.Len(t, avps, 1)
	assert.Equal(t, AVPChallenge, avps[0].Type)
	assert.True(t, avps[0].Mandatory)
	// The ciphertext is handed back verbatim, indistinguishable from plaintext.
	assert.Equal(t, ciphertext, avps[0].Value)

	// A plaintext AVP with identical bytes decodes to exactly the same struct:
	// the H bit is not recorded anywhere, so callers cannot tell them apart.
	plain := append([]byte(nil), hidden...)
	binary.BigEndian.PutUint16(plain[0:2], avpBitM|uint16(6+len(ciphertext)))
	plainAVPs, err := DecodeAVPs(plain)
	require.NoError(t, err)
	assert.Equal(t, plainAVPs, avps, "hidden and plaintext AVPs decode identically")
}

// CONFORMANCE GAP (RFC 2661 s4.1): the 4 reserved bits of the AVP flags field
// "MUST be 0"; an AVP received with a reserved bit set is not a well-formed
// AVP and must not be interpreted. DecodeAVPs masks the flags word with
// 0x8000 for M and 0x03FF for Length and never inspects 0x3C00, so reserved
// bits are silently ignored and the AVP is processed normally. This also
// hides the encoder overflow pinned by TestEncodeAVPWithFlagsLengthOverflow,
// where a too-long value spills its length into these very bits.
// This test pins the current behaviour so a future fix is a deliberate change.
func TestDecodeAVPsIgnoresReservedBits(t *testing.T) {
	for _, rsvd := range []uint16{0x0400, 0x0800, 0x1000, 0x2000, avpRsvdMsk} {
		var raw []byte
		raw = binary.BigEndian.AppendUint16(raw, avpBitM|rsvd|8)
		raw = binary.BigEndian.AppendUint16(raw, 0)
		raw = binary.BigEndian.AppendUint16(raw, AVPMessageType)
		raw = binary.BigEndian.AppendUint16(raw, MsgTypeHello)

		avps, err := DecodeAVPs(raw)
		require.NoError(t, err, "reserved bits %#04x are ignored, not rejected", rsvd)
		require.Len(t, avps, 1)
		assert.True(t, avps[0].Mandatory)
		assert.Equal(t, AVPMessageType, avps[0].Type)

		// And the message is fully usable downstream.
		mt, err := GetMessageType(avps)
		require.NoError(t, err)
		assert.Equal(t, MsgTypeHello, mt)
	}
}

// ---------------------------------------------------------------------------
// AVPs: length edge cases
// ---------------------------------------------------------------------------

func TestDecodeAVPsLengthEdgeCases(t *testing.T) {
	avpHdr := func(flags, attrType uint16) []byte {
		var b []byte
		b = binary.BigEndian.AppendUint16(b, flags)
		b = binary.BigEndian.AppendUint16(b, 0)
		b = binary.BigEndian.AppendUint16(b, attrType)
		return b
	}

	tests := []struct {
		name      string
		raw       []byte
		wantErr   bool
		wantCount int
		check     func(t *testing.T, avps []AVP)
	}{
		{
			name:      "empty payload decodes to no AVPs",
			raw:       []byte{},
			wantCount: 0,
		},
		{
			name:      "length exactly 6 is a valid empty-value AVP",
			raw:       avpHdr(avpBitM|6, AVPMessageType),
			wantCount: 1,
			check: func(t *testing.T, avps []AVP) {
				assert.Empty(t, avps[0].Value)
				assert.Equal(t, AVPMessageType, avps[0].Type)
			},
		},
		{"length 5 is rejected", avpHdr(avpBitM|5, 0), true, 0, nil},
		{"length 1 is rejected", avpHdr(avpBitM|1, 0), true, 0, nil},
		{"length 0 is rejected", avpHdr(avpBitM|0, 0), true, 0, nil},
		{
			name:    "length runs one byte past the buffer",
			raw:     append(avpHdr(avpBitM|9, AVPHostName), 0x01, 0x02),
			wantErr: true,
		},
		{
			name:    "length runs far past the buffer",
			raw:     append(avpHdr(avpBitM|avpMaxLen, AVPHostName), 0x01),
			wantErr: true,
		},
		{
			name:    "trailing bytes shorter than an AVP header",
			raw:     append(EncodeUint16AVP(AVPMessageType, MsgTypeHello), 0x00, 0x06, 0x00),
			wantErr: true,
		},
		{
			name:      "maximum length 1023 is accepted",
			raw:       append(avpHdr(avpBitM|avpMaxLen, AVPChallenge), make([]byte, avpMaxValue)...),
			wantCount: 1,
			check: func(t *testing.T, avps []AVP) {
				assert.Len(t, avps[0].Value, avpMaxValue)
			},
		},
		{
			name: "second AVP in the stream is malformed",
			raw: append(EncodeUint16AVP(AVPMessageType, MsgTypeHello),
				avpHdr(avpBitM|5, AVPHostName)...),
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			avps, err := DecodeAVPs(tt.raw)
			if tt.wantErr {
				require.ErrorIs(t, err, ErrBadAVP)
				assert.Nil(t, avps, "a malformed AVP discards every AVP already decoded")
				return
			}
			require.NoError(t, err)
			require.Len(t, avps, tt.wantCount)
			if tt.check != nil {
				tt.check(t, avps)
			}
		})
	}
}

func TestDecodeAVPsWalkAlwaysAdvances(t *testing.T) {
	// The avpLen < 6 guard is what makes the walk strictly monotonic: a
	// declared length of 0 (which would otherwise loop forever) is rejected.
	t.Run("zero-length AVP cannot stall the walk", func(t *testing.T) {
		raw := make([]byte, 6*100) // 100 AVPs all declaring length 0
		done := make(chan struct{})
		go func() {
			defer close(done)
			_, err := DecodeAVPs(raw)
			assert.ErrorIs(t, err, ErrBadAVP)
		}()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("DecodeAVPs did not terminate on a zero-length AVP")
		}
	})

	t.Run("minimum-length AVPs are consumed exactly once each", func(t *testing.T) {
		var raw []byte
		for i := 0; i < 200; i++ {
			raw = append(raw, EncodeAVPWithFlags(uint16(i), nil, i%2 == 0)...)
		}
		avps, err := DecodeAVPs(raw)
		require.NoError(t, err)
		require.Len(t, avps, 200)
		for i, a := range avps {
			assert.Equal(t, uint16(i), a.Type)
			assert.Equal(t, i%2 == 0, a.Mandatory)
		}
	})

	t.Run("successful decode consumes the buffer exactly", func(t *testing.T) {
		raw := BuildSCCRQ("lac", 1, 4, []byte{1, 2, 3})
		avps, err := DecodeAVPs(raw)
		require.NoError(t, err)
		total := 0
		for _, a := range avps {
			total += 6 + len(a.Value)
		}
		assert.Equal(t, len(raw), total, "AVP lengths must tile the payload exactly")
	})
}

// ---------------------------------------------------------------------------
// AVPs: encoder length overflow
// ---------------------------------------------------------------------------

// The AVP length field is 10 bits, so a value of 1018 octets or more used to
// make the encoder wrap it: at 1024 the length became 0 and spilled into the
// reserved bits, and at 1030 it became 6 -- so a peer would stop reading the
// value early and parse the remainder as further AVPs. Anyone who could
// influence the length of an encoded value could therefore choose AVPs that the
// LNS would act on. The live route was the Calling Number, which carries the
// subscriber's Hysteria2 identity.
//
// The encoder now truncates instead, which cannot produce a stream that
// reparses.
func TestEncodeAVPWithFlagsCannotOverflowIntoAnInjection(t *testing.T) {
	t.Run("the largest value that fits is encoded whole", func(t *testing.T) {
		value := bytes.Repeat([]byte{0x41}, avpMaxValue)
		enc := EncodeAVPWithFlags(AVPChallenge, value, true)
		flags := binary.BigEndian.Uint16(enc[0:2])
		assert.Equal(t, uint16(avpBitM|avpMaxLen), flags)
		assert.Zero(t, flags&avpRsvdMsk)

		avps, err := DecodeAVPs(enc)
		require.NoError(t, err)
		require.Len(t, avps, 1)
		assert.Equal(t, value, avps[0].Value)
	})

	t.Run("anything longer is truncated, never wrapped", func(t *testing.T) {
		for _, n := range []int{avpMaxValue + 1, 1024, 1030, 4096, 70000} {
			enc := EncodeAVPWithFlags(AVPChallenge, bytes.Repeat([]byte{0x41}, n), true)
			require.LessOrEqualf(t, len(enc), avpMaxLen, "%d-octet value", n)

			flags := binary.BigEndian.Uint16(enc[0:2])
			assert.Zerof(t, flags&avpRsvdMsk, "%d-octet value spilled into the reserved bits", n)
			assert.EqualValuesf(t, len(enc), flags&avpLenMsk,
				"%d-octet value: the Length field must match the bytes actually written", n)

			avps, err := DecodeAVPs(enc)
			require.NoErrorf(t, err, "%d-octet value produced an AVP stream we cannot parse", n)
			require.Lenf(t, avps, 1, "%d-octet value reparsed into %d AVPs", n, len(avps))
			assert.Equal(t, AVPChallenge, avps[0].Type)
		}
	})

	// The specific attack the wrap enabled: a value chosen to be well-formed AVPs,
	// which the peer would have read as its own.
	t.Run("a value shaped like an AVP stream stays one opaque value", func(t *testing.T) {
		var value []byte
		for i := 0; i < 128; i++ {
			value = append(value, EncodeUint16AVP(AVPHostName, uint16(0x1000+i))...)
		}
		require.Len(t, value, 1024)

		avps, err := DecodeAVPs(EncodeAVPWithFlags(AVPChallenge, value, true))
		require.NoError(t, err)
		require.Len(t, avps, 1, "the payload must not reparse into the AVPs it was built from")
		assert.Equal(t, AVPChallenge, avps[0].Type)
		assert.Nil(t, FindAVP(avps, 0, AVPHostName),
			"none of the smuggled AVPs may become visible to the peer")
	})
}

// The calling number is the one AVP value this LAC does not choose: it is the
// subscriber's Hysteria2 identity, which an external authenticator may return at
// any length. BuildICRQ bounds it explicitly.
func TestBuildICRQBoundsTheCallingNumber(t *testing.T) {
	avps, err := DecodeAVPs(BuildICRQ(1, 2, strings.Repeat("A", 5000)))
	require.NoError(t, err, "an over-long identity must still produce a parseable ICRQ")

	cn := FindAVP(avps, 0, AVPCallingNumber)
	require.NotNil(t, cn)
	assert.Len(t, cn.Value, maxCallingNumber)

	// And the rest of the message is intact -- the identity cannot displace it.
	require.NotNil(t, FindAVP(avps, 0, AVPAssignedSessionID))
	mt, err := GetMessageType(avps)
	require.NoError(t, err)
	assert.Equal(t, MsgTypeICRQ, mt)
}

func TestFindAVPSelection(t *testing.T) {
	var buf []byte
	buf = append(buf, EncodeUint16AVP(AVPMessageType, MsgTypeICRQ)...)
	buf = append(buf, EncodeUint16AVP(AVPAssignedSessionID, 0x1111)...)
	buf = append(buf, EncodeUint16AVP(AVPAssignedSessionID, 0x2222)...)
	avps, err := DecodeAVPs(buf)
	require.NoError(t, err)

	t.Run("returns the first match when an AVP is duplicated", func(t *testing.T) {
		got := FindAVP(avps, 0, AVPAssignedSessionID)
		require.NotNil(t, got)
		v, err := AVPUint16(got)
		require.NoError(t, err)
		assert.Equal(t, uint16(0x1111), v)
	})

	t.Run("vendor ID is part of the key", func(t *testing.T) {
		assert.Nil(t, FindAVP(avps, 1, AVPAssignedSessionID))
		assert.Nil(t, FindAVP(avps, 0xFFFF, AVPMessageType))
	})

	t.Run("missing AVP yields nil", func(t *testing.T) {
		assert.Nil(t, FindAVP(avps, 0, AVPHostName))
		assert.Nil(t, FindAVP(nil, 0, AVPMessageType))
		assert.Nil(t, FindAVP([]AVP{}, 0, AVPMessageType))
	})
}

// CONFORMANCE GAP (RFC 2661 s4.4): the fixed-width attributes these accessors
// serve are defined with exact sizes -- Message Type (s4.4.1) and Assigned
// Tunnel/Session ID are 2 octets, Framing Capabilities and Call Serial Number
// are 4. AVPUint16 and AVPUint32 only enforce a MINIMUM length, so a 3-octet
// Message Type or a 5-octet Framing Capabilities AVP is accepted and the
// trailing octets are silently dropped: two AVPs that differ on the wire are
// indistinguishable to every caller. This is leniency rather than a violation
// (the RFC does not say a receiver MUST reject an over-long fixed-width
// attribute), so it is pinned deliberately -- a future tightening should be a
// conscious choice, not an accident.
func TestAVPUintAccessorsOnShortValues(t *testing.T) {
	u16 := []struct {
		name    string
		value   []byte
		wantErr bool
		want    uint16
	}{
		{"empty value", nil, true, 0},
		{"1 byte", []byte{0x01}, true, 0},
		{"exactly 2 bytes", []byte{0x01, 0x02}, false, 0x0102},
		{"3 bytes: trailing octets ignored", []byte{0x01, 0x02, 0x03}, false, 0x0102},
	}
	for _, tt := range u16 {
		t.Run("AVPUint16/"+tt.name, func(t *testing.T) {
			got, err := AVPUint16(&AVP{Value: tt.value})
			if tt.wantErr {
				require.ErrorIs(t, err, ErrBadAVP)
				assert.Zero(t, got)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}

	u32 := []struct {
		name    string
		value   []byte
		wantErr bool
		want    uint32
	}{
		{"empty value", nil, true, 0},
		{"1 byte", []byte{0x01}, true, 0},
		{"3 bytes", []byte{0x01, 0x02, 0x03}, true, 0},
		{"exactly 4 bytes", []byte{0x01, 0x02, 0x03, 0x04}, false, 0x01020304},
		{"5 bytes: trailing octets ignored", []byte{0x01, 0x02, 0x03, 0x04, 0x05}, false, 0x01020304},
	}
	for _, tt := range u32 {
		t.Run("AVPUint32/"+tt.name, func(t *testing.T) {
			got, err := AVPUint32(&AVP{Value: tt.value})
			if tt.wantErr {
				require.ErrorIs(t, err, ErrBadAVP)
				assert.Zero(t, got)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestGetMessageTypeErrors(t *testing.T) {
	t.Run("missing Message Type AVP", func(t *testing.T) {
		avps, err := DecodeAVPs(EncodeStringAVP(AVPHostName, "lac"))
		require.NoError(t, err)
		_, err = GetMessageType(avps)
		require.ErrorIs(t, err, ErrMissingAVP)
	})

	t.Run("Message Type AVP with a 1-byte value", func(t *testing.T) {
		avps, err := DecodeAVPs(EncodeAVP(AVPMessageType, []byte{0x06}))
		require.NoError(t, err)
		_, err = GetMessageType(avps)
		require.ErrorIs(t, err, ErrBadAVP)
	})

	t.Run("Message Type AVP with an empty value", func(t *testing.T) {
		avps, err := DecodeAVPs(EncodeAVP(AVPMessageType, nil))
		require.NoError(t, err)
		_, err = GetMessageType(avps)
		require.ErrorIs(t, err, ErrBadAVP)
	})

	t.Run("Message Type is found even when it is not first", func(t *testing.T) {
		// RFC 2661 s4.4.1 requires Message Type to be the first AVP;
		// GetMessageType does not enforce that, it simply searches. Pinned here
		// because the builders below are asserted to put it first regardless.
		var buf []byte
		buf = append(buf, EncodeStringAVP(AVPHostName, "lac")...)
		buf = append(buf, EncodeUint16AVP(AVPMessageType, MsgTypeHello)...)
		avps, err := DecodeAVPs(buf)
		require.NoError(t, err)
		mt, err := GetMessageType(avps)
		require.NoError(t, err)
		assert.Equal(t, MsgTypeHello, mt)
	})
}

// ---------------------------------------------------------------------------
// Message builders: byte-level known answers (RFC 2661 Section 6)
// ---------------------------------------------------------------------------

type wantAVP struct {
	attrType  uint16
	mandatory bool
	value     []byte
}

func TestComputeChallengeResponseKnownVectors(t *testing.T) {
	// RFC 2661 s5.1.1: the Challenge Response value is
	//   MD5(Message Type octet || shared secret || Challenge value).
	challenge := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
	}
	secret := []byte("tunnelpass")

	tests := []struct {
		name      string
		msgType   uint8
		secret    []byte
		challenge []byte
		wantHex   string
	}{
		{
			name:      "SCCRP response (LNS proving itself to the LAC)",
			msgType:   uint8(MsgTypeSCCRP),
			secret:    secret,
			challenge: challenge,
			wantHex:   "2160b3a5e78a62fbdfb6f3dc3a566322",
		},
		{
			name:      "SCCCN response (LAC proving itself to the LNS)",
			msgType:   uint8(MsgTypeSCCCN),
			secret:    secret,
			challenge: challenge,
			wantHex:   "da3d80ca3d5e2067d02655796d6b8c66",
		},
		{
			name:    "empty secret and challenge is MD5 of a single zero octet",
			msgType: 0,
			wantHex: "93b885adfe0da089cdf634904fd59f71",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ComputeChallengeResponse(tt.msgType, tt.secret, tt.challenge)
			require.Len(t, got, md5.Size)
			assert.Equal(t, tt.wantHex, hex.EncodeToString(got))

			// The wantHex values above are the real known answers (generated
			// outside this package). This second check re-derives the same
			// digest through md5.Sum over one contiguous buffer, which pins
			// that the implementation's streaming md5.Write calls concatenate
			// the three inputs in that order with no separators or padding.
			var input []byte
			input = append(input, tt.msgType)
			input = append(input, tt.secret...)
			input = append(input, tt.challenge...)
			want := md5.Sum(input)
			assert.Equal(t, want[:], got)
		})
	}
}

func TestComputeChallengeResponseIsDomainSeparatedByMessageType(t *testing.T) {
	secret := []byte("s3cret")
	challenge := bytes.Repeat([]byte{0xAB}, 16)

	sccrp := ComputeChallengeResponse(uint8(MsgTypeSCCRP), secret, challenge)
	scccn := ComputeChallengeResponse(uint8(MsgTypeSCCCN), secret, challenge)
	assert.NotEqual(t, sccrp, scccn,
		"the Message Type octet must prevent replaying one direction into the other")

	// Deterministic.
	assert.Equal(t, sccrp, ComputeChallengeResponse(uint8(MsgTypeSCCRP), secret, challenge))
	// Sensitive to both the secret and the challenge.
	assert.NotEqual(t, sccrp, ComputeChallengeResponse(uint8(MsgTypeSCCRP), []byte("other"), challenge))
	assert.NotEqual(t, sccrp, ComputeChallengeResponse(uint8(MsgTypeSCCRP), secret, bytes.Repeat([]byte{0xAC}, 16)))
}

// ---------------------------------------------------------------------------
// Fuzz targets
// ---------------------------------------------------------------------------

func FuzzDecodeHeader(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0xC8, 0x02})
	f.Add(EncodeControlHeader(1, 2, 3, 4, 0))
	f.Add(append(EncodeControlHeader(1, 2, 3, 4, 8), BuildHello()...))
	f.Add(EncodeDataHeader(1, 2))
	f.Add([]byte{0x02, 0x02, 0x00, 0x01, 0x00, 0x02, 0xFF, 0xFF}) // O with huge pad
	f.Add([]byte{0x02, 0x02, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00}) // O with zero pad
	f.Add([]byte{0xCA, 0x02, 0x00, 0x0E, 0x00, 0x01, 0x00, 0x02, 0x00, 0x05, 0x00, 0x04, 0, 0, 0, 0, 0, 0})
	f.Add([]byte{0xC8, 0x03})                                     // bad version
	f.Add([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}) // all ones

	f.Fuzz(func(t *testing.T, data []byte) {
		h, off, err := DecodeHeader(data)
		if err != nil {
			if off != 0 {
				t.Fatalf("offset %d returned alongside error %v", off, err)
			}
			return
		}
		if off < 0 || off > len(data) {
			t.Fatalf("payload offset %d out of range for %d bytes", off, len(data))
		}
		if off < 6 {
			t.Fatalf("payload offset %d is smaller than the minimum header", off)
		}
		// Slicing at the returned offset must never panic.
		_ = data[off:]
		// Decoding is a pure function of the input.
		h2, off2, err2 := DecodeHeader(data)
		if err2 != nil || h2 != h || off2 != off {
			t.Fatalf("DecodeHeader is not deterministic")
		}
	})
}

func FuzzDecodeAVPs(f *testing.F) {
	f.Add([]byte{})
	f.Add(BuildHello())
	f.Add(BuildSCCRQ("lac", 1, 4, []byte{1, 2, 3, 4}))
	f.Add(BuildStopCCN(1, 2, 3, "err"))
	f.Add(BuildICCN())
	f.Add([]byte{0x80, 0x00, 0x00, 0x00, 0x00, 0x00})       // length 0
	f.Add([]byte{0x80, 0x05, 0x00, 0x00, 0x00, 0x00})       // length 5
	f.Add([]byte{0x80, 0x06, 0x00, 0x00, 0x00, 0x00})       // length 6, empty value
	f.Add([]byte{0xC0, 0x08, 0x00, 0x00, 0x00, 0x0B, 1, 2}) // hidden bit set
	f.Add([]byte{0xBC, 0x08, 0x00, 0x00, 0x00, 0x0B, 1, 2}) // reserved bits set
	f.Add([]byte{0x83, 0xFF, 0x00, 0x00, 0x00, 0x0B})       // length 1023, truncated
	f.Add(bytes.Repeat([]byte{0xFF}, 64))

	f.Fuzz(func(t *testing.T, data []byte) {
		avps, err := DecodeAVPs(data)
		if err != nil {
			if avps != nil {
				t.Fatalf("AVPs returned alongside error %v", err)
			}
			return
		}
		// A successful walk must tile the input exactly; anything else means
		// the walk either stalled or ran off the end.
		total := 0
		for i := range avps {
			if len(avps[i].Value) > avpMaxValue {
				t.Fatalf("AVP %d has a %d-byte value, larger than the 10-bit length allows",
					i, len(avps[i].Value))
			}
			total += 6 + len(avps[i].Value)
		}
		if total != len(data) {
			t.Fatalf("decoded AVPs cover %d of %d bytes", total, len(data))
		}

		// Re-encoding and re-decoding is a fixed point. The H and reserved
		// bits are not modelled by the AVP struct, so this only holds at the
		// level of the decoded AVP list -- which is exactly what it asserts.
		var reenc []byte
		for i := range avps {
			if avps[i].VendorID != 0 {
				// EncodeAVPWithFlags hardcodes Vendor ID 0.
				return
			}
			reenc = append(reenc, EncodeAVPWithFlags(avps[i].Type, avps[i].Value, avps[i].Mandatory)...)
		}
		again, err := DecodeAVPs(reenc)
		if err != nil {
			t.Fatalf("re-encoded AVP stream failed to decode: %v", err)
		}
		if len(again) != len(avps) {
			t.Fatalf("round trip changed the AVP count: %d -> %d", len(avps), len(again))
		}
		for i := range avps {
			if again[i].Type != avps[i].Type ||
				again[i].Mandatory != avps[i].Mandatory ||
				!bytes.Equal(again[i].Value, avps[i].Value) {
				t.Fatalf("round trip changed AVP %d", i)
			}
		}
	})
}

// FuzzEncodeAVPWithFlags fuzzes the encoder rather than a parser because its
// `value` argument is attacker-influenced: BuildICCN feeds it the proxied LCP
// CONFREQ straight from the PPP peer. The seed corpus straddles the 10-bit
// Length boundary in both directions (1017 encodes, 1018 wraps) since that is
// where the encoder is known to be wrong.
func FuzzEncodeAVPWithFlags(f *testing.F) {
	f.Add(uint16(0), []byte{}, true)
	f.Add(uint16(AVPHostName), []byte("lac"), false)
	f.Add(uint16(AVPChallenge), bytes.Repeat([]byte{0xAA}, avpMaxValue), true)   // last encodable
	f.Add(uint16(AVPChallenge), bytes.Repeat([]byte{0x41}, avpMaxValue+1), true) // first that wraps
	f.Add(uint16(0xFFFF), bytes.Repeat([]byte{0x00}, 512), true)
	f.Add(uint16(0), bytes.Repeat([]byte{0xFF}, 1024), false)

	f.Fuzz(func(t *testing.T, attrType uint16, value []byte, mandatory bool) {
		enc := EncodeAVPWithFlags(attrType, value, mandatory)

		// The value is carried whole when it fits and truncated when it does not,
		// but the encoder must never emit something whose declared length differs
		// from what it wrote -- that is the wrap that let a long value reparse
		// into AVPs of the caller's choosing.
		want := value
		if len(want) > avpMaxValue {
			want = want[:avpMaxValue]
		}
		if len(enc) != 6+len(want) {
			t.Fatalf("encoded length %d, want %d", len(enc), 6+len(want))
		}
		flags := binary.BigEndian.Uint16(enc[0:2])
		if binary.BigEndian.Uint16(enc[2:4]) != 0 {
			t.Fatalf("Vendor ID must be 0")
		}
		if binary.BigEndian.Uint16(enc[4:6]) != attrType {
			t.Fatalf("Attribute Type was not preserved")
		}
		if !bytes.Equal(enc[6:], want) {
			t.Fatalf("Attribute Value was not preserved")
		}
		if flags&avpRsvdMsk != 0 {
			t.Fatalf("length spilled into the reserved bits: flags %#04x", flags)
		}
		if int(flags&avpLenMsk) != len(enc) {
			t.Fatalf("Length field %d does not match the %d bytes written", flags&avpLenMsk, len(enc))
		}
		avps, err := DecodeAVPs(enc)
		if err != nil {
			t.Fatalf("encoder produced an AVP its own decoder rejects: %v", err)
		}
		if len(avps) != 1 {
			t.Fatalf("expected 1 AVP, got %d", len(avps))
		}
		if avps[0].Type != attrType || avps[0].Mandatory != mandatory {
			t.Fatalf("round trip changed type/M bit")
		}
		if !bytes.Equal(avps[0].Value, want) && !(len(want) == 0 && len(avps[0].Value) == 0) {
			t.Fatalf("round trip changed the value")
		}
	})
}

// ICCN conformance, and the whole shape of this LAC in one message.
//
// RFC 2661 s6.8 makes three AVPs mandatory and every proxy AVP optional. This
// LAC sends the three and nothing else, which per s4.4.5 is the signal that
// makes the LNS run LCP and authentication with the subscriber itself.
//
// The absence is load-bearing. Emitting Proxy Authen Type with a zero value
// would instead tell the LNS to use proxy authentication with an undefined
// type, which is worse than saying nothing.
func TestBuildICCNCarriesTheMandatoryAVPsAndNoProxyState(t *testing.T) {
	avps, err := DecodeAVPs(BuildICCN())
	require.NoError(t, err)

	mt, err := GetMessageType(avps)
	require.NoError(t, err)
	assert.Equal(t, MsgTypeICCN, mt)

	for _, want := range []struct {
		name string
		typ  uint16
	}{
		{"Message Type", AVPMessageType},
		{"(Tx) Connect Speed", AVPConnectSpeed},
		{"Framing Type", AVPFramingType},
	} {
		assert.NotNilf(t, FindAVP(avps, 0, want.typ),
			"RFC 2661 s6.8 requires %s in the ICCN", want.name)
	}

	for _, forbidden := range []struct {
		name string
		typ  uint16
	}{
		{"Initial Received LCP CONFREQ", AVPInitialReceivedLCPCONFREQ},
		{"Last Sent LCP CONFREQ", AVPLastSentLCPCONFREQ},
		{"Last Received LCP CONFREQ", AVPLastReceivedLCPCONFREQ},
		{"Proxy Authen Type", AVPProxyAuthenType},
		{"Proxy Authen Name", AVPProxyAuthenName},
		{"Proxy Authen Challenge", AVPProxyAuthenChallenge},
		{"Proxy Authen ID", AVPProxyAuthenID},
		{"Proxy Authen Response", AVPProxyAuthenResponse},
	} {
		assert.Nilf(t, FindAVP(avps, 0, forbidden.typ),
			"this LAC proxies nothing, so %s must not appear", forbidden.name)
	}
	assert.Len(t, avps, 3, "exactly the three mandatory AVPs, nothing more")
}

// ICCN takes no arguments, so nothing a subscriber says can shape it. That is
// not a stylistic point: a proxied CONFREQ was bounded only by the MRU, and one
// longer than an AVP's 10-bit length field used to make BuildICCN emit a byte
// stream that would not parse.
func TestBuildICCNIsConstantAndAlwaysParses(t *testing.T) {
	first := BuildICCN()
	for i := 0; i < 5; i++ {
		assert.Equal(t, first, BuildICCN(), "ICCN has no inputs, so it cannot vary")
	}
	_, err := DecodeAVPs(first)
	require.NoError(t, err)
	assert.Less(t, len(first), avpMaxValue, "and it can never approach the AVP length limit")
}
