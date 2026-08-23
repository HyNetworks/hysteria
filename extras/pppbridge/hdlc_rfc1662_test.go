package pppbridge

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RFC 1662 (PPP in HDLC-like Framing) conformance tests for hdlc.go.
//
// Terminology used below follows RFC 1662, with the wording each test relies on
// quoted at the point of use:
//   - "Flag Sequence"      = 0x7E                          (s4.1)
//   - "Control Escape"     = 0x7D                          (s4.2)
//   - Control Escape immediately followed by a Flag aborts the frame in
//     progress: s4.2 "unless it is the Flag Sequence (which aborts a frame)",
//     and s4.3 lists such frames among those "silently discarded, and not
//     counted as a FCS error".
//   - "ACCM"               = Async-Control-Character-Map   (s7.1)
//   - "good FCS" / residue = 0xF0B8                        (App. C.2)
//
// Several tests below are *characterization* tests: they lock in behaviour that
// deviates from the RFC so that a future fix is a deliberate, visible change.
// Each such test carries a "CONFORMANCE GAP" comment immediately above it.
// Tests whose comment says CHARACTERIZATION pin behaviour that is unusual but
// that no RFC text actually forbids — they are documentation, not a bug report.

// ---------------------------------------------------------------------------
// Independent FCS-16 reference implementation.
//
// hdlc.go computes FCS-16 with a 256-entry lookup table. The reference below is
// a bit-at-a-time implementation of the same CRC (reflected polynomial 0x8408,
// i.e. the reversed form of x^16 + x^12 + x^5 + 1) written directly from the
// RFC 1662 App. C description, so that agreement between the two is meaningful
// evidence and not a restatement of the same table.
// ---------------------------------------------------------------------------

func referenceFCS16(init uint16, data []byte) uint16 {
	fcs := init
	for _, b := range data {
		fcs ^= uint16(b)
		for i := 0; i < 8; i++ {
			if fcs&1 != 0 {
				fcs = (fcs >> 1) ^ 0x8408
			} else {
				fcs >>= 1
			}
		}
	}
	return fcs
}

func tableFCS16(init uint16, data []byte) uint16 {
	fcs := init
	for _, b := range data {
		fcs = hdlcFCSUpdate(fcs, b)
	}
	return fcs
}

// unescapeHDLCBody strips the leading/trailing flags of a single HDLC frame and
// undoes byte stuffing, yielding "content + FCS" as it appears on the wire
// before transparency processing (RFC 1662 s4.2).
func unescapeHDLCBody(t *testing.T, frame []byte) []byte {
	t.Helper()
	require.GreaterOrEqual(t, len(frame), 2)
	require.Equal(t, byte(hdlcFlag), frame[0])
	require.Equal(t, byte(hdlcFlag), frame[len(frame)-1])
	var out []byte
	esc := false
	for _, b := range frame[1 : len(frame)-1] {
		switch {
		case esc:
			out = append(out, b^0x20)
			esc = false
		case b == hdlcEscape:
			esc = true
		default:
			out = append(out, b)
		}
	}
	require.False(t, esc, "frame must not end mid-escape")
	return out
}

// ---------------------------------------------------------------------------
// FCS-16
// ---------------------------------------------------------------------------

func TestRFC1662FCSConstants(t *testing.T) {
	// RFC 1662 s C.2: the FCS register is preset to all ones, and a receiver
	// that runs the FCS over content + received FCS gets the "good FCS" value
	// 0xF0B8 when the frame is intact.
	assert.Equal(t, uint16(0xFFFF), hdlcFCSInit, "FCS-16 initial value (RFC 1662 s C.2)")
	assert.Equal(t, uint16(0xF0B8), hdlcFCSGood, "FCS-16 good residue (RFC 1662 s C.2)")
}

func TestRFC1662FCSTableMatchesBitwiseReference(t *testing.T) {
	// Every single-octet input, from every possible register state boundary we
	// can cheaply cover: all 256 octets against the all-ones preset, plus the
	// full 0x00..0xFF stream.
	all := make([]byte, 256)
	for i := range all {
		all[i] = byte(i)
	}
	for i := 0; i < 256; i++ {
		b := []byte{byte(i)}
		assert.Equalf(t, referenceFCS16(hdlcFCSInit, b), tableFCS16(hdlcFCSInit, b),
			"single octet 0x%02X", i)
	}
	assert.Equal(t, referenceFCS16(hdlcFCSInit, all), tableFCS16(hdlcFCSInit, all),
		"0x00..0xFF stream")
}

// The wantFCS* values below are hard-coded known answers computed OUTSIDE this
// codebase with a plain CRC-16/X-25 (reflected polynomial 0x8408, init 0xFFFF,
// final XOR 0xFFFF, low octet transmitted first), not read back out of hdlc.go.
// Recomputed by hand they are: FF03C021 01010004 -> D1 B5,
// 8021 01020004 -> DF 76, FF030021 -> E3 E6.
func TestRFC1662FCSKnownAnswerVectors(t *testing.T) {
	tests := []struct {
		name string
		ppp  string // hex, raw PPP frame (content, no FCS, no flags)
		// wantFCS is the value transmitted on the wire, i.e. the ones-complement
		// of the accumulated register, sent low-order octet first (RFC 1662 s3.1).
		wantFCSLow  byte
		wantFCSHigh byte
		wantEncoded string // hex, complete HDLC frame including both flags
	}{
		{
			// The canonical minimal LCP Configure-Request used throughout the
			// PPP RFCs: Address FF, Control 03, Protocol C021 (LCP),
			// Code 01 (Conf-Req), Identifier 01, Length 0004 (no options).
			name:        "LCP Configure-Request FF 03 C0 21 01 01 00 04",
			ppp:         "ff03c021010100 04",
			wantFCSLow:  0xD1,
			wantFCSHigh: 0xB5,
			// 0x03,0x01,0x01,0x00,0x04 are all < 0x20 and therefore escaped;
			// 0xFF, 0xC0, 0x21 and both FCS octets (0xD1, 0xB5) are not.
			wantEncoded: "7eff7d23c0217d217d217d207d24d1b57e",
		},
		{
			// IPCP Configure-Request, ACFC-compressed away (no FF 03):
			// Protocol 8021, Code 01, Identifier 02, Length 0004.
			name:        "IPCP Configure-Request without address/control",
			ppp:         "8021010200 04",
			wantFCSLow:  0xDF,
			wantFCSHigh: 0x76,
			wantEncoded: "7e80217d217d227d207d24df767e",
		},
		{
			// A bare IPv4 protocol header, no payload.
			name:        "IPv4 protocol header only",
			ppp:         "ff030021",
			wantFCSLow:  0xE3,
			wantFCSHigh: 0xE6,
			wantEncoded: "7eff7d237d2021e3e67e",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ppp := mustHex(t, tt.ppp)

			// The two independent FCS implementations must agree...
			reg := tableFCS16(hdlcFCSInit, ppp)
			require.Equal(t, referenceFCS16(hdlcFCSInit, ppp), reg)

			// ...and the transmitted (complemented, little-endian) FCS must be
			// the hand-checked value.
			txFCS := reg ^ 0xFFFF
			assert.Equal(t, tt.wantFCSLow, byte(txFCS&0xFF), "FCS low octet")
			assert.Equal(t, tt.wantFCSHigh, byte(txFCS>>8), "FCS high octet")

			encoded := EncodeHDLC(ppp)
			assert.Equal(t, tt.wantEncoded, hex.EncodeToString(encoded))

			// RFC 1662 s C.2: running the FCS over content *and* the received
			// FCS octets yields the good-FCS residue.
			body := unescapeHDLCBody(t, encoded)
			assert.Equal(t, hdlcFCSGood, tableFCS16(hdlcFCSInit, body),
				"receiver residue must be 0xF0B8")
			assert.Equal(t, hdlcFCSGood, referenceFCS16(hdlcFCSInit, body))

			// And the frame must decode back to exactly what went in.
			got, err := DecodeHDLC(encoded)
			require.NoError(t, err)
			assert.Equal(t, ppp, got)
		})
	}
}

func TestRFC1662FCSDetectsEverySingleOctetCorruption(t *testing.T) {
	ppp := []byte{0xFF, 0x03, 0xC0, 0x21, 0x01, 0x01, 0x00, 0x04}
	body := unescapeHDLCBody(t, EncodeHDLC(ppp))
	for i := range body {
		for _, mask := range []byte{0x01, 0x80, 0xFF} {
			corrupt := append([]byte(nil), body...)
			corrupt[i] ^= mask
			assert.NotEqualf(t, hdlcFCSGood, tableFCS16(hdlcFCSInit, corrupt),
				"corrupting octet %d with mask %02X must break the FCS residue", i, mask)
		}
	}
}

// ---------------------------------------------------------------------------
// Transparency (RFC 1662 s4.2)
// ---------------------------------------------------------------------------

func TestRFC1662TransparencyEveryOctetSurvivesRoundTrip(t *testing.T) {
	t.Run("each octet individually", func(t *testing.T) {
		for i := 0; i < 256; i++ {
			// Three octets keeps the frame at/above hdlcProcessFrame's minimum
			// once the two FCS octets are added.
			ppp := []byte{0xFF, 0x03, byte(i)}
			decoded, err := DecodeHDLC(EncodeHDLC(ppp))
			require.NoErrorf(t, err, "octet 0x%02X", i)
			assert.Equalf(t, ppp, decoded, "octet 0x%02X", i)
		}
	})

	t.Run("full 0x00..0xFF payload", func(t *testing.T) {
		ppp := make([]byte, 256)
		for i := range ppp {
			ppp[i] = byte(i)
		}
		decoded, err := DecodeHDLC(EncodeHDLC(ppp))
		require.NoError(t, err)
		assert.Equal(t, ppp, decoded)
	})

	t.Run("payload of nothing but flags and escapes", func(t *testing.T) {
		ppp := bytes.Repeat([]byte{hdlcFlag, hdlcEscape}, 64)
		encoded := EncodeHDLC(ppp)
		// Every payload octet is escaped, so it occupies two octets on the
		// wire: 2 flags + 2*128 payload + the (escaped or not) FCS octets.
		assert.Equal(t, len(ppp), len(unescapeHDLCBody(t, encoded))-2)
		assert.GreaterOrEqual(t, len(encoded), 2+2*len(ppp)+2)
		decoded, err := DecodeHDLC(encoded)
		require.NoError(t, err)
		assert.Equal(t, ppp, decoded)
	})
}

func TestRFC1662EscapingAppliesToExactlyTheRequiredOctets(t *testing.T) {
	// RFC 1662 s4.2: on transmission, each octet that must be escaped is
	// replaced by Control Escape (0x7D) followed by the octet XOR 0x20.
	// hdlc.go escapes 0x00-0x1F, 0x7D and 0x7E, and nothing else.
	for i := 0; i < 256; i++ {
		b := byte(i)
		wantEscaped := b < 0x20 || b == hdlcEscape || b == hdlcFlag

		// Encode direction. Use a wrapper whose own octets are never escaped
		// (0xAA) so the escaping of b is unambiguous in the output.
		encoded := EncodeHDLC([]byte{0xAA, b, 0xAA})
		body := unescapeHDLCBody(t, encoded)
		require.Equal(t, []byte{0xAA, b, 0xAA}, body[:3])

		// Locate b's on-wire representation: it starts at index 2 of the frame
		// (index 0 is the flag, index 1 is the unescaped 0xAA).
		if wantEscaped {
			require.Equalf(t, byte(hdlcEscape), encoded[2], "octet 0x%02X must be escaped", i)
			assert.Equalf(t, b^0x20, encoded[3], "octet 0x%02X escape complement", i)
		} else {
			assert.Equalf(t, b, encoded[2], "octet 0x%02X must NOT be escaped", i)
		}

		// Decode direction: 0x7D followed by (b^0x20) must always yield b,
		// including for octets the encoder would never have escaped.
		// 0x5E is the one exception: 0x5E^0x20 == 0x7E, so its escaped form is
		// literally the Abort Sequence 0x7D 0x7E (RFC 1662 s4.2) and can never
		// appear as an escaped data octet on the wire.
		if b == 0x5E {
			continue
		}
		esc := []byte{hdlcFlag, 0xAA, hdlcEscape, b ^ 0x20, 0xAA}
		fcs := tableFCS16(hdlcFCSInit, []byte{0xAA, b, 0xAA}) ^ 0xFFFF
		esc = hdlcAppendEscaped(esc, byte(fcs&0xFF))
		esc = hdlcAppendEscaped(esc, byte(fcs>>8))
		esc = append(esc, hdlcFlag)
		decoded, err := DecodeHDLC(esc)
		require.NoErrorf(t, err, "decoding escaped 0x%02X", i)
		assert.Equalf(t, []byte{0xAA, b, 0xAA}, decoded, "decoding escaped 0x%02X", i)
	}
}

// CHARACTERIZATION (RFC 1662 s7.1, Async-Control-Character-Map) — NOT a
// conformance gap. hdlc.go has no ACCM plumbing at all: EncodeHDLCTo always
// escapes every octet < 0x20, i.e. it behaves as if the sending ACCM were
// permanently 0xFFFFFFFF, and it ignores whatever LCP option 2 the peer sent.
// That is *conformant*, and deliberately so: RFC 1662 s7.1 states "the default
// sending ACCM is 0xffffffff", and s4.2 explicitly allows a transmitter to
// escape octets it is not required to escape. Escaping a superset of any ACCM a
// peer could ask for is therefore always safe on the wire, and Config-Acking an
// ACCM option costs correctness nothing — only bandwidth, since no ACCM a peer
// negotiates can ever reduce the escaping this encoder performs.
// The receive side accepts unescaped control octets, so an ACCM-0 peer
// interoperates in both directions. These tests pin the fixed escape set.
func TestRFC1662ACCMIsHardcodedToAllOnesOnSendAndIgnoredOnReceive(t *testing.T) {
	t.Run("encoder escapes all of 0x00-0x1F regardless of ACCM", func(t *testing.T) {
		for i := 0x00; i <= 0x1F; i++ {
			encoded := EncodeHDLC([]byte{0xAA, byte(i), 0xAA})
			require.Equalf(t, byte(hdlcEscape), encoded[2],
				"octet 0x%02X is escaped even though a peer may have negotiated ACCM 0", i)
			assert.Equal(t, byte(i)^0x20, encoded[3])
		}
		// 0x20..0x7C and 0x7F..0xFF (minus 0x7D/0x7E) are never escaped, so the
		// encoder does not over-escape either.
		for i := 0x20; i <= 0xFF; i++ {
			if byte(i) == hdlcEscape || byte(i) == hdlcFlag {
				continue
			}
			encoded := EncodeHDLC([]byte{0xAA, byte(i), 0xAA})
			assert.Equalf(t, byte(i), encoded[2], "octet 0x%02X must not be escaped", i)
		}
	})

	t.Run("decoder accepts unescaped control octets from an ACCM-0 peer", func(t *testing.T) {
		// Hand-built frame in which 0x01, 0x11 and 0x1F ride unescaped, exactly
		// as a peer that negotiated ACCM 0 would send them.
		content := []byte{0xFF, 0x03, 0x00, 0x21, 0x01, 0x11, 0x1F}
		fcs := tableFCS16(hdlcFCSInit, content) ^ 0xFFFF

		var wire []byte
		wire = append(wire, hdlcFlag)
		wire = append(wire, 0xFF)
		wire = append(wire, 0x03, 0x00, 0x21, 0x01, 0x11, 0x1F) // deliberately raw
		wire = hdlcAppendEscaped(wire, byte(fcs&0xFF))
		wire = hdlcAppendEscaped(wire, byte(fcs>>8))
		wire = append(wire, hdlcFlag)

		decoded, err := DecodeHDLC(wire)
		require.NoError(t, err)
		assert.Equal(t, content, decoded)
	})
}

// ---------------------------------------------------------------------------
// Framing: inter-frame fill, shared flags, leading garbage
// ---------------------------------------------------------------------------

func TestRFC1662InterFrameFillAndSharedFlags(t *testing.T) {
	f1 := []byte{0xFF, 0x03, 0xC0, 0x21, 0x01, 0x01, 0x00, 0x04}
	f2 := []byte{0xFF, 0x03, 0x80, 0x21, 0x01, 0x02, 0x00, 0x04}
	e1, e2 := EncodeHDLC(f1), EncodeHDLC(f2)

	tests := []struct {
		name  string
		build func() []byte
		want  [][]byte
	}{
		{
			// RFC 1662 s4.1: "only one Flag Sequence is required between two
			// frames" — the closing flag doubles as the next opening flag.
			name: "shared flag between adjacent frames",
			build: func() []byte {
				return append(append([]byte{}, e1...), e2[1:]...)
			},
			want: [][]byte{f1, f2},
		},
		{
			name: "both flags present between frames",
			build: func() []byte {
				return append(append([]byte{}, e1...), e2...)
			},
			want: [][]byte{f1, f2},
		},
		{
			// RFC 1662 s4.1: "Flag Sequences ... may be used as inter-frame
			// fill"; a receiver must silently discard the run.
			name: "long run of inter-frame fill flags",
			build: func() []byte {
				out := append([]byte{}, e1...)
				out = append(out, bytes.Repeat([]byte{hdlcFlag}, 32)...)
				out = append(out, e2...)
				return out
			},
			want: [][]byte{f1, f2},
		},
		{
			// RFC 1662 s4.1: octets received before the first Flag Sequence are
			// not part of any frame and must be discarded.
			name: "leading garbage before the first flag is ignored",
			build: func() []byte {
				out := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x7D, 0x01}
				return append(out, e1...)
			},
			want: [][]byte{f1},
		},
		{
			name: "trailing inter-frame fill after the last frame",
			build: func() []byte {
				return append(append([]byte{}, e1...), bytes.Repeat([]byte{hdlcFlag}, 8)...)
			},
			want: [][]byte{f1},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			frames, err := DecodeHDLCStream(tt.build())
			require.NoError(t, err)
			assert.Equal(t, tt.want, frames)
		})
	}
}

// CONFORMANCE GAP (RFC 1662 s3.1 + s4.1): a run of Flag Sequences with no frame
// between them is legal inter-frame fill / link idle. RFC 1662 s3.1: "Two
// consecutive Flag Sequences constitute an empty frame, which is silently
// discarded, and not counted as a FCS error." A conformant receiver therefore
// consumes idle fill and reports zero frames and no error. DecodeHDLCStream
// does silently skip the empty frames themselves, but then reports
// "hdlc: no valid frames found" for any input that yielded no frames, so a read
// that happens to land on nothing but idle fill is indistinguishable from
// garbage at the caller. This test pins the current behaviour.
func TestRFC1662FlagsOnlyBufferIsReportedAsAnError(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"single flag", []byte{hdlcFlag}},
		{"two flags", []byte{hdlcFlag, hdlcFlag}},
		{"long idle fill", bytes.Repeat([]byte{hdlcFlag}, 64)},
		{"empty buffer", nil},
		{"garbage with no flag at all", []byte{0x01, 0x02, 0x03}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			frames, err := DecodeHDLCStream(tt.data)
			require.Error(t, err)
			assert.EqualError(t, err, "hdlc: no valid frames found")
			assert.Nil(t, frames)

			_, err = DecodeHDLC(tt.data)
			assert.Error(t, err)
		})
	}
}

// ---------------------------------------------------------------------------
// Abort sequence and FCS failure handling
// ---------------------------------------------------------------------------

// CONFORMANCE GAP (RFC 1662 s4.2 + s4.3): Control Escape immediately followed
// by a Flag Sequence aborts the frame in progress — s4.2: the octet after a
// Control Escape is XOR'd with 0x20 "unless it is the Flag Sequence (which
// aborts a frame)" — and s4.3 puts frames "which end with a Control Escape
// octet followed immediately by a closing Flag Sequence" in the set that is
// "silently discarded, and not counted as a FCS error". DecodeHDLCStream checks
// `b == 0x7E` (hdlc.go:70) before it checks the pending-escape state, so
// 0x7D 0x7E is treated as an ordinary closing flag: the partial content is
// FCS-checked, fails, and the whole call returns "hdlc: bad FCS" — the exact
// error s4.3 says must not be raised, and every frame decoded so far is thrown
// away with it. This test pins the current behaviour.
func TestRFC1662AbortSequenceIsTreatedAsFrameEndAndFailsFCS(t *testing.T) {
	good := []byte{0xFF, 0x03, 0xC0, 0x21, 0x01, 0x01, 0x00, 0x04}
	encGood := EncodeHDLC(good)

	t.Run("aborted frame alone", func(t *testing.T) {
		// Start a frame, emit a few octets, then abort.
		data := append([]byte{}, encGood[:6]...)
		data = append(data, hdlcEscape, hdlcFlag)
		frames, err := DecodeHDLCStream(data)
		require.Error(t, err)
		assert.EqualError(t, err, "hdlc: bad FCS")
		assert.Nil(t, frames)
	})

	t.Run("abort after a good frame discards the good frame too", func(t *testing.T) {
		data := append([]byte{}, encGood...)
		data = append(data, 0xAA, 0xBB, 0xCC, hdlcEscape, hdlcFlag)
		frames, err := DecodeHDLCStream(data)
		require.Error(t, err)
		assert.Nil(t, frames, "the already-decoded good frame is thrown away")
	})

	t.Run("abort followed by a good frame yields nothing", func(t *testing.T) {
		data := []byte{hdlcFlag, 0xAA, 0xBB, 0xCC, hdlcEscape}
		data = append(data, encGood...)
		frames, err := DecodeHDLCStream(data)
		require.Error(t, err)
		assert.Nil(t, frames, "the frame after the abort is never reached")
	})

	t.Run("pending escape at end of buffer is silently dropped", func(t *testing.T) {
		// 0x7D as the very last octet leaves `escaped` true with empty content;
		// no error is raised for the dangling escape itself.
		data := append([]byte{}, encGood...)
		data = append(data, hdlcEscape)
		frames, err := DecodeHDLCStream(data)
		require.NoError(t, err)
		assert.Equal(t, [][]byte{good}, frames)
	})
}

// CONFORMANCE GAP (RFC 1662 s3.1 / s4.3 — frame validity is per frame): RFC 1662
// scopes every validity rule to the individual frame ("Two consecutive Flag
// Sequences constitute an empty frame, which is silently discarded"; frames that
// are too short or aborted "are silently discarded, and not counted as a FCS
// error"). Nothing in the RFC makes one damaged frame fatal to the rest of the
// octet stream — an FCS error is counted against that frame and reception
// continues with the next Flag Sequence. DecodeHDLCStream instead propagates
// hdlcProcessFrame's error immediately (hdlc.go:73-75), returning (nil, "hdlc:
// bad FCS"), so every good frame already decoded from the same buffer is thrown
// away and every good frame after it is never examined. On a stream where one
// read can contain several frames this turns a single-frame corruption into a
// multi-frame loss. This test pins the current behaviour.
func TestRFC1662OneBadFCSDestroysEveryFrameInTheBuffer(t *testing.T) {
	f1 := []byte{0xFF, 0x03, 0xC0, 0x21, 0x01, 0x01, 0x00, 0x04}
	f2 := []byte{0xFF, 0x03, 0x80, 0x21, 0x01, 0x02, 0x00, 0x04}
	f3 := []byte{0xFF, 0x03, 0x00, 0x21, 0x45, 0x00, 0x00, 0x14}

	corrupt := EncodeHDLC(f2)
	corrupt[len(corrupt)-2] ^= 0xFF // break the FCS high octet

	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "corrupt frame first",
			data: concatBytes(corrupt, EncodeHDLC(f1), EncodeHDLC(f3)),
		},
		{
			name: "corrupt frame in the middle",
			data: concatBytes(EncodeHDLC(f1), corrupt, EncodeHDLC(f3)),
		},
		{
			name: "corrupt frame last",
			data: concatBytes(EncodeHDLC(f1), EncodeHDLC(f3), corrupt),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			frames, err := DecodeHDLCStream(tt.data)
			require.Error(t, err)
			assert.EqualError(t, err, "hdlc: bad FCS")
			assert.Nil(t, frames, "good frames in the same buffer are lost")
		})
	}

	t.Run("sanity: the same buffer without corruption decodes all three", func(t *testing.T) {
		frames, err := DecodeHDLCStream(concatBytes(EncodeHDLC(f1), EncodeHDLC(f2), EncodeHDLC(f3)))
		require.NoError(t, err)
		assert.Equal(t, [][]byte{f1, f2, f3}, frames)
	})
}

// ---------------------------------------------------------------------------
// Degenerate frame lengths
// ---------------------------------------------------------------------------

// CONFORMANCE GAP (RFC 1662 s4.3 — Invalid Frames): "Frames which are too short
// (less than 4 octets when using the 16-bit FCS) ... are silently discarded, and
// not counted as a FCS error." hdlcProcessFrame (hdlc.go:112) instead returns
// "hdlc: frame too short", and because DecodeHDLCStream propagates that error a
// single runt frame anywhere in the buffer aborts decoding of the entire buffer.
// A zero-length frame (two adjacent flags) is the one case that *is* silently
// skipped, matching s3.1. Note the threshold itself also differs from the RFC:
// hdlc.go rejects below 3 octets, the RFC below 4, so a 3-octet frame (one
// content octet + FCS) is accepted here and would be discarded by a conformant
// receiver — pinned by the "three-octet frame" subtest below. This test pins
// exactly which lengths are dropped silently and which abort the stream.
func TestRFC1662ShortFramesAbortTheStreamExceptZeroLength(t *testing.T) {
	tests := []struct {
		name    string
		content []byte // raw, unescaped frame content between the flags
		wantErr string
	}{
		{name: "zero-length frame (two adjacent flags)", content: nil, wantErr: "hdlc: no valid frames found"},
		{name: "one octet", content: []byte{0xAA}, wantErr: "hdlc: frame too short"},
		{name: "two octets (FCS only, no content)", content: []byte{0xD1, 0xB5}, wantErr: "hdlc: frame too short"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var wire []byte
			wire = append(wire, hdlcFlag)
			for _, b := range tt.content {
				wire = hdlcAppendEscaped(wire, b)
			}
			wire = append(wire, hdlcFlag)

			frames, err := DecodeHDLCStream(wire)
			require.Error(t, err)
			assert.EqualError(t, err, tt.wantErr)
			assert.Nil(t, frames)
		})
	}

	t.Run("empty PPP frame encodes to an FCS-only frame that will not decode", func(t *testing.T) {
		// EncodeHDLC(nil) emits flag + FCS(2) + flag, which is below
		// hdlcProcessFrame's 3-octet minimum, so encode/decode is NOT a
		// round trip for the empty payload. The FCS of the empty string is
		// 0xFFFF, transmitted complemented as 0x00 0x00, so both octets are
		// themselves escaped: 7E 7D20 7D20 7E.
		encoded := EncodeHDLC(nil)
		assert.Equal(t, "7e7d207d207e", hex.EncodeToString(encoded))
		_, err := DecodeHDLC(encoded)
		require.Error(t, err)
		assert.EqualError(t, err, "hdlc: frame too short")
	})

	t.Run("three-octet frame is accepted although RFC 1662 s4.3 calls it too short", func(t *testing.T) {
		// hdlcProcessFrame's minimum is 3 octets (1 content + 2 FCS); RFC 1662
		// s4.3 puts the minimum at 4 octets for a 16-bit FCS. This frame is
		// therefore accepted here and would be silently discarded by a
		// conformant receiver.
		decoded, err := DecodeHDLC(EncodeHDLC([]byte{0xAA}))
		require.NoError(t, err)
		assert.Equal(t, []byte{0xAA}, decoded)
	})

	t.Run("runt frame in the middle kills the good frames around it", func(t *testing.T) {
		good := []byte{0xFF, 0x03, 0xC0, 0x21, 0x01, 0x01, 0x00, 0x04}
		data := concatBytes(EncodeHDLC(good), []byte{hdlcFlag, 0xAA, hdlcFlag}, EncodeHDLC(good))
		frames, err := DecodeHDLCStream(data)
		require.Error(t, err)
		assert.EqualError(t, err, "hdlc: frame too short")
		assert.Nil(t, frames)
	})
}

func TestRFC1662IncompleteFrameWithoutClosingFlag(t *testing.T) {
	good := []byte{0xFF, 0x03, 0xC0, 0x21, 0x01, 0x01, 0x00, 0x04}
	partial := EncodeHDLC(good)
	partial = partial[:len(partial)-1] // drop the closing flag

	frames, err := DecodeHDLCStream(partial)
	require.Error(t, err)
	assert.EqualError(t, err, "hdlc: incomplete frame (no closing flag)")
	assert.Nil(t, frames)

	// Even a fully decoded frame followed by a partial one is lost.
	frames, err = DecodeHDLCStream(concatBytes(EncodeHDLC(good), partial))
	require.Error(t, err)
	assert.Nil(t, frames)
}

// ---------------------------------------------------------------------------
// EncodeHDLCTo buffer semantics
// ---------------------------------------------------------------------------

// CONFORMANCE GAP (n/a — doc/implementation mismatch, hdlc.go:28-37): the doc
// comment on EncodeHDLCTo says it "appends to a caller-provided buffer", but the
// body starts with `buf = buf[:0]`, so it *overwrites* the buffer instead. A
// caller who follows the documented contract — accumulating several encoded
// frames into one buffer — silently gets only the last frame, and because the
// truncation is in-place the caller's own view of the earlier bytes is clobbered
// too. These tests pin the real (overwrite) semantics.
func TestEncodeHDLCToOverwritesRatherThanAppends(t *testing.T) {
	ppp := []byte{0xFF, 0x03, 0xC0, 0x21, 0x01, 0x01, 0x00, 0x04}
	want := EncodeHDLC(ppp)

	t.Run("prior buffer content is discarded", func(t *testing.T) {
		buf := []byte("PREVIOUS CONTENT THAT A CALLER WOULD EXPECT TO KEEP")
		got := EncodeHDLCTo(ppp, buf)
		assert.Equal(t, want, got, "output is only the new frame, not append")
		assert.NotContains(t, string(got), "PREVIOUS")
	})

	t.Run("caller's backing array is scribbled over in place", func(t *testing.T) {
		buf := make([]byte, 0, 512)
		buf = append(buf, bytes.Repeat([]byte{0x55}, 64)...)
		snapshot := append([]byte(nil), buf...)
		got := EncodeHDLCTo(ppp, buf)
		assert.Equal(t, want, got)
		// buf still has len 64, but its first bytes now hold the new frame.
		assert.Equal(t, 64, len(buf))
		assert.NotEqual(t, snapshot, buf, "the caller's slice was mutated in place")
		assert.Equal(t, want, buf[:len(want)])
	})

	t.Run("looping over frames keeps only the last one", func(t *testing.T) {
		frames := [][]byte{
			{0xFF, 0x03, 0xC0, 0x21, 0x01, 0x01, 0x00, 0x04},
			{0xFF, 0x03, 0x80, 0x21, 0x01, 0x02, 0x00, 0x04},
			{0xFF, 0x03, 0x00, 0x21, 0x45, 0x00},
		}
		var acc []byte
		for _, f := range frames {
			acc = EncodeHDLCTo(f, acc)
		}
		assert.Equal(t, EncodeHDLC(frames[len(frames)-1]), acc)
		decoded, err := DecodeHDLCStream(acc)
		require.NoError(t, err)
		assert.Equal(t, [][]byte{frames[len(frames)-1]}, decoded,
			"only the final frame survived the 'append' loop")
	})

	t.Run("nil buffer produces the known-answer frame", func(t *testing.T) {
		// Compared against the hex known answer rather than against
		// EncodeHDLC, which is defined as EncodeHDLCTo(ppp, nil) and would
		// make this assertion vacuous.
		assert.Equal(t, "7eff7d23c0217d217d217d207d24d1b57e",
			hex.EncodeToString(EncodeHDLCTo(ppp, nil)))
		assert.Equal(t, want, EncodeHDLCTo(ppp, nil))
	})

	t.Run("reuse across frames is safe when the result is consumed immediately", func(t *testing.T) {
		buf := make([]byte, 0, 4096)
		for _, f := range [][]byte{{0xAA}, {0xFF, 0x03, 0xC0, 0x21}, bytes.Repeat([]byte{0x7E}, 100)} {
			buf = EncodeHDLCTo(f, buf)
			decoded, err := DecodeHDLC(buf)
			require.NoError(t, err)
			assert.Equal(t, f, decoded)
		}
	})
}

// ---------------------------------------------------------------------------
// Fuzzing
// ---------------------------------------------------------------------------

func FuzzDecodeHDLCStream(f *testing.F) {
	good := []byte{0xFF, 0x03, 0xC0, 0x21, 0x01, 0x01, 0x00, 0x04}
	f.Add(EncodeHDLC(good))
	f.Add(concatBytes(EncodeHDLC(good), EncodeHDLC(good)))
	f.Add([]byte{hdlcFlag})
	f.Add([]byte{hdlcFlag, hdlcFlag})
	f.Add([]byte(nil))
	f.Add([]byte{hdlcFlag, hdlcEscape, hdlcFlag})         // abort sequence
	f.Add([]byte{hdlcFlag, hdlcEscape})                   // dangling escape
	f.Add([]byte{hdlcFlag, 0xAA, hdlcFlag})               // runt frame
	f.Add([]byte{0xDE, 0xAD, hdlcFlag, 0xFF, 0x03, 0xC0}) // leading garbage, no close
	f.Add(bytes.Repeat([]byte{hdlcFlag, hdlcEscape, 0x5E}, 8))
	f.Add(mustHexNoT("7eff7d23c0217d217d217d207d24d1b57e"))

	f.Fuzz(func(t *testing.T, data []byte) {
		frames, err := DecodeHDLCStream(data)
		if err != nil {
			// The current implementation is all-or-nothing: an error means no
			// frames are returned at all.
			if frames != nil {
				t.Fatalf("frames returned alongside error %v", err)
			}
			return
		}
		if len(frames) == 0 {
			t.Fatal("nil error but no frames")
		}
		for i, fr := range frames {
			if len(fr) == 0 {
				t.Fatalf("frame %d is empty", i)
			}
			// Invariant: anything the decoder accepted must survive a
			// re-encode/re-decode cycle unchanged.
			again, err := DecodeHDLC(EncodeHDLC(fr))
			if err != nil {
				t.Fatalf("frame %d failed re-decode: %v", i, err)
			}
			if !bytes.Equal(fr, again) {
				t.Fatalf("frame %d not stable under re-encode: %x vs %x", i, fr, again)
			}
		}
	})
}

func FuzzHDLCRoundTrip(f *testing.F) {
	f.Add([]byte{0xFF, 0x03, 0xC0, 0x21, 0x01, 0x01, 0x00, 0x04})
	f.Add([]byte{0xAA})
	f.Add([]byte{0x7E, 0x7D, 0x00, 0x1F, 0x20})
	f.Add(bytes.Repeat([]byte{0x00}, 300))
	f.Add([]byte{0xFF, 0x03})

	f.Fuzz(func(t *testing.T, ppp []byte) {
		encoded := EncodeHDLC(ppp)

		// Structural invariants that hold for every input.
		if encoded[0] != hdlcFlag || encoded[len(encoded)-1] != hdlcFlag {
			t.Fatalf("frame not flag-delimited: %x", encoded)
		}
		for _, b := range encoded[1 : len(encoded)-1] {
			if b == hdlcFlag {
				t.Fatalf("unescaped flag inside frame body: %x", encoded)
			}
		}

		decoded, err := DecodeHDLC(encoded)
		if len(ppp) == 0 {
			// FCS-only frame: below the 3-octet minimum, never decodes.
			if err == nil {
				t.Fatalf("expected error for empty payload, got %x", decoded)
			}
			return
		}
		if err != nil {
			t.Fatalf("round trip failed for %x: %v", ppp, err)
		}
		if !bytes.Equal(ppp, decoded) {
			t.Fatalf("round trip mismatch: in %x out %x", ppp, decoded)
		}

		// Encoding twice into the same reusable buffer must be deterministic.
		buf := make([]byte, 0, 8)
		buf = EncodeHDLCTo(ppp, buf)
		if !bytes.Equal(buf, encoded) {
			t.Fatalf("EncodeHDLCTo differs from EncodeHDLC: %x vs %x", buf, encoded)
		}
	})
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func concatBytes(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(stripSpaces(s))
	require.NoError(t, err)
	return b
}

func mustHexNoT(s string) []byte {
	b, err := hex.DecodeString(stripSpaces(s))
	if err != nil {
		panic(err)
	}
	return b
}

func stripSpaces(s string) string {
	var b []byte
	for i := 0; i < len(s); i++ {
		if s[i] != ' ' {
			b = append(b, s[i])
		}
	}
	return string(b)
}
