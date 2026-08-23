package pppbridge

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Tests for classify.go — the HDLC frame-boundary finder and the log helper.
//
// DELETED: everything about isControlFrame. That function decided whether a
// frame coming out of pppd rode the reliable control stream or an unreliable
// datagram, and it no longer exists: every PPP frame now travels the same way,
// through ppp.PPPDataIO, and the control stream carries only the session
// handshake and one closing SessionReason. Nothing routes on a protocol number
// any more, so there is no classification left to test. What replaced those
// assertions is TestBridgeSendsEveryProtocolOverDataIO in
// bridge_transport_test.go and TestLocalModeFullSessionLifecycle in
// e2e_test.go, which pin that no frame's contents can change its path.
//
// extractHDLCFrame survives because hdlcEndpoint still uses it to find frame
// boundaries in a pppd byte stream, and that is the one place in the package
// where HDLC is still spoken. Its own behaviour -- including that it never
// discards a buffer it cannot consume -- stays pinned here; the ceiling that
// bounds the accumulator it feeds is pinned in endpoint_test.go.

// ---------------------------------------------------------------------------
// extractHDLCFrame
// ---------------------------------------------------------------------------

func TestExtractHDLCFrame(t *testing.T) {
	f1 := []byte{0xFF, 0x03, 0xC0, 0x21, 0x01, 0x01, 0x00, 0x04}
	f2 := []byte{0xFF, 0x03, 0x80, 0x21, 0x01, 0x02, 0x00, 0x04}
	e1, e2 := EncodeHDLC(f1), EncodeHDLC(f2)

	tests := []struct {
		name      string
		buf       []byte
		wantOK    bool
		wantFrame []byte
		wantRest  []byte
	}{
		{
			name:      "single complete frame",
			buf:       append([]byte{}, e1...),
			wantOK:    true,
			wantFrame: e1,
			// The closing flag is left in rest so it can serve as the opening
			// flag of the next frame (RFC 1662 s4.1 shared flag).
			wantRest: []byte{hdlcFlag},
		},
		{
			name:      "two frames sharing one flag",
			buf:       concatBytes(e1, e2[1:]),
			wantOK:    true,
			wantFrame: e1,
			wantRest:  e2,
		},
		{
			name:      "two back-to-back frames with both flags",
			buf:       concatBytes(e1, e2),
			wantOK:    true,
			wantFrame: e1,
			wantRest:  concatBytes([]byte{hdlcFlag}, e2),
		},
		{
			name:      "leading garbage before the first flag is dropped",
			buf:       concatBytes([]byte{0xDE, 0xAD, 0xBE, 0xEF}, e1),
			wantOK:    true,
			wantFrame: e1,
			wantRest:  []byte{hdlcFlag},
		},
		{
			name:      "frame plus a partial second frame",
			buf:       concatBytes(e1, e2[1:len(e2)-1]),
			wantOK:    true,
			wantFrame: e1,
			wantRest:  e2[:len(e2)-1],
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			frame, rest, ok := extractHDLCFrame(tt.buf)
			require.Equal(t, tt.wantOK, ok)
			assert.Equal(t, tt.wantFrame, frame)
			assert.Equal(t, tt.wantRest, rest)

			decoded, err := DecodeHDLC(frame)
			require.NoError(t, err)
			assert.Equal(t, f1, decoded)
		})
	}

	t.Run("draining a stream of three frames", func(t *testing.T) {
		f3 := []byte{0xFF, 0x03, 0x00, 0x21, 0x45, 0x00}
		buf := concatBytes(EncodeHDLC(f1), EncodeHDLC(f2)[1:], EncodeHDLC(f3)[1:])
		var got [][]byte
		for {
			frame, rest, ok := extractHDLCFrame(buf)
			if !ok {
				break
			}
			buf = rest
			payload, err := DecodeHDLC(frame)
			require.NoError(t, err)
			got = append(got, payload)
		}
		assert.Equal(t, [][]byte{f1, f2, f3}, got)
		assert.Equal(t, []byte{hdlcFlag}, buf, "one trailing flag is left behind")
	})
}

// CONFORMANCE GAP (unbounded buffer growth, classify.go:21-35): when
// extractHDLCFrame finds no complete frame it returns ok=false together with
// `rest = buf`, i.e. the caller's accumulator is handed back untouched —
// including inputs that can never become a frame, such as a buffer with no 0x7E
// in it at all, or a run of flags with nothing between them (two adjacent flags
// are never consumed). The function itself has no maximum-frame-size cut-off.
//
// There is now exactly one caller: hdlcEndpoint.RecvPPP (endpoint.go), which
// appends reads into e.buf and only shrinks it on a successful extraction. That
// caller supplies the ceiling this function lacks — see
// TestHDLCEndpointBoundsTheAccumulator in endpoint_test.go — and its input is a
// local pppd rather than a remote peer, since negotiation no longer reads HDLC
// off the wire. These cases pin extractHDLCFrame's own behaviour.
func TestExtractHDLCFrameKeepsUnconsumableBuffers(t *testing.T) {
	tests := []struct {
		name string
		buf  []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"no flag at all", []byte{0xFF, 0x03, 0xC0, 0x21, 0x01}},
		{"long run with no flag at all", bytes.Repeat([]byte{0xAA}, 100000)},
		{"lone flag", []byte{hdlcFlag}},
		{"two adjacent flags", []byte{hdlcFlag, hdlcFlag}},
		{"long run of flags only", bytes.Repeat([]byte{hdlcFlag}, 4096)},
		{"opening flag then partial frame", []byte{hdlcFlag, 0xFF, 0x03, 0xC0, 0x21}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			frame, rest, ok := extractHDLCFrame(tt.buf)
			assert.False(t, ok)
			assert.Nil(t, frame)
			// rest is the *same* slice, so nothing is ever discarded.
			assert.Equal(t, tt.buf, rest)
			assert.Equal(t, len(tt.buf), len(rest))
		})
	}

	t.Run("flag fill is never consumed, so the accumulator only grows", func(t *testing.T) {
		var acc []byte
		for i := 0; i < 100; i++ {
			acc = append(acc, hdlcFlag)
			_, rest, ok := extractHDLCFrame(acc)
			require.False(t, ok)
			acc = rest
		}
		assert.Equal(t, 100, len(acc), "100 idle flags accumulated and never dropped")
	})
}

func TestExtractHDLCFrameSkipsZeroLengthFrames(t *testing.T) {
	// Two adjacent flags do not form a frame (i == start+1), so the extractor
	// slides `start` forward and keeps looking. A real frame after the empty
	// one is still found.
	f := []byte{0xFF, 0x03, 0xC0, 0x21, 0x01, 0x01, 0x00, 0x04}
	enc := EncodeHDLC(f)
	buf := concatBytes([]byte{hdlcFlag, hdlcFlag, hdlcFlag}, enc[1:])

	frame, rest, ok := extractHDLCFrame(buf)
	require.True(t, ok)
	assert.Equal(t, enc, frame)
	assert.Equal(t, []byte{hdlcFlag}, rest)

	decoded, err := DecodeHDLC(frame)
	require.NoError(t, err)
	assert.Equal(t, f, decoded)
}

func TestExtractHDLCFrameSingleOctetBetweenFlags(t *testing.T) {
	// One octet between two flags IS returned as a frame (i > start+1), even
	// though it is far too short to carry an FCS; the caller only finds out
	// when decoding fails.
	buf := []byte{hdlcFlag, 0xAA, hdlcFlag}
	frame, rest, ok := extractHDLCFrame(buf)
	require.True(t, ok)
	assert.Equal(t, []byte{hdlcFlag, 0xAA, hdlcFlag}, frame)
	assert.Equal(t, []byte{hdlcFlag}, rest)

	_, err := DecodeHDLC(frame)
	require.Error(t, err)
	assert.EqualError(t, err, "hdlc: frame too short")
}

// ---------------------------------------------------------------------------
// hexHead
// ---------------------------------------------------------------------------

func TestHexHeadTruncation(t *testing.T) {
	tests := []struct {
		name string
		n    int
		want string
	}{
		{"empty", 0, ""},
		{"one byte", 1, "aa"},
		{"exactly the limit", hexHeadMax, strings.Repeat("aa", hexHeadMax)},
		{"one over the limit", hexHeadMax + 1, strings.Repeat("aa", hexHeadMax) + "...(65 total)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, hexHead(bytes.Repeat([]byte{0xAA}, tt.n)))
		})
	}
	assert.Equal(t, "", hexHead(nil))
}

// ---------------------------------------------------------------------------
// Fuzzing
// ---------------------------------------------------------------------------

func FuzzExtractHDLCFrame(f *testing.F) {
	good := EncodeHDLC([]byte{0xFF, 0x03, 0xC0, 0x21, 0x01, 0x01, 0x00, 0x04})
	f.Add(good)
	f.Add(concatBytes(good, good))
	f.Add(concatBytes(good, good[1:]))
	f.Add([]byte{hdlcFlag})
	f.Add([]byte{hdlcFlag, hdlcFlag})
	f.Add([]byte{hdlcFlag, 0xAA, hdlcFlag})
	f.Add([]byte{0xAA, 0xBB, 0xCC})
	f.Add([]byte(nil))

	f.Fuzz(func(t *testing.T, buf []byte) {
		frame, rest, ok := extractHDLCFrame(buf)
		if !ok {
			if frame != nil {
				t.Fatalf("frame returned with ok=false: %x", frame)
			}
			if len(rest) != len(buf) {
				t.Fatalf("buffer changed on failure: %d -> %d", len(buf), len(rest))
			}
			return
		}
		// A returned frame is flag-delimited and at least 3 octets long.
		if len(frame) < 3 || frame[0] != hdlcFlag || frame[len(frame)-1] != hdlcFlag {
			t.Fatalf("malformed frame returned: %x", frame)
		}
		for _, b := range frame[1 : len(frame)-1] {
			if b == hdlcFlag {
				t.Fatalf("flag inside returned frame body: %x", frame)
			}
		}
		// rest always begins with the shared closing flag and is strictly
		// shorter than the input, so the drain loop always makes progress.
		if len(rest) == 0 || rest[0] != hdlcFlag {
			t.Fatalf("rest does not start with a flag: %x", rest)
		}
		if len(rest) >= len(buf) {
			t.Fatalf("no progress: buf %d, rest %d", len(buf), len(rest))
		}
		// Draining must terminate.
		for i := 0; ; i++ {
			var ok2 bool
			_, rest, ok2 = extractHDLCFrame(rest)
			if !ok2 {
				break
			}
			if i > len(buf) {
				t.Fatalf("drain loop did not terminate on %x", buf)
			}
		}
	})
}
