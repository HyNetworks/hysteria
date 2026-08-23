package pppbridge

import (
	"bytes"
	"errors"
	"io"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// endpoint.go is where the refactor put everything that used to be duplicated
// between the client bridge and the two server modes. Two things are worth
// pinning here.
//
// First, hdlcEndpoint is now the ONLY place in the package that speaks HDLC.
// Before, the LAC's negotiator decoded HDLC off the control stream and the
// bridge decoded it off the child, each with its own accumulator; the tests for
// the negotiator's copy moved here, because there is only one copy left.
//
// Second, the accumulator is bounded. That mattered more when it was fed by an
// unauthenticated peer -- it is fed by a local pppd now -- but the ceiling is
// what stops a peer that never emits a flag octet from growing it without limit,
// and extractHDLCFrame hands the buffer straight back when it finds no frame
// (TestExtractHDLCFrameKeepsUnconsumableBuffers), so nothing else would.

// ---------------------------------------------------------------------------
// hdlcEndpoint
// ---------------------------------------------------------------------------

// A frame handed to SendPPP reaches the byte stream as one well-formed HDLC
// frame, and comes back off RecvPPP byte-identical.
func TestHDLCEndpointRoundTripsRawPPPFrames(t *testing.T) {
	frames := [][]byte{
		frameLCPConfReq,
		frameCHAP,
		frameIPCP,
		frameIPv4,
		frameIPv6,
		frameMP,
		{0xFF, 0x03, 0x00, 0x21},      // header only
		{0x21, 0x45, 0x00},            // PFC, single-octet protocol
		{0x42},                        // not PPP at all
		bytes.Repeat([]byte{0x7E}, 8), // every octet needs escaping
		append([]byte{0xFF, 0x03, 0x00, 0x21}, bytes.Repeat([]byte{0x00}, 1400)...),
	}

	var wire bytes.Buffer
	out := newHDLCEndpoint(nil, &wire)
	for _, f := range frames {
		require.NoError(t, out.SendPPP(f))
	}

	in := newHDLCEndpoint(bytes.NewReader(wire.Bytes()), io.Discard)
	for i, want := range frames {
		got, err := in.RecvPPP()
		require.NoErrorf(t, err, "frame %d", i)
		assert.Equalf(t, want, got, "frame %d did not survive the round trip", i)
	}
}

// A corrupt or runt frame is discarded and reception resumes at the next flag
// (RFC 1662 s4.3). It must not end the session: pppd is entitled to emit noise
// on a serial line, and one bad FCS is a lost packet, not a lost link.
//
// REPLACES TestNegotiatorReadFrameSkipsUndecodableFrames, which asserted the
// same thing about the negotiator's own HDLC decoder.
func TestHDLCEndpointSkipsUndecodableFrames(t *testing.T) {
	good := []byte{0xFF, 0x03, 0xC0, 0x21, 0x01, 0x01, 0x00, 0x04}
	corrupt := EncodeHDLC([]byte{0xFF, 0x03, 0x80, 0x21})
	corrupt[len(corrupt)-2] ^= 0xFF
	runt := []byte{hdlcFlag, 0xAA, hdlcFlag}

	stream := concatBytes(
		[]byte{0xDE, 0xAD, 0xBE, 0xEF}, // leading garbage before the first flag
		runt,
		corrupt,
		EncodeHDLC(good),
	)

	ep := newHDLCEndpoint(bytes.NewReader(stream), io.Discard)
	got, err := ep.RecvPPP()
	require.NoError(t, err)
	assert.Equal(t, good, got, "runt and bad-FCS frames are skipped, not fatal")
}

// CONFORMANCE (bounded buffering, endpoint.go:95-105): a peer that never sends a
// flag octet, or nothing but idle flag fill, must not be able to grow the
// accumulator without bound. extractHDLCFrame returns the buffer untouched when
// it finds no frame, so this ceiling is the only thing that stops it.
//
// REPLACES TestNegotiatorReadFrameBoundsTheAccumulator.
func TestHDLCEndpointBoundsTheAccumulator(t *testing.T) {
	tests := []struct {
		name string
		junk []byte
	}{
		{"no flag octet at all", bytes.Repeat([]byte{0xAA}, 64<<10)},
		{"nothing but idle flag fill", bytes.Repeat([]byte{hdlcFlag}, 32<<10)},
		{
			"an opening flag and an endless frame body",
			append([]byte{hdlcFlag}, bytes.Repeat([]byte{0xAA}, 64<<10)...),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ep := newHDLCEndpoint(bytes.NewReader(tt.junk), io.Discard)
			raw, err := ep.RecvPPP()
			require.Error(t, err, "must give up rather than buffer forever")
			assert.NotErrorIs(t, err, io.EOF,
				"should fail on the size ceiling, not by exhausting the fake reader")
			assert.Nil(t, raw)
			assert.LessOrEqual(t, len(ep.buf), maxHDLCAccumulate+16384,
				"the accumulator must stay within one read of the ceiling")
		})
	}
}

// A dead byte stream ends the session. This is the difference between "pppd sent
// something we could not parse" and "pppd is gone".
func TestHDLCEndpointPropagatesReadErrors(t *testing.T) {
	want := errors.New("test: pty closed")
	ep := newHDLCEndpoint(errReader{err: want}, io.Discard)
	raw, err := ep.RecvPPP()
	assert.ErrorIs(t, err, want)
	assert.Nil(t, raw)
}

type errReader struct{ err error }

func (r errReader) Read([]byte) (int, error) { return 0, r.err }

// The relay's receive pump is one goroutine, but the endpoint's write lock is
// what keeps the byte stream intelligible if it ever stops being one. A frame
// interleaved with another is not a frame that can be decoded, so the guarantee
// is worth holding under -race rather than assuming a single writer forever.
func TestHDLCEndpointSerialisesConcurrentWrites(t *testing.T) {
	const (
		writers   = 8
		perWriter = 40
	)
	var mu sync.Mutex
	var wire bytes.Buffer
	ep := newHDLCEndpoint(nil, writerFunc(func(p []byte) (int, error) {
		mu.Lock()
		defer mu.Unlock()
		return wire.Write(p)
	}))

	var wg sync.WaitGroup
	for w := range writers {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			frame := append([]byte{0xFF, 0x03, 0x00, 0x21}, byte(w))
			for range perWriter {
				require.NoError(t, ep.SendPPP(frame))
			}
		}(w)
	}
	wg.Wait()

	frames, err := DecodeHDLCStream(wire.Bytes())
	require.NoError(t, err, "interleaved writes would produce an undecodable stream")
	assert.Len(t, frames, writers*perWriter)
	for _, f := range frames {
		require.Len(t, f, 5, "every frame must be whole: %x", f)
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

// The L2TP endpoint reads nothing and decides nothing, so there is no unit to
// test here -- it is two forwarding calls. What replaced the old
// drop-what-you-cannot-parse behaviour is a property of the whole path, and
// TestL2TPModeRelaysAWholePPPSessionVerbatim in e2e_test.go is where it is
// asserted: every frame shape a real LNS and pppd can agree on, arriving
// unaltered at the far end.

// ---------------------------------------------------------------------------
// dataIOFrameRW
// ---------------------------------------------------------------------------

// The adapter that lets LCP negotiation run over the data transport. It exists
// so NegotiateLCP does not have to know whether it is talking to a PPPDataIO or
// to an Endpoint -- which is the whole reason the L2TP handler can negotiate on
// the transport the client actually uses.
func TestDataIOFrameRWIsATransparentAdapter(t *testing.T) {
	pair := newFramePair(8)
	defer pair.shutdown()
	a, b := pair.ends()

	fr := dataIOFrameRW{send: a.SendData, recv: a.ReceiveData}

	require.NoError(t, fr.SendPPP(frameLCPConfReq))
	got, err := b.ReceiveData()
	require.NoError(t, err)
	assert.Equal(t, frameLCPConfReq, got)

	require.NoError(t, b.SendData(frameIPCP))
	got, err = fr.RecvPPP()
	require.NoError(t, err)
	assert.Equal(t, frameIPCP, got)

	// Both halves are the transport's own errors, unwrapped.
	pair.shutdown()
	_, err = fr.RecvPPP()
	assert.ErrorIs(t, err, io.EOF)
	assert.ErrorIs(t, fr.SendPPP(frameIPv4), io.ErrClosedPipe)
}

// FrameRW is satisfied by both sides of the relay by construction: an Endpoint
// and the transport adapter present the same two methods, which is what lets
// NegotiateLCP run over either without knowing which it has. These are
// compile-time assertions rather than a test function, because a test that can
// only fail at build time is not a test.
//
// The spy the negotiator tests drive is included deliberately -- it has to be
// the same shape as the real thing or those tests prove nothing about it.
var (
	_ FrameRW  = (*hdlcEndpoint)(nil)
	_ FrameRW  = (*l2tpEndpoint)(nil)
	_ FrameRW  = dataIOFrameRW{}
	_ FrameRW  = (*frameRWSpy)(nil)
	_ Endpoint = (*hdlcEndpoint)(nil)
	_ Endpoint = (*l2tpEndpoint)(nil)
)
