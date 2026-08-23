package ppp

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"net"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"

	corePPP "github.com/apernet/hysteria/core/v2/ppp"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/qlog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// In-process QUIC harness
//
// MultiStreamIO and CollectDataStreams hold concrete *quic.Stream values, so
// there is no interface seam to fake. These helpers stand up a real quic-go
// connection over a loopback UDP socket with an in-memory self-signed
// certificate; everything stays inside the process and finishes in
// milliseconds.
// ---------------------------------------------------------------------------

const testALPN = "hysteria-ppp-test"

func testTLSConfigs(t testing.TB) (server, client *tls.Config) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ppp-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:         true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return &tls.Config{
			Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}},
			NextProtos:   []string{testALPN},
		}, &tls.Config{
			RootCAs:    pool,
			ServerName: "127.0.0.1",
			NextProtos: []string{testALPN},
		}
}

type quicPair struct {
	client *quic.Conn
	server *quic.Conn
}

// newQUICPair brings up a connected client/server quic.Conn pair. conf may be
// nil for defaults; it is applied to both ends.
func newQUICPair(t testing.TB, conf *quic.Config) *quicPair {
	t.Helper()
	serverTLS, clientTLS := testTLSConfigs(t)
	conf = withQlog(conf)

	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	ln, err := quic.Listen(udpConn, serverTLS, conf)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = ln.Close()
		_ = udpConn.Close()
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	type acceptResult struct {
		conn *quic.Conn
		err  error
	}
	acceptCh := make(chan acceptResult, 1)
	go func() {
		c, err := ln.Accept(ctx)
		acceptCh <- acceptResult{c, err}
	}()

	// The elapsed time and goroutine count are in the failure message on purpose:
	// a handshake between two goroutines in this process does not fail for network
	// reasons, so if it ever does, those two numbers are the first thing worth
	// knowing. See withQlog above for the rest.
	dialStart := time.Now()
	clientConn, err := quic.DialAddr(ctx, udpConn.LocalAddr().String(), clientTLS, conf)
	require.NoErrorf(t, err, "in-process handshake failed after %s with %d goroutines live",
		time.Since(dialStart), runtime.NumGoroutine())
	res := <-acceptCh
	require.NoErrorf(t, res.err, "in-process accept failed after %s with %d goroutines live",
		time.Since(dialStart), runtime.NumGoroutine())

	t.Cleanup(func() {
		_ = clientConn.CloseWithError(0, "")
		_ = res.conn.CloseWithError(0, "")
	})
	return &quicPair{client: clientConn, server: res.conn}
}

// withQlog turns on quic-go's own tracing when QLOGDIR is set, and does nothing
// otherwise -- DefaultConnectionTracer returns nil without it, so a normal run
// and CI pay nothing.
//
// It is wired in because this package has had an intermittent failure in which
// the handshake below simply does not complete, and the one diagnostic that would
// identify it cannot be obtained from outside the process. Reproducing it needs
// heavy CPU starvation and it has never been caught in CI, so if it resurfaces,
// re-run with QLOGDIR pointed at an empty directory and read the trace for the
// connection that stalled.
func withQlog(conf *quic.Config) *quic.Config {
	if os.Getenv("QLOGDIR") == "" {
		return conf
	}
	if conf == nil {
		conf = &quic.Config{}
	} else {
		clone := *conf
		conf = &clone
	}
	conf.Tracer = qlog.DefaultConnectionTracer
	return conf
}

// openStreamPairs opens n bidirectional streams from the client and returns
// them alongside the matching server-side streams, ordered so that
// client[i] and server[i] are the two ends of the same stream.
//
// QUIC only surfaces a stream to the peer once data has been sent on it, so
// each stream is primed with a single index octet which the server side reads
// back off before the stream is handed to the caller.
func openStreamPairs(t testing.TB, p *quicPair, n int) (clientSide, serverSide []*quic.Stream) {
	t.Helper()
	require.LessOrEqual(t, n, 250, "the priming octet only encodes small indices")

	clientSide = make([]*quic.Stream, n)
	serverSide = make([]*quic.Stream, n)
	for i := 0; i < n; i++ {
		cs, err := p.client.OpenStream()
		require.NoError(t, err)
		_, err = cs.Write([]byte{byte(i)})
		require.NoError(t, err)
		clientSide[i] = cs
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for i := 0; i < n; i++ {
		ss, err := p.server.AcceptStream(ctx)
		require.NoError(t, err)
		var idx [1]byte
		_, err = io.ReadFull(ss, idx[:])
		require.NoError(t, err)
		require.Nil(t, serverSide[idx[0]], "duplicate stream index %d", idx[0])
		serverSide[idx[0]] = ss
	}
	return clientSide, serverSide
}

// ---------------------------------------------------------------------------
// Wire format mirror
// ---------------------------------------------------------------------------

// encodeFrames is an independent implementation of the length-prefix framing
// MultiStreamIO.SendData is supposed to produce: a 2-octet big-endian length
// followed by that many payload octets.
func encodeFrames(frames ...[]byte) []byte {
	var out []byte
	for _, f := range frames {
		out = binary.BigEndian.AppendUint16(out, uint16(len(f)))
		out = append(out, f...)
	}
	return out
}

// readN reads exactly n octets with a deadline so a desynchronised stream fails
// the test instead of hanging it.
func readN(t testing.TB, s *quic.Stream, n int, timeout time.Duration) ([]byte, error) {
	t.Helper()
	require.NoError(t, s.SetReadDeadline(time.Now().Add(timeout)))
	buf := make([]byte, n)
	_, err := io.ReadFull(s, buf)
	_ = s.SetReadDeadline(time.Time{})
	return buf, err
}

// receiveWithin returns the next frame from io, or fails if none arrives.
func receiveWithin(t testing.TB, rw interface {
	ReceiveData() ([]byte, error)
}, timeout time.Duration,
) ([]byte, error) {
	t.Helper()
	type result struct {
		frame []byte
		err   error
	}
	ch := make(chan result, 1)
	go func() {
		f, err := rw.ReceiveData()
		ch <- result{f, err}
	}()
	select {
	case r := <-ch:
		return r.frame, r.err
	case <-time.After(timeout):
		t.Fatalf("ReceiveData did not return within %s", timeout)
		return nil, nil
	}
}

// tryReceive reports whether a frame (or an error) turned up within timeout.
func tryReceive(rw interface {
	ReceiveData() ([]byte, error)
}, timeout time.Duration,
) (frame []byte, err error, ok bool) {
	type result struct {
		frame []byte
		err   error
	}
	ch := make(chan result, 1)
	go func() {
		f, e := rw.ReceiveData()
		ch <- result{f, e}
	}()
	select {
	case r := <-ch:
		return r.frame, r.err, true
	case <-time.After(timeout):
		return nil, nil, false
	}
}

// ---------------------------------------------------------------------------
// SendData: wire format
// ---------------------------------------------------------------------------

func TestSendDataWireFormat(t *testing.T) {
	tests := []struct {
		name  string
		frame []byte
	}{
		{"empty frame", []byte{}},
		{"one octet", []byte{0xAA}},
		{"ipv4 tcp frame", ipv4TCP("192.0.2.1", "198.51.100.7", 1234, 443)},
		{"255 octets", make([]byte, 255)},
		{"256 octets", make([]byte, 256)},
		{"1500 octets", func() []byte { b := make([]byte, 1500); b[0] = 0xFF; b[1499] = 0x11; return b }()},
		{"largest representable frame", make([]byte, 65535)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newQUICPair(t, nil)
			cs, ss := openStreamPairs(t, p, 1)
			m := NewMultiStreamIO(cs, nil)
			t.Cleanup(func() { _ = m.Close() })

			require.NoError(t, m.SendData(tt.frame))

			want := encodeFrames(tt.frame)
			got, err := readN(t, ss[0], len(want), 5*time.Second)
			require.NoError(t, err)
			assert.Equal(t, want, got, "on-the-wire framing must be a 2-octet big-endian length prefix")
		})
	}
}

func TestSendDataRoundTripThroughMultiStreamIO(t *testing.T) {
	for _, nStreams := range []int{1, 2, 4} {
		t.Run(fmt.Sprintf("streams=%d", nStreams), func(t *testing.T) {
			p := newQUICPair(t, nil)
			cs, ss := openStreamPairs(t, p, nStreams)
			sender := NewMultiStreamIO(cs, nil)
			receiver := NewMultiStreamIO(ss, nil)
			t.Cleanup(func() { _ = sender.Close(); _ = receiver.Close() })

			// Every frame belongs to the same flow, so they all take the same
			// stream and must therefore arrive in order.
			var sent [][]byte
			for i := 0; i < 20; i++ {
				f := ipv4TCP("192.0.2.1", "198.51.100.7", 1234, 443)
				f = append(f, byte(i))
				sent = append(sent, f)
				require.NoError(t, sender.SendData(f))
			}
			for i, want := range sent {
				got, err := receiveWithin(t, receiver, 5*time.Second)
				require.NoError(t, err)
				assert.Equal(t, want, got, "frame %d", i)
			}
		})
	}
}

// The length prefix is 16 bits, so a frame of 65536 octets or more cannot be
// framed at all: casting its length to uint16 would wrap and the peer's readLoop
// would parse payload octets as further length prefixes for the life of the
// stream. SendData rejects such a frame instead, as a FrameTooLargeError -- the
// "drop this packet" signal, not a session failure.
func TestMultiStreamSendDataRejectsAFrameThatCannotBeLengthPrefixed(t *testing.T) {
	tests := []struct {
		name    string
		size    int
		wantErr bool
	}{
		{"one octet below the ceiling", math.MaxUint16 - 1, false},
		{"exactly the 16-bit ceiling", math.MaxUint16, false},
		{"one octet past the ceiling", math.MaxUint16 + 1, true},
		{"65537 octets, would wrap to one", 65537, true},
		{"70000 octets, would wrap to 4464", 70000, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newQUICPair(t, nil)
			cs, ss := openStreamPairs(t, p, 1)
			m := NewMultiStreamIO(cs, nil)
			t.Cleanup(func() { _ = m.Close() })

			frame := make([]byte, tt.size)
			for i := range frame {
				frame[i] = byte(i)
			}
			err := m.SendData(frame)

			if !tt.wantErr {
				require.NoError(t, err)
				// It really went out, correctly framed.
				hdr, rerr := readN(t, ss[0], 2, 5*time.Second)
				require.NoError(t, rerr)
				require.Equal(t, uint16(tt.size), binary.BigEndian.Uint16(hdr))
				body, rerr := readN(t, ss[0], tt.size, 20*time.Second)
				require.NoError(t, rerr)
				assert.Equal(t, frame, body)
				return
			}

			require.Error(t, err)
			assert.True(t, corePPP.IsFrameTooLarge(err), "got %T: %v", err, err)
			var tooLarge *corePPP.FrameTooLargeError
			require.ErrorAs(t, err, &tooLarge)
			assert.Equal(t, tt.size, tooLarge.FrameSize)
			assert.Equal(t, math.MaxUint16, tooLarge.MaxSize,
				"MaxSize should name the largest frame the length prefix can describe")

			// Nothing at all was written, so the peer sees no orphan header.
			// A short read that times out is the proof; anything else means
			// octets escaped onto the stream.
			_, rerr := readN(t, ss[0], 1, 300*time.Millisecond)
			assert.Error(t, rerr, "a rejected frame must not put any octets on the wire")
		})
	}
}

// The rejection above must also leave the stream usable: the frame that follows
// an oversize one has to arrive intact and first, with no desynchronisation.
func TestMultiStreamRejectedOversizeFrameLeavesTheReceiverInSync(t *testing.T) {
	p := newQUICPair(t, nil)
	cs, ss := openStreamPairs(t, p, 1)
	sender := NewMultiStreamIO(cs, nil)
	receiver := NewMultiStreamIO(ss, nil)
	t.Cleanup(func() { _ = sender.Close(); _ = receiver.Close() })

	// An oversize frame whose first two octets would read as the length 4, so a
	// desynchronised receiver would visibly deliver big[2:6] instead.
	big := make([]byte, 65536)
	binary.BigEndian.PutUint16(big[0:2], 4)
	for i := 2; i < len(big); i++ {
		big[i] = byte(i)
	}
	good := []byte{0xDE, 0xAD, 0xBE, 0xEF}

	require.Error(t, sender.SendData(big))
	require.NoError(t, sender.SendData(good))

	first, err := receiveWithin(t, receiver, 5*time.Second)
	require.NoError(t, err)
	assert.Equal(t, good, first, "the frame after a rejected oversize frame must arrive intact and first")

	// And the stream keeps working for everything that follows.
	more := []byte{0x01, 0x02, 0x03}
	require.NoError(t, sender.SendData(more))
	second, err := receiveWithin(t, receiver, 5*time.Second)
	require.NoError(t, err)
	assert.Equal(t, more, second)
}

// CONFORMANCE GAP (n/a - plain bug): SendData writes the 2-octet header and the
// payload as two separate Write calls with no mutex and no rollback. If the
// second Write fails or only partially completes, the header (and any payload
// prefix that made it out) stays on the stream and the peer's readLoop is
// permanently misaligned; SendData reports an error but the caller has no way
// to resynchronise. Here the payload write is made to fail with a write
// deadline while the stream flow-control window is exhausted. The same missing
// mutex also allows two concurrent SendData calls that hash onto one stream to
// interleave as hdrA, hdrB, payloadA, payloadB - see the note in
// TestConcurrentSendDataOnOneStreamIsUnsynchronised. This test pins the current
// behaviour so a future fix is a deliberate change.
func TestSendDataLeavesAnOrphanHeaderWhenThePayloadWriteFails(t *testing.T) {
	const window = 16 * 1024
	p := newQUICPair(t, &quic.Config{
		InitialStreamReceiveWindow:     window,
		MaxStreamReceiveWindow:         window, // disable window auto-tuning
		InitialConnectionReceiveWindow: 4 << 20,
		MaxConnectionReceiveWindow:     4 << 20,
		MaxIdleTimeout:                 30 * time.Second,
	})
	cs, ss := openStreamPairs(t, p, 1)

	sender := NewMultiStreamIO(cs, nil)
	t.Cleanup(func() { _ = sender.Close() })

	// Nobody is reading the server end yet, so the first frame parks in the
	// receive window and the second frame's payload cannot be flushed.
	filler := make([]byte, window/2)
	require.NoError(t, sender.SendData(filler))

	require.NoError(t, cs[0].SetWriteDeadline(time.Now().Add(200*time.Millisecond)))
	orphan := make([]byte, 60000)
	err := sender.SendData(orphan)
	require.Error(t, err, "the payload write must fail once the window is exhausted")
	require.NoError(t, cs[0].SetWriteDeadline(time.Time{}))

	// Only now start reading, which is when the damage becomes visible.
	receiver := NewMultiStreamIO(ss, nil)
	t.Cleanup(func() { _ = receiver.Close() })

	got, rerr := receiveWithin(t, receiver, 5*time.Second)
	require.NoError(t, rerr)
	assert.Equal(t, filler, got, "the frame written before the failure still arrives intact")

	// The orphaned header claims 60000 octets, so everything sent afterwards is
	// swallowed as that phantom frame's payload.
	require.NoError(t, sender.SendData([]byte{1, 2, 3, 4}))
	_, _, ok := tryReceive(receiver, 500*time.Millisecond)
	assert.False(t, ok, "frames written after a failed SendData are swallowed by the orphaned header")
}

// TestConcurrentSendDataOnOneStreamIsUnsynchronised exercises many concurrent
// SendData calls that all hash onto a single stream, and inspects the raw
// octets that come out the other end.
//
// NOTE ON WHAT THIS CAN AND CANNOT PROVE: SendData holds no mutex across its
// two Write calls, so two goroutines can interleave as hdrA, hdrB, payloadA,
// payloadB and corrupt the stream. That interleaving cannot be *forced*
// deterministically through a *quic.Stream: quic-go serialises each individual
// Write internally, the streams field is a concrete []*quic.Stream with no
// interface seam to substitute a blocking writer for, and the vulnerable window
// is the few nanoseconds between the two calls. So corruption is reported, not
// asserted (it fired on 40 of 40 local runs - typically within the first few
// frames - but a single-CPU or heavily loaded machine could serialise the
// senders by luck, and a flaky test would be worse than a logged observation).
//
// What IS asserted deterministically: concurrency neither loses nor duplicates
// octets - exactly senders*perSender*(2+frameLen) bytes arrive and not one
// more - so any damage is purely a reordering of header and payload, which is
// what makes it invisible to the sender. The gap itself is pinned
// deterministically by TestSendDataLeavesAnOrphanHeaderWhenThePayloadWriteFails.
func TestConcurrentSendDataOnOneStreamIsUnsynchronised(t *testing.T) {
	p := newQUICPair(t, nil)
	cs, ss := openStreamPairs(t, p, 1)
	sender := NewMultiStreamIO(cs, nil)
	t.Cleanup(func() { _ = sender.Close() })

	const senders = 4
	const perSender = 100
	frames := make([][]byte, senders)
	for g := range frames {
		// There is only one stream, so every frame goes to it whatever flowHash
		// says; the last octet identifies the sender.
		frames[g] = append(ipv4TCP("192.0.2.1", "198.51.100.7", 1234, 443), byte(g))
	}
	frameLen := len(frames[0])
	totalBytes := senders * perSender * (2 + frameLen)

	// Drain the peer end concurrently so the senders can never block on flow
	// control and the test cannot deadlock on itself.
	type readResult struct {
		buf []byte
		err error
	}
	readCh := make(chan readResult, 1)
	go func() {
		buf := make([]byte, totalBytes)
		_ = ss[0].SetReadDeadline(time.Now().Add(10 * time.Second))
		_, err := io.ReadFull(ss[0], buf)
		readCh <- readResult{buf, err}
	}()

	errCh := make(chan error, senders*perSender)
	var wg sync.WaitGroup
	for g := 0; g < senders; g++ {
		frame := frames[g]
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perSender; i++ {
				if err := sender.SendData(frame); err != nil {
					errCh <- err
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		require.NoError(t, err, "SendData must not fail under concurrent use")
	}

	res := <-readCh
	require.NoError(t, res.err, "every octet SendData reported as written must reach the peer")

	// ...and nothing beyond them.
	require.NoError(t, ss[0].SetReadDeadline(time.Now().Add(200*time.Millisecond)))
	extra := make([]byte, 1)
	_, err := ss[0].Read(extra)
	require.Error(t, err, "no octets beyond the %d written may appear", totalBytes)
	require.NoError(t, ss[0].SetReadDeadline(time.Time{}))

	// Now characterise the ordering. A clean run decodes into exactly
	// senders*perSender intact frames; an interleaved one does not, and there is
	// no way back into alignment once it happens.
	decoded := decodeFrames(bytes.NewReader(res.buf))
	intact := 0
	for _, f := range decoded {
		if len(f) == frameLen && bytes.Equal(f, frames[int(f[frameLen-1])%senders]) {
			intact++
		}
	}
	if len(decoded) == senders*perSender && intact == senders*perSender {
		t.Logf("no interleave observed this run: all %d frames decoded intact", intact)
	} else {
		t.Logf("header/payload interleaving corrupted the stream: %d octets decoded into %d frames, %d of the expected %d intact",
			totalBytes, len(decoded), intact, senders*perSender)
	}
}

// CONFORMANCE GAP (n/a - plain bug): neither NewMultiStreamIO (impl.go:65) nor
// CollectDataStreams (impl.go:142) enforces a lower bound on the stream count,
// and flowHash returns 0 for n <= 1 including n == 0 - so SendData indexes
// streams[0] of an empty slice and panics, while ReceiveData blocks forever
// because no readLoop was ever started (see
// TestCollectDataStreamsZeroStreamsReturnsAnUnusableIO). Both constructors
// should reject a count below 1 instead of handing back an object that panics
// on first use. This is unreachable today - core/client/ppp.go:32 only builds a
// MultiStreamIO when the server answered serverDS > 0, and
// core/server/server.go:333 routes dataStreams == 0 to DatagramIO - so it is
// pinned as latent, not as a live crash.
func TestSendDataPanicsWithNoStreams(t *testing.T) {
	m := &MultiStreamIO{
		streams: nil,
		recvCh:  make(chan []byte, 1),
		done:    make(chan struct{}),
	}
	assert.Panics(t, func() { _ = m.SendData([]byte{1, 2, 3}) })
}

// ---------------------------------------------------------------------------
// readLoop
// ---------------------------------------------------------------------------

func TestReadLoopReassemblesFramesDeliveredInChunks(t *testing.T) {
	p := newQUICPair(t, nil)
	cs, ss := openStreamPairs(t, p, 1)
	receiver := NewMultiStreamIO(ss, nil)
	t.Cleanup(func() { _ = receiver.Close() })

	frame := make([]byte, 900)
	for i := range frame {
		frame[i] = byte(i * 7)
	}
	wire := encodeFrames(frame)

	// Dribble the frame out one small chunk at a time, splitting the length
	// prefix itself across two writes.
	chunks := [][]byte{wire[0:1], wire[1:2], wire[2:3], wire[3:100], wire[100:101], wire[101:]}
	for _, c := range chunks {
		_, err := cs[0].Write(c)
		require.NoError(t, err)
		time.Sleep(time.Millisecond)
	}

	got, err := receiveWithin(t, receiver, 5*time.Second)
	require.NoError(t, err)
	assert.Equal(t, frame, got)
}

func TestReadLoopTerminatesOnTruncatedFrames(t *testing.T) {
	tests := []struct {
		name string
		// wire is what the peer writes before closing its send side.
		wire []byte
		// want is the sequence of frames that must be delivered first.
		want [][]byte
	}{
		{
			name: "clean close after a whole frame",
			wire: encodeFrames([]byte("abcd")),
			want: [][]byte{[]byte("abcd")},
		},
		{
			name: "close in the middle of a length prefix",
			wire: append(encodeFrames([]byte("abcd")), 0x00),
			want: [][]byte{[]byte("abcd")},
		},
		{
			name: "close in the middle of a payload",
			wire: append(encodeFrames([]byte("abcd")), 0x00, 0x0A, 'x', 'y'),
			want: [][]byte{[]byte("abcd")},
		},
		{
			name: "close with nothing sent at all",
			wire: nil,
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newQUICPair(t, nil)
			cs, ss := openStreamPairs(t, p, 1)
			receiver := NewMultiStreamIO(ss, nil)
			t.Cleanup(func() { _ = receiver.Close() })

			if len(tt.wire) > 0 {
				_, err := cs[0].Write(tt.wire)
				require.NoError(t, err)
			}
			// Drain the complete frames first. Reading them before the stream
			// is closed keeps this deterministic - see
			// TestReceiveDataAfterCloseWithBufferedFramesIsNondeterministic
			// for why draining after Close is a coin flip.
			for i, want := range tt.want {
				got, err := receiveWithin(t, receiver, 5*time.Second)
				require.NoError(t, err, "frame %d", i)
				assert.Equal(t, want, got)
			}
			// The truncated tail must not produce a frame.
			_, _, ok := tryReceive(receiver, 100*time.Millisecond)
			assert.False(t, ok, "a partial frame must not be delivered")

			require.NoError(t, cs[0].Close()) // send FIN
			// With the only reader gone, activeReaders hits zero and the whole
			// MultiStreamIO closes, so ReceiveData reports EOF rather than
			// spinning on the dead stream.
			_, err := receiveWithin(t, receiver, 5*time.Second)
			assert.ErrorIs(t, err, io.EOF)
		})
	}
}

func TestReadLoopCloseHappensOnlyWhenEveryReaderIsDone(t *testing.T) {
	p := newQUICPair(t, nil)
	cs, ss := openStreamPairs(t, p, 3)
	receiver := NewMultiStreamIO(ss, nil)
	t.Cleanup(func() { _ = receiver.Close() })
	m := receiver.(*MultiStreamIO)
	require.EqualValues(t, 3, m.activeReaders.Load())

	// Tear down two of the three streams; the IO must stay open.
	for i := 0; i < 2; i++ {
		require.NoError(t, cs[i].Close())
	}
	require.Eventually(t, func() bool { return m.activeReaders.Load() == 1 },
		5*time.Second, 5*time.Millisecond)
	select {
	case <-m.done:
		t.Fatal("MultiStreamIO closed while a reader was still alive")
	default:
	}

	// The surviving stream still delivers.
	_, err := cs[2].Write(encodeFrames([]byte("still here")))
	require.NoError(t, err)
	got, err := receiveWithin(t, receiver, 5*time.Second)
	require.NoError(t, err)
	assert.Equal(t, []byte("still here"), got)

	// Once the last reader goes, the IO closes itself.
	require.NoError(t, cs[2].Close())
	_, err = receiveWithin(t, receiver, 5*time.Second)
	assert.ErrorIs(t, err, io.EOF)
	assert.EqualValues(t, 0, m.activeReaders.Load())
}

// A reader that has stopped taking frames parks the read loop on a full queue.
// Closing has to release it, or every stream's goroutine outlives the session it
// belonged to -- one leaked goroutine per stream, per subscriber, for as long as
// the server runs.
func TestReadLoopParkedOnAFullQueueIsReleasedByClose(t *testing.T) {
	p := newQUICPair(t, nil)
	cs, ss := openStreamPairs(t, p, 1)

	m := newDetachedMultiStreamIO(1)
	done := make(chan struct{})
	go func() { defer close(done); m.readLoop(0, ss[0]) }()

	// The first frame fills the queue; the second has nowhere to go.
	_, err := cs[0].Write(encodeFrames([]byte("first"), []byte("second")))
	require.NoError(t, err)
	require.Eventually(t, func() bool { return len(m.recvCh) == 1 },
		5*time.Second, 5*time.Millisecond, "the read loop never parked")

	select {
	case <-done:
		t.Fatal("the read loop ended while the queue was merely full")
	case <-time.After(50 * time.Millisecond):
	}

	require.NoError(t, m.Close())
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not release a read loop parked on a full queue")
	}
}

// A reliable stream has no per-frame limit of its own, so the ceiling is the
// 16-bit length prefix. It has to be reported rather than left unknown, or the
// black-hole probe would never run in multi-stream mode.
func TestMultiStreamIOReportsTheLengthPrefixCeiling(t *testing.T) {
	m := newDetachedMultiStreamIO(1)
	t.Cleanup(func() { _ = m.Close() })
	assert.Equal(t, math.MaxUint16, m.MaxFrameSize())
}

// ---------------------------------------------------------------------------
// MultiStreamIO: ReceiveData / Close
// ---------------------------------------------------------------------------

// newDetachedMultiStreamIO builds a MultiStreamIO with no streams and no read
// loops, for exercising ReceiveData/Close in isolation. Close tolerates an
// empty streams slice.
func newDetachedMultiStreamIO(buffer int) *MultiStreamIO {
	return &MultiStreamIO{
		recvCh: make(chan []byte, buffer),
		done:   make(chan struct{}),
	}
}

func TestMultiStreamIOReceiveDataAfterCloseReturnsEOF(t *testing.T) {
	m := newDetachedMultiStreamIO(4)
	require.NoError(t, m.Close())
	for i := 0; i < 5; i++ {
		frame, err := m.ReceiveData()
		assert.Nil(t, frame)
		assert.ErrorIs(t, err, io.EOF)
	}
}

func TestMultiStreamIOReceiveDataOnClosedChannelReturnsEOF(t *testing.T) {
	m := newDetachedMultiStreamIO(1)
	m.recvCh <- []byte("last")
	close(m.recvCh)

	frame, err := m.ReceiveData()
	require.NoError(t, err)
	assert.Equal(t, []byte("last"), frame)

	frame, err = m.ReceiveData()
	assert.Nil(t, frame)
	assert.ErrorIs(t, err, io.EOF)
}

// pppDataIO is the subset of corePPP.PPPDataIO the receive-path tests need.
type pppDataIO interface {
	ReceiveData() ([]byte, error)
	Close() error
}

// CONFORMANCE GAP (n/a - plain bug): both ReceiveData implementations
// (impl.go:38 for DatagramIO, impl.go:115 for MultiStreamIO) select over recvCh
// and done with no priority between them, so when the IO is closed while frames
// are still buffered the caller gets either a buffered frame or io.EOF at
// random - Go picks uniformly among ready cases. Neither draining nor prompt
// shutdown is guaranteed: a caller cannot tell "closed" from "one more frame",
// and already-received frames are dropped nondeterministically. This is not a
// corner case: MultiStreamIO closes itself as soon as the last readLoop exits
// (impl.go:81-83), which is exactly when up to 256 frames may still be sitting
// in recvCh. This test pins the current behaviour - both outcomes occur across
// repeated trials - so a future fix (drain first, or refuse to deliver after
// Close) is a deliberate change.
func TestReceiveDataAfterCloseWithBufferedFramesIsNondeterministic(t *testing.T) {
	tests := []struct {
		name string
		// build returns a closed-over IO with exactly one frame buffered.
		build func() pppDataIO
	}{
		{
			name: "multi stream io",
			build: func() pppDataIO {
				m := newDetachedMultiStreamIO(1)
				m.recvCh <- []byte("buffered")
				return m
			},
		},
		{
			name: "datagram io",
			build: func() pppDataIO {
				ch := make(chan []byte, 1)
				ch <- []byte("buffered")
				return &DatagramIO{recvCh: ch, done: make(chan struct{})}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			const trials = 400
			var gotFrame, gotEOF int
			for i := 0; i < trials; i++ {
				d := tt.build()
				require.NoError(t, d.Close())
				frame, err := d.ReceiveData()
				switch {
				case err == nil:
					assert.Equal(t, []byte("buffered"), frame)
					gotFrame++
				default:
					assert.ErrorIs(t, err, io.EOF)
					assert.Nil(t, frame)
					gotEOF++
				}
			}
			// With a uniform select over two ready cases, seeing only one
			// outcome in 400 trials has probability 2^-399.
			assert.NotZero(t, gotFrame, "expected some trials to deliver the buffered frame")
			assert.NotZero(t, gotEOF, "expected some trials to report EOF and drop the buffered frame")
			t.Logf("buffered frame delivered %d/%d, dropped for EOF %d/%d", gotFrame, trials, gotEOF, trials)
		})
	}
}

func TestMultiStreamIOCloseIsIdempotent(t *testing.T) {
	p := newQUICPair(t, nil)
	cs, _ := openStreamPairs(t, p, 2)
	m := NewMultiStreamIO(cs, nil)
	for i := 0; i < 5; i++ {
		assert.NoError(t, m.Close(), "Close call %d", i)
	}
	assert.NotPanics(t, func() { _ = m.Close() })
}

func TestMultiStreamIOCloseClosesEveryStream(t *testing.T) {
	p := newQUICPair(t, nil)
	cs, ss := openStreamPairs(t, p, 3)
	m := NewMultiStreamIO(cs, nil)
	require.NoError(t, m.Close())

	// Close() on a quic stream sends FIN, so each peer end sees EOF.
	for i, s := range ss {
		require.NoError(t, s.SetReadDeadline(time.Now().Add(5*time.Second)))
		_, err := io.ReadAll(s)
		assert.NoError(t, err, "stream %d should have been closed cleanly", i)
	}
}

// CONFORMANCE GAP (n/a - plain bug): MultiStreamIO.Close (impl.go:126-138)
// closes the done channel and calls Close on each stream, but quic.Stream.Close
// only shuts the *send* side - it never calls CancelRead. A readLoop parked in
// io.ReadFull (impl.go:87) is therefore not woken by Close at all: it stays
// blocked until the peer sends a FIN or the whole QUIC connection goes away.
// Since both call sites keep the connection alive after tearing the PPP session
// down (core/client/ppp.go:61-64 closes only dataIO and the control stream),
// every closed session leaks one goroutine per data stream for the lifetime of
// the connection. Worse, a frame that arrives after Close is still read and
// then raced into recvCh, a channel nobody will ever drain again - so a hostile
// or merely slow peer can also pin up to 256 frames of memory per closed
// session. Close should CancelRead each stream (or the read loops should select
// on done) so the goroutines exit promptly. This test pins the current
// behaviour so a future fix is a deliberate change.
func TestCloseDoesNotStopReadLoopsUntilThePeerCloses(t *testing.T) {
	p := newQUICPair(t, nil)
	cs, ss := openStreamPairs(t, p, 1)
	m := NewMultiStreamIO(ss, nil).(*MultiStreamIO)
	require.EqualValues(t, 1, m.activeReaders.Load())

	require.NoError(t, m.Close())
	select {
	case <-m.done:
	default:
		t.Fatal("Close did not close the done channel")
	}

	// Deterministic: the read loop is blocked in io.ReadFull with no data to
	// read, and nothing Close did can make that call return, so the goroutine
	// cannot have exited no matter how long we wait.
	require.Never(t, func() bool { return m.activeReaders.Load() == 0 },
		250*time.Millisecond, 25*time.Millisecond,
		"Close must not be able to retire a reader parked in ReadFull")

	// Only a FIN from the peer retires it.
	require.NoError(t, cs[0].Close())
	require.Eventually(t, func() bool { return m.activeReaders.Load() == 0 },
		5*time.Second, 5*time.Millisecond,
		"the read loop should exit once the peer closes its send side")
}

func TestMultiStreamIOSendDataAfterCloseFails(t *testing.T) {
	p := newQUICPair(t, nil)
	cs, _ := openStreamPairs(t, p, 1)
	m := NewMultiStreamIO(cs, nil)
	require.NoError(t, m.Close())
	assert.Error(t, m.SendData([]byte{1, 2, 3}), "writing to a closed stream must fail")
}

// ---------------------------------------------------------------------------
// DatagramIO
// ---------------------------------------------------------------------------

func TestDatagramIOReceiveDataDrainsChannel(t *testing.T) {
	ch := make(chan []byte, 4)
	d := &DatagramIO{recvCh: ch, done: make(chan struct{})}

	want := [][]byte{[]byte("one"), []byte("two"), {}, []byte("four")}
	for _, w := range want {
		ch <- w
	}
	for i, w := range want {
		got, err := d.ReceiveData()
		require.NoError(t, err, "frame %d", i)
		assert.Equal(t, w, got)
	}
}

func TestDatagramIOReceiveDataReturnsEOF(t *testing.T) {
	tests := []struct {
		name  string
		setup func() *DatagramIO
	}{
		{
			name: "closed channel",
			setup: func() *DatagramIO {
				ch := make(chan []byte)
				close(ch)
				return &DatagramIO{recvCh: ch, done: make(chan struct{})}
			},
		},
		{
			name: "closed io",
			setup: func() *DatagramIO {
				d := &DatagramIO{recvCh: make(chan []byte), done: make(chan struct{})}
				_ = d.Close()
				return d
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := tt.setup()
			for i := 0; i < 3; i++ {
				frame, err := d.ReceiveData()
				assert.Nil(t, frame)
				assert.ErrorIs(t, err, io.EOF, "call %d", i)
			}
		})
	}
}

func TestDatagramIOCloseUnblocksAPendingReceive(t *testing.T) {
	d := &DatagramIO{recvCh: make(chan []byte), done: make(chan struct{})}
	errCh := make(chan error, 1)
	go func() {
		_, err := d.ReceiveData()
		errCh <- err
	}()
	// Give the receiver a moment to park in the select.
	time.Sleep(5 * time.Millisecond)
	require.NoError(t, d.Close())
	select {
	case err := <-errCh:
		assert.ErrorIs(t, err, io.EOF)
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not unblock a pending ReceiveData")
	}
}

func TestDatagramIOCloseIsIdempotent(t *testing.T) {
	d := &DatagramIO{recvCh: make(chan []byte), done: make(chan struct{})}
	for i := 0; i < 5; i++ {
		assert.NoError(t, d.Close(), "Close call %d", i)
	}
}

// ---------------------------------------------------------------------------
// CollectDataStreams
// ---------------------------------------------------------------------------

func TestCollectDataStreamsSucceedsOnExactlyN(t *testing.T) {
	for _, n := range []int{1, 2, 5} {
		t.Run(fmt.Sprintf("n=%d", n), func(t *testing.T) {
			p := newQUICPair(t, nil)
			cs, ss := openStreamPairs(t, p, n)

			ch := make(chan *quic.Stream, n)
			for _, s := range ss {
				ch <- s
			}
			io0, err := CollectDataStreams(ch, n, 5*time.Second, nil)
			require.NoError(t, err)
			t.Cleanup(func() { _ = io0.Close() })

			m, ok := io0.(*MultiStreamIO)
			require.True(t, ok)
			assert.Len(t, m.streams, n)
			assert.EqualValues(t, n, m.activeReaders.Load())

			// The collected streams are live: a frame written from the far end
			// of each one comes back out of ReceiveData.
			for i := range cs {
				_, err := cs[i].Write(encodeFrames([]byte{byte(i)}))
				require.NoError(t, err)
			}
			seen := map[byte]bool{}
			for range cs {
				frame, err := receiveWithin(t, io0, 5*time.Second)
				require.NoError(t, err)
				require.Len(t, frame, 1)
				seen[frame[0]] = true
			}
			assert.Len(t, seen, n, "every collected stream must be read from")
		})
	}
}

func TestCollectDataStreamsTimesOutAndClosesWhatItCollected(t *testing.T) {
	const n = 3
	p := newQUICPair(t, nil)
	cs, ss := openStreamPairs(t, p, n-1)

	ch := make(chan *quic.Stream, n)
	for _, s := range ss {
		ch <- s
	}

	start := time.Now()
	io0, err := CollectDataStreams(ch, n, 100*time.Millisecond, nil)
	elapsed := time.Since(start)

	assert.Nil(t, io0)
	require.Error(t, err)
	assert.EqualError(t, err, "timed out waiting for data streams, got 2/3")
	assert.GreaterOrEqual(t, elapsed, 100*time.Millisecond)
	assert.Less(t, elapsed, 5*time.Second)

	// The two streams it did collect must have been closed, not leaked: their
	// peers see a clean EOF.
	for i, s := range cs {
		require.NoError(t, s.SetReadDeadline(time.Now().Add(5*time.Second)))
		_, err := io.ReadAll(s)
		assert.NoError(t, err, "collected stream %d was not closed on timeout", i)
	}
}

func TestCollectDataStreamsReportsAClosedChannel(t *testing.T) {
	tests := []struct {
		name    string
		have    int
		want    int
		wantErr string
	}{
		{"nothing collected", 0, 2, "data stream channel closed, got 0/2"},
		{"partially collected", 1, 3, "data stream channel closed, got 1/3"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newQUICPair(t, nil)
			_, ss := openStreamPairs(t, p, tt.have)
			ch := make(chan *quic.Stream, tt.want)
			for _, s := range ss {
				ch <- s
			}
			close(ch)

			io0, err := CollectDataStreams(ch, tt.want, 5*time.Second, nil)
			assert.Nil(t, io0)
			require.Error(t, err)
			assert.EqualError(t, err, tt.wantErr)
		})
	}
}

// CONFORMANCE GAP (n/a - plain bug): when the data stream channel is closed
// before n streams have arrived, CollectDataStreams returns an error without
// closing the streams it already collected - unlike the timeout path a few
// lines above, which does close them. Those streams stay open until the whole
// QUIC connection goes away. This test pins the current behaviour so a future
// fix is a deliberate change.
func TestCollectDataStreamsLeaksCollectedStreamsWhenTheChannelCloses(t *testing.T) {
	p := newQUICPair(t, nil)
	cs, ss := openStreamPairs(t, p, 1)

	ch := make(chan *quic.Stream, 2)
	ch <- ss[0]
	close(ch)

	_, err := CollectDataStreams(ch, 2, 5*time.Second, nil)
	require.Error(t, err)

	// If the collected stream had been closed, the peer would see EOF. It does
	// not: the read blocks until the deadline instead.
	require.NoError(t, cs[0].SetReadDeadline(time.Now().Add(200*time.Millisecond)))
	buf := make([]byte, 1)
	_, rerr := cs[0].Read(buf)
	require.Error(t, rerr)
	assert.False(t, errors.Is(rerr, io.EOF), "stream was left open, so no FIN arrived")
	var netErr net.Error
	require.True(t, errors.As(rerr, &netErr))
	assert.True(t, netErr.Timeout(), "expected a read timeout, got %v", rerr)
}

func TestCollectDataStreamsZeroStreamsReturnsAnUnusableIO(t *testing.T) {
	// n == 0 makes the loop body unreachable, so CollectDataStreams happily
	// hands back a MultiStreamIO with no streams at all. SendData on it panics
	// (see TestSendDataPanicsWithNoStreams) and no reader ever starts, so
	// ReceiveData blocks forever. No production caller reaches this - the
	// server only calls CollectDataStreams when dataStreams > 0 - but the
	// function does not reject it either.
	ch := make(chan *quic.Stream)
	io0, err := CollectDataStreams(ch, 0, time.Second, nil)
	require.NoError(t, err)
	m, ok := io0.(*MultiStreamIO)
	require.True(t, ok)
	assert.Empty(t, m.streams)
	assert.EqualValues(t, 0, m.activeReaders.Load())
	_, _, gotSomething := tryReceive(io0, 100*time.Millisecond)
	assert.False(t, gotSomething, "an IO with no readers never delivers and never reports EOF")
	assert.NoError(t, io0.Close())
}

// ---------------------------------------------------------------------------
// Fuzzing the length-prefix parser
// ---------------------------------------------------------------------------

// decodeFrames is an independent mirror of the framing loop readLoop
// implements. readLoop takes a concrete *quic.Stream, so it cannot be pointed
// at an arbitrary io.Reader; this mirror lets the framing invariants be fuzzed
// at full speed, and is kept honest against the real thing by
// TestReadLoopDecoderMirrorMatchesReadLoop and FuzzReadLoopFraming, which both
// compare its output to what readLoop actually delivers.
func decodeFrames(r io.Reader) [][]byte {
	var out [][]byte
	hdr := make([]byte, 2)
	for {
		if _, err := io.ReadFull(r, hdr); err != nil {
			return out
		}
		frame := make([]byte, int(binary.BigEndian.Uint16(hdr)))
		if _, err := io.ReadFull(r, frame); err != nil {
			return out
		}
		out = append(out, frame)
	}
}

func FuzzLengthPrefixFraming(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{0x00})
	f.Add([]byte{0x00, 0x00})
	f.Add([]byte{0xFF, 0xFF})
	f.Add([]byte{0xFF, 0xFF, 0x01})
	f.Add(encodeFrames([]byte("abcd")))
	f.Add(encodeFrames([]byte{}, []byte("x"), make([]byte, 300)))
	f.Add(encodeFrames(ipv4TCP("192.0.2.1", "198.51.100.7", 1234, 443)))

	f.Fuzz(func(t *testing.T, wire []byte) {
		frames := decodeFrames(newSlowReader(wire))
		// Whatever came out must be a prefix-consistent re-encoding of the
		// input: decoding is total and never invents data.
		var consumed int
		for _, fr := range frames {
			if consumed+2+len(fr) > len(wire) {
				t.Fatalf("decoder consumed more than it was given")
			}
			if got := int(binary.BigEndian.Uint16(wire[consumed : consumed+2])); got != len(fr) {
				t.Fatalf("frame length mismatch: header says %d, frame is %d", got, len(fr))
			}
			consumed += 2 + len(fr)
		}
		if len(wire)-consumed >= 2 {
			// A whole header plus its payload was left behind only if the
			// payload was short; otherwise the decoder stopped too early.
			want := int(binary.BigEndian.Uint16(wire[consumed : consumed+2]))
			if len(wire)-consumed-2 >= want {
				t.Fatalf("decoder stopped with a complete frame still pending")
			}
		}
		// Re-encoding the decoded frames must reproduce the consumed prefix.
		if got := encodeFrames(frames...); string(got) != string(wire[:consumed]) {
			t.Fatalf("re-encoding did not reproduce the input prefix")
		}
	})
}

// slowReader hands out one octet at a time so io.ReadFull's partial-read path
// is exercised, mimicking a QUIC stream that dribbles data in.
type slowReader struct {
	data []byte
	pos  int
}

func newSlowReader(b []byte) *slowReader { return &slowReader{data: b} }

func (s *slowReader) Read(p []byte) (int, error) {
	if s.pos >= len(s.data) {
		return 0, io.EOF
	}
	if len(p) == 0 {
		return 0, nil
	}
	p[0] = s.data[s.pos]
	s.pos++
	return 1, nil
}

// TestReadLoopDecoderMirrorMatchesReadLoop keeps decodeFrames honest: the same
// byte stream pushed through a real quic.Stream into the real readLoop must
// produce the same frames the mirror produces.
func TestReadLoopDecoderMirrorMatchesReadLoop(t *testing.T) {
	tests := []struct {
		name string
		wire []byte
	}{
		{"empty", nil},
		{"single frame", encodeFrames([]byte("abcd"))},
		{"zero length frame then a real one", encodeFrames([]byte{}, []byte("abcd"))},
		{"several frames", encodeFrames([]byte("a"), make([]byte, 300), []byte("zzz"))},
		{"trailing partial header", append(encodeFrames([]byte("abcd")), 0x00)},
		{"trailing partial payload", append(encodeFrames([]byte("abcd")), 0x00, 0x08, 'q')},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want := decodeFrames(newSlowReader(tt.wire))

			p := newQUICPair(t, nil)
			cs, ss := openStreamPairs(t, p, 1)
			receiver := NewMultiStreamIO(ss, nil)
			t.Cleanup(func() { _ = receiver.Close() })

			if len(tt.wire) > 0 {
				_, err := cs[0].Write(tt.wire)
				require.NoError(t, err)
			}

			var got [][]byte
			for range want {
				frame, err := receiveWithin(t, receiver, 5*time.Second)
				require.NoError(t, err)
				got = append(got, frame)
			}
			_, _, extra := tryReceive(receiver, 100*time.Millisecond)
			require.False(t, extra, "readLoop produced more frames than the mirror")

			require.NoError(t, cs[0].Close())
			_, err := receiveWithin(t, receiver, 5*time.Second)
			require.ErrorIs(t, err, io.EOF)

			require.Len(t, got, len(want))
			for i := range want {
				assert.Equal(t, want[i], got[i], "frame %d", i)
			}
		})
	}
}

// FuzzReadLoopFraming drives the real MultiStreamIO.readLoop over a real QUIC
// stream with arbitrary attacker-controlled bytes. readLoop is the only place
// in this package that parses untrusted input off the wire.
//
// The connection is built once for the whole run; each iteration gets a fresh
// stream pair, so a hostile byte sequence cannot leak into the next case.
func FuzzReadLoopFraming(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{0x00})
	f.Add([]byte{0x00, 0x00})
	f.Add([]byte{0xFF, 0xFF})
	f.Add([]byte{0xFF, 0xFF, 0x01})
	f.Add([]byte{0x00, 0x01})
	f.Add(encodeFrames([]byte("abcd")))
	f.Add(encodeFrames([]byte{}, []byte{}, []byte{}))
	f.Add(encodeFrames([]byte("a"), make([]byte, 300), []byte("zzz")))
	f.Add(encodeFrames(ipv4TCP("192.0.2.1", "198.51.100.7", 1234, 443)))

	p := newQUICPair(f, &quic.Config{
		MaxIdleTimeout:                 5 * time.Minute,
		KeepAlivePeriod:                5 * time.Second,
		MaxIncomingStreams:             1 << 20,
		MaxIncomingUniStreams:          0,
		InitialConnectionReceiveWindow: 16 << 20,
		MaxConnectionReceiveWindow:     16 << 20,
	})

	f.Fuzz(func(t *testing.T, wire []byte) {
		// Reject inputs too large to write in one go; they say nothing new
		// about the framing and only slow the fuzzer down.
		if len(wire) > 1<<14 {
			t.Skip()
		}
		want := decodeFrames(newSlowReader(wire))

		cs, ss := openStreamPairs(t, p, 1)
		receiver := NewMultiStreamIO(ss, nil)
		defer func() {
			_ = receiver.Close()
			// Close() only shuts the send side. Reset the receive side too so
			// any bytes readLoop never consumed stop counting against the
			// connection-level flow control window, which is shared by every
			// iteration.
			ss[0].CancelRead(0)
			cs[0].CancelWrite(0)
		}()

		if len(wire) > 0 {
			if _, err := cs[0].Write(wire); err != nil {
				t.Fatalf("write: %v", err)
			}
		}
		if err := cs[0].Close(); err != nil {
			t.Fatalf("close: %v", err)
		}

		// Everything readLoop does deliver must match the reference decoder, in
		// order. It may stop early: once the stream ends, activeReaders drops
		// to zero and ReceiveData races the remaining buffered frames against
		// io.EOF (pinned by
		// TestReceiveDataAfterCloseWithBufferedFramesIsNondeterministic),
		// so a short read is expected rather than a failure.
		for i := range want {
			frame, err := receiveWithin(t, receiver, 30*time.Second)
			if err != nil {
				if !errors.Is(err, io.EOF) {
					t.Fatalf("frame %d: unexpected error %v", i, err)
				}
				return
			}
			if string(frame) != string(want[i]) {
				t.Fatalf("frame %d: readLoop produced %x, reference decoder produced %x", i, frame, want[i])
			}
		}
	})
}

// newDelayedQUICPair is newQUICPair with a fixed round trip inserted between the
// two ends.
//
// Loopback is not a neutral place to test anything that reasons in round trips:
// there the round trip is microseconds, so every RTT-derived window collapses to
// its constant floor and orderings that are marginal on a real path are decided
// by a factor of a thousand. Path MTU discovery is exactly such a thing -- it
// probes once every five smoothed round trips -- and the bug this exists to
// catch was invisible on loopback for that reason alone, while being certain on
// any path with a WAN latency.
//
// The relay forwards each direction through a single goroutine that holds a
// packet for half the round trip. One goroutine per direction rather than one
// per packet, so a constant delay cannot reorder them.
func newDelayedQUICPair(t testing.TB, conf *quic.Config, rtt time.Duration) *quicPair {
	t.Helper()
	serverTLS, clientTLS := testTLSConfigs(t)
	conf = withQlog(conf)

	serverConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	relayConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	// The relay's own socket towards the server, so that replies are addressed
	// back to something it is reading from.
	upstreamConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)

	ln, err := quic.Listen(serverConn, serverTLS, conf)
	require.NoError(t, err)

	done := make(chan struct{})
	t.Cleanup(func() {
		close(done)
		_ = ln.Close()
		_ = serverConn.Close()
		_ = relayConn.Close()
		_ = upstreamConn.Close()
	})

	type packet struct {
		b    []byte
		when time.Time
	}
	// Buffered well past the number of packets a handshake and an MTU ladder put
	// in flight, so that the relay never blocks a reader and turns a latency
	// simulation into a loss simulation.
	toServer := make(chan packet, 1024)
	toClient := make(chan packet, 1024)

	var clientAddrMu sync.Mutex
	var clientAddr *net.UDPAddr

	forward := func(in chan packet, send func([]byte)) {
		for {
			select {
			case <-done:
				return
			case p := <-in:
				if d := time.Until(p.when); d > 0 {
					select {
					case <-time.After(d):
					case <-done:
						return
					}
				}
				send(p.b)
			}
		}
	}
	read := func(pc *net.UDPConn, out chan packet, note func(*net.UDPAddr)) {
		buf := make([]byte, 2048)
		for {
			n, addr, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if note != nil {
				note(addr)
			}
			b := make([]byte, n)
			copy(b, buf[:n])
			select {
			case out <- packet{b: b, when: time.Now().Add(rtt / 2)}:
			default: // full: drop, exactly as a saturated path would
			}
		}
	}

	go read(relayConn, toServer, func(addr *net.UDPAddr) {
		clientAddrMu.Lock()
		clientAddr = addr
		clientAddrMu.Unlock()
	})
	go read(upstreamConn, toClient, nil)
	go forward(toServer, func(b []byte) {
		_, _ = upstreamConn.WriteToUDP(b, serverConn.LocalAddr().(*net.UDPAddr))
	})
	go forward(toClient, func(b []byte) {
		clientAddrMu.Lock()
		addr := clientAddr
		clientAddrMu.Unlock()
		if addr != nil {
			_, _ = relayConn.WriteToUDP(b, addr)
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	type acceptResult struct {
		conn *quic.Conn
		err  error
	}
	acceptCh := make(chan acceptResult, 1)
	go func() {
		c, err := ln.Accept(ctx)
		acceptCh <- acceptResult{c, err}
	}()

	clientConn, err := quic.DialAddr(ctx, relayConn.LocalAddr().String(), clientTLS, conf)
	require.NoError(t, err)
	res := <-acceptCh
	require.NoError(t, res.err)

	t.Cleanup(func() {
		_ = clientConn.CloseWithError(0, "")
		_ = res.conn.CloseWithError(0, "")
	})
	return &quicPair{client: clientConn, server: res.conn}
}
