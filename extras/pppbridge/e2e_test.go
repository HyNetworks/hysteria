package pppbridge

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apernet/hysteria/core/v2/ppp"
	"github.com/apernet/hysteria/extras/v2/l2tp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

// Whole PPP lifecycles, client to remote, with nothing faked between the ends
// that matters.
//
// The refactor's central claim is that there is one path: every PPP frame -- LCP,
// authentication, IPCP, user data -- travels over ppp.PPPDataIO, and the control
// stream carries only the session handshake and, at the end, one SessionReason.
// The regression that motivated it is the reason this file exists at all: the
// LAC used to negotiate LCP on the CONTROL stream while the client sent
// everything on the DATA transport, so the two halves never met and L2TP mode
// was dead on arrival. Nothing short of running both ends against each other
// catches that, because each half is individually self-consistent.
//
// So these tests wire a real client Bridge to a real server through a paired
// in-memory PPPDataIO, with a scripted pppd on the client's stdio, and walk the
// lifecycle asserting the ORDER of the transitions rather than just the
// endpoints.
//
// What is real and what is not:
//   - L2TP mode runs the actual L2TPPPPHandler, the actual l2tp.TunnelManager
//     and a fake LNS speaking RFC 2661 over a loopback UDP socket.
//   - Local mode runs the same Bridge the server uses, in NoSpawn mode against a
//     scripted pppd, because ServerPPPHandler's only other job is to spawn a real
//     pppd binary and build its argv -- which TestBuildPPPDArgs covers, and which
//     cannot run in a test. Everything below the argv is this same Bridge.

// ---------------------------------------------------------------------------
// A scripted pppd
// ---------------------------------------------------------------------------

// scriptedPPPD stands in for a pppd on the far side of a bridge's stdio. It
// speaks HDLC, because that is what pppd speaks and what hdlcEndpoint expects,
// and it is driven a frame at a time so a test reads as a transcript.
type scriptedPPPD struct {
	t          *testing.T
	toBridge   *os.File
	fromBridge *os.File
	buf        []byte
}

// newScriptedPPPD returns the fake pppd and the two halves the Bridge takes as
// its stdin and stdout.
func newScriptedPPPD(t *testing.T) (*scriptedPPPD, io.ReadCloser, io.WriteCloser) {
	t.Helper()
	childR, testW, err := os.Pipe()
	require.NoError(t, err)
	testR, childW, err := os.Pipe()
	require.NoError(t, err)

	p := &scriptedPPPD{t: t, toBridge: testW, fromBridge: testR}
	t.Cleanup(func() {
		_ = testW.Close()
		_ = testR.Close()
	})
	return p, childR, childW
}

// send writes a raw PPP frame the way pppd would.
func (p *scriptedPPPD) send(rawPPP []byte) {
	p.t.Helper()
	_, err := p.toBridge.Write(EncodeHDLC(rawPPP))
	require.NoError(p.t, err)
}

// sendPacket is send for a protocol and payload.
func (p *scriptedPPPD) sendPacket(proto uint16, payload []byte) {
	p.t.Helper()
	p.send(buildPPPFrame(proto, payload))
}

// recv returns the next raw PPP frame the bridge wrote toward pppd.
func (p *scriptedPPPD) recv() []byte {
	p.t.Helper()
	return p.recvBefore(time.Now().Add(testTimeout))
}

func (p *scriptedPPPD) recvBefore(deadline time.Time) []byte {
	p.t.Helper()
	readBuf := make([]byte, 16384)
	for {
		if frame, rest, ok := extractHDLCFrame(p.buf); ok {
			p.buf = rest
			raw, err := DecodeHDLC(frame)
			if err != nil {
				continue
			}
			return raw
		}
		require.NoError(p.t, p.fromBridge.SetReadDeadline(deadline))
		n, err := p.fromBridge.Read(readBuf)
		require.NoError(p.t, err, "timed out waiting for a frame from the bridge")
		p.buf = append(p.buf, readBuf[:n]...)
	}
}

// recvPacket is recv, split into protocol and payload.
func (p *scriptedPPPD) recvPacket() (uint16, []byte) {
	p.t.Helper()
	return parsePPPFrame(p.recv())
}

// assertSilent fails if anything reaches pppd within a short window.
func (p *scriptedPPPD) assertSilent(why string) {
	p.t.Helper()
	require.NoError(p.t, p.fromBridge.SetReadDeadline(time.Now().Add(250*time.Millisecond)))
	readBuf := make([]byte, 4096)
	n, err := p.fromBridge.Read(readBuf)
	if n > 0 {
		p.t.Fatalf("%s, but %d bytes reached pppd: %x", why, n, readBuf[:n])
	}
	var ne interface{ Timeout() bool }
	require.Truef(p.t, errors.As(err, &ne) && ne.Timeout(),
		"%s: expected the child pipe to stay idle, got n=%d err=%v", why, n, err)
	require.NoError(p.t, p.fromBridge.SetReadDeadline(time.Time{}))
}

// ---------------------------------------------------------------------------
// An ordered transcript
// ---------------------------------------------------------------------------

// journal records the transitions a test walks through, so the assertion at the
// end is about the sequence rather than about whichever endpoint happened to be
// checked last.
type journal struct {
	mu sync.Mutex
	ev []string
}

func (j *journal) note(format string, args ...any) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.ev = append(j.ev, fmt.Sprintf(format, args...))
}

func (j *journal) events() []string {
	j.mu.Lock()
	defer j.mu.Unlock()
	return append([]string(nil), j.ev...)
}

// recordingConn keeps a copy of everything read from a control stream, so a test
// can inspect the SessionReason the bridge consumed without competing with it
// for the bytes.
type recordingConn struct {
	net.Conn
	mu   sync.Mutex
	seen bytes.Buffer
}

func (c *recordingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.mu.Lock()
		c.seen.Write(p[:n])
		c.mu.Unlock()
	}
	return n, err
}

func (c *recordingConn) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.seen.Reset()
}

func (c *recordingConn) snapshot() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.seen.Bytes()...)
}

// awaitReason waits for a complete SessionReason to appear on the stream. A
// partial read never parses -- the message length is checked with io.ReadFull --
// so polling for a successful decode is safe.
func (c *recordingConn) awaitReason(t *testing.T) SessionReason {
	t.Helper()
	deadline := time.Now().Add(testTimeout)
	for {
		if r, err := ReadSessionReason(bytes.NewReader(c.snapshot())); err == nil {
			return r
		}
		if time.Now().After(deadline) {
			t.Fatalf("no session reason arrived on the control stream (saw %x)", c.snapshot())
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// ---------------------------------------------------------------------------
// Local mode: two bridges, one paired transport
// ---------------------------------------------------------------------------

type localHarness struct {
	client *scriptedPPPD
	server *scriptedPPPD

	clientBridge *Bridge
	serverBridge *Bridge

	pair *framePair
	// toServer and toClient record every frame that crossed, in order, so a test
	// can assert that what arrived is byte-identical to what left.
	toServer, toClient *frameTap

	// clientCtl and serverCtl count what each Bridge wrote to its control stream,
	// which after the handshake must be nothing at all.
	clientCtl, serverCtl *writeCountingConn

	// clientLogs captures the client Bridge's logging. Some of its decisions --
	// the probe teardown above all -- currently have no other observable effect,
	// because Run swallows its own return value (see
	// TestBridgeRunSwallowsTheSessionReasonInsteadOfReturningLinkDownError).
	clientLogs *observer.ObservedLogs

	events *journal

	clientDone chan struct{}
	clientErr  error
	serverDone chan struct{}
}

// frameTap records frames as they are handed to a transport.
type frameTap struct {
	mu sync.Mutex
	f  [][]byte
}

func (t *frameTap) add(b []byte) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.f = append(t.f, b)
}

func (t *frameTap) frames() [][]byte {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([][]byte(nil), t.f...)
}

type localOpt func(*localCfg)

type localCfg struct {
	// clientLimit, when positive, is the per-frame ceiling on the client's
	// transport, so oversize handling can be driven end to end.
	clientLimit int

	// probeCeiling, when positive, makes the client's transport report a ceiling,
	// which is what turns its MTU probe loop on, and shortens the probe schedule
	// so the teardown decision happens in milliseconds.
	probeCeiling int

	// serverSwallowsProbes makes the server end drop probe requests before its
	// relay can answer them: a path that has stopped carrying full-size frames,
	// seen from the client.
	serverSwallowsProbes bool
}

func withClientFrameLimit(limit int) localOpt {
	return func(c *localCfg) { c.clientLimit = limit }
}

// withBlackHoledProbes makes the client probe at ceiling and the server swallow
// every probe, which is exactly what a path that narrowed after the MTU was
// agreed looks like.
func withBlackHoledProbes(ceiling int) localOpt {
	return func(c *localCfg) {
		c.probeCeiling = ceiling
		c.serverSwallowsProbes = true
	}
}

func newLocalHarness(t *testing.T, opts ...localOpt) *localHarness {
	t.Helper()
	var cfg localCfg
	for _, o := range opts {
		o(&cfg)
	}

	clientPPPD, clientIn, clientOut := newScriptedPPPD(t)
	serverPPPD, serverIn, serverOut := newScriptedPPPD(t)

	pair := newFramePair(64)
	clientData, serverData := pair.ends()
	clientData.limit = cfg.clientLimit
	serverData.dropProbeRequests = cfg.serverSwallowsProbes

	h := &localHarness{
		client:     clientPPPD,
		server:     serverPPPD,
		pair:       pair,
		toServer:   &frameTap{},
		toClient:   &frameTap{},
		events:     &journal{},
		clientDone: make(chan struct{}),
		serverDone: make(chan struct{}),
	}
	clientData.tap = h.toServer.add
	serverData.tap = h.toClient.add

	rawClientCtl, rawServerCtl := net.Pipe()
	h.clientCtl = &writeCountingConn{Conn: rawClientCtl}
	h.serverCtl = &writeCountingConn{Conn: rawServerCtl}

	core, logs := observer.New(zap.DebugLevel)
	h.clientLogs = logs
	h.clientBridge = &Bridge{NoSpawn: true, ReadReason: true, Logger: zap.New(core), In: clientIn, Out: clientOut}
	h.serverBridge = &Bridge{NoSpawn: true, Logger: zap.NewNop(), In: serverIn, Out: serverOut}

	var clientTransport ppp.PPPDataIO = clientData
	if cfg.probeCeiling > 0 {
		clientData.limit = cfg.probeCeiling
		clientTransport = sizedDataIO{clientData}
		h.clientBridge.ProbeInterval = 40 * time.Millisecond
		h.clientBridge.ProbeGrace = 10 * time.Millisecond
		h.clientBridge.ProbeFailures = 2
	}

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		defer close(h.serverDone)
		// Exactly what ServerPPPHandler.HandlePPP does once it has an IP and a
		// data transport: hand the already-open control stream and transport to a
		// Bridge through a one-shot dial.
		var dialed atomic.Bool
		_ = h.serverBridge.Run(ctx, func() (io.ReadWriteCloser, ppp.PPPDataIO, func(), error) {
			if !dialed.CompareAndSwap(false, true) {
				return nil, nil, nil, permanentDialError{errors.New("one-shot")}
			}
			return h.serverCtl, serverData, func() {}, nil
		})
	}()

	go func() {
		defer close(h.clientDone)
		var dialed atomic.Bool
		h.clientErr = h.clientBridge.Run(ctx, func() (io.ReadWriteCloser, ppp.PPPDataIO, func(), error) {
			if !dialed.CompareAndSwap(false, true) {
				return nil, nil, nil, permanentDialError{errors.New("one-shot")}
			}
			return h.clientCtl, clientTransport, func() {}, nil
		})
	}()

	t.Cleanup(func() {
		cancel()
		pair.shutdown()
		_ = rawClientCtl.Close()
		_ = rawServerCtl.Close()
		for _, done := range []chan struct{}{h.clientDone, h.serverDone} {
			select {
			case <-done:
			case <-time.After(testTimeout):
				t.Error("a Bridge.Run did not return")
			}
		}
	})
	return h
}

// bringUp gets both bridges past the frame that triggers their dial. Each side's
// pppd opens with an LCP Configure-Request, which is what a real pppd does and
// what makes the bridge establish its session.
func (h *localHarness) bringUp(t *testing.T) {
	t.Helper()
	h.server.sendPacket(pppProtoLCP, buildLCPPacket(lcpConfigRequest, 0x80, serverLCPOpts))
	h.client.sendPacket(pppProtoLCP, buildLCPPacket(lcpConfigRequest, 0x01, clientLCPOpts))
}

// relayed sends a frame from one pppd and requires it to arrive, unchanged, at
// the other, noting the transition.
func (h *localHarness) relayed(t *testing.T, from, to *scriptedPPPD, label string, rawPPP []byte) {
	t.Helper()
	from.send(rawPPP)
	got := to.recv()
	require.Equalf(t, rawPPP, got, "%s did not arrive byte-identical", label)
	h.events.note("%s", label)
}

var (
	clientLCPOpts = []byte{lcpOptMRU, 4, 0x05, 0x78, lcpOptMagicNumber, 6, 0x11, 0x22, 0x33, 0x44}
	serverLCPOpts = []byte{lcpOptMRU, 4, 0x05, 0x78, lcpOptMagicNumber, 6, 0xAA, 0xBB, 0xCC, 0xDD}
)

// ---------------------------------------------------------------------------
// 1. Local mode, full session
// ---------------------------------------------------------------------------

// A complete PPP lifecycle across a real client Bridge and a real server-side
// Bridge: LCP up, IPCP up, user data both ways, LCP down. Every frame is
// asserted byte-identical at the far end and the transitions are asserted in
// order, because "the frames arrived" and "the frames arrived in the order the
// state machine needs" are different claims and only the second one is a working
// PPP link.
func TestLocalModeFullSessionLifecycle(t *testing.T) {
	h := newLocalHarness(t)
	h.bringUp(t)

	// --- LCP ---
	// Each side's opening Configure-Request is the frame that brought its own
	// bridge up, so both are already in flight; collect them in order.
	proto, pkt := h.server.recvPacket()
	require.Equal(t, pppProtoLCP, proto)
	require.Equal(t, lcpConfigRequest, pkt[0], "the client's opening frame must reach the server")
	require.Equal(t, clientLCPOpts, pkt[4:], "and it must arrive unmodified")
	h.events.note("client -> server: LCP Configure-Request")

	proto, pkt = h.client.recvPacket()
	require.Equal(t, pppProtoLCP, proto)
	require.Equal(t, lcpConfigRequest, pkt[0])
	require.Equal(t, serverLCPOpts, pkt[4:])
	h.events.note("server -> client: LCP Configure-Request")

	h.relayed(t, h.server, h.client, "server -> client: LCP Configure-Ack",
		buildPPPFrame(pppProtoLCP, buildLCPPacket(lcpConfigAck, 0x01, clientLCPOpts)))
	h.relayed(t, h.client, h.server, "client -> server: LCP Configure-Ack",
		buildPPPFrame(pppProtoLCP, buildLCPPacket(lcpConfigAck, 0x80, serverLCPOpts)))

	// --- IPCP ---
	clientIP := []byte{0x03, 0x06, 10, 0, 0, 2} // IP-Address option
	serverIP := []byte{0x03, 0x06, 10, 0, 0, 1}
	h.relayed(t, h.client, h.server, "client -> server: IPCP Configure-Request",
		buildPPPFrame(pppProtoIPCP, buildLCPPacket(lcpConfigRequest, 0x11, clientIP)))
	h.relayed(t, h.server, h.client, "server -> client: IPCP Configure-Ack",
		buildPPPFrame(pppProtoIPCP, buildLCPPacket(lcpConfigAck, 0x11, clientIP)))
	h.relayed(t, h.server, h.client, "server -> client: IPCP Configure-Request",
		buildPPPFrame(pppProtoIPCP, buildLCPPacket(lcpConfigRequest, 0x12, serverIP)))
	h.relayed(t, h.client, h.server, "client -> server: IPCP Configure-Ack",
		buildPPPFrame(pppProtoIPCP, buildLCPPacket(lcpConfigAck, 0x12, serverIP)))

	// --- user data, both directions ---
	up := buildPPPFrame(pppProtoIPv4, bytes.Repeat([]byte{0xA1}, 200))
	down := buildPPPFrame(pppProtoIPv4, bytes.Repeat([]byte{0xB2}, 400))
	h.relayed(t, h.client, h.server, "client -> server: IPv4", up)
	h.relayed(t, h.server, h.client, "server -> client: IPv4", down)

	// --- LCP down ---
	h.relayed(t, h.client, h.server, "client -> server: LCP Terminate-Request",
		buildPPPFrame(pppProtoLCP, buildLCPPacket(lcpTermRequest, 0x20, nil)))
	h.relayed(t, h.server, h.client, "server -> client: LCP Terminate-Ack",
		buildPPPFrame(pppProtoLCP, buildLCPPacket(lcpTermAck, 0x20, nil)))

	assert.Equal(t, []string{
		"client -> server: LCP Configure-Request",
		"server -> client: LCP Configure-Request",
		"server -> client: LCP Configure-Ack",
		"client -> server: LCP Configure-Ack",
		"client -> server: IPCP Configure-Request",
		"server -> client: IPCP Configure-Ack",
		"server -> client: IPCP Configure-Request",
		"client -> server: IPCP Configure-Ack",
		"client -> server: IPv4",
		"server -> client: IPv4",
		"client -> server: LCP Terminate-Request",
		"server -> client: LCP Terminate-Ack",
	}, h.events.events(), "the lifecycle must proceed in this order")

	// The journal above is the test's own view of the walk. The taps are the
	// wire's: every frame that actually crossed each direction of the transport,
	// in the order it crossed, recorded by the transport rather than by the
	// assertions. A stage skipped, duplicated, reordered or invented shows up
	// here even though each individual hop was verified as it happened.
	assert.Equal(t, [][]byte{
		buildPPPFrame(pppProtoLCP, buildLCPPacket(lcpConfigRequest, 0x01, clientLCPOpts)),
		buildPPPFrame(pppProtoLCP, buildLCPPacket(lcpConfigAck, 0x80, serverLCPOpts)),
		buildPPPFrame(pppProtoIPCP, buildLCPPacket(lcpConfigRequest, 0x11, clientIP)),
		buildPPPFrame(pppProtoIPCP, buildLCPPacket(lcpConfigAck, 0x12, serverIP)),
		up,
		buildPPPFrame(pppProtoLCP, buildLCPPacket(lcpTermRequest, 0x20, nil)),
	}, h.toServer.frames(), "the client-to-server transcript, as the transport saw it")

	assert.Equal(t, [][]byte{
		buildPPPFrame(pppProtoLCP, buildLCPPacket(lcpConfigRequest, 0x80, serverLCPOpts)),
		buildPPPFrame(pppProtoLCP, buildLCPPacket(lcpConfigAck, 0x01, clientLCPOpts)),
		buildPPPFrame(pppProtoIPCP, buildLCPPacket(lcpConfigAck, 0x11, clientIP)),
		buildPPPFrame(pppProtoIPCP, buildLCPPacket(lcpConfigRequest, 0x12, serverIP)),
		down,
		buildPPPFrame(pppProtoLCP, buildLCPPacket(lcpTermAck, 0x20, nil)),
	}, h.toClient.frames(), "the server-to-client transcript, as the transport saw it")

	// 7. A PPP-layer teardown is not a link event: the transport is untouched and
	// still carries traffic afterwards.
	select {
	case <-h.clientDone:
		t.Fatal("LCP Terminate must not bring the Hysteria2 link down")
	case <-time.After(200 * time.Millisecond):
	}
	h.relayed(t, h.client, h.server, "client -> server: IPv4 after terminate",
		buildPPPFrame(pppProtoIPv4, []byte{0xCC}))
}

// Every frame that crossed did so on the data transport, and nothing at all was
// written to the control stream after the handshake. This is the invariant the
// old control/data split violated, stated directly.
func TestLocalModeEveryFrameTakesTheDataTransport(t *testing.T) {
	h := newLocalHarness(t)
	h.bringUp(t)

	// One frame of each class the old classifier would have split on.
	frames := [][]byte{
		buildPPPFrame(pppProtoLCP, buildLCPPacket(lcpConfigAck, 0x80, serverLCPOpts)),
		buildPPPFrame(pppProtoCHAP, []byte{chapResponse, 0x01, 0x00, 0x04}),
		buildPPPFrame(pppProtoIPCP, buildLCPPacket(lcpConfigRequest, 0x11, nil)),
		buildPPPFrame(pppProtoIPv4, []byte{0x45, 0x00}),
		buildPPPFrame(pppProtoIPv6, []byte{0x60, 0x00}),   // IPv6
		buildPPPFrame(pppProtoMPFrag, []byte{0xC0, 0x01}), // multilink fragment
		buildPPPFrame(pppProtoLCP, []byte{lcpEchoRequest, 0x02, 0x00, 0x04}),
	}

	// The opening Configure-Requests are already on the wire from bringUp.
	require.Equal(t, lcpConfigRequest, h.server.recv()[4], "the dial-triggering frame is carried")
	_ = h.client.recv()

	for _, f := range frames {
		h.client.send(f)
		require.Equal(t, f, h.server.recv())
	}

	// Every one of them appears on the client-to-server tap, in order, and
	// nothing else did.
	sent := h.toServer.frames()
	require.Len(t, sent, 1+len(frames))
	assert.Equal(t, frames, sent[1:],
		"a frame's protocol number must not be able to change its path")

	// And nothing at all went the other way -- onto the control stream. Neither
	// Bridge writes to it after the handshake; the server writes one closing
	// SessionReason and that is all it is for.
	assert.Empty(t, h.clientCtl.wrote(),
		"the client must write nothing to the control stream after the handshake")
	assert.Empty(t, h.serverCtl.wrote(),
		"and nor may the server, until it has a reason to report")
}

// ---------------------------------------------------------------------------
// 7. Link drop
// ---------------------------------------------------------------------------

// The Hysteria2 connection IS the link. When it goes, it takes the PPP session
// with it at both ends, and neither side tries to rebuild underneath a live
// pppd: the server releases the address the moment the connection drops, so a
// client holding its old PPP state would be using an address that has already
// been reassigned.
//
// Note what is NOT asserted here: that Run returns *LinkDownError. It does not
// -- see TestBridgeRunSwallowsTheSessionReasonInsteadOfReturningLinkDownError,
// which pins why.
func TestLocalModeLinkDropMidSessionEndsBothSides(t *testing.T) {
	h := newLocalHarness(t)
	h.bringUp(t)

	require.Equal(t, lcpConfigRequest, h.server.recv()[4])
	_ = h.client.recv()
	h.relayed(t, h.client, h.server, "client -> server: IPv4",
		buildPPPFrame(pppProtoIPv4, []byte{0x45, 0x00}))

	// The connection goes away underneath both bridges.
	h.pair.shutdown()

	for _, tc := range []struct {
		name string
		done chan struct{}
	}{
		{"client", h.clientDone},
		{"server", h.serverDone},
	} {
		select {
		case <-tc.done:
		case <-time.After(testTimeout):
			t.Fatalf("%s Bridge.Run did not return after the link dropped", tc.name)
		}
	}

	// Both children were released, which is what gives a real pppd its SIGHUP.
	_, err := h.client.toBridge.Write(EncodeHDLC(frameIPv4))
	assert.Error(t, err, "the client bridge must close its side of the child pipe")

	// The caller is told the link went down, which is what it needs to decide
	// whether rebuilding is worth attempting.
	var linkDown *LinkDownError
	require.ErrorAs(t, h.clientErr, &linkDown)
	assert.Equal(t, ReasonLinkDown, linkDown.Reason.Code)
	assert.False(t, linkDown.Reason.Code.Permanent(), "a dropped link is retryable")
}

// ---------------------------------------------------------------------------
// 5. Oversize frames, end to end
// ---------------------------------------------------------------------------

// A transport that refuses a frame for being too large costs that frame and
// nothing else: the counter rises, smaller frames keep flowing in both
// directions, and the session stays up. Tearing down instead would turn one
// oversized download into a full PPP renegotiation.
func TestOversizeFramesAreDroppedAndCountedWhileTheSessionSurvives(t *testing.T) {
	const limit = 300
	h := newLocalHarness(t, withClientFrameLimit(limit))
	h.bringUp(t)

	require.Equal(t, lcpConfigRequest, h.server.recv()[4])
	_ = h.client.recv()
	require.Zero(t, h.clientBridge.OversizeDropped())

	small := buildPPPFrame(pppProtoIPv4, bytes.Repeat([]byte{0x11}, 32))
	big := buildPPPFrame(pppProtoIPv4, bytes.Repeat([]byte{0x22}, limit))

	for round := 1; round <= 3; round++ {
		h.client.send(big)
		h.client.send(small)
		// The relay's endpoint pump is sequential, so once the small frame has
		// arrived the big one before it has already been decided.
		require.Equalf(t, small, h.server.recv(),
			"round %d: a frame that fits must still get through after an oversized one", round)
		assert.Equalf(t, uint64(round), h.clientBridge.OversizeDropped(),
			"round %d: the oversized frame must be counted", round)
	}

	// The oversized frames never reached the far side.
	for _, f := range h.toServer.frames() {
		assert.LessOrEqual(t, len(f), limit, "an oversized frame was forwarded after all")
	}

	// The session is alive in both directions.
	select {
	case <-h.clientDone:
		t.Fatal("an oversized frame must not end the session")
	default:
	}
	h.relayed(t, h.server, h.client, "server -> client: IPv4",
		buildPPPFrame(pppProtoIPv4, bytes.Repeat([]byte{0x33}, 64)))
}

// ---------------------------------------------------------------------------
// 6a. MTU probes, local mode
// ---------------------------------------------------------------------------

// A probe crossing a live session is answered by the peer's relay and is
// invisible at both ends: the server's pppd never sees the request and the
// client's pppd never sees the reply. Protocol 0x4001 is not something pppd
// understands, and a full-size frame of padding delivered as PPP would at best
// be rejected and at worst counted as a protocol error against the link.
func TestLocalModeMTUProbesAreConsumedByThePeerAndNeverReachPPPD(t *testing.T) {
	h := newLocalHarness(t)
	h.bringUp(t)

	require.Equal(t, lcpConfigRequest, h.server.recv()[4])
	_ = h.client.recv()

	h.client.send(buildMTUProbe(mtuProbeRequest, 77, 1200))

	// The server's relay answers it; the reply crosses back and the client's
	// relay consumes it.
	deadline := time.Now().Add(testTimeout)
	var reply []byte
	for reply == nil && time.Now().Before(deadline) {
		for _, f := range h.toClient.frames() {
			if kind, seq, ok := parseMTUProbe(f); ok && kind == mtuProbeReply && seq == 77 {
				reply = f
			}
		}
		time.Sleep(2 * time.Millisecond)
	}
	require.NotNil(t, reply, "the peer must answer a probe request")
	assert.Len(t, reply, mtuProbeHeaderLen,
		"the reply is small on purpose: what is being established is that the big one arrived")

	h.server.assertSilent("a probe request is consumed by the peer's relay")
	h.client.assertSilent("a probe reply is bookkeeping, not traffic")

	// And the session is undisturbed.
	h.relayed(t, h.client, h.server, "client -> server: IPv4 after a probe",
		buildPPPFrame(pppProtoIPv4, []byte{0x45, 0x00}))
}

// ---------------------------------------------------------------------------
// 6b. Unanswered probes
// ---------------------------------------------------------------------------

// A path that stops carrying full-size frames is invisible to everything else in
// the stack -- quic-go never lowers its MTU estimate, and LCP Echo is small
// enough to keep getting through -- so unanswered probes are the only signal.
//
// This is the whole decision end to end: a real client Bridge with a live PPP
// session, a peer that stops answering full-size frames, and the session torn
// down so it can be rebuilt at the smaller size. Nothing here calls the relay
// directly; the only thing arranged is that probes go into a hole.
func TestBlackHoledProbesEndTheSessionEndToEnd(t *testing.T) {
	h := newLocalHarness(t, withBlackHoledProbes(1400))
	h.bringUp(t)

	require.Equal(t, lcpConfigRequest, h.server.recv()[4])
	_ = h.client.recv()

	// Small frames keep flowing, which is the point: nothing but the probe loop
	// can see this path narrowing.
	h.relayed(t, h.client, h.server, "client -> server: IPv4",
		buildPPPFrame(pppProtoIPv4, []byte{0x45, 0x00}))

	select {
	case <-h.clientDone:
	case <-time.After(testTimeout):
		t.Fatal("a path that stopped carrying full-size frames must end the client's session")
	}

	// It ended for that reason and not by accident: the teardown is the probe
	// loop's, and it happened after several probes went unanswered rather than on
	// the first one.
	const teardownMsg = "path no longer carries the negotiated MTU, tearing down the session " +
		"so it can be rebuilt at the smaller size"
	assert.Positive(t, h.clientLogs.FilterMessage(teardownMsg).Len(),
		"the probe loop must be what tore the session down")
	assert.GreaterOrEqual(t, h.clientLogs.FilterMessage("full-size MTU probe unanswered").Len(), 2,
		"a single lost probe must never be enough; datagrams are lossy by design")

	var probes int
	for _, f := range h.toServer.frames() {
		if kind, _, ok := parseMTUProbe(f); ok && kind == mtuProbeRequest {
			probes++
		}
	}
	assert.GreaterOrEqual(t, probes, 2, "the client must actually have probed")

	// The child is released, which is what gives a real pppd its SIGHUP.
	_, err := h.client.toBridge.Write(EncodeHDLC(frameIPv4))
	assert.Error(t, err, "the client bridge must close its side of the child pipe")

	// ReasonPathNarrowed is the one code that tells a caller to rebuild at a
	// smaller size rather than retry as-is.
	var linkDown *LinkDownError
	require.ErrorAs(t, h.clientErr, &linkDown)
	assert.Equal(t, ReasonPathNarrowed, linkDown.Reason.Code)
	assert.NotZero(t, h.clientLogs.FilterMessage("PPP link down").Len(),
		"and it is reported, not just returned")
}

// The relay's half of the same decision, in isolation: the error it reports is
// errPathNarrowed specifically, which is what bridge.go keys the reason code off
// and what must never be mistaken for a droppable frame
// (TestErrPathNarrowedIsASessionFailure).
func TestRelayReportsPathNarrowedWhenProbesGoUnanswered(t *testing.T) {
	pair := newFramePair(64)
	defer pair.shutdown()
	a, b := pair.ends()
	a.limit, b.limit = 1400, 1400

	// A peer that reads everything and answers nothing -- exactly what a bridge
	// on the far side of a narrowed path looks like.
	go func() {
		for {
			if _, err := b.ReceiveData(); err != nil {
				return
			}
		}
	}()

	epPair := newFramePair(8)
	defer epPair.shutdown()
	epNear, _ := epPair.ends()

	r := newRelay(sizedDataIO{a}, &dataIOEndpoint{epNear}, zap.NewNop(), nil)
	r.ProbeInterval, r.ProbeGrace, r.ProbeFailures = 40*time.Millisecond, 10*time.Millisecond, 2

	errCh := make(chan error, 1)
	go func() { errCh <- r.run(context.Background()) }()

	select {
	case err := <-errCh:
		require.ErrorIs(t, err, errPathNarrowed,
			"a path that stopped carrying full-size frames must end the session")
	case <-time.After(testTimeout):
		t.Fatal("the relay did not tear the session down")
	}

	// A narrowed path is worth rebuilding at the smaller size, so the reason it
	// maps to must not stop a caller from trying again.
	assert.False(t, ReasonPathNarrowed.Permanent())
}

// dataIOEndpoint presents a paired transport as an Endpoint, for relay tests
// that care about the transport side and want an endpoint that simply exists.
type dataIOEndpoint struct{ io *pairedDataIO }

func (e *dataIOEndpoint) SendPPP(raw []byte) error { return e.io.SendData(raw) }
func (e *dataIOEndpoint) RecvPPP() ([]byte, error) { return e.io.ReceiveData() }

// ---------------------------------------------------------------------------
// A fake LNS
// ---------------------------------------------------------------------------

const (
	lnsTunnelID  uint16 = 0x2020
	lnsSessionID uint16 = 0x4242
)

// lnsAssignedIDs are the session IDs the fake LNS hands out, one per call.
//
// They are deliberately scattered rather than consecutive. A real LNS picks
// whatever is free, and sequential IDs would let a bug that correlates calls by
// arrival order -- or assumes the LAC's Nth call is the LNS's Nth ID -- pass by
// coincidence. lnsSessionID stays as the first of them so the single-call tests
// keep their familiar value.
var lnsAssignedIDs = []uint16{lnsSessionID, 0x8137, 0x0009, 0xF0A1}

// PPP protocol numbers these tests build frames for. LCP, PAP and CHAP already
// have constants in lac_ppp.go; the network-layer ones do not, because nothing
// in the package routes on them any more.
const (
	pppProtoIPv4   uint16 = 0x0021
	pppProtoIPv6   uint16 = 0x0057
	pppProtoMPFrag uint16 = 0x003D
	pppProtoIPCP   uint16 = 0x8021
)

type lnsDataFrame struct {
	proto   uint16
	payload []byte
	// raw is the L2TP information field exactly as it arrived -- the whole PPP
	// frame, before this fake makes any sense of it. Tests about what the LAC
	// does to a frame have to compare against this rather than the split fields,
	// because the splitting is the fake's own doing.
	raw []byte
	// session is the header's Session field: the ID this LNS assigned, which is
	// how a test with more than one subscriber tells them apart.
	session uint16
}

// fakeLNS is an RFC 2661 LNS on a loopback UDP socket. It answers the tunnel and
// session handshakes on its own and hands everything else to the test.
type fakeLNS struct {
	t    *testing.T
	conn *net.UDPConn
	addr string

	mu           sync.Mutex
	peer         *net.UDPAddr
	ns           uint16
	nr           uint16
	lacTunnelID  uint16
	lacSessionID uint16 // the most recent, for the single-session helpers

	// calls records every session in arrival order, mapping the ID the LAC chose
	// to the distinct one this LNS assigned it. A real LNS multiplexes many calls
	// down one tunnel, and that is where a session mix-up would show.
	calls []lnsCall

	iccn chan []l2tp.AVP
	data chan lnsDataFrame
	seen chan uint16 // message types received, for StopCCN/CDN observation

	// cdnAtICCN, when set, makes the LNS disconnect the session the moment it is
	// connected -- an LNS that read the proxied credentials and did not like them.
	// sccrqs counts tunnel handshakes, so a test can prove that a second call
	// reused the tunnel instead of building another.
	sccrqs atomic.Uint32

	cdnAtICCN atomic.Bool
	cdnResult atomic.Uint32
	cdnError  atomic.Uint32
	cdnMsg    atomic.Value // string

	closed chan struct{}
	once   sync.Once
}

func newFakeLNS(t *testing.T) *fakeLNS {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)

	f := &fakeLNS{
		t:      t,
		conn:   conn,
		addr:   conn.LocalAddr().String(),
		iccn:   make(chan []l2tp.AVP, 4),
		data:   make(chan lnsDataFrame, 64),
		seen:   make(chan uint16, 64),
		closed: make(chan struct{}),
	}
	f.cdnMsg.Store("")
	go f.readLoop()
	t.Cleanup(f.close)
	return f
}

func (f *fakeLNS) close() {
	f.once.Do(func() {
		close(f.closed)
		_ = f.conn.Close()
	})
}

func (f *fakeLNS) readLoop() {
	buf := make([]byte, 4096)
	for {
		n, addr, err := f.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		raw := append([]byte(nil), buf[:n]...)
		f.mu.Lock()
		f.peer = addr
		f.mu.Unlock()

		hdr, off, err := l2tp.DecodeHeader(raw)
		if err != nil || off > n {
			continue
		}
		if !hdr.IsControl {
			if len(raw[off:]) < 2 {
				continue
			}
			frame := append([]byte(nil), raw[off:]...)
			body := frame
			// Some senders include the FF 03 address/control pair.
			if len(body) >= 4 && body[0] == 0xFF && body[1] == 0x03 {
				body = body[2:]
			}
			if len(body) < 2 {
				continue
			}
			select {
			case f.data <- lnsDataFrame{
				proto:   binary.BigEndian.Uint16(body[0:2]),
				payload: append([]byte(nil), body[2:]...),
				raw:     frame,
				session: hdr.Session,
			}:
			default:
			}
			continue
		}
		if off >= n {
			continue // ZLB ack from the LAC
		}
		avps, err := l2tp.DecodeAVPs(raw[off:n])
		if err != nil {
			continue
		}
		msgType, err := l2tp.GetMessageType(avps)
		if err != nil {
			continue
		}
		f.mu.Lock()
		f.nr = hdr.Ns + 1
		f.mu.Unlock()
		select {
		case f.seen <- msgType:
		default:
		}
		f.handle(msgType, hdr, avps)
	}
}

func (f *fakeLNS) handle(msgType uint16, hdr l2tp.Header, avps []l2tp.AVP) {
	switch msgType {
	case l2tp.MsgTypeSCCRQ:
		f.sccrqs.Add(1)
		if tid := l2tp.FindAVP(avps, 0, l2tp.AVPAssignedTunnelID); tid != nil {
			v, _ := l2tp.AVPUint16(tid)
			f.mu.Lock()
			f.lacTunnelID = v
			f.mu.Unlock()
		}
		f.sendControl(0, buildFakeSCCRP())
	case l2tp.MsgTypeSCCCN:
		f.sendZLB()
	case l2tp.MsgTypeICRQ:
		sid := l2tp.FindAVP(avps, 0, l2tp.AVPAssignedSessionID)
		if sid == nil {
			return
		}
		v, _ := l2tp.AVPUint16(sid)
		f.mu.Lock()
		assigned := lnsAssignedIDs[len(f.calls)%len(lnsAssignedIDs)]
		f.calls = append(f.calls, lnsCall{lac: v, lns: assigned})
		f.lacSessionID = v
		f.mu.Unlock()
		f.sendControl(v, buildFakeICRPFor(assigned))
	case l2tp.MsgTypeICCN:
		f.sendZLB()
		select {
		case f.iccn <- avps:
		default:
		}
		if f.cdnAtICCN.Load() {
			f.sendCDN(uint16(f.cdnResult.Load()), uint16(f.cdnError.Load()), f.cdnMsg.Load().(string))
		}
	case l2tp.MsgTypeHello:
		f.sendZLB()
	}
}

// sendCDN disconnects the most recent session with an RFC 2661 s4.4.2 Result
// Code.
func (f *fakeLNS) sendCDN(result, errCode uint16, msg string) {
	f.mu.Lock()
	sid := f.lacSessionID
	f.mu.Unlock()
	f.sendCDNFor(sid, result, errCode, msg)
}

// sendCDNFor disconnects one specific call. The Assigned Session ID AVP carries
// the ID this LNS gave that call -- not a fixed constant -- because that AVP is
// what handleCDN falls back to when a peer leaves the header Session zero, and a
// fake that always names the same call cannot tell a correct fallback from one
// that closes whichever session it happens to find first.
func (f *fakeLNS) sendCDNFor(lacSID, result, errCode uint16, msg string) {
	f.mu.Lock()
	lnsSID := lnsSessionID
	for _, c := range f.calls {
		if c.lac == lacSID {
			lnsSID = c.lns
			break
		}
	}
	f.mu.Unlock()
	f.sendControl(lacSID, l2tp.BuildCDN(lnsSID, result, errCode, msg))
}

// sendBareCDN clears the most recent call with no Result Code AVP at all.
//
// RFC 2661 s4.4.2 makes that AVP mandatory in a CDN, so this is a peer that is
// out of spec -- but one the LAC still has to survive, and one that still told
// it something: the far end hung up on this subscriber, as opposed to the path
// to the far end breaking.
func (f *fakeLNS) sendBareCDN() {
	f.mu.Lock()
	lacSID := f.lacSessionID
	lnsSID := lnsSessionID
	for _, c := range f.calls {
		if c.lac == lacSID {
			lnsSID = c.lns
			break
		}
	}
	f.mu.Unlock()
	payload := append(
		l2tp.EncodeUint16AVP(l2tp.AVPMessageType, l2tp.MsgTypeCDN),
		l2tp.EncodeUint16AVP(l2tp.AVPAssignedSessionID, lnsSID)...,
	)
	f.sendControl(lacSID, payload)
}

// sendStopCCN tears the control connection down, which RFC 2661 s3.3 makes an
// implicit teardown of every session in it -- without saying anything about any
// of their subscribers.
func (f *fakeLNS) sendStopCCN(result, errCode uint16, msg string) {
	f.sendControl(0, l2tp.BuildStopCCN(lnsTunnelID, result, errCode, msg))
}

// sendPPP delivers a PPP frame to the LAC on the session's data channel.
func (f *fakeLNS) sendPPP(proto uint16, payload []byte) {
	f.mu.Lock()
	pkt := l2tp.EncodeDataHeader(f.lacTunnelID, f.lacSessionID)
	f.mu.Unlock()
	pkt = append(pkt, byte(proto>>8), byte(proto))
	pkt = append(pkt, payload...)
	f.write(pkt)
}

// sendPPPTo delivers a frame to one specific call. The data header carries the
// session ID the LAC chose, because that is what the LAC demultiplexes on.
// sendPPPRaw puts an exact PPP frame on the wire, so a test can send a shape
// sendPPP could not build -- one with no address and control octets, or with a
// compressed protocol field.
func (f *fakeLNS) sendPPPRaw(frame []byte) {
	f.mu.Lock()
	pkt := l2tp.EncodeDataHeader(f.lacTunnelID, f.lacSessionID)
	f.mu.Unlock()
	f.write(append(pkt, frame...))
}

func (f *fakeLNS) sendPPPTo(lacSID, proto uint16, payload []byte) {
	f.mu.Lock()
	pkt := l2tp.EncodeDataHeader(f.lacTunnelID, lacSID)
	f.mu.Unlock()
	pkt = append(pkt, byte(proto>>8), byte(proto))
	pkt = append(pkt, payload...)
	f.write(pkt)
}

// call returns the nth session to be set up, in ICRQ order.
func (f *fakeLNS) call(t *testing.T, n int) lnsCall {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	require.Greater(t, len(f.calls), n, "the LNS has only seen %d calls", len(f.calls))
	return f.calls[n]
}

func (f *fakeLNS) sendControl(session uint16, payload []byte) {
	f.mu.Lock()
	ns, nr, tid := f.ns, f.nr, f.lacTunnelID
	f.ns++
	f.mu.Unlock()
	f.write(append(l2tp.EncodeControlHeader(tid, session, ns, nr, len(payload)), payload...))
}

func (f *fakeLNS) sendZLB() {
	f.mu.Lock()
	ns, nr, tid := f.ns, f.nr, f.lacTunnelID
	f.mu.Unlock()
	f.write(l2tp.EncodeControlHeader(tid, 0, ns, nr, 0))
}

func (f *fakeLNS) write(pkt []byte) {
	f.mu.Lock()
	peer := f.peer
	f.mu.Unlock()
	if peer == nil {
		return
	}
	select {
	case <-f.closed:
		return
	default:
	}
	_, _ = f.conn.WriteToUDP(pkt, peer)
}

// nextData returns the next PPP frame the LAC sent to the LNS.
func (f *fakeLNS) nextData(t *testing.T) lnsDataFrame {
	t.Helper()
	select {
	case d := <-f.data:
		return d
	case <-time.After(testTimeout):
		t.Fatal("timed out waiting for a PPP frame at the LNS")
		return lnsDataFrame{}
	}
}

func (f *fakeLNS) awaitICCN(t *testing.T) []l2tp.AVP {
	t.Helper()
	select {
	case avps := <-f.iccn:
		return avps
	case <-time.After(testTimeout):
		t.Fatal("the LAC never sent ICCN")
		return nil
	}
}

func buildFakeSCCRP() []byte {
	var buf []byte
	buf = append(buf, l2tp.EncodeUint16AVP(l2tp.AVPMessageType, l2tp.MsgTypeSCCRP)...)
	buf = append(buf, l2tp.EncodeAVP(l2tp.AVPProtocolVersion,
		[]byte{l2tp.ProtocolVersion, l2tp.ProtocolRevision})...)
	buf = append(buf, l2tp.EncodeStringAVP(l2tp.AVPHostName, "fake-lns")...)
	buf = append(buf, l2tp.EncodeUint32AVP(l2tp.AVPFramingCapabilities,
		l2tp.FramingAsync|l2tp.FramingSync)...)
	buf = append(buf, l2tp.EncodeUint16AVP(l2tp.AVPAssignedTunnelID, lnsTunnelID)...)
	return buf
}

// lnsCall pairs the session ID the LAC chose with the one this LNS assigned it.
type lnsCall struct{ lac, lns uint16 }

func buildFakeICRPFor(assigned uint16) []byte {
	var buf []byte
	buf = append(buf, l2tp.EncodeUint16AVP(l2tp.AVPMessageType, l2tp.MsgTypeICRP)...)
	buf = append(buf, l2tp.EncodeUint16AVP(l2tp.AVPAssignedSessionID, assigned)...)
	return buf
}

// ---------------------------------------------------------------------------
// L2TP mode harness
// ---------------------------------------------------------------------------

type l2tpHarness struct {
	client  *scriptedPPPD
	bridge  *Bridge
	lns     *fakeLNS
	tm      *l2tp.TunnelManager
	control *recordingConn
	events  *journal

	// toLAC records every frame the client's transport carried toward the server.
	toLAC, toClient *frameTap

	handlerDone chan struct{}
	runDone     chan struct{}
	runErr      error
	pair        *framePair

	// handshake carries the PPP response the dialer read, from Bridge.Run's
	// goroutine to the test's, where it can be asserted.
	handshake chan pppHandshake

	// iccn is what the LAC told the LNS when the session was connected, kept by
	// bringUp so a test can assert on what is -- and is not -- in it.
	iccn []l2tp.AVP
}

type pppHandshake struct {
	ok  bool
	mtu int
}

// awaitHandshake checks the response the handler wrote before any PPP frame
// moved. It is asserted here rather than in the dialer because only the test
// goroutine may call FailNow.
func (h *l2tpHarness) awaitHandshake(t *testing.T) {
	t.Helper()
	select {
	case hs := <-h.handshake:
		require.True(t, hs.ok, "the handler must accept the session")
		assert.Equal(t, 1400, hs.mtu, "the PPP MTU is the transport ceiling less the PPP header")
	case <-time.After(testTimeout):
		t.Fatal("the handler never wrote its handshake response")
	}
}

type l2tpOpt func(*l2tpCfg)

type l2tpCfg struct {
	clientID   string // the Hysteria2 identity this harness presents
	route      string // identity pattern the router knows about, mapped to the LNS group
	emptyGroup bool   // point the route at a group with no LNS in it
	badLNS     bool   // point the group at an address that cannot be dialled
	sized      bool   // make the client's transport report a ceiling
	ceiling    int

	sharedLNS *fakeLNS
	sharedTM  *l2tp.TunnelManager
}

func withEmptyLNSGroup() l2tpOpt { return func(c *l2tpCfg) { c.emptyGroup = true } }

// withSharedInfra points a harness at an existing LNS and tunnel manager, so two
// harnesses become two subscribers whose calls share one L2TP tunnel.
func withSharedInfra(lns *fakeLNS, tm *l2tp.TunnelManager) l2tpOpt {
	return func(c *l2tpCfg) { c.sharedLNS, c.sharedTM = lns, tm }
}

// withRoute replaces the identity pattern the router is configured with.
func withRoute(pattern string) l2tpOpt { return func(c *l2tpCfg) { c.route = pattern } }

// withClientID changes the Hysteria2 identity this harness authenticates as, so
// two harnesses can be two different subscribers.
func withClientID(id string) l2tpOpt { return func(c *l2tpCfg) { c.clientID = id } }

// withUnreachableLNS points the group at an address the LAC cannot even dial, so
// CreateSession fails immediately instead of spending the tunnel's full retry
// budget. What is under test is how the failure is reported.
func withUnreachableLNS() l2tpOpt { return func(c *l2tpCfg) { c.badLNS = true } }

// withSizedTransport makes both ends report a per-frame ceiling, which is what
// turns the MTU probe loops on at both ends.
func withSizedTransport(ceiling int) l2tpOpt {
	return func(c *l2tpCfg) { c.sized, c.ceiling = true, ceiling }
}

func newL2TPHarness(t *testing.T, opts ...l2tpOpt) *l2tpHarness {
	t.Helper()
	cfg := l2tpCfg{route: testClientID, clientID: testClientID}
	for _, o := range opts {
		o(&cfg)
	}

	lns, tm := cfg.sharedLNS, cfg.sharedTM
	if lns == nil {
		lns = newFakeLNS(t)
	}
	if tm == nil {
		tm = l2tp.NewTunnelManager("test-lac", 0, zap.NewNop())
		t.Cleanup(func() { _ = tm.Close() })
	}

	groups := map[string][]l2tp.LNSConfig{"grp": {{Address: lns.addr}}}
	if cfg.emptyGroup {
		groups = map[string][]l2tp.LNSConfig{"grp": {}}
	}
	if cfg.badLNS {
		groups = map[string][]l2tp.LNSConfig{"grp": {{Address: "no-port-here"}}}
	}
	handler := &L2TPPPPHandler{
		TunnelManager: tm,
		IDRouter:      l2tp.NewIDRouter([]l2tp.RouteRule{{Pattern: cfg.route, Group: "grp"}}),
		LoadBalancer:  l2tp.NewLoadBalancer(groups),
		Logger:        zap.NewNop(),
		ProbeInterval: 40 * time.Millisecond,
		ProbeGrace:    10 * time.Millisecond,
		ProbeFailures: 2,
	}

	clientPPPD, clientIn, clientOut := newScriptedPPPD(t)
	pair := newFramePair(64)
	clientData, serverData := pair.ends()
	if cfg.sized {
		clientData.limit, serverData.limit = cfg.ceiling, cfg.ceiling
	}

	h := &l2tpHarness{
		client:      clientPPPD,
		lns:         lns,
		tm:          tm,
		events:      &journal{},
		toLAC:       &frameTap{},
		toClient:    &frameTap{},
		handlerDone: make(chan struct{}),
		runDone:     make(chan struct{}),
		pair:        pair,
		handshake:   make(chan pppHandshake, 1),
	}
	clientData.tap = h.toLAC.add
	serverData.tap = h.toClient.add

	rawClientCtl, serverCtl := net.Pipe()
	h.control = &recordingConn{Conn: rawClientCtl}

	h.bridge = &Bridge{NoSpawn: true, ReadReason: true, Logger: zap.NewNop(), In: clientIn, Out: clientOut}
	if cfg.sized {
		h.bridge.ProbeInterval, h.bridge.ProbeGrace, h.bridge.ProbeFailures =
			40*time.Millisecond, 10*time.Millisecond, 2
	}

	ctx, cancel := context.WithCancel(context.Background())

	var dialed atomic.Bool
	dialFn := func() (io.ReadWriteCloser, ppp.PPPDataIO, func(), error) {
		if !dialed.CompareAndSwap(false, true) {
			return nil, nil, nil, permanentDialError{errors.New("one-shot")}
		}
		go func() {
			defer close(h.handlerDone)
			var transport ppp.PPPDataIO = serverData
			if cfg.sized {
				transport = sizedDataIO{serverData}
			}
			handler.HandlePPP(
				serverCtl,
				ppp.SessionParams{ClientMaxFrame: 1404, ServerMaxFrame: 1404},
				func() (ppp.PPPDataIO, error) { return transport, nil },
				&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345},
				cfg.clientID,
			)
		}()
		// The real client reads the handshake response in its dialer, before the
		// control stream is handed to Run. Doing it here keeps the bridge from
		// reading the response as a session reason.
		//
		// This runs on Bridge.Run's goroutine, not the test's, so it reports the
		// handshake back through a channel rather than calling require here: a
		// FailNow off the test goroutine would abandon Run mid-dial and deadlock
		// the cleanup instead of failing cleanly.
		ok, _, _, mtu, err := readPPPResponse(h.control)
		if err != nil {
			return nil, nil, nil, permanentDialError{err}
		}
		h.handshake <- pppHandshake{ok: ok, mtu: mtu}
		h.control.reset()

		var transport ppp.PPPDataIO = clientData
		if cfg.sized {
			transport = sizedDataIO{clientData}
		}
		return h.control, transport, func() {}, nil
	}

	go func() {
		defer close(h.runDone)
		h.runErr = h.bridge.Run(ctx, dialFn)
	}()

	t.Cleanup(func() {
		cancel()
		pair.shutdown()
		_ = rawClientCtl.Close()
		select {
		case <-h.runDone:
		case <-time.After(testTimeout):
			t.Error("client Bridge.Run did not return")
		}
		select {
		case <-h.handlerDone:
		case <-time.After(testTimeout):
			t.Error("L2TPPPPHandler.HandlePPP did not return")
		}
	})
	return h
}

// testClientID is the Hysteria2 identity the harness authenticates as. It is
// what selects the LNS now: the LAC never learns a PPP username.
const testClientID = "e2e-client"

// bringUp starts a session the way a real one starts: the client's pppd emits
// its first PPP frame, which is what makes the Bridge dial, which is what starts
// the handler. The handler routes on the identity, builds the L2TP session, and
// only then does the relay begin -- so this also pins that the first frame waits
// for session setup instead of being dropped.
func (h *l2tpHarness) bringUp(t *testing.T) {
	t.Helper()
	first := buildLCPPacket(lcpConfigRequest, 0x01, clientLCPOpts)
	h.client.sendPacket(pppProtoLCP, first)
	h.events.note("client -> LAC: LCP Configure-Request")

	h.awaitHandshake(t)
	h.iccn = h.lns.awaitICCN(t)
	h.events.note("LAC -> LNS: ICCN")

	got := h.lns.nextData(t)
	require.Equal(t, pppProtoLCP, got.proto,
		"the client's first frame must survive session setup and reach the LNS")
	require.Equal(t, first, got.payload, "verbatim")
}

// ---------------------------------------------------------------------------
// 2 and 3. L2TP mode: the LAC as a pure data-plane bridge
// ---------------------------------------------------------------------------

// The whole session, and the point of the design in one test: the LAC routes on
// the Hysteria2 identity, opens an L2TP session, and from then on every PPP
// frame crosses it untouched in both directions. LCP, the CHAP challenge and
// response, the result, IPCP and user data are all conversations between the
// subscriber's pppd and the LNS. The LAC contributes nothing to them.
func TestL2TPModeRelaysAWholePPPSessionVerbatim(t *testing.T) {
	h := newL2TPHarness(t)
	h.bringUp(t)

	// The LNS starts LCP itself, because nothing was proxied to it.
	lnsCR := buildLCPPacket(lcpConfigRequest, 0x21, []byte{
		lcpOptMRU, 4, 0x05, 0xDC,
		lcpOptAuthProtocol, 5, 0xC2, 0x23, 0x05,
	})
	h.lns.sendPPP(pppProtoLCP, lnsCR)
	proto, pkt := h.client.recvPacket()
	require.Equal(t, pppProtoLCP, proto)
	assert.Equal(t, lnsCR, pkt, "the LNS's Configure-Request reaches pppd verbatim")

	// pppd answers the LNS, not the LAC.
	clientAck := buildLCPPacket(lcpConfigAck, 0x21, lnsCR[4:])
	h.client.sendPacket(pppProtoLCP, clientAck)
	got := h.lns.nextData(t)
	assert.Equal(t, pppProtoLCP, got.proto)
	assert.Equal(t, clientAck, got.payload, "and the Ack goes straight back")

	// CHAP, end to end. The LAC never issues a challenge of its own, and never
	// sees a credential.
	challenge := buildLCPPacket(chapChallenge, 0x01, append([]byte{16}, bytes.Repeat([]byte{0x5A}, 16)...))
	h.lns.sendPPP(pppProtoCHAP, challenge)
	proto, pkt = h.client.recvPacket()
	require.Equal(t, pppProtoCHAP, proto)
	assert.Equal(t, challenge, pkt)

	response := buildLCPPacket(chapResponse, 0x01,
		append(append([]byte{16}, bytes.Repeat([]byte{0xA5}, 16)...), "alice@ispa.net"...))
	h.client.sendPacket(pppProtoCHAP, response)
	got = h.lns.nextData(t)
	assert.Equal(t, pppProtoCHAP, got.proto)
	assert.Equal(t, response, got.payload,
		"the subscriber's credential goes to the LNS inside PPP, not in an AVP")

	success := buildLCPPacket(chapSuccess, 0x01, []byte("Welcome"))
	h.lns.sendPPP(pppProtoCHAP, success)
	proto, pkt = h.client.recvPacket()
	require.Equal(t, pppProtoCHAP, proto)
	assert.Equal(t, success, pkt, "the LNS's verdict is the only one there is")

	// Network phase and user data.
	ipcp := buildLCPPacket(lcpConfigRequest, 0x31, []byte{0x03, 0x06, 10, 0, 0, 1})
	h.lns.sendPPP(pppProtoIPCP, ipcp)
	proto, pkt = h.client.recvPacket()
	require.Equal(t, pppProtoIPCP, proto)
	assert.Equal(t, ipcp, pkt)

	h.client.sendPacket(pppProtoIPv4, []byte{0x45, 0x00, 0x00, 0x14})
	got = h.lns.nextData(t)
	assert.Equal(t, pppProtoIPv4, got.proto)

	h.lns.sendPPP(pppProtoIPv6, []byte{0x60, 0x00})
	proto, _ = h.client.recvPacket()
	assert.Equal(t, pppProtoIPv6, proto)

	// And the LNS ends it.
	h.lns.sendCDN(2, 0, "session cleared")
	select {
	case <-h.handlerDone:
	case <-time.After(testTimeout):
		t.Fatal("a CDN must end the session")
	}
	reason := h.control.awaitReason(t)
	assert.Equal(t, ReasonLNSDisconnected, reason.Code)
	assert.Equal(t, "session cleared", reason.Message)
}

// Whatever the subscriber and the LNS agreed on, the LAC carries it unread.
//
// Address-and-Control-Field-Compression and Protocol-Field-Compression are
// settled between the subscriber's pppd and the LNS, end to end through this
// tunnel, and neither of them tells the LAC. PPP implementations commonly
// request PFC and peers may negotiate Multilink, so all of these shapes are
// reachable in an ordinary session.
//
// Sending the bytes on untouched is the only thing that cannot be wrong about an
// agreement made by two other parties, and it is the property asserted here.
func TestL2TPModeCarriesEveryFrameShapeUnaltered(t *testing.T) {
	shapes := []struct {
		name  string
		frame []byte
	}{
		{"address/control and a full protocol field", []byte{0xFF, 0x03, 0x00, 0x21, 0x45, 0x00, 0x00, 0x14}},
		{"ACFC: no address/control", []byte{0x00, 0x21, 0x45, 0x00, 0x00, 0x14}},
		{"PFC: a one-octet protocol field", []byte{0x21, 0x45, 0x00, 0x00, 0x14}},
		{"both, on IPv6", []byte{0x57, 0x60, 0x00, 0x00, 0x00}},
		{"both, on a multilink fragment", []byte{0x3D, 0xC0, 0x01, 0xDE, 0xAD}},
		{"address/control with a compressed protocol", []byte{0xFF, 0x03, 0x21, 0x45, 0x00}},
	}

	t.Run("from the subscriber to the LNS", func(t *testing.T) {
		h := newL2TPHarness(t)
		h.bringUp(t)
		for _, s := range shapes {
			t.Run(s.name, func(t *testing.T) {
				h.client.send(s.frame)
				assert.Equal(t, s.frame, h.lns.nextData(t).raw)
			})
		}
	})

	t.Run("from the LNS to the subscriber", func(t *testing.T) {
		h := newL2TPHarness(t)
		h.bringUp(t)
		for _, s := range shapes {
			t.Run(s.name, func(t *testing.T) {
				h.lns.sendPPPRaw(s.frame)
				assert.Equal(t, s.frame, h.client.recv())
			})
		}
	})
}

// The ICCN this LAC sends carries no proxy state, which is what makes the LNS
// run LCP and authentication itself (RFC 2661 s4.4.5). Asserted end to end
// because it is the hinge the whole design turns on: if any proxy AVP crept
// back in, an LNS would try to skip negotiation and the session above would
// never happen.
func TestL2TPModeSendsNoProxyStateToTheLNS(t *testing.T) {
	h := newL2TPHarness(t)
	h.bringUp(t)

	for _, forbidden := range []struct {
		name string
		typ  uint16
	}{
		{"Initial Received LCP CONFREQ", l2tp.AVPInitialReceivedLCPCONFREQ},
		{"Last Sent LCP CONFREQ", l2tp.AVPLastSentLCPCONFREQ},
		{"Last Received LCP CONFREQ", l2tp.AVPLastReceivedLCPCONFREQ},
		{"Proxy Authen Type", l2tp.AVPProxyAuthenType},
		{"Proxy Authen Name", l2tp.AVPProxyAuthenName},
		{"Proxy Authen Challenge", l2tp.AVPProxyAuthenChallenge},
		{"Proxy Authen ID", l2tp.AVPProxyAuthenID},
		{"Proxy Authen Response", l2tp.AVPProxyAuthenResponse},
	} {
		assert.Nilf(t, l2tp.FindAVP(h.iccn, 0, forbidden.typ),
			"the LAC proxies nothing, so %s must not be in the ICCN", forbidden.name)
	}
	require.NotNil(t, l2tp.FindAVP(h.iccn, 0, l2tp.AVPFramingType),
		"the mandatory AVPs are still there")
}

// ---------------------------------------------------------------------------
// Routing on the Hysteria2 identity
// ---------------------------------------------------------------------------

// An identity with no configured route is refused, permanently: no amount of
// retrying makes a config file grow a rule.
func TestL2TPModeUnknownIdentityIsRefusedPermanently(t *testing.T) {
	h := newL2TPHarness(t, withRoute("somebody-else"))
	h.client.sendPacket(pppProtoLCP, buildLCPPacket(lcpConfigRequest, 0x01, clientLCPOpts))
	h.awaitHandshake(t)

	select {
	case <-h.handlerDone:
	case <-time.After(testTimeout):
		t.Fatal("an unroutable identity must be refused, not left hanging")
	}

	reason := h.control.awaitReason(t)
	assert.Equal(t, ReasonNoRoute, reason.Code)
	assert.True(t, reason.Code.Permanent(), "a missing route cannot be fixed by trying again")
	assert.Contains(t, reason.Message, testClientID)

	select {
	case <-h.lns.iccn:
		t.Fatal("an unroutable identity must not reach the LNS at all")
	case <-time.After(200 * time.Millisecond):
	}
}

// A catch-all route is what a single-LNS deployment configures, and it has to
// work for any identity the server hands over.
func TestL2TPModeCatchAllRouteAcceptsAnyIdentity(t *testing.T) {
	h := newL2TPHarness(t, withRoute("*"), withClientID("somebody-new@example.net"))
	h.bringUp(t)
}

// ---------------------------------------------------------------------------
// Reasons
// ---------------------------------------------------------------------------

func TestReasonPropagationPerScenario(t *testing.T) {
	tests := []struct {
		name         string
		opts         []l2tpOpt
		armCDNAtICCN bool
		drive        func(t *testing.T, h *l2tpHarness)
		want         SessionReason
	}{
		{
			name:  "an identity with no route",
			opts:  []l2tpOpt{withRoute("nobody")},
			drive: func(t *testing.T, h *l2tpHarness) {},
			want: SessionReason{
				Code:    ReasonNoRoute,
				Message: "no LNS group is configured for identity " + testClientID,
			},
		},
		{
			name:  "a group with no LNS in it",
			opts:  []l2tpOpt{withEmptyLNSGroup()},
			drive: func(t *testing.T, h *l2tpHarness) {},
			want:  SessionReason{Code: ReasonNoLNS, Message: "no LNS available in group grp"},
		},
		{
			name:  "an LNS the LAC cannot reach",
			opts:  []l2tpOpt{withUnreachableLNS()},
			drive: func(t *testing.T, h *l2tpHarness) {},
			want:  SessionReason{Code: ReasonLNSUnreachable},
		},
		{
			name:         "the LNS clears the call as soon as it is connected",
			armCDNAtICCN: true,
			drive:        func(t *testing.T, h *l2tpHarness) { h.lns.awaitICCN(t) },
			want: SessionReason{
				Code: ReasonLNSDisconnected, Result: 2, Error: 6,
				Message: "administratively cleared",
			},
		},
		{
			name:         "an LNS that is permanently unavailable",
			armCDNAtICCN: true,
			drive:        func(t *testing.T, h *l2tpHarness) { h.lns.awaitICCN(t) },
			want: SessionReason{
				Code: ReasonNoLNS, Result: 5, Error: 0,
				Message: "facilities permanently unavailable",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newL2TPHarness(t, tt.opts...)
			if tt.armCDNAtICCN {
				h.lns.cdnResult.Store(uint32(tt.want.Result))
				h.lns.cdnError.Store(uint32(tt.want.Error))
				h.lns.cdnMsg.Store(tt.want.Message)
				h.lns.cdnAtICCN.Store(true)
			}

			h.client.sendPacket(pppProtoLCP, buildLCPPacket(lcpConfigRequest, 0x01, clientLCPOpts))
			h.awaitHandshake(t)
			tt.drive(t, h)

			select {
			case <-h.handlerDone:
			case <-time.After(testTimeout):
				t.Fatal("the handler did not finish the session")
			}

			got := h.control.awaitReason(t)
			if tt.want.Code == ReasonLNSUnreachable {
				// The message quotes the dial error verbatim, which is the point of
				// it but not something to pin character by character.
				assert.Equal(t, tt.want.Code, got.Code)
				assert.Contains(t, got.Message, "could not be established")
				assert.False(t, got.Code.Permanent(), "an unreachable LNS may come back")
				return
			}
			assert.Equal(t, tt.want, got, "the reason on the wire must say exactly what happened")
		})
	}
}

// The permanence rule, stated once. Only two codes tell a client to stop: a
// Hysteria2 credential that was refused, and an identity with no route. Both are
// facts about configuration, not about the network.
func TestReasonCodePermanentOnlyForAuthFailedAndNoRoute(t *testing.T) {
	permanent := map[ReasonCode]bool{ReasonAuthFailed: true, ReasonNoRoute: true}
	for _, code := range []ReasonCode{
		ReasonUnknown, ReasonLinkDown, ReasonAuthFailed, ReasonNoRoute,
		ReasonNoLNS, ReasonLNSUnreachable, ReasonLNSDisconnected, ReasonPathNarrowed,
	} {
		assert.Equalf(t, permanent[code], code.Permanent(), "%s permanence", code)
	}
}

// ---------------------------------------------------------------------------
// 6c. MTU probes in L2TP mode
// ---------------------------------------------------------------------------

// The LAC answers probes itself. Before the refactor it had no idea what they
// were: it forwarded a full-size 0x4001 frame to the LNS every probe interval
// for the life of the session, and any reply would have gone back on the control
// stream where the client was not looking -- so the client's probe loop saw
// nothing come back and tore down a session that was never in trouble.
func TestL2TPModeMTUProbesAreAnsweredByTheLACAndNeverReachTheLNS(t *testing.T) {
	h := newL2TPHarness(t)
	h.bringUp(t)

	// A probe from the client, sent the way its own probe loop would.
	h.client.send(buildMTUProbe(mtuProbeRequest, 1234, 1200))

	deadline := time.Now().Add(testTimeout)
	var reply []byte
	for reply == nil && time.Now().Before(deadline) {
		for _, f := range h.toClient.frames() {
			if kind, seq, ok := parseMTUProbe(f); ok && kind == mtuProbeReply && seq == 1234 {
				reply = f
			}
		}
		time.Sleep(2 * time.Millisecond)
	}
	require.NotNil(t, reply, "the LAC must answer the probe itself")
	assert.Len(t, reply, mtuProbeHeaderLen)

	// It never reached the LNS, and ordinary traffic still does.
	h.client.sendPacket(pppProtoIPv4, []byte{0x45, 0x00})
	got := h.lns.nextData(t)
	assert.Equal(t, pppProtoIPv4, got.proto,
		"the first frame the LNS sees after the probe must be the IPv4 packet, not the probe")

	select {
	case extra := <-h.lns.data:
		t.Fatalf("another frame reached the LNS: proto %04X %x", extra.proto, extra.payload)
	case <-time.After(200 * time.Millisecond):
	}

	// And the client's pppd never saw the reply.
	h.client.assertSilent("a probe reply is consumed by the client's own relay")
}

// Both directions probe once both transports report a ceiling, and the session
// survives it: the LAC answers the client's probes and the client answers the
// LAC's, so neither probe loop ever reaches its failure count. The LNS sees none
// of it.
//
// Both ends answer from relay.run, which is now the only place a probe is ever
// consumed: with no negotiator in the LAC there is no second path a probe could
// take.
func TestL2TPModeBothEndsProbeAndTheSessionSurvives(t *testing.T) {
	h := newL2TPHarness(t, withSizedTransport(1400))
	h.bringUp(t)

	// Long enough for many probe rounds in both directions: the schedule is
	// 10ms grace, 40ms interval, teardown after 2 unanswered.
	deadline := time.After(600 * time.Millisecond)
	select {
	case <-h.runDone:
		t.Fatal("the client tore the session down even though its probes were answered")
	case <-h.handlerDone:
		t.Fatal("the LAC tore the session down even though its probes were answered")
	case <-deadline:
	}

	// Probes really did flow, in both directions.
	var clientProbes, lacProbes int
	for _, f := range h.toLAC.frames() {
		if kind, _, ok := parseMTUProbe(f); ok && kind == mtuProbeRequest {
			clientProbes++
		}
	}
	for _, f := range h.toClient.frames() {
		if kind, _, ok := parseMTUProbe(f); ok && kind == mtuProbeRequest {
			lacProbes++
		}
	}
	assert.Positive(t, clientProbes, "the client must probe a transport that reports a ceiling")
	assert.Positive(t, lacProbes, "and so must the LAC")

	// None of them reached pppd or the LNS, and traffic still gets through.
	h.client.assertSilent("probes are consumed by the relay at each end")
	h.client.sendPacket(pppProtoIPv4, []byte{0x45, 0x00})
	got := h.lns.nextData(t)
	assert.Equal(t, pppProtoIPv4, got.proto,
		"no probe may reach the LNS, so the IPv4 packet is the first thing it sees")
}
