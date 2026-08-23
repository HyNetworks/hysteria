package pppbridge

import (
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/apernet/hysteria/core/v2/ppp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// Local termination, driven through the real spawn path.
//
// ServerPPPHandler is the mode where the server runs its own pppd for the
// client, and nothing exercised HandlePPP at all -- only the argument builder
// underneath it. That left the whole session lifecycle untested: the IP
// allocation and its release, the handshake response, the child process, the
// pty, and the reason written when it all ends.
//
// The child here is a shell standing in for pppd. That matters more than it
// looks: it makes these tests cover Bridge.startProcess and the pty allocation
// in bridge_unix.go, which no fake can reach, and which is the code that runs in
// production every time a subscriber connects in this mode.

// standInPPPD returns a command that behaves enough like pppd for a session to
// run: it puts the tty into raw mode so binary HDLC survives the line
// discipline, emits one LCP Configure-Request to bring the link up, then echoes
// whatever it is sent.
//
// The echo is what makes it useful -- every frame the client sends comes back,
// so the relay is exercised in both directions against a real process rather
// than an in-process fake.
func standInPPPD(t *testing.T) (path string, args []string) {
	t.Helper()
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh to stand in for pppd")
	}
	first := EncodeHDLC(buildPPPFrame(pppProtoLCP, buildLCPPacket(lcpConfigRequest, 1, nil)))
	var esc strings.Builder
	for _, b := range first {
		fmt.Fprintf(&esc, "\\%03o", b)
	}
	// stty failing is not fatal: where the tty is already raw the rest still
	// works, and where it is not, the frame reads below time out with a clear
	// message rather than hanging.
	return "/bin/sh", []string{"-c", "stty raw -echo 2>/dev/null; printf '" + esc.String() + "'; exec cat"}
}

type localSession struct {
	pool    *IPPool
	client  *pairedDataIO
	control *recordingConn
	pair    *framePair
	done    chan struct{}
}

func startLocalSession(t *testing.T, opts ...func(*ServerPPPHandler)) *localSession {
	t.Helper()
	pool, err := NewIPPool("10.9.0.0/29")
	require.NoError(t, err)

	path, args := standInPPPD(t)
	h := &ServerPPPHandler{
		PPPDPath: path,
		PPPDArgs: args,
		IPv4Pool: pool,
		DNS:      []string{"1.1.1.1"},
		Logger:   zap.NewNop(),
	}
	for _, o := range opts {
		o(h)
	}

	pair := newFramePair(64)
	clientData, serverData := pair.ends()
	rawCtl, serverCtl := net.Pipe()
	ctl := &recordingConn{Conn: rawCtl}

	s := &localSession{pool: pool, client: clientData, control: ctl, pair: pair, done: make(chan struct{})}
	go func() {
		defer close(s.done)
		h.HandlePPP(
			serverCtl,
			ppp.SessionParams{ClientMaxFrame: 1404, ServerMaxFrame: 1404},
			func() (ppp.PPPDataIO, error) { return serverData, nil },
			&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4242},
			"local-subscriber",
		)
	}()
	t.Cleanup(func() {
		pair.shutdown()
		_ = rawCtl.Close()
		select {
		case <-s.done:
		case <-time.After(testTimeout):
			t.Error("ServerPPPHandler.HandlePPP did not return")
		}
	})
	return s
}

// drainControl reads the control stream in the background so the recorder sees
// everything the server writes and the server never blocks writing it. Without
// a reader the teardown blocks on writeSessionReason until its 2s deadline
// expires and the reason is lost -- which is what the deadline is there to
// bound, but not what these tests are about. A real client's reason reader does
// exactly this.
func (s *localSession) drainControl() {
	go func() {
		buf := make([]byte, 512)
		for {
			if _, err := s.control.Read(buf); err != nil {
				return
			}
		}
	}()
}

func (s *localSession) recvFrame(t *testing.T) []byte {
	t.Helper()
	type res struct {
		f   []byte
		err error
	}
	ch := make(chan res, 1)
	go func() { f, err := s.client.ReceiveData(); ch <- res{f, err} }()
	select {
	case r := <-ch:
		require.NoError(t, r.err)
		return r.f
	case <-time.After(testTimeout):
		t.Fatal("no frame arrived from the server's pppd")
		return nil
	}
}

// drainPool allocates until the pool is empty and returns everything it handed
// out, which is how a test counts what was still available.
func drainPool(t *testing.T, p *IPPool) []string {
	t.Helper()
	var got []string
	for {
		ip, err := p.Allocate()
		if err != nil {
			return got
		}
		got = append(got, ip)
	}
}

// The whole local session: handshake, an address out of the pool, the child's
// first frame reaching the client, traffic both ways, and the address returned
// when it ends.
func TestServerPPPHandlerRunsALocalSessionEndToEnd(t *testing.T) {
	s := startLocalSession(t)

	// The handshake tells the client what the link can carry: 1404 octets of
	// transport less the 4-octet PPP header.
	ok, msg, ds, mtu, err := readPPPResponse(s.control)
	require.NoError(t, err)
	require.True(t, ok, "the handler must accept the session, got %q", msg)
	assert.Equal(t, 0, ds, "datagram mode was requested")
	assert.Equal(t, 1400, mtu)
	// Drop the handshake bytes so the reason read at the end is not parsed out of
	// them, then keep reading the way a real client does.
	s.control.reset()
	s.drainControl()

	// The child came up and its first frame reached the client through the relay.
	proto, _ := parsePPPFrame(s.recvFrame(t))
	assert.Equal(t, pppProtoLCP, proto,
		"the server's pppd opens with LCP, and that frame must cross to the client")

	// Traffic both ways: the stand-in echoes, so what the client sends returns.
	want := buildPPPFrame(pppProtoIPv4, []byte{0x45, 0x00, 0x11, 0x22})
	require.NoError(t, s.client.SendData(want))
	assert.Equal(t, want, s.recvFrame(t), "frames cross to pppd and back unaltered")

	// One address is out of the pool while the session holds it.
	inUse := drainPool(t, s.pool)
	assert.Len(t, inUse, 4,
		"a /29 has 6 usable addresses; one is the gateway and one is with the subscriber")
	for _, ip := range inUse {
		s.pool.Release(ip)
	}

	// Ending the session releases it and tells the client why.
	s.pair.shutdown()
	select {
	case <-s.done:
	case <-time.After(testTimeout):
		t.Fatal("a dead transport must end the local session")
	}

	reason := s.control.awaitReason(t)
	assert.Equal(t, ReasonLinkDown, reason.Code,
		"local mode has no LNS to quote, so the reason is a plain link down")
	assert.NotEmpty(t, reason.Message)

	assert.Len(t, drainPool(t, s.pool), 5,
		"the subscriber's address must go back to the pool when the session ends")
}

// A pool with nothing left must refuse the session cleanly, before any child is
// spawned, and say so in the handshake rather than dropping the connection.
func TestServerPPPHandlerRefusesWhenThePoolIsExhausted(t *testing.T) {
	pool, err := NewIPPool("10.9.1.0/30")
	require.NoError(t, err)
	drainPool(t, pool)

	h := &ServerPPPHandler{
		PPPDPath: "/nonexistent/pppd", // must never be reached
		IPv4Pool: pool,
		Logger:   zap.NewNop(),
	}
	rawCtl, serverCtl := net.Pipe()
	ctl := &recordingConn{Conn: rawCtl}
	t.Cleanup(func() { _ = rawCtl.Close() })

	done := make(chan struct{})
	go func() {
		defer close(done)
		h.HandlePPP(serverCtl, ppp.SessionParams{ClientMaxFrame: 1404, ServerMaxFrame: 1404},
			func() (ppp.PPPDataIO, error) {
				t.Error("the data transport must not be built for a session we refuse")
				return nil, nil
			},
			&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4242}, "unlucky")
	}()

	ok, msg, _, _, err := readPPPResponse(ctl)
	require.NoError(t, err)
	assert.False(t, ok, "an exhausted pool must be refused")
	assert.Contains(t, msg, "pool exhausted")

	select {
	case <-done:
	case <-time.After(testTimeout):
		t.Fatal("the handler did not return after refusing")
	}
}

// An IPv6-only deployment configures no IPv4 pool at all. The session still has
// to come up; there is simply no address to hand out.
func TestServerPPPHandlerRunsWithoutAnIPv4Pool(t *testing.T) {
	path, args := standInPPPD(t)
	h := &ServerPPPHandler{PPPDPath: path, PPPDArgs: args, Logger: zap.NewNop()}

	pair := newFramePair(64)
	clientData, serverData := pair.ends()
	rawCtl, serverCtl := net.Pipe()
	ctl := &recordingConn{Conn: rawCtl}

	done := make(chan struct{})
	go func() {
		defer close(done)
		h.HandlePPP(serverCtl, ppp.SessionParams{ClientMaxFrame: 1404, ServerMaxFrame: 1404},
			func() (ppp.PPPDataIO, error) { return serverData, nil },
			&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4242}, "v6-only")
	}()
	t.Cleanup(func() {
		pair.shutdown()
		_ = rawCtl.Close()
		select {
		case <-done:
		case <-time.After(testTimeout):
			t.Error("HandlePPP did not return")
		}
	})

	ok, _, _, _, err := readPPPResponse(ctl)
	require.NoError(t, err)
	require.True(t, ok, "an IPv6-only session must still be accepted")

	type res struct {
		f   []byte
		err error
	}
	ch := make(chan res, 1)
	go func() { f, err := clientData.ReceiveData(); ch <- res{f, err} }()
	select {
	case r := <-ch:
		require.NoError(t, r.err)
		proto, _ := parsePPPFrame(r.f)
		assert.Equal(t, pppProtoLCP, proto)
	case <-time.After(testTimeout):
		t.Fatal("no frame from the server's pppd in IPv6-only mode")
	}
}
