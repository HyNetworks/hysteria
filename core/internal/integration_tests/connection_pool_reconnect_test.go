package integration_tests

import (
	"bytes"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/apernet/hysteria/core/v2/client"
	coreErrs "github.com/apernet/hysteria/core/v2/errors"
	"github.com/apernet/hysteria/core/v2/internal/integration_tests/mocks"
	"github.com/apernet/hysteria/core/v2/server"
)

type poolTrackingFactory struct {
	mu    sync.Mutex
	conns []*net.UDPConn
}

func (f *poolTrackingFactory) New(net.Addr) (net.PacketConn, error) {
	u, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, err
	}
	f.mu.Lock()
	f.conns = append(f.conns, u)
	f.mu.Unlock()
	return u, nil
}

func (f *poolTrackingFactory) snapshot() []*net.UDPConn {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*net.UDPConn(nil), f.conns...)
}

// A failed member is reconnected on a subsequent open. Existing flows on
// healthy members stay usable; failed opens/established flows are not replayed.
// This deliberately closes the failed socket to model a local transport fault.
// It does not prove retired-transport cleanup after a peer-initiated QUIC close.
func TestConnectionPoolMemberReconnect(t *testing.T) {
	for _, size := range []int{2, 3} {
		for _, lazy := range []bool{false, true} {
			t.Run(strconv.Itoa(size)+"/lazy="+strconv.FormatBool(lazy), func(t *testing.T) {
				poolMemberReconnect(t, size, lazy)
			})
		}
	}
}

func poolMemberReconnect(t *testing.T, size int, lazy bool) {
	u, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	auth := mocks.NewMockAuthenticator(t)
	auth.EXPECT().Authenticate(mock.Anything, "pool-test", uint64(0)).Return(true, "pool-test")
	s, err := server.NewServer(&server.Config{TLSConfig: serverTLSConfig(), Conn: u, Authenticator: auth})
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	go s.Serve()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	echo := &tcpEchoServer{Listener: l}
	t.Cleanup(func() { _ = echo.Close() })
	go echo.Serve()

	factory := &poolTrackingFactory{}
	// Also closes any deliberately faulted generations if an assertion fails.
	t.Cleanup(func() {
		for _, conn := range factory.snapshot() {
			_ = conn.Close()
		}
	})
	var members []client.Client
	var counts []int
	c, err := client.NewReconnectableClientPool(func() (*client.Config, error) {
		return &client.Config{
			ConnFactory: factory, ServerAddr: u.LocalAddr(), Auth: "pool-test",
			TLSConfig:  client.TLSConfig{InsecureSkipVerify: true},
			QUICConfig: client.QUICConfig{DisableChromeParrot: true},
		}, nil
	}, func(member client.Client, _ *client.HandshakeInfo, count int) {
		members = append(members, member)
		counts = append(counts, count)
	}, lazy, size)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })

	var streams []net.Conn
	for range size {
		conn, err := c.TCP(l.Addr().String())
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })
		streams = append(streams, conn)
	}
	require.Len(t, members, size)
	faulted := members[0]
	for cycle := range 3 {
		conns := factory.snapshot()
		require.Len(t, conns, size+cycle)
		index := 0
		if cycle > 0 {
			index = len(conns) - 1
		}
		require.NoError(t, conns[index].Close())
		// UDP() observes the failed QUIC receiver and retires this generation.
		require.Eventually(t, func() bool {
			uc, err := faulted.UDP()
			if err == nil {
				_ = uc.Close()
				return false
			}
			_, closed := err.(coreErrs.ClosedError)
			return closed
		}, 3*time.Second, 5*time.Millisecond)
		conn, err := faulted.TCP(l.Addr().String())
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })
		poolCheckEcho(t, conn, byte(cycle))
		require.Len(t, factory.snapshot(), size+cycle+1)
		require.Same(t, faulted, members[len(members)-1])
		for _, healthy := range streams[1:] {
			poolCheckEcho(t, healthy, byte(cycle+10))
		}
	}
	for i, count := range counts {
		require.Equal(t, i+1, count)
	}
	require.NoError(t, c.Close())
	for _, conn := range factory.snapshot() {
		_, err = conn.WriteToUDP([]byte{0}, u.LocalAddr().(*net.UDPAddr))
		require.ErrorIs(t, err, net.ErrClosed)
	}
}

func poolCheckEcho(t *testing.T, conn net.Conn, value byte) {
	t.Helper()
	require.NoError(t, conn.SetDeadline(time.Now().Add(3*time.Second)))
	want := bytes.Repeat([]byte{value}, 4096)
	_, err := conn.Write(want)
	require.NoError(t, err)
	got := make([]byte, len(want))
	_, err = io.ReadFull(conn, got)
	require.NoError(t, err)
	require.Equal(t, want, got)
}
