package integration_tests

import (
	"bytes"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/apernet/hysteria/core/v2/client"
	"github.com/apernet/hysteria/core/v2/internal/integration_tests/mocks"
	"github.com/apernet/hysteria/core/v2/server"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestConnectionPoolTCPUDP(t *testing.T) {
	for _, size := range []int{1, 2, 3, client.MaxConnectionPoolSize} {
		for _, lazy := range []bool{false, true} {
			for _, disableParrot := range []bool{false, true} {
				t.Run(strconv.Itoa(size)+"/lazy="+strconv.FormatBool(lazy)+"/disableParrot="+strconv.FormatBool(disableParrot), func(t *testing.T) {
					testConnectionPoolTCPUDP(t, size, lazy, disableParrot)
				})
			}
		}
	}
}

func testConnectionPoolTCPUDP(t *testing.T, size int, lazy, disableParrot bool) {
	u, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = u.Close() })
	auth := mocks.NewMockAuthenticator(t)
	auth.EXPECT().Authenticate(mock.Anything, "pool-test", uint64(450000000/8)/uint64(size)).Return(true, "pool-test").Times(size)
	s, err := server.NewServer(&server.Config{TLSConfig: serverTLSConfig(), Conn: u, Authenticator: auth})
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	go s.Serve()

	var handshakes int
	var members []client.Client
	c, err := client.NewReconnectableClientPool(func() (*client.Config, error) {
		return &client.Config{
			ServerAddr:      u.LocalAddr(),
			Auth:            "pool-test",
			TLSConfig:       client.TLSConfig{InsecureSkipVerify: true},
			QUICConfig:      client.QUICConfig{DisableChromeParrot: disableParrot},
			BandwidthConfig: client.BandwidthConfig{MaxRx: 450000000 / 8, MaxTx: 300000000 / 8},
		}, nil
	}, func(member client.Client, info *client.HandshakeInfo, count int) {
		handshakes++
		members = append(members, member)
		require.Equal(t, handshakes, count)
		require.Equal(t, uint64(300000000/8)/uint64(size), info.Tx)
	}, lazy, size)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	if lazy {
		require.Zero(t, handshakes)
	} else {
		require.Equal(t, size, handshakes)
	}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	echo := &tcpEchoServer{Listener: l}
	t.Cleanup(func() { _ = echo.Close() })
	go echo.Serve()
	var streams []net.Conn
	var addresses []string
	for range size {
		conn, err := c.TCP(l.Addr().String())
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })
		require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
		streams = append(streams, conn)
		addresses = append(addresses, conn.LocalAddr().String())
	}
	require.Equal(t, size, handshakes)
	require.Equal(t, size, len(members))
	for i := range size {
		for j := range i {
			require.NotSame(t, members[i], members[j])
			require.NotEqual(t, addresses[i], addresses[j])
		}
	}
	// Opening more streams rotates the selection, without replacing streams
	// that are already established on a member.
	for i := range size {
		conn, err := c.TCP(l.Addr().String())
		require.NoError(t, err)
		require.Equal(t, addresses[i], conn.LocalAddr().String())
		require.NoError(t, conn.Close())
	}
	for i, conn := range streams {
		for round := range 3 {
			want := bytes.Repeat([]byte{byte(i + round)}, 32768)
			_, err = conn.Write(want)
			require.NoError(t, err)
			got := make([]byte, len(want))
			_, err = io.ReadFull(conn, got)
			require.NoError(t, err)
			require.Equal(t, want, got)
			require.Equal(t, addresses[i], conn.LocalAddr().String())
		}
	}

	uEcho, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	udpEcho := &udpEchoServer{Conn: uEcho}
	t.Cleanup(func() { _ = udpEcho.Close() })
	go udpEcho.Serve()
	var sessions []client.HyUDPConn
	for range size {
		uc, err := c.UDP()
		require.NoError(t, err)
		t.Cleanup(func() { _ = uc.Close() })
		sessions = append(sessions, uc)
	}
	for i, uc := range sessions {
		for round := range 3 {
			// Also exercises Hysteria UDP fragmentation/reassembly.
			want := bytes.Repeat([]byte{byte(i + round)}, 1800)
			require.NoError(t, uc.Send(want, uEcho.LocalAddr().String()))
			type result struct {
				data []byte
				err  error
			}
			done := make(chan result, 1)
			go func() {
				got, _, err := uc.Receive()
				done <- result{data: got, err: err}
			}()
			select {
			case got := <-done:
				require.NoError(t, got.err)
				require.Equal(t, want, got.data)
			case <-time.After(5 * time.Second):
				t.Fatal("pooled UDP echo timed out")
			}
		}
	}
	require.Equal(t, size, handshakes)
	require.NoError(t, c.Close())
	require.NoError(t, c.Close())
	_, err = c.TCP(l.Addr().String())
	require.Error(t, err)
	_, err = c.UDP()
	require.Error(t, err)
}
