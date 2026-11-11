package integration_tests

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/apernet/hysteria/core/v2/client"
	"github.com/apernet/hysteria/core/v2/internal/integration_tests/mocks"
	"github.com/apernet/hysteria/core/v2/server"
)

// TestServerTCPStalledTarget tests that a TCP target which stops reading while
// keeping its connection open does not stall the client's other streams.
//
// Without the stall timeout, the stalled stream's unread upload data occupies
// the connection-level flow-control window, the client cannot send on any
// stream of the connection, and new requests never complete.
func TestServerTCPStalledTarget(t *testing.T) {
	udpConn, udpAddr, err := serverConn()
	assert.NoError(t, err)
	serverOb := mocks.NewMockOutbound(t)
	auth := mocks.NewMockAuthenticator(t)
	auth.EXPECT().Authenticate(mock.Anything, mock.Anything, mock.Anything).Return(true, "nobody")
	s, err := server.NewServer(&server.Config{
		TLSConfig:       serverTLSConfig(),
		Conn:            udpConn,
		Outbound:        serverOb,
		Authenticator:   auth,
		TCPStallTimeout: 2 * time.Second,
	})
	assert.NoError(t, err)
	defer s.Close()
	go s.Serve()

	// Stalled targets: one end of an unbuffered pipe whose other end is never
	// read, so every write into it blocks. One stream can only fill its own
	// receive window (8 MB by default); a few of them use up the
	// connection-level window (20 MB by default).
	const stalledStreams = 4
	for i := 0; i < stalledStreams; i++ {
		stalledConn, stalledPeer := net.Pipe()
		defer stalledPeer.Close()
		serverOb.EXPECT().TCP("stalled:80").Return(stalledConn, nil).Once()
	}

	// A working target for the follow-up request.
	echoListener, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	echo := &tcpEchoServer{Listener: echoListener}
	defer echo.Close()
	go echo.Serve()
	serverOb.EXPECT().TCP("echo:80").RunAndReturn(func(string) (net.Conn, error) {
		return net.Dial("tcp", echoListener.Addr().String())
	}).Once()

	c, _, err := client.NewClient(&client.Config{
		ServerAddr: udpAddr,
		TLSConfig:  client.TLSConfig{InsecureSkipVerify: true},
	})
	assert.NoError(t, err)
	defer c.Close()

	// Upload into the stalled targets until the windows are used up. The
	// client's writers block and are left blocked, as a client whose local
	// connections hang would.
	for i := 0; i < stalledStreams; i++ {
		stalled, err := c.TCP("stalled:80")
		assert.NoError(t, err)
		go func() {
			buf := make([]byte, 64*1024)
			for j := 0; j < 16*16; j++ { // 16 MB per stream
				if _, err := stalled.Write(buf); err != nil {
					return
				}
			}
		}()
	}
	time.Sleep(time.Second)

	// A new request on the same connection must work once the stall timeout
	// has released the stalled stream.
	done := make(chan error, 1)
	go func() {
		conn, err := c.TCP("echo:80")
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		if _, err := conn.Write([]byte("ping")); err != nil {
			done <- err
			return
		}
		buf := make([]byte, 4)
		_, err = io.ReadFull(conn, buf)
		if err == nil && string(buf) != "ping" {
			err = io.ErrUnexpectedEOF
		}
		done <- err
	}()
	select {
	case err := <-done:
		assert.NoError(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("a new request did not complete while another stream's target was stalled")
	}
}
