package integration_tests

import (
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apernet/hysteria/core/v2/client"
	"github.com/apernet/hysteria/core/v2/internal/integration_tests/mocks"
	"github.com/apernet/hysteria/core/v2/server"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type gatedOutbound struct {
	blocked     string
	checkCalls  atomic.Int32
	dialedAddrs atomic.Int32
}

func (o *gatedOutbound) TCP(info *server.RequestInfo, reqAddr string) (net.Conn, error) {
	return net.Dial("tcp", reqAddr)
}

func (o *gatedOutbound) UDP(info *server.RequestInfo, reqAddr string) (server.UDPConn, error) {
	if reqAddr == o.blocked {
		return nil, errors.New("rejected")
	}
	o.dialedAddrs.Add(1)
	c, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}
	return &gatedUDPConn{UDPConn: c}, nil
}

func (o *gatedOutbound) CheckUDP(info *server.RequestInfo, reqAddr string) error {
	o.checkCalls.Add(1)
	if reqAddr == o.blocked {
		return errors.New("rejected")
	}
	return nil
}

type gatedUDPConn struct {
	*net.UDPConn
}

func (c *gatedUDPConn) ReadFrom(b []byte) (int, string, error) {
	n, addr, err := c.UDPConn.ReadFrom(b)
	if addr != nil {
		return n, addr.String(), err
	}
	return n, "", err
}

func (c *gatedUDPConn) WriteTo(b []byte, addr string) (int, error) {
	uAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return 0, err
	}
	return c.UDPConn.WriteTo(b, uAddr)
}

func TestClientServerUDPACLBypass(t *testing.T) {
	const allowed, blocked = "127.0.0.1:22444", "127.0.0.1:22445"
	ob := &gatedOutbound{blocked: blocked}

	udpConn, udpAddr, err := serverConn()
	assert.NoError(t, err)
	auth := mocks.NewMockAuthenticator(t)
	auth.EXPECT().Authenticate(mock.Anything, mock.Anything, mock.Anything).Return(true, "nobody")
	s, err := server.NewServer(&server.Config{
		TLSConfig:     serverTLSConfig(),
		Conn:          udpConn,
		Authenticator: auth,
		Outbound:      ob,
	})
	assert.NoError(t, err)
	defer s.Close()
	go s.Serve()

	allowedConn, err := net.ListenPacket("udp", allowed)
	assert.NoError(t, err)
	defer allowedConn.Close()
	go (&udpEchoServer{Conn: allowedConn}).Serve()

	blockedConn, err := net.ListenPacket("udp", blocked)
	assert.NoError(t, err)
	defer blockedConn.Close()
	go (&udpEchoServer{Conn: blockedConn}).Serve()

	c, _, err := client.NewClient(&client.Config{
		ServerAddr: udpAddr,
		TLSConfig:  client.TLSConfig{InsecureSkipVerify: true},
	})
	assert.NoError(t, err)
	defer c.Close()

	conn, err := c.UDP()
	assert.NoError(t, err)
	defer conn.Close()

	assert.NoError(t, conn.Send([]byte("hello"), allowed))
	rData, rAddr, err := conn.Receive()
	assert.NoError(t, err)
	assert.Equal(t, []byte("hello"), rData)
	assert.Equal(t, allowed, rAddr)

	assert.NoError(t, conn.Send([]byte("ssrf"), blocked))

	done := make(chan struct{})
	var leakedAddr string
	go func() {
		_, addr, err := conn.Receive()
		if err == nil {
			leakedAddr = addr
		}
		close(done)
	}()
	select {
	case <-done:
		assert.NotEqual(t, blocked, leakedAddr, "ACL bypass: blocked destination relayed")
	case <-time.After(500 * time.Millisecond):
	}

	assert.GreaterOrEqual(t, ob.checkCalls.Load(), int32(1), "CheckUDP not invoked for subsequent packet")
	assert.Equal(t, int32(1), ob.dialedAddrs.Load(), "outbound dial must happen only on first allowed destination")
}

func TestClientServerUDPACLMultiDestAllowed(t *testing.T) {
	const dest1, dest2 = "127.0.0.1:22448", "127.0.0.1:22449"
	ob := &gatedOutbound{blocked: ""}

	udpConn, udpAddr, err := serverConn()
	assert.NoError(t, err)
	auth := mocks.NewMockAuthenticator(t)
	auth.EXPECT().Authenticate(mock.Anything, mock.Anything, mock.Anything).Return(true, "nobody")
	s, err := server.NewServer(&server.Config{
		TLSConfig:     serverTLSConfig(),
		Conn:          udpConn,
		Authenticator: auth,
		Outbound:      ob,
	})
	assert.NoError(t, err)
	defer s.Close()
	go s.Serve()

	for _, addr := range []string{dest1, dest2} {
		ec, err := net.ListenPacket("udp", addr)
		assert.NoError(t, err)
		defer ec.Close()
		go (&udpEchoServer{Conn: ec}).Serve()
	}

	c, _, err := client.NewClient(&client.Config{
		ServerAddr: udpAddr,
		TLSConfig:  client.TLSConfig{InsecureSkipVerify: true},
	})
	assert.NoError(t, err)
	defer c.Close()

	conn, err := c.UDP()
	assert.NoError(t, err)
	defer conn.Close()

	for _, addr := range []string{dest1, dest2} {
		assert.NoError(t, conn.Send([]byte("hi"), addr))
		rData, rAddr, err := conn.Receive()
		assert.NoError(t, err)
		assert.Equal(t, []byte("hi"), rData)
		assert.Equal(t, addr, rAddr)
	}
}
