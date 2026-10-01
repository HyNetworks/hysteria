package integration_tests

import (
	"io"
	"net"
	"testing"

	"github.com/apernet/hysteria/core/v2/client"
	"github.com/apernet/hysteria/core/v2/internal/integration_tests/mocks"
	"github.com/apernet/hysteria/core/v2/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestClientServerHookTCP(t *testing.T) {
	fakeEchoAddr := "hahanope:6666"
	realEchoAddr := "127.0.0.1:22333"

	// Create server
	udpConn, udpAddr, err := serverConn()
	assert.NoError(t, err)
	auth := mocks.NewMockAuthenticator(t)
	auth.EXPECT().Authenticate(mock.Anything, mock.Anything, mock.Anything).Return(true, "nobody")
	hook := mocks.NewMockRequestHook(t)
	hook.EXPECT().Check(false, fakeEchoAddr).Return(true).Once()
	hook.EXPECT().TCP(mock.Anything, mock.Anything).RunAndReturn(func(stream server.HyStream, s *string) ([]byte, error) {
		assert.Equal(t, fakeEchoAddr, *s)
		// Change the address
		*s = realEchoAddr
		// Read the first 5 bytes and replace them with "byeee"
		data := make([]byte, 5)
		_, err := io.ReadFull(stream, data)
		if err != nil {
			return nil, err
		}
		assert.Equal(t, []byte("hello"), data)
		return []byte("byeee"), nil
	}).Once()
	s, err := server.NewServer(&server.Config{
		TLSConfig:     serverTLSConfig(),
		Conn:          udpConn,
		RequestHook:   hook,
		Authenticator: auth,
	})
	assert.NoError(t, err)
	defer s.Close()
	go s.Serve()

	// Create TCP echo server
	echoListener, err := net.Listen("tcp", realEchoAddr)
	assert.NoError(t, err)
	echoServer := &tcpEchoServer{Listener: echoListener}
	defer echoServer.Close()
	go echoServer.Serve()

	// Create client
	c, _, err := client.NewClient(&client.Config{
		ServerAddr: udpAddr,
		TLSConfig:  client.TLSConfig{InsecureSkipVerify: true},
	})
	assert.NoError(t, err)
	defer c.Close()

	// Dial TCP
	conn, err := c.TCP(fakeEchoAddr)
	assert.NoError(t, err)
	defer conn.Close()

	// Send and receive data
	sData := []byte("hello world")
	_, err = conn.Write(sData)
	assert.NoError(t, err)
	rData := make([]byte, len(sData))
	_, err = io.ReadFull(conn, rData)
	assert.NoError(t, err)
	assert.Equal(t, []byte("byeee world"), rData)
}

func TestClientServerHookUDP(t *testing.T) {
	fakeEchoAddr := "hahanope:6666"
	realEchoAddr := "127.0.0.1:22333"

	// Create server
	udpConn, udpAddr, err := serverConn()
	assert.NoError(t, err)
	auth := mocks.NewMockAuthenticator(t)
	auth.EXPECT().Authenticate(mock.Anything, mock.Anything, mock.Anything).Return(true, "nobody")
	hook := mocks.NewMockRequestHook(t)
	hook.EXPECT().Check(true, fakeEchoAddr).Return(true).Twice()
	hook.EXPECT().UDP(mock.Anything, mock.Anything).RunAndReturn(func(packets [][]byte, s *string) (bool, error) {
		assert.Equal(t, fakeEchoAddr, *s)
		if len(packets) == 1 {
			// Hold the first packet back
			assert.Equal(t, [][]byte{[]byte("hello")}, packets)
			return false, nil
		}
		assert.Equal(t, [][]byte{[]byte("hello"), []byte(" world")}, packets)
		// Change the address
		*s = realEchoAddr
		return true, nil
	}).Twice()
	s, err := server.NewServer(&server.Config{
		TLSConfig:     serverTLSConfig(),
		Conn:          udpConn,
		RequestHook:   hook,
		Authenticator: auth,
	})
	assert.NoError(t, err)
	defer s.Close()
	go s.Serve()

	// Create UDP echo server
	echoConn, err := net.ListenPacket("udp", realEchoAddr)
	assert.NoError(t, err)
	echoServer := &udpEchoServer{Conn: echoConn}
	defer echoServer.Close()
	go echoServer.Serve()

	// Create client
	c, _, err := client.NewClient(&client.Config{
		ServerAddr: udpAddr,
		TLSConfig:  client.TLSConfig{InsecureSkipVerify: true},
	})
	assert.NoError(t, err)
	defer c.Close()

	// Listen UDP
	conn, err := c.UDP()
	assert.NoError(t, err)
	defer conn.Close()

	// Send and receive data, both held packets should reach the real echo server
	for _, sData := range [][]byte{[]byte("hello"), []byte(" world")} {
		err = conn.Send(sData, fakeEchoAddr)
		assert.NoError(t, err)
	}
	for _, sData := range [][]byte{[]byte("hello"), []byte(" world")} {
		rData, rAddr, err := conn.Receive()
		assert.NoError(t, err)
		assert.Equal(t, sData, rData)
		// Hook address change is transparent,
		// the client should still see the fake echo address it sent packets to
		assert.Equal(t, fakeEchoAddr, rAddr)
	}

	// Subsequent packets should also be sent to the real echo server
	sData := []byte("never stop fighting")
	err = conn.Send(sData, fakeEchoAddr)
	assert.NoError(t, err)
	rData, rAddr, err := conn.Receive()
	assert.NoError(t, err)
	assert.Equal(t, sData, rData)
	assert.Equal(t, fakeEchoAddr, rAddr)
}
