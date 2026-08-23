package utils_test

import (
	"io"
	"net"
	"time"

	"github.com/apernet/hysteria/core/v2/client"
)

var _ client.Client = (*MockEchoHyClient)(nil)

type MockEchoHyClient struct{}

func (c *MockEchoHyClient) TCP(addr string) (net.Conn, error) {
	return &mockEchoTCPConn{
		BufChan: make(chan []byte, 10),
	}, nil
}

func (c *MockEchoHyClient) UDP() (client.HyUDPConn, error) {
	return &mockEchoUDPConn{
		BufChan: make(chan mockEchoUDPPacket, 10),
	}, nil
}

func (c *MockEchoHyClient) PPP(dataStreams, maxFrameSize int) (*client.PPPConn, error) {
	return nil, io.ErrClosedPipe
}

func (c *MockEchoHyClient) RemoteAddr() net.Addr {
	return nil
}

func (c *MockEchoHyClient) Close() error {
	return nil
}

type mockEchoTCPConn struct {
	BufChan chan []byte
}

func (c *mockEchoTCPConn) Read(b []byte) (n int, err error) {
	buf := <-c.BufChan
	if buf == nil {
		// EOF
		return 0, io.EOF
	}
	return copy(b, buf), nil
}

func (c *mockEchoTCPConn) Write(b []byte) (n int, err error) {
	c.BufChan <- b
	return len(b), nil
}

func (c *mockEchoTCPConn) Close() error {
	close(c.BufChan)
	return nil
}

func (c *mockEchoTCPConn) LocalAddr() net.Addr {
	// Not implemented
	return nil
}

func (c *mockEchoTCPConn) RemoteAddr() net.Addr {
	// Not implemented
	return nil
}

func (c *mockEchoTCPConn) SetDeadline(t time.Time) error {
	// Not implemented
	return nil
}

func (c *mockEchoTCPConn) SetReadDeadline(t time.Time) error {
	// Not implemented
	return nil
}

func (c *mockEchoTCPConn) SetWriteDeadline(t time.Time) error {
	// Not implemented
	return nil
}

type mockEchoUDPPacket struct {
	Data []byte
	Addr string
}

type mockEchoUDPConn struct {
	BufChan chan mockEchoUDPPacket
}

func (c *mockEchoUDPConn) Receive() ([]byte, string, error) {
	p := <-c.BufChan
	if p.Data == nil {
		// EOF
		return nil, "", io.EOF
	}
	return p.Data, p.Addr, nil
}

func (c *mockEchoUDPConn) Send(bytes []byte, s string) error {
	c.BufChan <- mockEchoUDPPacket{
		Data: bytes,
		Addr: s,
	}
	return nil
}

func (c *mockEchoUDPConn) Close() error {
	close(c.BufChan)
	return nil
}
