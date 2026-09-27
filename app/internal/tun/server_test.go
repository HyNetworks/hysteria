package tun

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/apernet/hysteria/app/v2/internal/utils_test"
	"github.com/apernet/hysteria/core/v2/client"
)

type eventRecord struct {
	addr, reqAddr string
	err           error
}

type recordingEventLogger struct {
	tcpRequest chan eventRecord
	tcpError   chan eventRecord
	udpRequest chan eventRecord
	udpError   chan eventRecord
}

func newRecordingEventLogger() *recordingEventLogger {
	return &recordingEventLogger{
		tcpRequest: make(chan eventRecord, 1),
		tcpError:   make(chan eventRecord, 1),
		udpRequest: make(chan eventRecord, 1),
		udpError:   make(chan eventRecord, 1),
	}
}

func (l *recordingEventLogger) TCPRequest(addr, reqAddr string) {
	l.tcpRequest <- eventRecord{addr: addr, reqAddr: reqAddr}
}

func (l *recordingEventLogger) TCPError(addr, reqAddr string, err error) {
	l.tcpError <- eventRecord{addr: addr, reqAddr: reqAddr, err: err}
}

func (l *recordingEventLogger) UDPRequest(addr string) {
	l.udpRequest <- eventRecord{addr: addr}
}

func (l *recordingEventLogger) UDPError(addr string, err error) {
	l.udpError <- eventRecord{addr: addr, err: err}
}

func receive[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(5 * time.Second):
		t.Fatal("timed out")
		panic("unreachable")
	}
}

func TestHandlerTCP(t *testing.T) {
	events := newRecordingEventLogger()
	h := &tunHandler{&Server{
		HyClient:    &utils_test.MockEchoHyClient{},
		EventLogger: events,
	}}
	local, stackSide := net.Pipe()
	source := M.ParseSocksaddr("100.100.100.101:40000")
	destination := M.ParseSocksaddr("[2001:db8::1]:443")
	closed := make(chan error, 1)
	go h.NewConnectionEx(context.Background(), stackSide, source, destination, func(err error) {
		closed <- err
	})

	assert.Equal(t, eventRecord{addr: "100.100.100.101:40000", reqAddr: "[2001:db8::1]:443"}, receive(t, events.tcpRequest))
	_, err := local.Write([]byte("hello"))
	require.NoError(t, err)
	recv := make([]byte, 5)
	_, err = io.ReadFull(local, recv)
	require.NoError(t, err)
	assert.Equal(t, "hello", string(recv))

	_ = local.Close()
	assert.NoError(t, receive(t, closed))
	assert.Equal(t, eventRecord{addr: "100.100.100.101:40000", reqAddr: "[2001:db8::1]:443"}, receive(t, events.tcpError))
}

func TestHandlerTCPServerClosed(t *testing.T) {
	events := newRecordingEventLogger()
	h := &tunHandler{&Server{
		HyClient:    &utils_test.MockEchoHyClient{},
		EventLogger: events,
	}}
	local, stackSide := net.Pipe()
	defer local.Close()
	ctx, cancel := context.WithCancel(context.Background())
	go h.NewConnectionEx(ctx, stackSide, M.ParseSocksaddr("100.100.100.101:40000"), M.ParseSocksaddr("1.1.1.1:80"), nil)
	receive(t, events.tcpRequest)

	cancel()
	assert.NoError(t, receive(t, events.tcpError).err)
	// The connection from the stack must be closed as well
	_, err := local.Read(make([]byte, 1))
	assert.ErrorIs(t, err, io.EOF)
}

func TestHandlerTCPDialError(t *testing.T) {
	events := newRecordingEventLogger()
	dialErr := errors.New("dial failed")
	h := &tunHandler{&Server{
		HyClient:    failingHyClient{dialErr},
		EventLogger: events,
	}}
	local, stackSide := net.Pipe()
	defer local.Close()
	go h.NewConnectionEx(context.Background(), stackSide, M.ParseSocksaddr("100.100.100.101:40000"), M.ParseSocksaddr("1.1.1.1:80"), nil)
	receive(t, events.tcpRequest)
	assert.ErrorIs(t, receive(t, events.tcpError).err, dialErr)
	_, err := local.Read(make([]byte, 1))
	assert.ErrorIs(t, err, io.EOF)
}

func TestHandlerUDP(t *testing.T) {
	events := newRecordingEventLogger()
	h := &tunHandler{&Server{
		HyClient:    &utils_test.MockEchoHyClient{},
		EventLogger: events,
	}}
	conn := newMockPacketConn()
	source := M.ParseSocksaddr("100.100.100.101:40000")
	closed := make(chan error, 1)
	go h.NewPacketConnectionEx(context.Background(), conn, source, M.ParseSocksaddr("1.1.1.1:53"), func(err error) {
		closed <- err
	})
	assert.Equal(t, "100.100.100.101:40000", receive(t, events.udpRequest).addr)

	// The echo client sends every packet back from the address it was sent to
	for _, dst := range []string{"1.1.1.1:53", "8.8.8.8:53"} {
		conn.in <- mockPacket{data: []byte("query " + dst), addr: M.ParseSocksaddr(dst)}
		p := receive(t, conn.out)
		assert.Equal(t, "query "+dst, string(p.data))
		assert.Equal(t, netip.MustParseAddrPort(dst), p.addr.AddrPort())
	}

	// Closing the session from the stack side (idle timeout) is not an error
	_ = conn.Close()
	assert.NoError(t, receive(t, closed))
	assert.NoError(t, receive(t, events.udpError).err)
}

func TestHandlerUDPSkipsNonIPSource(t *testing.T) {
	events := newRecordingEventLogger()
	rc := &scriptedUDPConn{packets: make(chan scriptedPacket, 2)}
	rc.packets <- scriptedPacket{data: []byte("dropped"), addr: "example.com:53"}
	rc.packets <- scriptedPacket{data: []byte("delivered"), addr: "1.1.1.1:53"}
	h := &tunHandler{&Server{
		HyClient:    scriptedHyClient{rc},
		EventLogger: events,
	}}
	conn := newMockPacketConn()
	defer conn.Close()
	go h.NewPacketConnectionEx(context.Background(), conn, M.ParseSocksaddr("100.100.100.101:40000"), M.ParseSocksaddr("1.1.1.1:53"), nil)
	p := receive(t, conn.out)
	assert.Equal(t, "delivered", string(p.data))
	assert.Equal(t, "1.1.1.1:53", p.addr.String())
}

type failingHyClient struct {
	err error
}

func (c failingHyClient) TCP(addr string) (net.Conn, error) {
	return nil, c.err
}

func (c failingHyClient) UDP() (client.HyUDPConn, error) {
	return nil, c.err
}

func (c failingHyClient) Close() error {
	return nil
}

type scriptedPacket struct {
	data []byte
	addr string
}

type scriptedHyClient struct {
	udp *scriptedUDPConn
}

func (c scriptedHyClient) TCP(addr string) (net.Conn, error) {
	return nil, errors.New("not implemented")
}

func (c scriptedHyClient) UDP() (client.HyUDPConn, error) {
	return c.udp, nil
}

func (c scriptedHyClient) Close() error {
	return nil
}

// scriptedUDPConn replays packets, then blocks until closed.
type scriptedUDPConn struct {
	packets chan scriptedPacket
}

func (c *scriptedUDPConn) Receive() ([]byte, string, error) {
	p, ok := <-c.packets
	if !ok {
		return nil, "", io.EOF
	}
	return p.data, p.addr, nil
}

func (c *scriptedUDPConn) Send([]byte, string) error {
	return nil
}

func (c *scriptedUDPConn) Close() error {
	close(c.packets)
	return nil
}

type mockPacket struct {
	data []byte
	addr M.Socksaddr
}

// mockPacketConn stands in for a UDP session of the system stack, which
// reports io.ErrClosedPipe from ReadPacket once the session is closed.
type mockPacketConn struct {
	in     chan mockPacket
	out    chan mockPacket
	closed chan struct{}
}

func newMockPacketConn() *mockPacketConn {
	return &mockPacketConn{
		in:     make(chan mockPacket, 10),
		out:    make(chan mockPacket, 10),
		closed: make(chan struct{}),
	}
}

func (c *mockPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	select {
	case p := <-c.in:
		_, err := buffer.Write(p.data)
		return p.addr, err
	case <-c.closed:
		return M.Socksaddr{}, io.ErrClosedPipe
	}
}

func (c *mockPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	defer buffer.Release()
	c.out <- mockPacket{data: append([]byte(nil), buffer.Bytes()...), addr: destination}
	return nil
}

func (c *mockPacketConn) Close() error {
	select {
	case <-c.closed:
	default:
		close(c.closed)
	}
	return nil
}

func (c *mockPacketConn) LocalAddr() net.Addr {
	return nil
}

func (c *mockPacketConn) SetDeadline(time.Time) error {
	return nil
}

func (c *mockPacketConn) SetReadDeadline(time.Time) error {
	return nil
}

func (c *mockPacketConn) SetWriteDeadline(time.Time) error {
	return nil
}
