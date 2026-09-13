package obfs

import (
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/ipv4"
)

// fakeUDPLikeConn satisfies udpLikePacketConn without being a *net.UDPConn,
// representing wrappers like realm.PunchPacketConn that proxy SyscallConn /
// Set{Read,Write}Buffer through to a real UDP socket.
type fakeUDPLikeConn struct{}

func (fakeUDPLikeConn) ReadFrom([]byte) (int, net.Addr, error) { return 0, nil, nil }
func (fakeUDPLikeConn) WriteTo([]byte, net.Addr) (int, error)  { return 0, nil }
func (fakeUDPLikeConn) Close() error                           { return nil }
func (fakeUDPLikeConn) LocalAddr() net.Addr                    { return &net.UDPAddr{} }
func (fakeUDPLikeConn) SetDeadline(time.Time) error            { return nil }
func (fakeUDPLikeConn) SetReadDeadline(time.Time) error        { return nil }
func (fakeUDPLikeConn) SetWriteDeadline(time.Time) error       { return nil }
func (fakeUDPLikeConn) SyscallConn() (syscall.RawConn, error)  { return nil, nil }
func (fakeUDPLikeConn) SetReadBuffer(int) error                { return nil }
func (fakeUDPLikeConn) SetWriteBuffer(int) error               { return nil }

type fakeOOBConn struct {
	fakeUDPLikeConn

	readData []byte
	readOOB  []byte
	readAddr *net.UDPAddr

	writtenData []byte
	writtenOOB  []byte
	writtenAddr *net.UDPAddr
}

func (c *fakeOOBConn) ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr *net.UDPAddr, err error) {
	n = copy(b, c.readData)
	oobn = copy(oob, c.readOOB)
	return n, oobn, 123, c.readAddr, nil
}

func (c *fakeOOBConn) WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error) {
	c.writtenData = append(c.writtenData[:0], b...)
	c.writtenOOB = append(c.writtenOOB[:0], oob...)
	c.writtenAddr = addr
	return len(b), len(oob), nil
}

type fakePlainConn struct{}

func (fakePlainConn) ReadFrom([]byte) (int, net.Addr, error) { return 0, nil, nil }
func (fakePlainConn) WriteTo([]byte, net.Addr) (int, error)  { return 0, nil }
func (fakePlainConn) Close() error                           { return nil }
func (fakePlainConn) LocalAddr() net.Addr                    { return &net.UDPAddr{} }
func (fakePlainConn) SetDeadline(time.Time) error            { return nil }
func (fakePlainConn) SetReadDeadline(time.Time) error        { return nil }
func (fakePlainConn) SetWriteDeadline(time.Time) error       { return nil }

type noopObfs struct{}

func (noopObfs) Obfuscate(in, out []byte) int   { return copy(out, in) }
func (noopObfs) Deobfuscate(in, out []byte) int { return copy(out, in) }

func TestWrapPacketConnUsesUDPVariantForUDPConn(t *testing.T) {
	udp, err := net.ListenUDP("udp", &net.UDPAddr{})
	require.NoError(t, err)
	defer udp.Close()

	wrapped := wrapPacketConn(udp, noopObfs{})
	_, ok := wrapped.(*obfsPacketConnOOB)
	assert.True(t, ok, "wrapping a *net.UDPConn should return *obfsPacketConnOOB")
}

func TestWrapPacketConnUsesUDPVariantForUDPLikeWrapper(t *testing.T) {
	wrapped := wrapPacketConn(fakeUDPLikeConn{}, noopObfs{})
	_, ok := wrapped.(*obfsPacketConnUDP)
	assert.True(t, ok, "wrapping a udpLikePacketConn should return *obfsPacketConnUDP")
}

func TestWrapPacketConnFallsBackForPlainPacketConn(t *testing.T) {
	wrapped := wrapPacketConn(fakePlainConn{}, noopObfs{})
	_, isUDP := wrapped.(*obfsPacketConnUDP)
	assert.False(t, isUDP, "wrapping a plain net.PacketConn should not return *obfsPacketConnUDP")
}

func TestObfsPacketConnOOBReadBatchAndWriteMsgUseWrapper(t *testing.T) {
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}
	inner := &fakeOOBConn{
		readData: []byte("plain"),
		readOOB:  []byte{1, 2, 3},
		readAddr: addr,
	}
	wrapped := wrapPacketConn(inner, noopObfs{})
	oobWrapped, ok := wrapped.(interface {
		oobCapablePacketConn
		ReadBatch([]ipv4.Message, int) (int, error)
	})
	require.True(t, ok, "OOB-capable inner conn should keep quic-go OOB methods")

	buf := make([]byte, 32)
	oob := make([]byte, 8)
	msgs := []ipv4.Message{{Buffers: [][]byte{buf}, OOB: oob}}
	n, err := oobWrapped.ReadBatch(msgs, 0)
	require.NoError(t, err)
	require.Equal(t, 1, n)
	require.Equal(t, 5, msgs[0].N)
	require.Equal(t, 3, msgs[0].NN)
	require.Equal(t, 123, msgs[0].Flags)
	require.Equal(t, addr, msgs[0].Addr)
	require.Equal(t, []byte("plain"), buf[:msgs[0].N])
	require.Equal(t, []byte{1, 2, 3}, oob[:msgs[0].NN])

	_, _, err = oobWrapped.WriteMsgUDP([]byte("reply"), []byte{9, 8}, addr)
	require.NoError(t, err)
	require.Equal(t, []byte("reply"), inner.writtenData)
	require.Equal(t, []byte{9, 8}, inner.writtenOOB)
	require.Equal(t, addr, inner.writtenAddr)
}

var _ interface {
	oobCapablePacketConn
	ReadBatch([]ipv4.Message, int) (int, error)
} = (*obfsPacketConnOOB)(nil)
