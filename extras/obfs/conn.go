package obfs

import (
	"errors"
	"net"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/ipv4"
)

const udpBufferSize = 2048 // QUIC packets are at most 1500 bytes long, so 2k should be more than enough

// obfuscator wraps a per-packet, length-preserving cipher.
// Obfuscate / Deobfuscate return the number of bytes written to out.
// If a packet is not valid, the methods should return 0.
type obfuscator interface {
	Obfuscate(in, out []byte) int
	Deobfuscate(in, out []byte) int
}

var _ net.PacketConn = (*obfsPacketConn)(nil)

type obfsPacketConn struct {
	Conn net.PacketConn
	Obfs obfuscator

	readBuf    []byte
	readMutex  sync.Mutex
	writeBuf   []byte
	writeMutex sync.Mutex
}

// udpLikePacketConn is the subset of *net.UDPConn methods that quic-go relies
// on for UDP-specific optimizations (DF/PMTU detection and recv/send buffer
// sizing). Anything that satisfies this interface — including a wrapper such
// as realm.PunchPacketConn that proxies these calls down to a *net.UDPConn —
// will keep those optimizations when wrapped in obfs.
type udpLikePacketConn interface {
	net.PacketConn
	SyscallConn() (syscall.RawConn, error)
	SetReadBuffer(int) error
	SetWriteBuffer(int) error
}

type oobCapablePacketConn interface {
	udpLikePacketConn
	ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr *net.UDPAddr, err error)
	WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error)
}

type oobMessagePacketConn interface {
	ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr *net.UDPAddr, err error)
}

// obfsPacketConnUDP is a special case of obfsPacketConn that wraps a
// UDP-flavored PacketConn. We pass additional methods through to quic-go to
// enable UDP-specific optimizations.
type obfsPacketConnUDP struct {
	*obfsPacketConn
	UDPConn udpLikePacketConn
}

type obfsPacketConnOOB struct {
	*obfsPacketConnUDP
	OOBConn oobCapablePacketConn
}

// wrapPacketConn enables per-packet obfuscation on a net.PacketConn.
// The obfuscation is transparent to the caller - the n bytes returned by
// ReadFrom and WriteTo are the number of original bytes, not after
// obfuscation/deobfuscation.
func wrapPacketConn(conn net.PacketConn, ob obfuscator) net.PacketConn {
	opc := &obfsPacketConn{
		Conn:     conn,
		Obfs:     ob,
		readBuf:  make([]byte, udpBufferSize),
		writeBuf: make([]byte, udpBufferSize),
	}
	if oobConn, ok := conn.(oobCapablePacketConn); ok {
		return &obfsPacketConnOOB{
			obfsPacketConnUDP: &obfsPacketConnUDP{
				obfsPacketConn: opc,
				UDPConn:        oobConn,
			},
			OOBConn: oobConn,
		}
	}
	if udpConn, ok := conn.(udpLikePacketConn); ok {
		return &obfsPacketConnUDP{
			obfsPacketConn: opc,
			UDPConn:        udpConn,
		}
	} else {
		return opc
	}
}

func (c *obfsPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	for {
		c.readMutex.Lock()
		n, addr, err = c.Conn.ReadFrom(c.readBuf)
		if n <= 0 {
			c.readMutex.Unlock()
			return n, addr, err
		}
		n = c.Obfs.Deobfuscate(c.readBuf[:n], p)
		c.readMutex.Unlock()
		if n > 0 || err != nil {
			return n, addr, err
		}
		// Invalid packet, try again
	}
}

func (c *obfsPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	c.writeMutex.Lock()
	nn := c.Obfs.Obfuscate(p, c.writeBuf)
	_, err = c.Conn.WriteTo(c.writeBuf[:nn], addr)
	c.writeMutex.Unlock()
	if err == nil {
		n = len(p)
	}
	return n, err
}

func (c *obfsPacketConn) Close() error {
	return c.Conn.Close()
}

func (c *obfsPacketConn) LocalAddr() net.Addr {
	return c.Conn.LocalAddr()
}

func (c *obfsPacketConn) SetDeadline(t time.Time) error {
	return c.Conn.SetDeadline(t)
}

func (c *obfsPacketConn) SetReadDeadline(t time.Time) error {
	return c.Conn.SetReadDeadline(t)
}

func (c *obfsPacketConn) SetWriteDeadline(t time.Time) error {
	return c.Conn.SetWriteDeadline(t)
}

// UDP-specific methods below

func (c *obfsPacketConnUDP) SetReadBuffer(bytes int) error {
	return c.UDPConn.SetReadBuffer(bytes)
}

func (c *obfsPacketConnUDP) SetWriteBuffer(bytes int) error {
	return c.UDPConn.SetWriteBuffer(bytes)
}

func (c *obfsPacketConnUDP) SyscallConn() (syscall.RawConn, error) {
	return c.UDPConn.SyscallConn()
}

func (c *obfsPacketConnOOB) ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr *net.UDPAddr, err error) {
	for {
		c.readMutex.Lock()
		n, oobn, flags, addr, err = c.OOBConn.ReadMsgUDP(c.readBuf, oob)
		if n <= 0 {
			c.readMutex.Unlock()
			return n, oobn, flags, addr, err
		}
		n = c.Obfs.Deobfuscate(c.readBuf[:n], b)
		c.readMutex.Unlock()
		if n > 0 || err != nil {
			return n, oobn, flags, addr, err
		}
		// Invalid packet, try again
	}
}

func (c *obfsPacketConnOOB) WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error) {
	c.writeMutex.Lock()
	nn := c.Obfs.Obfuscate(b, c.writeBuf)
	_, oobn, err = c.OOBConn.WriteMsgUDP(c.writeBuf[:nn], oob, addr)
	c.writeMutex.Unlock()
	if err == nil {
		n = len(b)
	}
	return n, oobn, err
}

func (c *obfsPacketConnOOB) ReadBatch(ms []ipv4.Message, flags int) (int, error) {
	return readBatchOne(c, ms, flags)
}

func readBatchOne(c oobMessagePacketConn, ms []ipv4.Message, _ int) (int, error) {
	if len(ms) == 0 {
		return 0, nil
	}
	if len(ms[0].Buffers) == 0 {
		return 0, errors.New("obfs: ReadBatch requires a data buffer")
	}
	n, oobn, msgFlags, addr, err := c.ReadMsgUDP(ms[0].Buffers[0], ms[0].OOB)
	if err != nil {
		return 0, err
	}
	ms[0].N = n
	ms[0].NN = oobn
	ms[0].Flags = msgFlags
	ms[0].Addr = addr
	return 1, nil
}
