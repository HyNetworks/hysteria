package udphop

import (
	"errors"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strconv"
	"sync"
	"syscall"
	"time"
)

const (
	packetQueueSize = 1024
	udpBufferSize   = 2048 // QUIC packets are at most 1500 bytes long, so 2k should be more than enough

	defaultHopInterval = 30 * time.Second

	debugEnv = "HYSTERIA_UDPHOP_DEBUG"
)

type HopIntervalConfig struct {
	Min time.Duration
	Max time.Duration
}

type udpHopPacketConn struct {
	Addr          net.Addr
	Addrs         []net.Addr
	HopInterval   HopIntervalConfig
	ListenUDPFunc ListenUDPFunc

	connMutex   sync.RWMutex
	prevConn    net.PacketConn
	currentConn net.PacketConn
	addrIndex   int

	readBufferSize  int
	writeBufferSize int
	deadline        time.Time
	readDeadline    time.Time
	writeDeadline   time.Time

	recvQueue chan *udpPacket
	closeChan chan struct{}
	closed    bool

	bufPool sync.Pool
	debug   bool
}

type udpPacket struct {
	Buf  []byte
	N    int
	Addr net.Addr
	Err  error
}

type ListenUDPFunc = func() (net.PacketConn, error)

func NewUDPHopPacketConn(addr *UDPHopAddr, hopInterval HopIntervalConfig, listenUDPFunc ListenUDPFunc) (net.PacketConn, error) {
	hopInterval, err := hopInterval.normalized()
	if err != nil {
		return nil, err
	}
	if listenUDPFunc == nil {
		listenUDPFunc = func() (net.PacketConn, error) {
			return net.ListenUDP("udp", nil)
		}
	}
	addrs, err := addr.addrs()
	if err != nil {
		return nil, err
	}
	curConn, err := listenUDPFunc()
	if err != nil {
		return nil, err
	}
	debug, _ := strconv.ParseBool(os.Getenv(debugEnv))
	hConn := &udpHopPacketConn{
		Addr:          addr,
		Addrs:         addrs,
		HopInterval:   hopInterval,
		ListenUDPFunc: listenUDPFunc,
		prevConn:      nil,
		currentConn:   curConn,
		addrIndex:     rand.Intn(len(addrs)),
		recvQueue:     make(chan *udpPacket, packetQueueSize),
		closeChan:     make(chan struct{}),
		bufPool: sync.Pool{
			New: func() interface{} {
				return make([]byte, udpBufferSize)
			},
		},
		debug: debug,
	}
	if hConn.debug {
		hConn.debugPrint("Initialized: local=%s target=%s interval=%s", curConn.LocalAddr(), addr, hopInterval)
	}
	go hConn.recvLoop(curConn)
	go hConn.hopLoop()
	return hConn, nil
}

func (c HopIntervalConfig) normalized() (HopIntervalConfig, error) {
	if c.Min == 0 && c.Max == 0 {
		return HopIntervalConfig{Min: defaultHopInterval, Max: defaultHopInterval}, nil
	}
	if c.Min == 0 || c.Max == 0 {
		return HopIntervalConfig{}, errors.New("min and max hop interval must both be set")
	}
	if c.Min > c.Max {
		return HopIntervalConfig{}, errors.New("min hop interval must not be greater than max hop interval")
	}
	if c.Min < 5*time.Second {
		return HopIntervalConfig{}, errors.New("hop interval must be at least 5 seconds")
	}
	return c, nil
}

func (u *udpHopPacketConn) recvLoop(conn net.PacketConn) {
	for {
		buf := u.bufPool.Get().([]byte)
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			u.bufPool.Put(buf)
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				// Pass through timeout errors, but not permanent errors such as connection closed.
				// Connection close is normal as we close the old connection to exit this loop every time we hop.
				select {
				case u.recvQueue <- &udpPacket{nil, 0, nil, netErr}:
				case <-u.closeChan:
					return
				}
				continue
			}
			return
		}
		select {
		case u.recvQueue <- &udpPacket{buf, n, addr, nil}:
			// Packet successfully queued
		default:
			// Queue is full, drop the packet
			u.bufPool.Put(buf)
		}
	}
}

func (u *udpHopPacketConn) hopLoop() {
	next := u.nextHopInterval()
	timer := time.NewTimer(next)
	defer timer.Stop()
	for {
		select {
		case <-timer.C:
			hopInterval := next
			u.hop(hopInterval)
			next = u.nextHopInterval()
			timer.Reset(next)
		case <-u.closeChan:
			return
		}
	}
}

func (u *udpHopPacketConn) nextHopInterval() time.Duration {
	if u.HopInterval.Min == u.HopInterval.Max {
		return u.HopInterval.Min
	}
	return u.HopInterval.Min + time.Duration(rand.Int63n(int64(u.HopInterval.Max-u.HopInterval.Min)+1))
}

func (u *udpHopPacketConn) hop(hopInterval time.Duration) {
	u.connMutex.Lock()
	defer u.connMutex.Unlock()
	if u.closed {
		return
	}
	newConn, err := u.ListenUDPFunc()
	if err != nil {
		// Could be temporary, just skip this hop
		if u.debug {
			u.debugPrint("Hop skipped: listen failed: %v", err)
		}
		return
	}
	// We need to keep receiving packets from the previous connection,
	// because otherwise there will be packet loss due to the time gap
	// between we hop to a new port and the server acknowledges this change.
	// So we do the following:
	// Close prevConn,
	// move currentConn to prevConn,
	// set newConn as currentConn,
	// start recvLoop on newConn.
	if u.prevConn != nil {
		_ = u.prevConn.Close() // recvLoop for this conn will exit
	}
	u.prevConn = u.currentConn
	u.currentConn = newConn
	// Set buffer sizes if previously set
	if u.readBufferSize > 0 {
		_ = trySetReadBuffer(u.currentConn, u.readBufferSize)
	}
	if u.writeBufferSize > 0 {
		_ = trySetWriteBuffer(u.currentConn, u.writeBufferSize)
	}
	if !u.deadline.IsZero() {
		_ = u.currentConn.SetDeadline(u.deadline)
	}
	if !u.readDeadline.IsZero() {
		_ = u.currentConn.SetReadDeadline(u.readDeadline)
	}
	if !u.writeDeadline.IsZero() {
		_ = u.currentConn.SetWriteDeadline(u.writeDeadline)
	}
	go u.recvLoop(newConn)
	// Update addrIndex to a new random value
	prevRemote := u.Addrs[u.addrIndex]
	u.addrIndex = rand.Intn(len(u.Addrs))
	if u.debug {
		u.debugPrint("Hop after %s: local=%s -> %s remote=%s -> %s",
			formatHopInterval(hopInterval),
			u.prevConn.LocalAddr(), u.currentConn.LocalAddr(),
			prevRemote, u.Addrs[u.addrIndex])
	}
}

func (u *udpHopPacketConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	for {
		select {
		case p := <-u.recvQueue:
			if p.Err != nil {
				return 0, nil, p.Err
			}
			// Currently we do not check whether the packet is from
			// the server or not due to performance reasons.
			n := copy(b, p.Buf[:p.N])
			u.bufPool.Put(p.Buf)
			return n, u.Addr, nil
		case <-u.closeChan:
			return 0, nil, net.ErrClosed
		}
	}
}

func (u *udpHopPacketConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	u.connMutex.RLock()
	defer u.connMutex.RUnlock()
	if u.closed {
		return 0, net.ErrClosed
	}
	// Skip the check for now, always write to the server,
	// for the same reason as in ReadFrom.
	return u.currentConn.WriteTo(b, u.Addrs[u.addrIndex])
}

func (u *udpHopPacketConn) Close() error {
	u.connMutex.Lock()
	defer u.connMutex.Unlock()
	if u.closed {
		return nil
	}
	// Close prevConn and currentConn
	// Close closeChan to unblock ReadFrom & hopLoop
	// Set closed flag to true to prevent double close
	if u.prevConn != nil {
		_ = u.prevConn.Close()
	}
	err := u.currentConn.Close()
	close(u.closeChan)
	u.closed = true
	u.Addrs = nil // For GC
	return err
}

func (u *udpHopPacketConn) LocalAddr() net.Addr {
	u.connMutex.RLock()
	defer u.connMutex.RUnlock()
	return u.currentConn.LocalAddr()
}

func (u *udpHopPacketConn) SetDeadline(t time.Time) error {
	u.connMutex.Lock()
	defer u.connMutex.Unlock()
	u.deadline = t
	u.readDeadline = t
	u.writeDeadline = t
	if u.prevConn != nil {
		_ = u.prevConn.SetDeadline(t)
	}
	return u.currentConn.SetDeadline(t)
}

func (u *udpHopPacketConn) SetReadDeadline(t time.Time) error {
	u.connMutex.Lock()
	defer u.connMutex.Unlock()
	u.deadline = time.Time{}
	u.readDeadline = t
	if u.prevConn != nil {
		_ = u.prevConn.SetReadDeadline(t)
	}
	return u.currentConn.SetReadDeadline(t)
}

func (u *udpHopPacketConn) SetWriteDeadline(t time.Time) error {
	u.connMutex.Lock()
	defer u.connMutex.Unlock()
	u.deadline = time.Time{}
	u.writeDeadline = t
	if u.prevConn != nil {
		_ = u.prevConn.SetWriteDeadline(t)
	}
	return u.currentConn.SetWriteDeadline(t)
}

// UDP-specific methods below

func (u *udpHopPacketConn) SetReadBuffer(bytes int) error {
	u.connMutex.Lock()
	defer u.connMutex.Unlock()
	u.readBufferSize = bytes
	if u.prevConn != nil {
		_ = trySetReadBuffer(u.prevConn, bytes)
	}
	return trySetReadBuffer(u.currentConn, bytes)
}

func (u *udpHopPacketConn) SetWriteBuffer(bytes int) error {
	u.connMutex.Lock()
	defer u.connMutex.Unlock()
	u.writeBufferSize = bytes
	if u.prevConn != nil {
		_ = trySetWriteBuffer(u.prevConn, bytes)
	}
	return trySetWriteBuffer(u.currentConn, bytes)
}

func (u *udpHopPacketConn) SyscallConn() (syscall.RawConn, error) {
	u.connMutex.RLock()
	defer u.connMutex.RUnlock()
	sc, ok := u.currentConn.(syscall.Conn)
	if !ok {
		return nil, errors.New("not supported")
	}
	return sc.SyscallConn()
}

func trySetReadBuffer(pc net.PacketConn, bytes int) error {
	sc, ok := pc.(interface {
		SetReadBuffer(bytes int) error
	})
	if ok {
		return sc.SetReadBuffer(bytes)
	}
	return nil
}

func trySetWriteBuffer(pc net.PacketConn, bytes int) error {
	sc, ok := pc.(interface {
		SetWriteBuffer(bytes int) error
	})
	if ok {
		return sc.SetWriteBuffer(bytes)
	}
	return nil
}

func (u *udpHopPacketConn) debugPrint(format string, a ...any) {
	fmt.Printf("[UDPHop] [%s] %s\n",
		time.Now().Format("15:04:05"),
		fmt.Sprintf(format, a...))
}

func formatHopInterval(d time.Duration) string {
	seconds := d.Seconds()
	return fmt.Sprintf("%.2fs", seconds)
}
