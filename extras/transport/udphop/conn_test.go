package udphop

import (
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type timeoutError struct{}

func (timeoutError) Error() string   { return "timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

type stubPacketConn struct {
	mu                    sync.Mutex
	readResults           []readResult
	setDeadlineCalls      []time.Time
	setReadDeadlineCalls  []time.Time
	setWriteDeadlineCalls []time.Time
	closed                bool
}

type readResult struct {
	n    int
	addr net.Addr
	err  error
}

type observedPacketConn struct {
	*stubPacketConn
	read chan struct{}
}

func (c *observedPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := c.stubPacketConn.ReadFrom(p)
	select {
	case c.read <- struct{}{}:
	default:
	}
	return n, addr, err
}

func TestCloseUnblocksTimeoutDeliveryToFullQueue(t *testing.T) {
	conn := &observedPacketConn{
		stubPacketConn: &stubPacketConn{readResults: []readResult{{err: timeoutError{}}}},
		read:           make(chan struct{}, 1),
	}
	u := &udpHopPacketConn{
		currentConn: conn,
		recvQueue:   make(chan *udpPacket, 1),
		closeChan:   make(chan struct{}),
		bufPool: sync.Pool{New: func() interface{} {
			return make([]byte, udpBufferSize)
		}},
	}
	u.recvQueue <- &udpPacket{}
	done := make(chan struct{})
	go func() {
		u.recvLoop(conn)
		close(done)
	}()
	select {
	case <-conn.read:
	case <-time.After(time.Second):
		t.Fatal("receive loop did not read the timeout")
	}
	require.NoError(t, u.Close())
	select {
	case <-done:
	case <-time.After(time.Second):
		// Drain the queued packet so the test does not leave a blocked receiver.
		<-u.recvQueue
		<-done
		t.Fatal("receive loop remained blocked on timeout delivery after Close")
	}
}

func (c *stubPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, nil, net.ErrClosed
	}
	if len(c.readResults) == 0 {
		return 0, nil, net.ErrClosed
	}
	r := c.readResults[0]
	c.readResults = c.readResults[1:]
	if r.n > 0 {
		copy(p, []byte("payload")[:r.n])
	}
	return r.n, r.addr, r.err
}

func (c *stubPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) { return len(p), nil }
func (c *stubPacketConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return nil
}
func (c *stubPacketConn) LocalAddr() net.Addr { return &net.UDPAddr{} }
func (c *stubPacketConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.setDeadlineCalls = append(c.setDeadlineCalls, t)
	return nil
}

func (c *stubPacketConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.setReadDeadlineCalls = append(c.setReadDeadlineCalls, t)
	return nil
}

func (c *stubPacketConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.setWriteDeadlineCalls = append(c.setWriteDeadlineCalls, t)
	return nil
}

func TestRecvLoopTimeoutIsNotFatal(t *testing.T) {
	conn := &stubPacketConn{
		readResults: []readResult{
			{err: timeoutError{}},
			{n: 3, addr: &net.UDPAddr{}},
		},
	}
	u := &udpHopPacketConn{
		Addr:      &net.UDPAddr{},
		recvQueue: make(chan *udpPacket, 2),
		closeChan: make(chan struct{}),
		bufPool: sync.Pool{New: func() any {
			return make([]byte, udpBufferSize)
		}},
	}

	go u.recvLoop(conn)

	first := <-u.recvQueue
	require.Error(t, first.Err)
	require.True(t, errors.As(first.Err, new(net.Error)))

	second := <-u.recvQueue
	require.NoError(t, second.Err)
	require.Equal(t, 3, second.N)
	u.bufPool.Put(second.Buf)
}

func TestHopReappliesStoredDeadlines(t *testing.T) {
	firstConn := &stubPacketConn{}
	secondConn := &stubPacketConn{}
	listenCalls := 0
	u := &udpHopPacketConn{
		Addr:  &net.UDPAddr{},
		Addrs: []net.Addr{&net.UDPAddr{Port: 1}},
		ListenUDPFunc: func() (net.PacketConn, error) {
			listenCalls++
			if listenCalls == 1 {
				return secondConn, nil
			}
			return nil, errors.New("unexpected extra listen")
		},
		currentConn: firstConn,
		closeChan:   make(chan struct{}),
		bufPool: sync.Pool{New: func() any {
			return make([]byte, udpBufferSize)
		}},
	}

	deadline := time.Now().Add(time.Minute)
	readDeadline := time.Now().Add(2 * time.Minute)
	writeDeadline := time.Now().Add(3 * time.Minute)

	require.NoError(t, u.SetDeadline(deadline))
	require.NoError(t, u.SetReadDeadline(readDeadline))
	require.NoError(t, u.SetWriteDeadline(writeDeadline))

	u.hop(time.Second)

	require.Empty(t, secondConn.setDeadlineCalls)
	require.Equal(t, []time.Time{readDeadline}, secondConn.setReadDeadlineCalls)
	require.Equal(t, []time.Time{writeDeadline}, secondConn.setWriteDeadlineCalls)
}

func TestHopIntervalConfigNormalized(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		cfg, err := (HopIntervalConfig{}).normalized()
		require.NoError(t, err)
		require.Equal(t, defaultHopInterval, cfg.Min)
		require.Equal(t, defaultHopInterval, cfg.Max)
	})

	t.Run("rejects partial range", func(t *testing.T) {
		_, err := (HopIntervalConfig{Min: 10 * time.Second}).normalized()
		require.EqualError(t, err, "min and max hop interval must both be set")
	})

	t.Run("rejects reversed range", func(t *testing.T) {
		_, err := (HopIntervalConfig{Min: 30 * time.Second, Max: 10 * time.Second}).normalized()
		require.EqualError(t, err, "min hop interval must not be greater than max hop interval")
	})

	t.Run("rejects too short interval", func(t *testing.T) {
		_, err := (HopIntervalConfig{Min: 4 * time.Second, Max: 6 * time.Second}).normalized()
		require.EqualError(t, err, "hop interval must be at least 5 seconds")
	})
}

func TestNextHopIntervalWithinRange(t *testing.T) {
	u := &udpHopPacketConn{
		HopInterval: HopIntervalConfig{
			Min: 10 * time.Second,
			Max: 30 * time.Second,
		},
	}

	for i := 0; i < 1000; i++ {
		d := u.nextHopInterval()
		require.GreaterOrEqual(t, d, 10*time.Second)
		require.LessOrEqual(t, d, 30*time.Second)
	}
}
