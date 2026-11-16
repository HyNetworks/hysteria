package forwarding

import (
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/apernet/hysteria/core/v2/client"
)

const (
	udpBufferSize = 4096

	defaultTimeout      = 60 * time.Second
	idleCleanupInterval = 1 * time.Second
)

var atomicTimeBase = time.Now()

// atomicTime stores a time as an offset from atomicTimeBase, so that Set does not allocate.
type atomicTime struct {
	v atomic.Int64
}

func newAtomicTime(t time.Time) *atomicTime {
	a := &atomicTime{}
	a.Set(t)
	return a
}

func (t *atomicTime) Set(new time.Time) {
	t.v.Store(int64(new.Sub(atomicTimeBase)))
}

func (t *atomicTime) Get() time.Time {
	return atomicTimeBase.Add(time.Duration(t.v.Load()))
}

// sessionKey avoids calling String() on a UDP address for every packet.
type sessionKey struct {
	AddrPort netip.AddrPort
	String   string
}

func newSessionKey(addr net.Addr) sessionKey {
	if udpAddr, ok := addr.(*net.UDPAddr); ok {
		if addrPort := udpAddr.AddrPort(); addrPort.IsValid() {
			// Both forms of an IPv4 address must give the same key
			return sessionKey{AddrPort: netip.AddrPortFrom(addrPort.Addr().Unmap(), addrPort.Port())}
		}
	}
	return sessionKey{String: addr.String()}
}

type sessionEntry struct {
	HyConn  client.HyUDPConn
	Last    *atomicTime
	Timeout bool // true if the session is closed due to timeout
}

func (e *sessionEntry) Feed(data []byte, addr string) error {
	e.Last.Set(time.Now())
	return e.HyConn.Send(data, addr)
}

func (e *sessionEntry) ReceiveLoop(pc net.PacketConn, addr net.Addr) error {
	for {
		data, _, err := e.HyConn.Receive()
		if err != nil {
			return err
		}
		_, err = pc.WriteTo(data, addr)
		if err != nil {
			return err
		}
		e.Last.Set(time.Now())
	}
}

type UDPTunnel struct {
	HyClient    client.Client
	Remote      string
	Timeout     time.Duration
	EventLogger UDPEventLogger

	m     map[sessionKey]*sessionEntry // addr -> HyConn
	mutex sync.RWMutex
}

type UDPEventLogger interface {
	Connect(addr net.Addr)
	Error(addr net.Addr, err error)
}

func (t *UDPTunnel) Serve(pc net.PacketConn) error {
	t.m = make(map[sessionKey]*sessionEntry)

	stopCh := make(chan struct{})
	go t.idleCleanupLoop(stopCh)
	defer close(stopCh)
	defer t.cleanup(false)

	buf := make([]byte, udpBufferSize)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return err
		}
		t.feed(pc, addr, buf[:n])
	}
}

func (t *UDPTunnel) idleCleanupLoop(stopCh <-chan struct{}) {
	ticker := time.NewTicker(idleCleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			t.cleanup(true)
		case <-stopCh:
			return
		}
	}
}

func (t *UDPTunnel) cleanup(idleOnly bool) {
	// We use RLock here as we are only scanning the map, not deleting from it.
	t.mutex.RLock()
	defer t.mutex.RUnlock()

	timeout := t.Timeout
	if timeout == 0 {
		timeout = defaultTimeout
	}

	now := time.Now()
	for _, entry := range t.m {
		if !idleOnly || now.Sub(entry.Last.Get()) > timeout {
			entry.Timeout = true
			_ = entry.HyConn.Close()
			// Closing the connection here will cause the ReceiveLoop to exit,
			// and the session will be removed from the map there.
		}
	}
}

func (t *UDPTunnel) feed(pc net.PacketConn, addr net.Addr, data []byte) {
	key := newSessionKey(addr)
	t.mutex.RLock()
	entry := t.m[key]
	t.mutex.RUnlock()

	// Create a new session if not exists
	if entry == nil {
		if t.EventLogger != nil {
			t.EventLogger.Connect(addr)
		}
		hyConn, err := t.HyClient.UDP()
		if err != nil {
			if t.EventLogger != nil {
				t.EventLogger.Error(addr, err)
			}
			return
		}
		entry = &sessionEntry{
			HyConn: hyConn,
			Last:   newAtomicTime(time.Now()),
		}
		// Start the receive loop for this session
		// Local <- Remote
		go func() {
			err := entry.ReceiveLoop(pc, addr)
			if !entry.Timeout {
				_ = hyConn.Close()
				if t.EventLogger != nil {
					t.EventLogger.Error(addr, err)
				}
			} else {
				// Connection already closed by timeout cleanup,
				// no need to close again here.
				// Use nil error to indicate timeout.
				if t.EventLogger != nil {
					t.EventLogger.Error(addr, nil)
				}
			}
			// Remove the session from the map
			t.mutex.Lock()
			delete(t.m, key)
			t.mutex.Unlock()
		}()
		// Insert the session into the map
		t.mutex.Lock()
		t.m[key] = entry
		t.mutex.Unlock()
	}

	// Feed the message to the session
	_ = entry.Feed(data, t.Remote)
}
