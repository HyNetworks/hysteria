package proxymux

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// sniffTimeout bounds how long we wait for the first byte that tells HTTP from
// SOCKS5 apart.
const sniffTimeout = 10 * time.Second

func newMuxListener(listener net.Listener, deleteFunc func()) *muxListener {
	l := &muxListener{
		base:       listener,
		acceptChan: make(chan net.Conn),
		closeChan:  make(chan struct{}),
		deleteFunc: deleteFunc,
	}
	go l.acceptLoop()
	go l.mainLoop()
	return l
}

type muxListener struct {
	lock      sync.Mutex
	base      net.Listener
	acceptErr error

	acceptChan chan net.Conn
	closeChan  chan struct{}

	socksListener *subListener
	httpListener  *subListener

	deleteFunc func()
}

func (l *muxListener) acceptLoop() {
	defer close(l.acceptChan)

	for {
		conn, err := l.base.Accept()
		if err != nil {
			l.lock.Lock()
			l.acceptErr = err
			l.lock.Unlock()
			return
		}
		select {
		case <-l.closeChan:
			return
		case l.acceptChan <- conn:
		}
	}
}

func (l *muxListener) mainLoop() {
	defer func() {
		l.deleteFunc()
		l.base.Close()

		close(l.closeChan)

		l.lock.Lock()
		defer l.lock.Unlock()

		if sl := l.httpListener; sl != nil {
			close(sl.acceptChan)
			l.httpListener = nil
		}
		if sl := l.socksListener; sl != nil {
			close(sl.acceptChan)
			l.socksListener = nil
		}
	}()

	for {
		var socksCloseChan, httpCloseChan chan struct{}
		l.lock.Lock()
		if l.httpListener != nil {
			httpCloseChan = l.httpListener.closeChan
		}
		if l.socksListener != nil {
			socksCloseChan = l.socksListener.closeChan
		}
		l.lock.Unlock()
		select {
		case <-l.closeChan:
			return
		case conn, ok := <-l.acceptChan:
			if !ok {
				return
			}
			go l.dispatch(conn)
		case <-socksCloseChan:
			l.lock.Lock()
			if socksCloseChan == l.socksListener.closeChan {
				// not replaced by another ListenSOCKS()
				l.socksListener = nil
			}
			l.lock.Unlock()
			if l.checkIdle() {
				return
			}
		case <-httpCloseChan:
			l.lock.Lock()
			if httpCloseChan == l.httpListener.closeChan {
				// not replaced by another ListenHTTP()
				l.httpListener = nil
			}
			l.lock.Unlock()
			if l.checkIdle() {
				return
			}
		}
	}
}

func (l *muxListener) dispatch(conn net.Conn) {
	// Bound the protocol sniff. A client that connects and sends nothing would
	// otherwise hold this goroutine and its file descriptor forever.
	_ = conn.SetReadDeadline(time.Now().Add(sniffTimeout))
	var b [1]byte
	if _, err := io.ReadFull(conn, b[:]); err != nil {
		conn.Close()
		return
	}
	_ = conn.SetReadDeadline(time.Time{})

	l.lock.Lock()
	var target *subListener
	if b[0] == 5 {
		target = l.socksListener
	} else {
		target = l.httpListener
	}
	l.lock.Unlock()

	if target == nil {
		conn.Close()
		return
	}

	wconn := &connWithOneByte{Conn: conn, b: b[0]}

	select {
	case <-target.closeChan:
	case target.acceptChan <- wconn:
	}
}

func (l *muxListener) checkIdle() bool {
	l.lock.Lock()
	defer l.lock.Unlock()

	return l.httpListener == nil && l.socksListener == nil
}

func (l *muxListener) getAndClearAcceptError() error {
	l.lock.Lock()
	defer l.lock.Unlock()

	if l.acceptErr == nil {
		return nil
	}
	err := l.acceptErr
	l.acceptErr = nil
	return err
}

func (l *muxListener) ListenHTTP() (net.Listener, error) {
	l.lock.Lock()
	defer l.lock.Unlock()

	if l.httpListener != nil {
		subListenerPendingClosed := false
		select {
		case <-l.httpListener.closeChan:
			subListenerPendingClosed = true
		default:
		}
		if !subListenerPendingClosed {
			return nil, OpErr{
				Addr:     l.base.Addr(),
				Protocol: "http",
				Op:       "bind-protocol",
				Err:      ErrProtocolInUse,
			}
		}
		l.httpListener = nil
	}

	select {
	case <-l.closeChan:
		return nil, net.ErrClosed
	default:
	}

	sl := newSubListener(l.getAndClearAcceptError, l.base.Addr)
	l.httpListener = sl
	return sl, nil
}

func (l *muxListener) ListenSOCKS() (net.Listener, error) {
	l.lock.Lock()
	defer l.lock.Unlock()

	if l.socksListener != nil {
		subListenerPendingClosed := false
		select {
		case <-l.socksListener.closeChan:
			subListenerPendingClosed = true
		default:
		}
		if !subListenerPendingClosed {
			return nil, OpErr{
				Addr:     l.base.Addr(),
				Protocol: "socks",
				Op:       "bind-protocol",
				Err:      ErrProtocolInUse,
			}
		}
		l.socksListener = nil
	}

	select {
	case <-l.closeChan:
		return nil, net.ErrClosed
	default:
	}

	sl := newSubListener(l.getAndClearAcceptError, l.base.Addr)
	l.socksListener = sl
	return sl, nil
}

func newSubListener(acceptErrorFunc func() error, addrFunc func() net.Addr) *subListener {
	return &subListener{
		acceptChan:      make(chan net.Conn),
		acceptErrorFunc: acceptErrorFunc,
		closeChan:       make(chan struct{}),
		addrFunc:        addrFunc,
	}
}

type subListener struct {
	// receive connections or closure from upstream
	acceptChan chan net.Conn
	// get an error of Accept() from upstream
	acceptErrorFunc func() error
	// notify upstream that we are closed
	closeChan chan struct{}

	// Listener.Addr() implementation of base listener
	addrFunc func() net.Addr
}

func (l *subListener) Accept() (net.Conn, error) {
	select {
	case <-l.closeChan:
		// closed by ourselves
		return nil, net.ErrClosed
	case conn, ok := <-l.acceptChan:
		if !ok {
			// closed by upstream
			if acceptErr := l.acceptErrorFunc(); acceptErr != nil {
				return nil, acceptErr
			}
			return nil, net.ErrClosed
		}
		return conn, nil
	}
}

func (l *subListener) Addr() net.Addr {
	return l.addrFunc()
}

// Close implements net.Listener.Close.
// Upstream should use close(l.acceptChan) instead.
func (l *subListener) Close() error {
	select {
	case <-l.closeChan:
		return nil
	default:
	}
	close(l.closeChan)
	return nil
}

// connWithOneByte is a net.Conn that returns b for the first read
// request, then forwards everything else to Conn.
type connWithOneByte struct {
	net.Conn

	b     byte
	bRead bool
}

func (c *connWithOneByte) Read(bs []byte) (int, error) {
	if c.bRead {
		return c.Conn.Read(bs)
	}
	if len(bs) == 0 {
		return 0, nil
	}
	c.bRead = true
	bs[0] = c.b
	return 1, nil
}

type OpErr struct {
	Addr     net.Addr
	Protocol string
	Op       string
	Err      error
}

func (m OpErr) Error() string {
	return fmt.Sprintf("mux-listen: %s[%s]: %s: %v", m.Addr, m.Protocol, m.Op, m.Err)
}

func (m OpErr) Unwrap() error {
	return m.Err
}

var ErrProtocolInUse = errors.New("protocol already in use")
