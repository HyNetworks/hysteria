package client

import (
	"net"
	"sync"
	"time"

	coreErrs "github.com/apernet/hysteria/core/v2/errors"
)

// reconnectableClientImpl is a wrapper of Client, which can reconnect when the connection is closed,
// except when the caller explicitly calls Close() to permanently close this client.
type reconnectableClientImpl struct {
	configFunc    func() (*Config, error)           // called before connecting
	connectedFunc func(Client, *HandshakeInfo, int) // called when successfully connected
	client        Client
	count         int
	m             sync.Mutex
	closed        bool // permanent close
}

// NewReconnectableClient creates a reconnectable client.
// If lazy is true, the client will not connect until the first call to TCP() or UDP().
// We use a function for config mainly to delay config evaluation
// (which involves DNS resolution) until the actual connection attempt.
func NewReconnectableClient(configFunc func() (*Config, error), connectedFunc func(Client, *HandshakeInfo, int), lazy bool) (Client, error) {
	rc := &reconnectableClientImpl{
		configFunc:    configFunc,
		connectedFunc: connectedFunc,
	}
	if !lazy {
		if err := rc.reconnect(); err != nil {
			return nil, err
		}
	}
	return rc, nil
}

func (rc *reconnectableClientImpl) reconnect() error {
	if rc.client != nil {
		_ = rc.client.Close()
	}
	var info *HandshakeInfo
	config, err := rc.configFunc()
	if err != nil {
		return err
	}
	rc.client, info, err = NewClient(config)
	if err != nil {
		return err
	} else {
		rc.count++
		if rc.connectedFunc != nil {
			rc.connectedFunc(rc, info, rc.count)
		}
		return nil
	}
}

// clientDo calls f with the current client.
// If the client is nil, it will first reconnect.
// It will also detect if the client is closed, and if so,
// set it to nil for reconnect next time.
func (rc *reconnectableClientImpl) clientDo(f func(Client) (interface{}, error)) (interface{}, error) {
	rc.m.Lock()
	if rc.closed {
		rc.m.Unlock()
		return nil, coreErrs.ClosedError{}
	}
	if rc.client == nil {
		// No active connection, connect first
		if err := rc.reconnect(); err != nil {
			rc.m.Unlock()
			return nil, err
		}
	}
	client := rc.client
	rc.m.Unlock()

	ret, err := f(client)
	if _, ok := err.(coreErrs.ClosedError); ok {
		// Connection closed, set client to nil for reconnect next time
		rc.m.Lock()
		if rc.client == client {
			// This check is in case the client is already changed by another goroutine
			rc.client = nil
		}
		rc.m.Unlock()
	}
	return ret, err
}

func (rc *reconnectableClientImpl) TCP(addr string) (net.Conn, error) {
	if c, err := rc.clientDo(func(client Client) (interface{}, error) {
		return client.TCP(addr)
	}); err != nil {
		return nil, err
	} else {
		return c.(net.Conn), nil
	}
}

func (rc *reconnectableClientImpl) UDP() (HyUDPConn, error) {
	if c, err := rc.clientDo(func(client Client) (interface{}, error) {
		return client.UDP()
	}); err != nil {
		return nil, err
	} else {
		return c.(HyUDPConn), nil
	}
}

func (rc *reconnectableClientImpl) L3() (HyL3Conn, error) {
	return &reL3{rc: rc}, nil
}

func (rc *reconnectableClientImpl) drop(owner Client) {
	rc.m.Lock()
	defer rc.m.Unlock()
	if rc.client == owner {
		_ = rc.client.Close()
		rc.client = nil
	}
}

func (rc *reconnectableClientImpl) isClosed() bool {
	rc.m.Lock()
	defer rc.m.Unlock()
	return rc.closed
}

// reL3 keeps a TUN reading and writing across QUIC reconnects.
// A closed connection is dropped and dialed again. A permanent Close stops the loop.
type reL3 struct {
	rc      *reconnectableClientImpl
	mu      sync.Mutex
	inner   HyL3Conn
	owner   Client
	dialing bool
}

func (r *reL3) Send(ipPkt []byte) error {
	for {
		inner, err := r.conn()
		if err != nil {
			return err
		}
		err = inner.Send(ipPkt)
		if _, ok := err.(coreErrs.ClosedError); ok {
			r.reset(inner)
			continue
		}
		return err
	}
}

func (r *reL3) Receive() ([]byte, error) {
	for {
		inner, err := r.conn()
		if err != nil {
			return nil, err
		}
		pkt, err := inner.Receive()
		if _, ok := err.(coreErrs.ClosedError); ok {
			r.reset(inner)
			continue
		}
		return pkt, err
	}
}

func (r *reL3) conn() (HyL3Conn, error) {
	r.mu.Lock()
	for {
		if r.inner != nil {
			inner := r.inner
			r.mu.Unlock()
			return inner, nil
		}
		if r.dialing {
			r.mu.Unlock()
			time.Sleep(20 * time.Millisecond)
			r.mu.Lock()
			continue
		}
		r.dialing = true
		r.mu.Unlock()

		inner, owner, err := r.dial()

		r.mu.Lock()
		r.dialing = false
		if err != nil {
			r.mu.Unlock()
			return nil, err
		}
		if r.inner == nil {
			r.inner = inner
			r.owner = owner
		}
		got := r.inner
		r.mu.Unlock()
		return got, nil
	}
}

func (r *reL3) dial() (HyL3Conn, Client, error) {
	for {
		var owner Client
		v, err := r.rc.clientDo(func(c Client) (interface{}, error) {
			owner = c
			return c.L3()
		})
		if err == nil {
			return v.(HyL3Conn), owner, nil
		}
		if _, ok := err.(coreErrs.DialError); ok || r.rc.isClosed() {
			return nil, nil, err
		}
		time.Sleep(time.Second)
	}
}

func (r *reL3) reset(inner HyL3Conn) {
	r.mu.Lock()
	owner := r.owner
	if r.inner == inner {
		r.inner = nil
		r.owner = nil
	}
	r.mu.Unlock()
	r.rc.drop(owner)
}

func (rc *reconnectableClientImpl) Close() error {
	rc.m.Lock()
	defer rc.m.Unlock()
	rc.closed = true
	if rc.client != nil {
		return rc.client.Close()
	}
	return nil
}
