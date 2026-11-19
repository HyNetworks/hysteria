package client

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"

	coreErrs "github.com/apernet/hysteria/core/v2/errors"
)

// MaxConnectionPoolSize bounds the resources allocated by a connection pool.
// Increasing the size is not guaranteed to increase throughput.
const MaxConnectionPoolSize = 8

type reconnectableClientConstructor func(func() (*Config, error), func(Client, *HandshakeInfo, int), bool) (Client, error)

// NewReconnectableClientPool creates a fixed-size pool of reconnectable clients.
// Size 1 preserves NewReconnectableClient's behavior. Larger pools assign new
// TCP streams and UDP sessions round-robin, without migrating established flows
// or splitting one stream's data across connections.
//
// Each nonzero bandwidth target is statically divided among the members. Idle
// members' allocations are not borrowed by busy members. Zero targets remain
// zero, preserving automatic congestion-control selection. These are aggregate
// bandwidth targets, not a shared rate limiter or a wire-rate guarantee.
//
// Config evaluation and connected callbacks are serialized within the pool.
// The callback receives the connected member and a pool-wide handshake count,
// including initial connections and reconnects. A supplied ConnFactory must be
// able to create independent packet connections for concurrent members.
// Callbacks must not synchronously re-enter a member or the pool.
// Lazy mode initializes each member only when that member is selected.
func NewReconnectableClientPool(configFunc func() (*Config, error), connectedFunc func(Client, *HandshakeInfo, int), lazy bool, size int) (Client, error) {
	return newReconnectableClientPool(configFunc, connectedFunc, lazy, size, NewReconnectableClient)
}

func newReconnectableClientPool(configFunc func() (*Config, error), connectedFunc func(Client, *HandshakeInfo, int), lazy bool, size int, newMember reconnectableClientConstructor) (Client, error) {
	if size < 1 || size > MaxConnectionPoolSize {
		return nil, coreErrs.ConfigError{Field: "ConnectionPool.Size", Reason: "must be between 1 and 8"}
	}
	if configFunc == nil {
		return nil, coreErrs.ConfigError{Field: "Config", Reason: "config function must be set"}
	}
	if size == 1 {
		return newMember(configFunc, connectedFunc, lazy)
	}

	p := &connectionPool{members: make([]Client, 0, size)}
	var configMu, callbackMu sync.Mutex
	var handshakes int
	for i := range size {
		member, err := newMember(func() (*Config, error) {
			configMu.Lock()
			defer configMu.Unlock()
			config, err := configFunc()
			if err != nil {
				return nil, err
			}
			return connectionPoolConfig(config, size, i)
		}, func(c Client, info *HandshakeInfo, _ int) {
			callbackMu.Lock()
			defer callbackMu.Unlock()
			handshakes++
			if connectedFunc != nil {
				connectedFunc(c, info, handshakes)
			}
		}, lazy)
		if err != nil {
			return nil, errors.Join(err, p.Close())
		}
		p.members = append(p.members, member)
	}
	return p, nil
}

func connectionPoolConfig(original *Config, size, member int) (*Config, error) {
	if original == nil {
		return nil, coreErrs.ConfigError{Field: "Config", Reason: "pool config must not be nil"}
	}
	c := *original
	c.filled = false
	for _, target := range []*uint64{&c.BandwidthConfig.MaxRx, &c.BandwidthConfig.MaxTx} {
		if *target == 0 {
			continue
		}
		if *target < uint64(size) {
			return nil, coreErrs.ConfigError{Field: "BandwidthConfig", Reason: "nonzero target must be at least the pool size"}
		}
		value := *target
		*target = value / uint64(size)
		if uint64(member) < value%uint64(size) {
			*target += 1
		}
	}
	return &c, nil
}

type connectionPool struct {
	members   []Client
	next      atomic.Uint64
	closed    atomic.Bool
	closeOnce sync.Once
	closeErr  error
}

func (p *connectionPool) pick() (Client, error) {
	if p.closed.Load() {
		return nil, coreErrs.ClosedError{}
	}
	return p.members[(p.next.Add(1)-1)%uint64(len(p.members))], nil
}

func (p *connectionPool) TCP(addr string) (net.Conn, error) {
	c, err := p.pick()
	if err != nil {
		return nil, err
	}
	return c.TCP(addr)
}

func (p *connectionPool) UDP() (HyUDPConn, error) {
	c, err := p.pick()
	if err != nil {
		return nil, err
	}
	return c.UDP()
}

func (p *connectionPool) Close() error {
	p.closeOnce.Do(func() {
		p.closed.Store(true)
		for _, c := range p.members {
			p.closeErr = errors.Join(p.closeErr, c.Close())
		}
	})
	return p.closeErr
}
