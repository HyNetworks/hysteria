package client

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"

	coreErrs "github.com/apernet/hysteria/core/v2/errors"
	"github.com/stretchr/testify/require"
)

type poolTestClient struct {
	calls    atomic.Int64
	closes   atomic.Int64
	closeErr error
}

func (c *poolTestClient) TCP(string) (net.Conn, error) {
	c.calls.Add(1)
	return nil, nil
}

func (c *poolTestClient) UDP() (HyUDPConn, error) {
	c.calls.Add(1)
	return nil, nil
}

func (c *poolTestClient) Close() error {
	c.closes.Add(1)
	return c.closeErr
}

func TestConnectionPoolConfig(t *testing.T) {
	for _, size := range []int{2, 3, MaxConnectionPoolSize} {
		original := &Config{BandwidthConfig: BandwidthConfig{MaxRx: 101, MaxTx: 1003, DisableLossCompensation: true}, filled: true}
		var rx, tx uint64
		for member := range size {
			config, err := connectionPoolConfig(original, size, member)
			require.NoError(t, err)
			require.NotSame(t, original, config)
			require.False(t, config.filled)
			require.True(t, config.BandwidthConfig.DisableLossCompensation)
			rx += config.BandwidthConfig.MaxRx
			tx += config.BandwidthConfig.MaxTx
		}
		require.Equal(t, uint64(101), rx)
		require.Equal(t, uint64(1003), tx)
		require.Equal(t, uint64(101), original.BandwidthConfig.MaxRx)
		require.Equal(t, uint64(1003), original.BandwidthConfig.MaxTx)
		require.True(t, original.filled)
	}
	config, err := connectionPoolConfig(&Config{}, 3, 0)
	require.NoError(t, err)
	require.Zero(t, config.BandwidthConfig.MaxRx)
	require.Zero(t, config.BandwidthConfig.MaxTx)
	_, err = connectionPoolConfig(nil, 2, 0)
	require.Error(t, err)
	for _, bandwidth := range []BandwidthConfig{{MaxRx: 1}, {MaxTx: 1}} {
		_, err = connectionPoolConfig(&Config{BandwidthConfig: bandwidth}, 2, 0)
		require.Error(t, err)
	}
}

func TestConnectionPoolValidation(t *testing.T) {
	for _, size := range []int{-1, 0, MaxConnectionPoolSize + 1} {
		c, err := NewReconnectableClientPool(func() (*Config, error) { return &Config{}, nil }, nil, true, size)
		require.Nil(t, c)
		require.Error(t, err)
	}
	c, err := NewReconnectableClientPool(nil, nil, true, 2)
	require.Nil(t, c)
	require.Error(t, err)
}

func TestConnectionPoolSizeOne(t *testing.T) {
	var configs, connected int
	fake := &poolTestClient{}
	c, err := newReconnectableClientPool(func() (*Config, error) {
		configs++
		return &Config{BandwidthConfig: BandwidthConfig{MaxRx: 1}}, nil
	}, func(c Client, info *HandshakeInfo, count int) {
		connected++
		require.Same(t, fake, c)
		require.Equal(t, 7, count)
	}, false, 1, func(configFunc func() (*Config, error), callback func(Client, *HandshakeInfo, int), lazy bool) (Client, error) {
		require.False(t, lazy)
		config, err := configFunc()
		require.NoError(t, err)
		require.Equal(t, uint64(1), config.BandwidthConfig.MaxRx)
		callback(fake, &HandshakeInfo{}, 7)
		return fake, nil
	})
	require.NoError(t, err)
	require.Same(t, fake, c)
	require.Equal(t, 1, configs)
	require.Equal(t, 1, connected)
}

func TestConnectionPoolConcurrentSelectionAndClose(t *testing.T) {
	for _, size := range []int{2, 3, MaxConnectionPoolSize} {
		p := &connectionPool{}
		for range size {
			p.members = append(p.members, &poolTestClient{})
		}
		var wg sync.WaitGroup
		errs := make(chan error, 240)
		for i := range 240 {
			wg.Go(func() {
				if i%2 == 0 {
					_, err := p.TCP("example.test:443")
					errs <- err
				} else {
					_, err := p.UDP()
					errs <- err
				}
			})
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			require.NoError(t, err)
		}
		for _, c := range p.members {
			require.Equal(t, int64(240/size), c.(*poolTestClient).calls.Load())
		}
		for range 10 {
			wg.Go(func() { _ = p.Close() })
		}
		wg.Wait()
		for _, c := range p.members {
			require.Equal(t, int64(1), c.(*poolTestClient).closes.Load())
		}
		_, err := p.TCP("example.test:443")
		require.ErrorAs(t, err, &coreErrs.ClosedError{})
		_, err = p.UDP()
		require.ErrorAs(t, err, &coreErrs.ClosedError{})
	}
}

func TestConnectionPoolCloseErrorsAndPartialInitialization(t *testing.T) {
	first := errors.New("first member close")
	second := errors.New("second member close")
	f1 := &poolTestClient{closeErr: first}
	f2 := &poolTestClient{closeErr: second}
	p := &connectionPool{members: []Client{f1, f2}}
	err := p.Close()
	require.ErrorIs(t, err, first)
	require.ErrorIs(t, err, second)
	require.ErrorIs(t, p.Close(), first)
	require.Equal(t, int64(1), f1.closes.Load())
	require.Equal(t, int64(1), f2.closes.Load())

	fake := &poolTestClient{}
	initErr := errors.New("second member initialization")
	calls := 0
	c, err := newReconnectableClientPool(func() (*Config, error) { return &Config{}, nil }, nil, false, 3,
		func(func() (*Config, error), func(Client, *HandshakeInfo, int), bool) (Client, error) {
			calls++
			if calls == 2 {
				return nil, initErr
			}
			return fake, nil
		})
	require.Nil(t, c)
	require.ErrorIs(t, err, initErr)
	require.Equal(t, 2, calls)
	require.Equal(t, int64(1), fake.closes.Load())
}

func TestConnectionPoolConcurrentOpenAndClose(t *testing.T) {
	p := &connectionPool{members: []Client{&poolTestClient{}, &poolTestClient{}}}
	var wg sync.WaitGroup
	errs := make(chan error, 200)
	start := make(chan struct{})
	for range 100 {
		wg.Go(func() {
			<-start
			_, err := p.TCP("example.test:443")
			errs <- err
			_, err = p.UDP()
			errs <- err
		})
	}
	wg.Go(func() {
		<-start
		_ = p.Close()
	})
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			require.ErrorAs(t, err, &coreErrs.ClosedError{})
		}
	}
	for _, c := range p.members {
		require.Equal(t, int64(1), c.(*poolTestClient).closes.Load())
	}
}

func TestConnectionPoolSerializesConfigAndCallbacks(t *testing.T) {
	var configFuncs []func() (*Config, error)
	var callbacks []func(Client, *HandshakeInfo, int)
	// These variables deliberately are not atomic. The race detector checks
	// that evaluation and callbacks are serialized across different members.
	configCalls, connectedCalls := 0, 0
	c, err := newReconnectableClientPool(func() (*Config, error) {
		configCalls++
		return &Config{}, nil
	}, func(Client, *HandshakeInfo, int) {
		connectedCalls++
	}, true, 3, func(configFunc func() (*Config, error), callback func(Client, *HandshakeInfo, int), lazy bool) (Client, error) {
		require.True(t, lazy)
		configFuncs = append(configFuncs, configFunc)
		callbacks = append(callbacks, callback)
		return &poolTestClient{}, nil
	})
	require.NoError(t, err)
	defer c.Close()
	require.Zero(t, configCalls)
	require.Zero(t, connectedCalls)
	var wg sync.WaitGroup
	for member := range 3 {
		wg.Go(func() {
			for range 100 {
				_, _ = configFuncs[member]()
				callbacks[member](nil, &HandshakeInfo{}, 1)
			}
		})
	}
	wg.Wait()
	require.Equal(t, 300, configCalls)
	require.Equal(t, 300, connectedCalls)
}

func TestConnectionPoolPropagatesMemberErrors(t *testing.T) {
	configErr := errors.New("config unavailable")
	c, err := NewReconnectableClientPool(func() (*Config, error) { return nil, configErr }, nil, false, 2)
	require.Nil(t, c)
	require.ErrorIs(t, err, configErr)
	c, err = NewReconnectableClientPool(func() (*Config, error) { return nil, configErr }, nil, true, 2)
	require.NoError(t, err)
	defer c.Close()
	_, err = c.TCP("example.test:443")
	require.ErrorIs(t, err, configErr)
	_, err = c.UDP()
	require.ErrorIs(t, err, configErr)
}
