package client

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	coreErrs "github.com/apernet/hysteria/core/v2/errors"
)

type reconnectTestClient struct {
	err    error
	closes atomic.Int32
	closed chan struct{}
}

func (c *reconnectTestClient) TCP(string) (net.Conn, error) { return nil, c.err }
func (c *reconnectTestClient) UDP() (HyUDPConn, error)      { return nil, c.err }
func (c *reconnectTestClient) Close() error {
	if c.closes.Add(1) == 1 && c.closed != nil {
		close(c.closed)
	}
	return nil
}

func TestReconnectReleasesClosedClient(t *testing.T) {
	for _, name := range []string{"TCP", "UDP"} {
		t.Run(name, func(t *testing.T) {
			old := &reconnectTestClient{err: coreErrs.ClosedError{}}
			configErr := errors.New("config unavailable")
			attempts := 0
			rc := &reconnectableClientImpl{
				client: old,
				configFunc: func() (*Config, error) {
					attempts++
					return nil, configErr
				},
			}
			call := func() error {
				if name == "UDP" {
					_, err := rc.UDP()
					return err
				}
				_, err := rc.TCP("example.com:443")
				return err
			}
			var closedErr coreErrs.ClosedError
			require.ErrorAs(t, call(), &closedErr)
			require.Nil(t, rc.client)
			require.EqualValues(t, 1, old.closes.Load())
			require.ErrorIs(t, call(), configErr)
			require.Equal(t, 1, attempts)
			require.NoError(t, rc.Close())
			require.EqualValues(t, 1, old.closes.Load())
		})
	}
}

func TestReconnectRetainsRecoverableClient(t *testing.T) {
	err := errors.New("transient stream error")
	old := &reconnectTestClient{err: err}
	rc := &reconnectableClientImpl{client: old}
	_, got := rc.TCP("example.com:443")
	require.ErrorIs(t, got, err)
	require.Same(t, old, rc.client)
	require.Zero(t, old.closes.Load())
	require.NoError(t, rc.Close())
	require.EqualValues(t, 1, old.closes.Load())
	_, got = rc.TCP("example.com:443")
	var closedErr coreErrs.ClosedError
	require.ErrorAs(t, got, &closedErr)
	_, got = rc.UDP()
	require.ErrorAs(t, got, &closedErr)
}

func TestReconnectConcurrentClosedErrors(t *testing.T) {
	old := &reconnectTestClient{}
	rc := &reconnectableClientImpl{client: old}
	var entered, finished sync.WaitGroup
	entered.Add(20)
	finished.Add(20)
	release := make(chan struct{})
	for i := 0; i < 20; i++ {
		go func() {
			defer finished.Done()
			_, _ = rc.clientDo(func(Client) (interface{}, error) {
				entered.Done()
				<-release
				return nil, coreErrs.ClosedError{}
			})
		}()
	}
	entered.Wait()
	close(release)
	finished.Wait()
	require.EqualValues(t, 1, old.closes.Load())
	require.Nil(t, rc.client)
}

func TestReconnectStaleErrorPreservesReplacement(t *testing.T) {
	old, next := &reconnectTestClient{}, &reconnectTestClient{}
	rc := &reconnectableClientImpl{client: old}
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		_, _ = rc.clientDo(func(Client) (interface{}, error) {
			close(entered)
			<-release
			return nil, coreErrs.ClosedError{}
		})
	}()
	<-entered
	_, _ = rc.clientDo(func(Client) (interface{}, error) { return nil, coreErrs.ClosedError{} })
	rc.m.Lock()
	rc.client = next
	rc.m.Unlock()
	close(release)
	<-done
	require.EqualValues(t, 1, old.closes.Load())
	require.Zero(t, next.closes.Load())
	require.Same(t, next, rc.client)
	require.NoError(t, rc.Close())
}

func TestReconnectCloseUnblocksPendingCall(t *testing.T) {
	old := &reconnectTestClient{closed: make(chan struct{})}
	rc := &reconnectableClientImpl{client: old}
	entered, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		_, _ = rc.clientDo(func(Client) (interface{}, error) {
			close(entered)
			<-old.closed
			return nil, coreErrs.ClosedError{}
		})
	}()
	<-entered
	require.NoError(t, rc.Close())
	<-done
	_, err := rc.UDP()
	var closedErr coreErrs.ClosedError
	require.ErrorAs(t, err, &closedErr)
}
