package proxymux

import (
	"bytes"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/apernet/hysteria/app/v2/internal/proxymux/internal/mocks"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

//go:generate mockery

func testMockListener(t *testing.T, connChan <-chan net.Conn) net.Listener {
	closedChan := make(chan struct{})
	mockListener := mocks.NewMockListener(t)
	mockListener.EXPECT().Accept().RunAndReturn(func() (net.Conn, error) {
		select {
		case <-closedChan:
			return nil, net.ErrClosed
		case conn, ok := <-connChan:
			if !ok {
				panic("unexpected closed channel (connChan)")
			}
			return conn, nil
		}
	})
	mockListener.EXPECT().Close().RunAndReturn(func() error {
		select {
		case <-closedChan:
		default:
			close(closedChan)
		}
		return nil
	})
	return mockListener
}

func testMockConn(t *testing.T, b []byte) net.Conn {
	buf := bytes.NewReader(b)
	isClosed := false
	mockConn := mocks.NewMockConn(t)
	mockConn.EXPECT().Read(mock.Anything).RunAndReturn(func(b []byte) (int, error) {
		if isClosed {
			return 0, net.ErrClosed
		}
		return buf.Read(b)
	})
	mockConn.EXPECT().Close().RunAndReturn(func() error {
		isClosed = true
		return nil
	})
	// dispatch() bounds the protocol sniff with a read deadline and clears it
	// afterwards. Maybe() because not every caller of this helper reaches
	// dispatch.
	mockConn.EXPECT().SetReadDeadline(mock.Anything).Return(nil).Maybe()
	return mockConn
}

func TestMuxHTTP(t *testing.T) {
	connChan := make(chan net.Conn)
	mockListener := testMockListener(t, connChan)
	mockConn := testMockConn(t, []byte("CONNECT example.com:443 HTTP/1.1\r\n\r\n"))

	mux := newMuxListener(mockListener, func() {})
	hl, err := mux.ListenHTTP()
	if !assert.NoError(t, err) {
		return
	}
	sl, err := mux.ListenSOCKS()
	if !assert.NoError(t, err) {
		return
	}

	connChan <- mockConn

	var socksConn, httpConn net.Conn
	var socksErr, httpErr error

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		socksConn, socksErr = sl.Accept()
		wg.Done()
	}()
	go func() {
		httpConn, httpErr = hl.Accept()
		wg.Done()
	}()

	time.Sleep(time.Second)

	sl.Close()
	hl.Close()

	wg.Wait()

	assert.Nil(t, socksConn)
	assert.ErrorIs(t, socksErr, net.ErrClosed)
	assert.NotNil(t, httpConn)
	httpConn.Close()
	assert.NoError(t, httpErr)

	// Wait for muxListener released
	<-mux.acceptChan
}

func TestMuxSOCKS(t *testing.T) {
	connChan := make(chan net.Conn)
	mockListener := testMockListener(t, connChan)
	mockConn := testMockConn(t, []byte{0x05, 0x02, 0x00, 0x01}) // SOCKS5 Connect Request: NOAUTH+GSSAPI

	mux := newMuxListener(mockListener, func() {})
	hl, err := mux.ListenHTTP()
	if !assert.NoError(t, err) {
		return
	}
	sl, err := mux.ListenSOCKS()
	if !assert.NoError(t, err) {
		return
	}

	connChan <- mockConn

	var socksConn, httpConn net.Conn
	var socksErr, httpErr error

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		socksConn, socksErr = sl.Accept()
		wg.Done()
	}()
	go func() {
		httpConn, httpErr = hl.Accept()
		wg.Done()
	}()

	time.Sleep(time.Second)

	sl.Close()
	hl.Close()

	wg.Wait()

	assert.NotNil(t, socksConn)
	socksConn.Close()
	assert.NoError(t, socksErr)
	assert.Nil(t, httpConn)
	assert.ErrorIs(t, httpErr, net.ErrClosed)

	// Wait for muxListener released
	<-mux.acceptChan
}
