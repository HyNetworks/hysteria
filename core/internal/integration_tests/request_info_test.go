package integration_tests

import (
	"errors"
	"net"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/apernet/hysteria/core/v2/client"
	"github.com/apernet/hysteria/core/v2/internal/integration_tests/mocks"
	"github.com/apernet/hysteria/core/v2/server"
)

// infoRecordingOutbound records the RequestInfo of every call.
// TCP always fails (we only care about the info), UDP uses a real socket.
type infoRecordingOutbound struct {
	mu    sync.Mutex
	calls map[string][]*server.RequestInfo
}

func (o *infoRecordingOutbound) record(method string, info *server.RequestInfo) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.calls == nil {
		o.calls = make(map[string][]*server.RequestInfo)
	}
	o.calls[method] = append(o.calls[method], info)
}

func (o *infoRecordingOutbound) get(method string) []*server.RequestInfo {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]*server.RequestInfo(nil), o.calls[method]...)
}

func (o *infoRecordingOutbound) TCP(info *server.RequestInfo, reqAddr string) (net.Conn, error) {
	o.record("TCP", info)
	return nil, errors.New("not dialing")
}

func (o *infoRecordingOutbound) UDP(info *server.RequestInfo, reqAddr string) (server.UDPConn, error) {
	o.record("UDP", info)
	c, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}
	return &gatedUDPConn{UDPConn: c}, nil
}

func (o *infoRecordingOutbound) CheckUDP(info *server.RequestInfo, reqAddr string) error {
	o.record("CheckUDP", info)
	return nil
}

// TestClientServerRequestInfo tests that the outbound receives the auth ID and
// client address for TCP requests, the first UDP packet, and later UDP destinations.
func TestClientServerRequestInfo(t *testing.T) {
	const dest1, dest2 = "127.0.0.1:22452", "127.0.0.1:22453"
	ob := &infoRecordingOutbound{}

	udpConn, udpAddr, err := serverConn()
	assert.NoError(t, err)
	auth := mocks.NewMockAuthenticator(t)
	auth.EXPECT().Authenticate(mock.Anything, mock.Anything, mock.Anything).Return(true, "alice")
	s, err := server.NewServer(&server.Config{
		TLSConfig:     serverTLSConfig(),
		Conn:          udpConn,
		Authenticator: auth,
		Outbound:      ob,
	})
	assert.NoError(t, err)
	defer s.Close()
	go s.Serve()

	for _, addr := range []string{dest1, dest2} {
		ec, err := net.ListenPacket("udp", addr)
		assert.NoError(t, err)
		defer ec.Close()
		go (&udpEchoServer{Conn: ec}).Serve()
	}

	c, _, err := client.NewClient(&client.Config{
		ServerAddr: udpAddr,
		TLSConfig:  client.TLSConfig{InsecureSkipVerify: true},
	})
	assert.NoError(t, err)
	defer c.Close()

	// TCP
	_, err = c.TCP("example.com:443")
	assert.Error(t, err)

	// UDP: first destination dials, second goes through CheckUDP
	conn, err := c.UDP()
	assert.NoError(t, err)
	defer conn.Close()
	for _, addr := range []string{dest1, dest2} {
		assert.NoError(t, conn.Send([]byte("hi"), addr))
		_, rAddr, err := conn.Receive()
		assert.NoError(t, err)
		assert.Equal(t, addr, rAddr)
	}

	for _, method := range []string{"TCP", "UDP", "CheckUDP"} {
		infos := ob.get(method)
		if !assert.NotEmpty(t, infos, method) {
			continue
		}
		for _, info := range infos {
			if !assert.NotNil(t, info, method) {
				continue
			}
			assert.Equal(t, "alice", info.AuthID, method)
			uAddr, ok := info.ClientAddr.(*net.UDPAddr)
			if assert.True(t, ok, method) {
				assert.True(t, uAddr.IP.IsLoopback(), method)
				assert.NotZero(t, uAddr.Port, method)
			}
		}
	}
}
