package forwarding

import (
	"crypto/rand"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/apernet/hysteria/app/v2/internal/utils_test"
)

func TestUDPTunnel(t *testing.T) {
	// Start the tunnel
	l, err := net.ListenPacket("udp", "127.0.0.1:34567")
	assert.NoError(t, err)
	defer l.Close()
	tunnel := &UDPTunnel{
		HyClient: &utils_test.MockEchoHyClient{},
	}
	go tunnel.Serve(l)

	for i := 0; i < 10; i++ {
		conn, err := net.Dial("udp", "127.0.0.1:34567")
		assert.NoError(t, err)

		data := make([]byte, 1024)
		_, _ = rand.Read(data)
		_, err = conn.Write(data)
		assert.NoError(t, err)

		recv := make([]byte, 1024)
		_, err = conn.Read(recv)
		assert.NoError(t, err)

		assert.Equal(t, data, recv)
		_ = conn.Close()
	}
}

func TestSessionKey(t *testing.T) {
	a := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 1234}
	b := &net.UDPAddr{IP: net.IP{192, 0, 2, 1}, Port: 1234}
	assert.NotEqual(t, newSessionKey(a), newSessionKey(&net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 1235}))
	assert.NotEqual(t, newSessionKey(a), newSessionKey(&net.UDPAddr{IP: net.IPv4(192, 0, 2, 2), Port: 1234}))
	assert.NotEqual(t, newSessionKey(a), newSessionKey(&net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 1234}))
	assert.Equal(t, newSessionKey(a), newSessionKey(b))
	// Other kinds of addresses, and invalid ones, are keyed by their string
	assert.Equal(t, newSessionKey(&net.UnixAddr{Name: "a"}), newSessionKey(&net.UnixAddr{Name: "a"}))
	assert.NotEqual(t, newSessionKey(&net.UnixAddr{Name: "a"}), newSessionKey(&net.UnixAddr{Name: "b"}))
	assert.NotEqual(t, newSessionKey(&net.UDPAddr{Port: 1}), newSessionKey(&net.UDPAddr{Port: 2}))
}

func TestAtomicTime(t *testing.T) {
	now := time.Now()
	at := newAtomicTime(now)
	assert.True(t, at.Get().Equal(now))
	later := now.Add(42 * time.Second)
	at.Set(later)
	assert.True(t, at.Get().Equal(later))
	assert.Equal(t, 42*time.Second, at.Get().Sub(now))
}
