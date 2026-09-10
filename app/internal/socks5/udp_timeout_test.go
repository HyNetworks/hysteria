package socks5

import (
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/apernet/hysteria/app/v2/internal/utils_test"
)

// associate performs a SOCKS5 handshake and a UDP ASSOCIATE, returning the
// control connection and the ephemeral port the server bound for the relay.
func associate(t *testing.T, addr string) (net.Conn, int) {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	assert.NoError(t, err)

	// Negotiation: VER=5, NMETHODS=1, METHOD=0 (no auth)
	_, err = conn.Write([]byte{5, 1, 0})
	assert.NoError(t, err)
	nego := make([]byte, 2)
	_, err = io.ReadFull(conn, nego)
	assert.NoError(t, err)
	assert.Equal(t, byte(5), nego[0])

	// Request: VER=5, CMD=3 (UDP ASSOCIATE), RSV=0, ATYP=1, 0.0.0.0:0
	_, err = conn.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0})
	assert.NoError(t, err)
	rep := make([]byte, 10)
	_, err = io.ReadFull(conn, rep)
	assert.NoError(t, err)
	assert.Equal(t, byte(0), rep[1], "UDP ASSOCIATE should succeed")

	return conn, int(binary.BigEndian.Uint16(rep[8:10]))
}

// relayPortFree reports whether the server has released the relay port.
func relayPortFree(port int) bool {
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// TestUDPAssociationIdleTimeout is the regression test for the port-exhaustion
// class: an association that carries no traffic must release its ephemeral port
// on its own, without waiting for the client to close the control connection.
// Before the fix the port was pinned for as long as the client held the TCP
// connection open — which a tun2socks-style client may never do.
func TestUDPAssociationIdleTimeout(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer l.Close()

	s := &Server{
		HyClient:   &utils_test.MockEchoHyClient{},
		UDPTimeout: 300 * time.Millisecond,
	}
	go func() { _ = s.Serve(l) }()

	conn, port := associate(t, l.Addr().String())
	defer conn.Close()

	// CONTROL: while the association is live the port must be held. Without this
	// the test would pass even if ASSOCIATE had never bound anything.
	assert.False(t, relayPortFree(port),
		"control: relay port must be held while the association is live")

	// The client deliberately sends nothing and never closes the control
	// connection — exactly the shape that pinned ports before the fix.
	assert.Eventually(t, func() bool { return relayPortFree(port) },
		3*time.Second, 50*time.Millisecond,
		"idle association must release its ephemeral port")
}

// TestUDPAssociationSurvivesTraffic is the opposite control: an association
// that is carrying traffic must NOT be torn down by the idle timeout.
func TestUDPAssociationSurvivesTraffic(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer l.Close()

	s := &Server{
		HyClient:   &utils_test.MockEchoHyClient{},
		UDPTimeout: 300 * time.Millisecond,
	}
	go func() { _ = s.Serve(l) }()

	conn, port := associate(t, l.Addr().String())
	defer conn.Close()

	relay, err := net.Dial("udp", net.JoinHostPort("127.0.0.1", itoa(port)))
	assert.NoError(t, err)
	defer relay.Close()

	// Keep the association busy for well over one timeout period.
	deadline := time.Now().Add(900 * time.Millisecond)
	for time.Now().Before(deadline) {
		// SOCKS5 UDP datagram: RSV(2) FRAG(1) ATYP(1) ADDR(4) PORT(2) DATA
		_, _ = relay.Write([]byte{0, 0, 0, 1, 127, 0, 0, 1, 0, 80, 'h', 'i'})
		time.Sleep(100 * time.Millisecond)
	}
	assert.False(t, relayPortFree(port),
		"an association carrying traffic must not be timed out")
}

func itoa(i int) string {
	return net.JoinHostPort("", "")[:0] + func() string {
		b := make([]byte, 0, 5)
		if i == 0 {
			return "0"
		}
		for i > 0 {
			b = append([]byte{byte('0' + i%10)}, b...)
			i /= 10
		}
		return string(b)
	}()
}
