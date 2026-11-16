package outbounds

import (
	"net"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func udpTestPeer(t *testing.T, network, addr string) (*net.UDPConn, uint16) {
	conn, err := net.ListenPacket(network, addr)
	if err != nil {
		t.Skipf("cannot listen on %s %s: %v", network, addr, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn.(*net.UDPConn), uint16(conn.LocalAddr().(*net.UDPAddr).Port)
}

func TestDirectOutboundUDP(t *testing.T) {
	ob := NewDirectOutboundSimple(DirectOutboundModeAuto)
	conn, err := ob.UDP(&AddrEx{Host: "127.0.0.1", Port: 1})
	require.NoError(t, err)
	defer conn.Close()

	peer4a, port4a := udpTestPeer(t, "udp4", "127.0.0.1:0")
	peer4b, port4b := udpTestPeer(t, "udp4", "127.0.0.1:0")
	peer6, port6 := udpTestPeer(t, "udp6", "[::1]:0")

	buf := make([]byte, 1024)
	// Every address is followed by both the same and a different one
	for i, tt := range []struct {
		peer *net.UDPConn
		host string
		port uint16
	}{
		{peer4a, "127.0.0.1", port4a},
		{peer4a, "127.0.0.1", port4a},
		{peer4b, "127.0.0.1", port4b},
		{peer6, "::1", port6},
		{peer6, "::1", port6},
		{peer4a, "127.0.0.1", port4a},
		{peer4b, "127.0.0.1", port4b},
		{peer4b, "127.0.0.1", port4b},
	} {
		payload := []byte("packet " + strconv.Itoa(i))

		n, err := conn.WriteTo(payload, &AddrEx{Host: tt.host, Port: tt.port})
		require.NoError(t, err)
		assert.Equal(t, len(payload), n)
		n, from, err := tt.peer.ReadFrom(buf)
		require.NoError(t, err)
		assert.Equal(t, payload, buf[:n])

		// The reply must come from the address we sent to, not its IPv4-mapped IPv6 form
		_, err = tt.peer.WriteTo(payload, from)
		require.NoError(t, err)
		n, addr, err := conn.ReadFrom(buf)
		require.NoError(t, err)
		assert.Equal(t, payload, buf[:n])
		assert.Equal(t, &AddrEx{Host: tt.host, Port: tt.port}, addr)
	}
}

func TestDirectOutboundUDPAddressErrors(t *testing.T) {
	ob := NewDirectOutboundSimple(DirectOutboundMode6)
	conn, err := ob.UDP(&AddrEx{Host: "::1", Port: 1})
	require.NoError(t, err)
	defer conn.Close()

	// IPv6 only, so an IPv4 address must fail every time
	for range 2 {
		_, err = conn.WriteTo([]byte("test"), &AddrEx{Host: "127.0.0.1", Port: 1234})
		assert.ErrorIs(t, err, noAddressError{IPv6: true})
	}
	// An existing ResolveInfo is used as is
	_, err = conn.WriteTo([]byte("test"), &AddrEx{
		Host:        "localhost",
		Port:        1234,
		ResolveInfo: &ResolveInfo{Err: assert.AnError},
	})
	assert.ErrorIs(t, err, resolveError{Err: assert.AnError})
}

// A change of address must never be missed.
func TestUDPConnAdapterAddresses(t *testing.T) {
	mc := newMockUDPConn(t)
	adapter := &udpConnAdapter{UDPConn: mc}

	for _, tt := range []struct {
		addr string
		host string
		port uint16
	}{
		{"1.1.1.1:53", "1.1.1.1", 53},
		{"1.1.1.1:53", "1.1.1.1", 53},
		{"1.1.1.1:5353", "1.1.1.1", 5353},
		{"8.8.8.8:5353", "8.8.8.8", 5353},
		{"[2001:db8::1]:53", "2001:db8::1", 53},
		{"example.com:53", "example.com", 53},
		{"1.1.1.1:53", "1.1.1.1", 53},
	} {
		mc.EXPECT().WriteTo([]byte("out"), &AddrEx{Host: tt.host, Port: tt.port}).Return(3, nil).Once()
		n, err := adapter.WriteTo([]byte("out"), tt.addr)
		assert.NoError(t, err)
		assert.Equal(t, 3, n)

		mc.EXPECT().ReadFrom(mock.Anything).Return(2, &AddrEx{Host: tt.host, Port: tt.port}, nil).Once()
		n, addr, err := adapter.ReadFrom(nil)
		assert.NoError(t, err)
		assert.Equal(t, 2, n)
		assert.Equal(t, tt.addr, addr)
	}

	// Invalid addresses always fail, and don't replace the cached one
	for range 2 {
		_, err := adapter.WriteTo([]byte("out"), "no-port")
		assert.Error(t, err)
		_, err = adapter.WriteTo([]byte("out"), "1.1.1.1:99999")
		assert.Error(t, err)
	}
	mc.EXPECT().WriteTo([]byte("out"), &AddrEx{Host: "1.1.1.1", Port: 53}).Return(3, nil).Once()
	_, err := adapter.WriteTo([]byte("out"), "1.1.1.1:53")
	assert.NoError(t, err)

	// Errors of the connection are passed on
	mc.EXPECT().ReadFrom(mock.Anything).Return(0, nil, assert.AnError).Once()
	_, addr, err := adapter.ReadFrom(nil)
	assert.ErrorIs(t, err, assert.AnError)
	assert.Equal(t, "", addr)
}
