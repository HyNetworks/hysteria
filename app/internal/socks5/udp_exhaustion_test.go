package socks5

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/apernet/hysteria/app/v2/internal/utils_test"
)

// countHeldPorts reports how many of the given relay ports are still bound.
func countHeldPorts(ports []int) int {
	held := 0
	for _, p := range ports {
		c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: p})
		if err != nil {
			held++
			continue
		}
		_ = c.Close()
	}
	return held
}

// TestUDPAssociationsDoNotAccumulate measures the defect directly: a client that
// opens many UDP associations and keeps every control connection open — the
// shape produced by a tun-to-SOCKS bridge forwarding DNS — must not pin one
// ephemeral port per association indefinitely.
//
// Run against the unpatched code this reports "held after idle: 50 of 50".
func TestUDPAssociationsDoNotAccumulate(t *testing.T) {
	const associations = 50
	const idle = 300 * time.Millisecond

	l, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer l.Close()

	s := &Server{
		HyClient:   &utils_test.MockEchoHyClient{},
		UDPTimeout: idle,
	}
	go func() { _ = s.Serve(l) }()

	conns := make([]net.Conn, 0, associations)
	ports := make([]int, 0, associations)
	for i := 0; i < associations; i++ {
		c, p := associate(t, l.Addr().String())
		conns = append(conns, c)
		ports = append(ports, p)
	}
	defer func() {
		for _, c := range conns {
			_ = c.Close()
		}
	}()

	heldWhileLive := countHeldPorts(ports)
	t.Logf("held while live:  %d of %d", heldWhileLive, associations)
	assert.Equal(t, associations, heldWhileLive,
		"control: every live association must hold its port")

	// Every control connection stays open. Only the idle timeout can release
	// these ports.
	assert.Eventually(t, func() bool { return countHeldPorts(ports) == 0 },
		5*time.Second, 100*time.Millisecond,
		"all idle associations must release their ports")

	heldAfterIdle := countHeldPorts(ports)
	t.Logf("held after idle:  %d of %d  (control connections still open)", heldAfterIdle, associations)
}
