package vxrelay

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func TestRelayCarriesVNIs(t *testing.T) {
	vtepA := listenLoopback(t)
	vtepB := listenLoopback(t)
	vtepC := listenLoopback(t)

	relayA := mustRelay(t, Config{
		Listen:  "127.0.0.1:0",
		Address: netip.MustParseAddr("10.200.0.1"),
		Peer:    netip.MustParseAddr("10.200.0.2"),
		VNIs: []VNI{
			{ID: 500, VTEP: vtepA.LocalAddr().(*net.UDPAddr).AddrPort()},
			{ID: 600, VTEP: vtepA.LocalAddr().(*net.UDPAddr).AddrPort()},
		},
	})
	relayB := mustRelay(t, Config{
		Listen:  "127.0.0.1:0",
		Address: netip.MustParseAddr("10.200.0.2"),
		Peer:    netip.MustParseAddr("10.200.0.1"),
		VNIs: []VNI{
			{ID: 500, VTEP: vtepB.LocalAddr().(*net.UDPAddr).AddrPort()},
			{ID: 600, VTEP: vtepC.LocalAddr().(*net.UDPAddr).AddrPort()},
		},
	})
	ab, ba := newPipe(), newPipe()
	serveRelay(t, relayA, memEnd{in: ba, out: ab})
	serveRelay(t, relayB, memEnd{in: ab, out: ba})
	t.Cleanup(func() {
		_ = relayA.Close()
		_ = relayB.Close()
		ab.Close()
		ba.Close()
	})

	frame500 := testVXLAN(500, innerFrame(10, 80))
	frame600 := testVXLAN(600, innerFrame(10, 81))
	sendVXLAN(t, vtepA, relayA.LocalAddr(), frame500)
	sendVXLAN(t, vtepA, relayA.LocalAddr(), frame600)
	if got := recvVXLAN(t, vtepB); string(got) != string(frame500) {
		t.Fatalf("vni 500 = %x", got)
	}
	if got := recvVXLAN(t, vtepC); string(got) != string(frame600) {
		t.Fatalf("vni 600 = %x", got)
	}

	sendVXLAN(t, vtepB, relayB.LocalAddr(), frame500)
	if got := recvVXLAN(t, vtepA); string(got) != string(frame500) {
		t.Fatalf("return = %x", got)
	}
}

func TestRelayDropsUnwanted(t *testing.T) {
	sender := listenLoopback(t)
	cap := newCapture()
	relay := mustRelay(t, Config{
		Listen:  "127.0.0.1:0",
		Address: netip.MustParseAddr("10.200.0.1"),
		Peer:    netip.MustParseAddr("10.200.0.2"),
		VNIs: []VNI{{
			ID:   500,
			VTEP: sender.LocalAddr().(*net.UDPAddr).AddrPort(),
		}},
	})
	serveRelay(t, relay, cap)
	t.Cleanup(func() {
		_ = relay.Close()
		cap.Close()
	})

	sendVXLAN(t, sender, relay.LocalAddr(), testVXLAN(9, innerFrame(1, 2)))
	oversized := make([]byte, maxPacket)
	oversized[0] = vxlanIBit
	oversized[5] = 0x01
	oversized[6] = 0xf4
	sendVXLAN(t, sender, relay.LocalAddr(), oversized)
	if cap.wait(200 * time.Millisecond) {
		t.Fatal("dropped datagram was forwarded")
	}

	open := mustRelay(t, Config{
		Listen:  "127.0.0.1:0",
		Address: netip.MustParseAddr("10.200.0.1"),
		Peer:    netip.MustParseAddr("10.200.0.2"),
		VNIs: []VNI{{
			ID:    500,
			VTEP:  netip.MustParseAddrPort("192.0.2.1:4789"),
			Allow: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")},
		}},
	})
	allowed := newCapture()
	serveRelay(t, open, allowed)
	t.Cleanup(func() {
		_ = open.Close()
		allowed.Close()
	})
	sendVXLAN(t, sender, open.LocalAddr(), testVXLAN(500, innerFrame(1, 2)))
	if !allowed.wait(2 * time.Second) {
		t.Fatal("allowed source was dropped")
	}
}

func TestRelayCloseUnblocksServe(t *testing.T) {
	relay := mustRelay(t, Config{
		Listen:  "127.0.0.1:0",
		Address: netip.MustParseAddr("10.200.0.1"),
		Peer:    netip.MustParseAddr("10.200.0.2"),
		VNIs:    []VNI{{ID: 1, VTEP: netip.MustParseAddrPort("127.0.0.1:9")}},
	})
	errCh := make(chan error, 1)
	go func() { errCh <- relay.Serve(memEnd{in: newPipe(), out: newPipe()}) }()
	time.Sleep(20 * time.Millisecond)
	if err := relay.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return")
	}
	if err := relay.Serve(memEnd{in: newPipe(), out: newPipe()}); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Serve after Close = %v", err)
	}
}

func TestSetVNIsSwapsTable(t *testing.T) {
	vtepA := listenLoopback(t)
	vtepB := listenLoopback(t)
	vtepC := listenLoopback(t)
	addrA := vtepA.LocalAddr().(*net.UDPAddr).AddrPort()
	addrB := vtepB.LocalAddr().(*net.UDPAddr).AddrPort()
	addrC := vtepC.LocalAddr().(*net.UDPAddr).AddrPort()

	relayA := mustRelay(t, Config{
		Listen:  "127.0.0.1:0",
		Address: netip.MustParseAddr("10.200.0.1"),
		Peer:    netip.MustParseAddr("10.200.0.2"),
		VNIs:    []VNI{{ID: 501, VTEP: addrA}},
	})
	relayB := mustRelay(t, Config{
		Listen:  "127.0.0.1:0",
		Address: netip.MustParseAddr("10.200.0.2"),
		Peer:    netip.MustParseAddr("10.200.0.1"),
		VNIs:    []VNI{{ID: 501, VTEP: addrB}},
	})
	ab, ba := newPipe(), newPipe()
	serveRelay(t, relayA, memEnd{in: ba, out: ab})
	serveRelay(t, relayB, memEnd{in: ab, out: ba})
	t.Cleanup(func() {
		_ = relayA.Close()
		_ = relayB.Close()
		ab.Close()
		ba.Close()
	})

	frame501 := testVXLAN(501, innerFrame(10, 80))
	frame502 := testVXLAN(502, innerFrame(10, 81))
	sendVXLAN(t, vtepA, relayA.LocalAddr(), frame501)
	if got := recvVXLAN(t, vtepB); string(got) != string(frame501) {
		t.Fatalf("before reload = %x", got)
	}

	diff, err := relayA.SetVNIs([]VNI{{ID: 502, VTEP: addrA}})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := diff.Added, []uint32{502}; !slicesEqual(got, want) {
		t.Fatalf("added = %v", got)
	}
	if got, want := diff.Removed, []uint32{501}; !slicesEqual(got, want) {
		t.Fatalf("removed = %v", got)
	}
	if _, err := relayB.SetVNIs([]VNI{{ID: 502, VTEP: addrC}}); err != nil {
		t.Fatal(err)
	}

	sendVXLAN(t, vtepA, relayA.LocalAddr(), frame501)
	sendVXLAN(t, vtepA, relayA.LocalAddr(), frame502)
	if got := recvVXLAN(t, vtepC); string(got) != string(frame502) {
		t.Fatalf("vni 502 = %x", got)
	}
	assertNoPacket(t, vtepB)
	assertNoPacket(t, vtepC)
}

func TestSetVNIsChangesVTEP(t *testing.T) {
	oldVTEP := listenLoopback(t)
	newVTEP := listenLoopback(t)
	local := netip.MustParseAddr("10.200.0.1")
	peer := netip.MustParseAddr("10.200.0.2")
	relay := mustRelay(t, Config{
		Listen:  "127.0.0.1:0",
		Address: local,
		Peer:    peer,
		VNIs:    []VNI{{ID: 501, VTEP: oldVTEP.LocalAddr().(*net.UDPAddr).AddrPort()}},
	})
	in := newPipe()
	serveRelay(t, relay, memEnd{in: in, out: newPipe()})
	t.Cleanup(func() {
		_ = relay.Close()
		in.Close()
	})

	frame := testVXLAN(501, innerFrame(10, 80))
	pkt := Wrap(peer, local, 1, frame)
	if pkt == nil {
		t.Fatal("wrap failed")
	}
	if err := in.Send(pkt); err != nil {
		t.Fatal(err)
	}
	if got := recvVXLAN(t, oldVTEP); string(got) != string(frame) {
		t.Fatalf("old vtep = %x", got)
	}

	next := newVTEP.LocalAddr().(*net.UDPAddr).AddrPort()
	diff, err := relay.SetVNIs([]VNI{{
		ID:    501,
		VTEP:  next,
		Allow: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := diff.Changed, []uint32{501}; !slicesEqual(got, want) {
		t.Fatalf("changed = %v", got)
	}
	if err := in.Send(pkt); err != nil {
		t.Fatal(err)
	}
	if got := recvVXLAN(t, newVTEP); string(got) != string(frame) {
		t.Fatalf("new vtep = %x", got)
	}
	assertNoPacket(t, oldVTEP)
}

func TestSetVNIsRejectsBadTable(t *testing.T) {
	sender := listenLoopback(t)
	vtep := sender.LocalAddr().(*net.UDPAddr).AddrPort()
	relay := mustRelay(t, Config{
		Listen:  "127.0.0.1:0",
		Address: netip.MustParseAddr("10.200.0.1"),
		Peer:    netip.MustParseAddr("10.200.0.2"),
		VNIs:    []VNI{{ID: 501, VTEP: vtep}},
	})
	cap := newCapture()
	serveRelay(t, relay, cap)
	t.Cleanup(func() {
		_ = relay.Close()
		cap.Close()
	})

	if _, err := relay.SetVNIs([]VNI{
		{ID: 501, VTEP: vtep},
		{ID: 501, VTEP: netip.MustParseAddrPort("127.0.0.1:9")},
	}); err == nil {
		t.Fatal("duplicate vni was accepted")
	}
	if _, err := relay.SetVNIs([]VNI{{ID: 0, VTEP: vtep}}); err == nil {
		t.Fatal("vni 0 was accepted")
	}
	if _, err := relay.SetVNIs(nil); err == nil {
		t.Fatal("empty table was accepted")
	}

	sendVXLAN(t, sender, relay.LocalAddr(), testVXLAN(501, innerFrame(1, 2)))
	if !cap.wait(2 * time.Second) {
		t.Fatal("old table was dropped after a rejected reload")
	}
}

func TestSetVNIsConcurrent(t *testing.T) {
	vtep := listenLoopback(t)
	other := listenLoopback(t)
	local := netip.MustParseAddr("10.200.0.1")
	peer := netip.MustParseAddr("10.200.0.2")
	addr := vtep.LocalAddr().(*net.UDPAddr).AddrPort()
	otherAddr := other.LocalAddr().(*net.UDPAddr).AddrPort()
	relay := mustRelay(t, Config{
		Listen:  "127.0.0.1:0",
		Address: local,
		Peer:    peer,
		VNIs:    []VNI{{ID: 501, VTEP: addr}},
	})
	frame := testVXLAN(501, innerFrame(1, 2))
	pkt := Wrap(peer, local, 1, frame)
	if pkt == nil {
		t.Fatal("wrap failed")
	}
	done := make(chan struct{})
	serveRelay(t, relay, &spinEnd{pkt: pkt, done: done})
	t.Cleanup(func() {
		close(done)
		_ = relay.Close()
	})

	tables := [][]VNI{
		{{ID: 501, VTEP: addr}},
		{{ID: 502, VTEP: otherAddr}},
		{{ID: 501, VTEP: otherAddr, Allow: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}}},
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		deadline := time.Now().Add(150 * time.Millisecond)
		for time.Now().Before(deadline) {
			if _, err := vtep.WriteTo(frame, relay.LocalAddr()); err != nil {
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		deadline := time.Now().Add(150 * time.Millisecond)
		for time.Now().Before(deadline) {
			for _, table := range tables {
				if _, err := relay.SetVNIs(table); err != nil {
					t.Error(err)
					return
				}
			}
		}
	}()
	wg.Wait()
}

func TestNewRejectsBadTable(t *testing.T) {
	base := Config{
		Listen:  "127.0.0.1:0",
		Address: netip.MustParseAddr("10.200.0.1"),
		Peer:    netip.MustParseAddr("2001:db8::1"),
		VNIs:    []VNI{{ID: 1, VTEP: netip.MustParseAddrPort("127.0.0.1:1")}},
	}
	if _, err := New(base); err == nil {
		t.Fatal("mixed IP versions were accepted")
	}
	base.Peer = netip.MustParseAddr("10.200.0.2")
	base.VNIs = []VNI{
		{ID: 1, VTEP: netip.MustParseAddrPort("127.0.0.1:1")},
		{ID: 1, VTEP: netip.MustParseAddrPort("127.0.0.1:2")},
	}
	if _, err := New(base); err == nil {
		t.Fatal("duplicate vni was accepted")
	}
	base.VNIs = []VNI{{ID: 0, VTEP: netip.MustParseAddrPort("127.0.0.1:1")}}
	if _, err := New(base); err == nil {
		t.Fatal("vni 0 was accepted")
	}
}

func assertNoPacket(t *testing.T, conn *net.UDPConn) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err == nil {
		t.Fatalf("unexpected packet %x", buf[:n])
	}
}

func slicesEqual(got, want []uint32) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

type spinEnd struct {
	pkt  []byte
	done chan struct{}
}

func (e *spinEnd) Send([]byte) error { return nil }

func (e *spinEnd) Receive() ([]byte, error) {
	select {
	case <-e.done:
		return nil, net.ErrClosed
	default:
		return append([]byte(nil), e.pkt...), nil
	}
}

func mustRelay(t *testing.T, cfg Config) *Relay {
	t.Helper()
	relay, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return relay
}

func listenLoopback(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func serveRelay(t *testing.T, relay *Relay, conn L3Conn) {
	t.Helper()
	go func() { _ = relay.Serve(conn) }()
}

func sendVXLAN(t *testing.T, conn *net.UDPConn, dst net.Addr, payload []byte) {
	t.Helper()
	if _, err := conn.WriteTo(payload, dst); err != nil {
		t.Fatal(err)
	}
}

func recvVXLAN(t *testing.T, conn *net.UDPConn) []byte {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	return buf[:n]
}

type memPipe struct {
	ch   chan []byte
	done chan struct{}
	once sync.Once
}

func newPipe() *memPipe {
	return &memPipe{ch: make(chan []byte, 8), done: make(chan struct{})}
}

func (p *memPipe) Send(b []byte) error {
	select {
	case <-p.done:
		return net.ErrClosed
	case p.ch <- append([]byte(nil), b...):
		return nil
	}
}

func (p *memPipe) Receive() ([]byte, error) {
	select {
	case <-p.done:
		return nil, net.ErrClosed
	case b := <-p.ch:
		return b, nil
	}
}

func (p *memPipe) Close() { p.once.Do(func() { close(p.done) }) }

type memEnd struct{ in, out *memPipe }

func (e memEnd) Send(b []byte) error      { return e.out.Send(b) }
func (e memEnd) Receive() ([]byte, error) { return e.in.Receive() }

type capture struct {
	got  chan struct{}
	done chan struct{}
	once sync.Once
}

func newCapture() *capture {
	return &capture{got: make(chan struct{}, 1), done: make(chan struct{})}
}

func (c *capture) Send(b []byte) error {
	select {
	case c.got <- struct{}{}:
	default:
	}
	return nil
}

func (c *capture) Receive() ([]byte, error) {
	<-c.done
	return nil, net.ErrClosed
}

func (c *capture) wait(d time.Duration) bool {
	select {
	case <-c.got:
		return true
	case <-time.After(d):
		return false
	}
}

func (c *capture) Close() { c.once.Do(func() { close(c.done) }) }
