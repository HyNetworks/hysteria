package server

import (
	"testing"
	"time"

	coreErrs "github.com/apernet/hysteria/core/v2/errors"
	"github.com/apernet/hysteria/core/v2/internal/protocol"
)

func TestHubDropsWithoutPeer(t *testing.T) {
	h := newL3Hub()
	if err := h.Send([]byte{0x45, 0x00}); err != nil {
		t.Fatal(err)
	}
	h.close()
	if _, err := h.Receive(); err == nil {
		t.Fatal("receive on a closed hub succeeded")
	} else if _, ok := err.(coreErrs.ClosedError); !ok {
		t.Fatalf("error = %T", err)
	}
}

func TestHubReplacesPeer(t *testing.T) {
	h := newL3Hub()
	old := h.adopt(nil, "old", nil, false)
	cur := h.adopt(nil, "new", nil, false)
	if old == nil || cur == nil {
		t.Fatal("adopt failed")
	}
	old.accept(protocol.L3Fragment{PacketID: 1, FragID: 0, FragCount: 1, Data: []byte{0x45}})
	select {
	case pkt := <-h.recv:
		t.Fatalf("replaced peer delivered %d bytes", len(pkt))
	default:
	}
	cur.accept(protocol.L3Fragment{PacketID: 2, FragID: 0, FragCount: 1, Data: []byte{0x45, 0x00}})
	select {
	case pkt := <-h.recv:
		if len(pkt) != 2 || pkt[0] != 0x45 {
			t.Fatalf("packet = %v", pkt)
		}
	case <-time.After(time.Second):
		t.Fatal("current peer packet was not delivered")
	}
}

func TestHubKeepsLivePeerOfAnotherUser(t *testing.T) {
	h := newL3Hub()
	owner := h.adopt(nil, "alice", nil, true)
	owner.alive = func() bool { return true }
	if p := h.adopt(nil, "mallory", nil, true); p != nil {
		t.Fatal("another user took over a live tunnel")
	}
	if h.current() != owner {
		t.Fatal("owner lost the binding")
	}
	select {
	case <-owner.down.done:
		t.Fatal("refused takeover closed the owner downlink")
	default:
	}
}

func TestHubSameUserReplacesAndEvicts(t *testing.T) {
	h := newL3Hub()
	old := h.adopt(nil, "alice", nil, true)
	old.alive = func() bool { return true }
	cur := h.adopt(nil, "alice", nil, true)
	if cur == nil || h.current() != cur {
		t.Fatal("same user did not replace its stale peer")
	}
	select {
	case <-old.down.done:
	default:
		t.Fatal("replaced peer downlink still running")
	}
}

func TestDownLinkDropsWhenLaneFull(t *testing.T) {
	d := newDownLink()
	defer d.close()
	pkt := []byte{0x45, 0x00}
	done := make(chan struct{})
	go func() {
		for i := 0; i < pipeQueue+10; i++ {
			d.send(pkt)
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("send blocked on a lane with no writer")
	}
	if got := d.drops.Load(); got != 10 {
		t.Fatalf("drops = %d, want 10", got)
	}
}

func TestConfigL3Allowed(t *testing.T) {
	open := &Config{}
	if !open.l3Allowed("anyone") {
		t.Fatal("empty list rejected a user")
	}
	c := &Config{L3AuthIDs: []string{"alice"}}
	if !c.l3Allowed("alice") || c.l3Allowed("bob") {
		t.Fatal("allow list not applied")
	}
}
