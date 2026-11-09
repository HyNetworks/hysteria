package client

import (
	"testing"
	"time"

	"github.com/apernet/hysteria/core/v2/internal/protocol"
)

func TestStreamSendDropsWhenLaneFull(t *testing.T) {
	e := &l3StreamEndpoint{
		up:   make([]chan []byte, protocol.L3PipeLanes),
		done: make(chan struct{}),
	}
	for i := range e.up {
		e.up[i] = make(chan []byte, pipeQueue)
	}
	pkt := []byte{0x45, 0x00}
	done := make(chan error, 1)
	go func() {
		for i := 0; i < pipeQueue+10; i++ {
			if err := e.Send(pkt); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("send blocked on a lane with no writer")
	}
	if got := e.drops.Load(); got != 10 {
		t.Fatalf("drops = %d, want 10", got)
	}
}
