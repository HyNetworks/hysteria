package cmd

import (
	"strings"
	"testing"
)

func TestRelayL3Reload(t *testing.T) {
	base := l3TunConfig{
		Type:    "relay",
		Mode:    "stream",
		Lanes:   8,
		Address: "10.200.0.2/30",
		Peer:    "10.200.0.1",
		Relay: l3RelayConfig{
			Listen: "127.0.0.1:0",
			VNIs:   []l3RelayVNI{{VNI: 501, VTEP: "192.168.7.64"}},
		},
	}
	dev, err := newL3Device(base)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = dev.Close() })
	reloader, ok := dev.(l3Reloader)
	if !ok {
		t.Fatal("relay does not reload")
	}

	next := base
	next.Relay.Listen = "127.0.0.1:1"
	next.Mode = "datagram"
	next.Relay.VNIs = []l3RelayVNI{{VNI: 502, VTEP: "192.168.7.65:4790"}}
	diff, err := reloader.Reload(next)
	if err != nil {
		t.Fatal(err)
	}
	if len(diff.Added) != 1 || diff.Added[0] != 502 || len(diff.Removed) != 1 || diff.Removed[0] != 501 {
		t.Fatalf("diff = %+v", diff)
	}

	next.Relay.VNIs = []l3RelayVNI{
		{VNI: 502, VTEP: "192.168.7.65"},
		{VNI: 502, VTEP: "192.168.7.66"},
	}
	if _, err := reloader.Reload(next); err == nil {
		t.Fatal("duplicate vni was accepted")
	}
	next.Relay.VNIs = []l3RelayVNI{{VNI: 502, VTEP: "192.168.7.65:4790"}}
	diff, err = reloader.Reload(next)
	if err != nil {
		t.Fatal(err)
	}
	if len(diff.Added)+len(diff.Removed)+len(diff.Changed) != 0 {
		t.Fatalf("rejected reload changed the table: %+v", diff)
	}
}

func TestNewL3Relay(t *testing.T) {
	tunDev, err := newL3Device(l3TunConfig{
		Name:    "hytun0",
		Address: "10.200.0.2/30",
		Peer:    "10.200.0.1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := tunDev.Close(); err != nil {
		t.Fatal(err)
	}

	dev, err := newL3Device(l3TunConfig{
		Type:    "relay",
		Address: "10.200.0.2/30",
		Peer:    "10.200.0.1",
		Relay: l3RelayConfig{
			Listen: "127.0.0.1:0",
			VNIs: []l3RelayVNI{
				{VNI: 500, VTEP: "192.168.7.1"},
				{VNI: 600, VTEP: "192.168.7.20:4790", Allow: []string{"192.168.7.0/24"}},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := dev.Close(); err != nil {
		t.Fatal(err)
	}

	_, err = newL3Device(l3TunConfig{
		Type:    "relay",
		Address: "10.200.0.2",
		Peer:    "2001:db8::1",
		Relay: l3RelayConfig{
			Listen: "127.0.0.1:0",
			VNIs:   []l3RelayVNI{{VNI: 1, VTEP: "127.0.0.1"}},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "l3tun") {
		t.Fatalf("mixed versions: %v", err)
	}

	cases := []l3TunConfig{
		{Type: "relay", Address: "10.200.0.2/30", Peer: "10.200.0.1"},
		{
			Type: "nope", Address: "10.200.0.2/30", Peer: "10.200.0.1",
		},
		{
			Type: "relay", Address: "10.200.0.2/30", Peer: "10.200.0.1",
			Relay: l3RelayConfig{
				Listen: "127.0.0.1:0",
				VNIs:   []l3RelayVNI{{VNI: 1, VTEP: "192.168.7.1"}, {VNI: 1, VTEP: "192.168.7.2"}},
			},
		},
		{
			Type: "relay", Address: "10.200.0.2/30", Peer: "10.200.0.1",
			Relay: l3RelayConfig{
				Listen: "127.0.0.1:0",
				VNIs:   []l3RelayVNI{{VNI: 0, VTEP: "192.168.7.1"}},
			},
		},
		{
			Type: "relay", Address: "10.200.0.2/30", Peer: "10.200.0.1",
			Relay: l3RelayConfig{
				Listen: "not an address",
				VNIs:   []l3RelayVNI{{VNI: 1, VTEP: "192.168.7.1"}},
			},
		},
	}
	for _, cfg := range cases {
		if _, err := newL3Device(cfg); err == nil {
			t.Fatalf("accepted %#v", cfg)
		}
	}
}

func TestParseVTEP(t *testing.T) {
	bare, err := parseVTEP("192.168.7.1")
	if err != nil || bare.Port() != 4789 || bare.Addr().String() != "192.168.7.1" {
		t.Fatalf("bare = %v %v", bare, err)
	}
	full, err := parseVTEP("192.168.7.20:4790")
	if err != nil || full.Port() != 4790 {
		t.Fatalf("full = %v %v", full, err)
	}
}

func TestL3TUNFilter(t *testing.T) {
	base := l3TunConfig{Name: "hytun0", Address: "10.200.0.1/30", Peer: "10.200.0.2"}
	for filter, want := range map[string]bool{"": true, "vxlan": true, "None": false} {
		cfg := base
		cfg.Filter = filter
		dev, err := newL3Device(cfg)
		if err != nil {
			t.Fatalf("filter %q: %v", filter, err)
		}
		if got := dev.(tunL3).VXLANOnly; got != want {
			t.Errorf("filter %q: VXLANOnly = %v, want %v", filter, got, want)
		}
	}
	cfg := base
	cfg.Filter = "bogus"
	if _, err := newL3Device(cfg); err == nil {
		t.Fatal("unknown filter was accepted")
	}
}
