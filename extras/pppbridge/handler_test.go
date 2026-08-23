//go:build !windows

package pppbridge

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

func TestBuildPPPDArgs(t *testing.T) {
	tests := []struct {
		name       string
		handler    *ServerPPPHandler
		gatewayIP  string
		clientIP   string
		remoteName string
		wantArgs   []string
		wantMTU    int
	}{
		{
			name: "dual-stack with DNS and MTU defaults",
			handler: &ServerPPPHandler{
				DNS:    []string{"8.8.8.8"},
				MTU:    1420,
				Logger: zap.NewNop(),
			},
			gatewayIP:  "10.0.0.1",
			clientIP:   "10.0.0.2",
			remoteName: "alice",
			wantArgs: []string{
				"nodetach", "local", "+ipv6", "require-pap", "multilink", "mpshortseq", "lcp-echo-interval", "5", "lcp-echo-failure", "3", "lcp-echo-adaptive",
				"10.0.0.1:10.0.0.2",
				"ms-dns", "8.8.8.8",
				"mtu", "1420", "mru", "1420",
				"remotename", "alice",
			},
			wantMTU: 1420,
		},
		{
			name: "ipv6-only no IPv4 defaults",
			handler: &ServerPPPHandler{
				MTU:    1400,
				Logger: zap.NewNop(),
			},
			gatewayIP:  "",
			clientIP:   "",
			remoteName: "bob",
			wantArgs: []string{
				"nodetach", "local", "+ipv6", "require-pap", "multilink", "mpshortseq", "lcp-echo-interval", "5", "lcp-echo-failure", "3", "lcp-echo-adaptive",
				"mtu", "1400", "mru", "1400",
				"remotename", "bob",
			},
			wantMTU: 1400,
		},
		{
			name: "ipv4 only no MTU defaults",
			handler: &ServerPPPHandler{
				MTU:    0,
				Logger: zap.NewNop(),
			},
			gatewayIP:  "10.0.0.1",
			clientIP:   "10.0.0.2",
			remoteName: "charlie",
			wantArgs: []string{
				"nodetach", "local", "+ipv6", "require-pap", "multilink", "mpshortseq", "lcp-echo-interval", "5", "lcp-echo-failure", "3", "lcp-echo-adaptive",
				"10.0.0.1:10.0.0.2",
				"mtu", "1376", "mru", "1382",
				"remotename", "charlie",
			},
			wantMTU: 1376,
		},
		{
			name: "custom args override defaults",
			handler: &ServerPPPHandler{
				MTU:      1400,
				DNS:      []string{"8.8.8.8"},
				PPPDArgs: []string{"nodetach", "require-chap", "name", "myvpn", "mtu", "1300"},
				Logger:   zap.NewNop(),
			},
			gatewayIP:  "10.0.0.1",
			clientIP:   "10.0.0.2",
			remoteName: "dave",
			wantArgs: []string{
				"nodetach", "require-chap", "name", "myvpn", "mtu", "1300",
				"remotename", "dave",
			},
			wantMTU: 0,
		},
		{
			name: "custom args with empty remotename",
			handler: &ServerPPPHandler{
				PPPDArgs: []string{"nodetach", "debug"},
				Logger:   zap.NewNop(),
			},
			gatewayIP:  "",
			clientIP:   "",
			remoteName: "",
			wantArgs: []string{
				"nodetach", "debug",
			},
			wantMTU: 0,
		},
		{
			name: "ipv6-only with DNS defaults",
			handler: &ServerPPPHandler{
				DNS:    []string{"2001:4860:4860::8888"},
				MTU:    1400,
				Logger: zap.NewNop(),
			},
			gatewayIP:  "",
			clientIP:   "",
			remoteName: "eve",
			wantArgs: []string{
				"nodetach", "local", "+ipv6", "require-pap", "multilink", "mpshortseq", "lcp-echo-interval", "5", "lcp-echo-failure", "3", "lcp-echo-adaptive",
				"ms-dns", "2001:4860:4860::8888",
				"mtu", "1400", "mru", "1400",
				"remotename", "eve",
			},
			wantMTU: 1400,
		},
		{
			name: "empty remotename omitted defaults",
			handler: &ServerPPPHandler{
				MTU:    1400,
				Logger: zap.NewNop(),
			},
			gatewayIP:  "",
			clientIP:   "",
			remoteName: "",
			wantArgs: []string{
				"nodetach", "local", "+ipv6", "require-pap", "multilink", "mpshortseq", "lcp-echo-interval", "5", "lcp-echo-failure", "3", "lcp-echo-adaptive",
				"mtu", "1400", "mru", "1400",
			},
			wantMTU: 1400,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotArgs, gotMTU := tt.handler.buildPPPDArgs(tt.gatewayIP, tt.clientIP, tt.remoteName, nil, 0, 0)
			assert.Equal(t, tt.wantArgs, gotArgs)
			assert.Equal(t, tt.wantMTU, gotMTU)
		})
	}
}
