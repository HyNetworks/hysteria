package cmd

import (
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"

	"github.com/apernet/hysteria/core/v2/client"
	"github.com/apernet/hysteria/core/v2/server"
)

func TestClientConnectionPoolConfig(t *testing.T) {
	for _, size := range []int{0, 1, 2, 3, client.MaxConnectionPoolSize, -1, client.MaxConnectionPoolSize + 1} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			v := viper.New()
			v.SetConfigType("yaml")
			require.NoError(t, v.ReadConfig(strings.NewReader(fmt.Sprintf("quic:\n  connectionPoolSize: %d\n", size))))
			var config clientConfig
			require.NoError(t, v.Unmarshal(&config))
			got, err := config.connectionPoolSize()
			if size < 0 || size > client.MaxConnectionPoolSize {
				require.ErrorContains(t, err, "quic.connectionPoolSize")
				c, err := config.newClient(nil)
				require.Nil(t, c)
				require.ErrorContains(t, err, "quic.connectionPoolSize")
			} else {
				require.NoError(t, err)
				require.Equal(t, max(1, size), got)
			}
		})
	}

	t.Run("omitted", func(t *testing.T) {
		var config clientConfig
		size, err := config.connectionPoolSize()
		require.NoError(t, err)
		require.Equal(t, 1, size)
	})
	t.Run("realm rejects pool before opening sockets", func(t *testing.T) {
		config := clientConfig{Server: "realm://pool-test@example.com/realm", QUIC: clientConfigQUIC{ConnectionPoolSize: 2}}
		c, err := config.newClient(nil)
		require.Nil(t, c)
		require.ErrorContains(t, err, "connection pooling is not supported in realm mode")
		config.QUIC.ConnectionPoolSize = 1
		size, err := config.connectionPoolSize()
		require.NoError(t, err)
		require.Equal(t, 1, size)
	})
}

// Exercise the same config-to-client constructor used by client mode, not just
// YAML decoding. Each member must perform a distinct authenticated handshake.
func TestClientConnectionPoolTCPUDP(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key")
	_, err := runCert(certOptions{Hosts: "localhost", CertFile: certFile, KeyFile: keyFile, ValidFor: time.Hour})
	require.NoError(t, err)
	for _, size := range []int{0, 1, 2, 3, client.MaxConnectionPoolSize} {
		for _, lazy := range []bool{false, true} {
			t.Run(fmt.Sprintf("size=%d/lazy=%t", size, lazy), func(t *testing.T) {
				packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
				require.NoError(t, err)
				t.Cleanup(func() { _ = packetConn.Close() })
				sc := &server.Config{Conn: packetConn}
				config := serverConfig{
					TLS:  &serverConfigTLS{Cert: certFile, Key: keyFile},
					Auth: serverConfigAuth{Type: "password", Password: "pool-test"},
				}
				require.NoError(t, config.fillTLSConfig(sc))
				require.NoError(t, config.fillAuthenticator(sc))
				s, err := server.NewServer(sc)
				require.NoError(t, err)
				t.Cleanup(func() { _ = s.Close() })
				go s.Serve()

				v := viper.New()
				v.SetConfigType("yaml")
				yaml := fmt.Sprintf("server: %q\nauth: pool-test\nlazy: %t\ntls:\n  sni: localhost\n  ca: %q\nquic:\n  connectionPoolSize: %d\n  disableChromeParrot: true\nbandwidth:\n  up: 450 mbps\n  down: 450 mbps\n", packetConn.LocalAddr().String(), lazy, certFile, size)
				require.NoError(t, v.ReadConfig(strings.NewReader(yaml)))
				var cc clientConfig
				require.NoError(t, v.Unmarshal(&cc))
				effectiveSize := max(1, size)
				var members []client.Client
				c, err := cc.newClient(func(member client.Client, info *client.HandshakeInfo, count int) {
					members = append(members, member)
					require.Equal(t, len(members), count)
					require.True(t, info.UDPEnabled)
					require.Equal(t, uint64(450000000/8)/uint64(effectiveSize), info.Tx)
				})
				require.NoError(t, err)
				t.Cleanup(func() { _ = c.Close() })
				if lazy {
					require.Empty(t, members)
				} else {
					require.Len(t, members, effectiveSize)
				}
				for range effectiveSize {
					assertECHProxyTraffic(t, c)
				}
				require.Len(t, members, effectiveSize)
				for i := range members {
					for j := range i {
						require.NotSame(t, members[i], members[j])
					}
				}
				require.NoError(t, c.Close())
			})
		}
	}
}
