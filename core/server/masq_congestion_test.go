package server

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/apernet/hysteria/core/v2/internal/protocol"
	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	"github.com/stretchr/testify/require"
)

type masqTestAuthenticator struct{}

func (masqTestAuthenticator) Authenticate(_ net.Addr, auth string, _ uint64) (bool, string) {
	return auth == "secret", "test"
}

func masqTestConfig(t *testing.T) *Config {
	t.Helper()
	certServer := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(certServer.Close)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = pc.Close() })
	return &Config{
		TLSConfig: TLSConfig{Certificates: certServer.TLS.Certificates},
		Conn:      pc, Authenticator: masqTestAuthenticator{}, DisableUDP: true,
	}
}

// A real QUIC connection exercises installation without exposing test hooks in
// production. Do not run ServeQUICConn: requests are driven directly by tests.
func masqTestHandler(t *testing.T, config *Config) *h3sHandler {
	t.Helper()
	require.NoError(t, config.fill())
	tr := &quic.Transport{Conn: config.Conn}
	listener, err := tr.Listen(convertToStdTLSConfig(config), &quic.Config{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = tr.Close() })
	t.Cleanup(func() { _ = listener.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := quic.DialAddr(ctx, config.Conn.LocalAddr().String(), &tls.Config{
		InsecureSkipVerify: true, NextProtos: []string{http3.NextProtoH3},
	}, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.CloseWithError(0, "") })
	conn, err := listener.Accept(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.CloseWithError(0, "") })
	return newH3sHandler(config, conn)
}

// The pinned quic-go fork has no controller getter. Inspect only the installed
// object's identity/type, never its live congestion state. Call after all
// application controller-installation goroutines have joined.
func installedController(conn *quic.Conn) reflect.Value {
	handler := reflect.ValueOf(conn).Elem().FieldByName("sentPacketHandler").Elem()
	if handler.Kind() == reflect.Pointer {
		handler = handler.Elem()
	}
	cc := handler.FieldByName("congestion").Elem()
	if cc.Type().Elem().Name() == "ccAdapter" || cc.Type().Elem().Name() == "ccAdapterEx" {
		return cc.Elem().Field(0).Elem()
	}
	return cc
}

func serveMasqTestRequest(h *h3sHandler, auth string, rx uint64) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "https://hysteria/auth", nil)
	protocol.AuthRequestToHeader(r.Header, protocol.AuthRequest{Auth: auth, Rx: rx})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestMasqCongestionValidation(t *testing.T) {
	for _, tt := range []struct {
		name string
		cc   *CongestionConfig
		want *CongestionConfig
		err  string
	}{
		{name: "omitted"},
		{name: "defaults", cc: &CongestionConfig{}, want: &CongestionConfig{Type: "bbr", BBRProfile: "standard"}},
		{name: "independent profile", cc: &CongestionConfig{Type: "BBR", BBRProfile: "Conservative"}, want: &CongestionConfig{Type: "bbr", BBRProfile: "conservative"}},
		{name: "reno", cc: &CongestionConfig{Type: "reno"}, want: &CongestionConfig{Type: "reno"}},
		{name: "invalid type", cc: &CongestionConfig{Type: "brutal"}, err: "MasqCongestionConfig.Type"},
		{name: "invalid profile", cc: &CongestionConfig{Type: "bbr", BBRProfile: "turbo"}, err: "MasqCongestionConfig.BBRProfile"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			config := masqTestConfig(t)
			config.CongestionConfig = CongestionConfig{Type: "bbr", BBRProfile: "aggressive"}
			config.MasqCongestionConfig = tt.cc
			err := config.fill()
			if tt.err != "" {
				require.ErrorContains(t, err, tt.err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, config.MasqCongestionConfig)
			require.Equal(t, "aggressive", config.CongestionConfig.BBRProfile)
		})
	}
}

func TestMasqCongestionOnce(t *testing.T) {
	for _, kind := range []string{"omitted", "reno", "bbr"} {
		t.Run(kind, func(t *testing.T) {
			config := masqTestConfig(t)
			if kind != "omitted" {
				config.MasqCongestionConfig = &CongestionConfig{Type: kind, BBRProfile: "conservative"}
			}
			h := masqTestHandler(t, config)
			before := installedController(h.conn).Pointer()
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "https://site/game.data", nil))
			require.Equal(t, http.StatusNotFound, w.Code)
			first := installedController(h.conn)
			if kind == "bbr" {
				require.NotEqual(t, before, first.Pointer())
				require.Equal(t, "*bbr.bbrSender", first.Type().String())
				require.Equal(t, "conservative", first.Elem().FieldByName("profile").String())
			} else {
				require.Equal(t, before, first.Pointer())
			}
			var wg sync.WaitGroup
			for range 128 {
				wg.Go(func() {
					h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "https://site/asset", nil))
				})
			}
			wg.Wait()
			require.Equal(t, first.Pointer(), installedController(h.conn).Pointer())
		})
	}
}

func TestMasqCongestionAuthentication(t *testing.T) {
	for _, tt := range []struct {
		name      string
		proxyType string
		rx        uint64
		ignore    bool
		wantType  string
	}{
		{name: "proxy bbr", proxyType: "bbr", wantType: "*bbr.bbrSender"},
		{name: "proxy reno restored", proxyType: "reno", wantType: "*reno.Sender"},
		{name: "bandwidth selects brutal", proxyType: "reno", rx: 1000000, wantType: "*brutal.BrutalSender"},
		{name: "ignore bandwidth keeps bbr", proxyType: "bbr", rx: 1000000, ignore: true, wantType: "*bbr.bbrSender"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			config := masqTestConfig(t)
			config.CongestionConfig = CongestionConfig{Type: tt.proxyType, BBRProfile: "aggressive"}
			config.IgnoreClientBandwidth = tt.ignore
			config.MasqCongestionConfig = &CongestionConfig{Type: "bbr", BBRProfile: "conservative"}
			h := masqTestHandler(t, config)
			// Failed authentication enters masquerade without self-deadlocking.
			require.Equal(t, http.StatusNotFound, serveMasqTestRequest(h, "wrong", 0).Code)
			require.Equal(t, "*bbr.bbrSender", installedController(h.conn).Type().String())
			require.Equal(t, protocol.StatusAuthOK, serveMasqTestRequest(h, "secret", tt.rx).Code)
			proxy := installedController(h.conn)
			require.Equal(t, tt.wantType, proxy.Type().String())
			if tt.proxyType == "bbr" {
				require.Equal(t, "aggressive", proxy.Elem().FieldByName("profile").String())
			}
			for range 10 {
				h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "https://site/asset", nil))
			}
			require.Equal(t, protocol.StatusAuthOK, serveMasqTestRequest(h, "secret", tt.rx).Code)
			require.Equal(t, proxy.Pointer(), installedController(h.conn).Pointer())
		})
	}
}

func TestMasqCongestionConcurrentAuthentication(t *testing.T) {
	config := masqTestConfig(t)
	config.CongestionConfig = CongestionConfig{Type: "bbr", BBRProfile: "aggressive"}
	config.MasqCongestionConfig = &CongestionConfig{Type: "bbr", BBRProfile: "conservative"}
	h := masqTestHandler(t, config)
	var wg sync.WaitGroup
	for range 128 {
		wg.Go(func() {
			h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "https://site/asset", nil))
		})
	}
	wg.Go(func() { serveMasqTestRequest(h, "secret", 0) })
	wg.Wait()
	cc := installedController(h.conn)
	require.True(t, h.proxyCongestionSet)
	require.Equal(t, "aggressive", cc.Elem().FieldByName("profile").String())
}

func TestMasqCongestionFreshProxyUnaffected(t *testing.T) {
	config := masqTestConfig(t)
	config.CongestionConfig = CongestionConfig{Type: "reno"}
	config.MasqCongestionConfig = &CongestionConfig{Type: "bbr", BBRProfile: "aggressive"}
	h := masqTestHandler(t, config)
	before := installedController(h.conn).Pointer()
	require.Equal(t, protocol.StatusAuthOK, serveMasqTestRequest(h, "secret", 0).Code)
	h.initMasqCongestion()
	require.False(t, h.masqCongestionSet)
	require.Equal(t, before, installedController(h.conn).Pointer())
}

func TestMasqCongestionHTTP3Download(t *testing.T) {
	config := masqTestConfig(t)
	config.MasqCongestionConfig = &CongestionConfig{Type: "bbr", BBRProfile: "standard"}
	const content = "game resource"
	config.MasqHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, content)
	})
	s, err := NewServer(config)
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() { done <- s.Serve() }()
	t.Cleanup(func() { _ = s.Close(); <-done })
	tr := &http3.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	t.Cleanup(func() { _ = tr.Close() })
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	// Model a preloader's queue: many resources, bounded parallel requests,
	// sharing the transport's HTTP/3 connection.
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			for range 64 {
				resp, err := client.Get("https://" + config.Conn.LocalAddr().String() + "/game.data")
				if err != nil {
					t.Errorf("HTTP/3 download: %v", err)
					return
				}
				body, err := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				if err != nil || resp.ProtoMajor != 3 || string(body) != content {
					t.Errorf("unexpected HTTP/3 response: protocol=%s body=%q error=%v", resp.Proto, body, err)
					return
				}
			}
		})
	}
	wg.Wait()
}
