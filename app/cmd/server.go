package cmd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/apernet/hysteria/app/v2/internal/mimic"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/cloudflare"
	"github.com/libdns/duckdns"
	"github.com/libdns/gandi"
	"github.com/libdns/godaddy"
	"github.com/libdns/namecheap"
	"github.com/libdns/njalla"
	"github.com/libdns/porkbun"
	"github.com/libdns/vultr/v2"
	"github.com/mholt/acmez/v3/acme"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"golang.org/x/sync/singleflight"

	"github.com/apernet/hysteria/app/v2/internal/firewall"
	"github.com/apernet/hysteria/app/v2/internal/utils"
	"github.com/apernet/hysteria/core/v2/server"
	"github.com/apernet/hysteria/extras/v2/auth"
	"github.com/apernet/hysteria/extras/v2/correctnet"
	"github.com/apernet/hysteria/extras/v2/masq"
	"github.com/apernet/hysteria/extras/v2/obfs"
	"github.com/apernet/hysteria/extras/v2/outbounds"
	"github.com/apernet/hysteria/extras/v2/realm"
	"github.com/apernet/hysteria/extras/v2/sniff"
	"github.com/apernet/hysteria/extras/v2/trafficlogger"
	eUtils "github.com/apernet/hysteria/extras/v2/utils"
)

const defaultListenAddr = ":443"

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Server mode",
	Run:   runServerCmd,
}

func init() {
	rootCmd.AddCommand(serverCmd)
}

type serverConfig struct {
	Listen                string                      `mapstructure:"listen"`
	Realm                 serverConfigRealm           `mapstructure:"realm"`
	Obfs                  serverConfigObfs            `mapstructure:"obfs"`
	TLS                   *serverConfigTLS            `mapstructure:"tls"`
	ACME                  *serverConfigACME           `mapstructure:"acme"`
	ECH                   *serverConfigECH            `mapstructure:"ech"`
	QUIC                  serverConfigQUIC            `mapstructure:"quic"`
	Mimic                 mimicConfig                 `mapstructure:"mimic"`
	Congestion            serverConfigCongestion      `mapstructure:"congestion"`
	Bandwidth             serverConfigBandwidth       `mapstructure:"bandwidth"`
	IgnoreClientBandwidth bool                        `mapstructure:"ignoreClientBandwidth"`
	SpeedTest             bool                        `mapstructure:"speedTest"`
	DisableUDP            bool                        `mapstructure:"disableUDP"`
	UDPIdleTimeout        time.Duration               `mapstructure:"udpIdleTimeout"`
	Auth                  serverConfigAuth            `mapstructure:"auth"`
	Resolver              serverConfigResolver        `mapstructure:"resolver"`
	Sniff                 serverConfigSniff           `mapstructure:"sniff"`
	ACL                   serverConfigACL             `mapstructure:"acl"`
	Outbounds             []serverConfigOutboundEntry `mapstructure:"outbounds"`
	TrafficStats          serverConfigTrafficStats    `mapstructure:"trafficStats"`
	Masquerade            serverConfigMasquerade      `mapstructure:"masquerade"`
}

type serverConfigRealm struct {
	STUNServers       []string               `mapstructure:"stunServers"`
	STUNTimeout       time.Duration          `mapstructure:"stunTimeout"`
	PunchTimeout      time.Duration          `mapstructure:"punchTimeout"`
	HeartbeatInterval time.Duration          `mapstructure:"heartbeatInterval"`
	Insecure          bool                   `mapstructure:"insecure"`
	IPMode            string                 `mapstructure:"ipMode"`
	PortMapping       realmPortMappingConfig `mapstructure:"portMapping"`
}

type serverConfigObfsSalamander struct {
	Password string `mapstructure:"password"`
}

type serverConfigObfsGecko struct {
	Password      string `mapstructure:"password"`
	MinPacketSize int    `mapstructure:"minPacketSize"`
	MaxPacketSize int    `mapstructure:"maxPacketSize"`
}

type serverConfigObfs struct {
	Type       string                     `mapstructure:"type"`
	Salamander serverConfigObfsSalamander `mapstructure:"salamander"`
	Gecko      serverConfigObfsGecko      `mapstructure:"gecko"`
}

type serverConfigTLS struct {
	Cert     string `mapstructure:"cert"`
	Key      string `mapstructure:"key"`
	SNIGuard string `mapstructure:"sniGuard"` // "disable", "dns-san", "strict"
	ClientCA string `mapstructure:"clientCA"`
}

type serverConfigECH struct {
	KeyPath string `mapstructure:"keyPath"`
}

type serverConfigACME struct {
	// Common fields
	Domains    []string `mapstructure:"domains"`
	Email      string   `mapstructure:"email"`
	CA         string   `mapstructure:"ca"`
	ListenHost string   `mapstructure:"listenHost"`
	Dir        string   `mapstructure:"dir"`

	// Type selection
	Type string               `mapstructure:"type"`
	HTTP serverConfigACMEHTTP `mapstructure:"http"`
	TLS  serverConfigACMETLS  `mapstructure:"tls"`
	DNS  serverConfigACMEDNS  `mapstructure:"dns"`

	// Legacy fields for backwards compatibility
	// Only applicable when Type is empty
	DisableHTTP    bool `mapstructure:"disableHTTP"`
	DisableTLSALPN bool `mapstructure:"disableTLSALPN"`
	AltHTTPPort    int  `mapstructure:"altHTTPPort"`
	AltTLSALPNPort int  `mapstructure:"altTLSALPNPort"`
}

type serverConfigACMEHTTP struct {
	AltPort int `mapstructure:"altPort"`
}

type serverConfigACMETLS struct {
	AltPort int `mapstructure:"altPort"`
}

type serverConfigACMEDNS struct {
	Name   string            `mapstructure:"name"`
	Config map[string]string `mapstructure:"config"`
}

type serverConfigQUIC struct {
	InitStreamReceiveWindow     uint64        `mapstructure:"initStreamReceiveWindow"`
	MaxStreamReceiveWindow      uint64        `mapstructure:"maxStreamReceiveWindow"`
	InitConnectionReceiveWindow uint64        `mapstructure:"initConnReceiveWindow"`
	MaxConnectionReceiveWindow  uint64        `mapstructure:"maxConnReceiveWindow"`
	MaxIdleTimeout              time.Duration `mapstructure:"maxIdleTimeout"`
	MaxIncomingStreams          int64         `mapstructure:"maxIncomingStreams"`
	DisablePathMTUDiscovery     bool          `mapstructure:"disablePathMTUDiscovery"`
	DisableStatelessReset       bool          `mapstructure:"disableStatelessReset"`
}

type serverConfigBandwidth struct {
	Up                      string `mapstructure:"up"`
	Down                    string `mapstructure:"down"`
	DisableLossCompensation bool   `mapstructure:"disableLossCompensation"`
}

type serverConfigCongestion struct {
	Type       string `mapstructure:"type"`
	BBRProfile string `mapstructure:"bbrProfile"`
}

type serverConfigAuthHTTP struct {
	URL      string `mapstructure:"url"`
	Insecure bool   `mapstructure:"insecure"`
}

type serverConfigAuth struct {
	Type     string               `mapstructure:"type"`
	Password string               `mapstructure:"password"`
	UserPass map[string]string    `mapstructure:"userpass"`
	HTTP     serverConfigAuthHTTP `mapstructure:"http"`
	Command  string               `mapstructure:"command"`
}

type serverConfigResolverTCP struct {
	Addr    string        `mapstructure:"addr"`
	Timeout time.Duration `mapstructure:"timeout"`
}

type serverConfigResolverUDP struct {
	Addr    string        `mapstructure:"addr"`
	Timeout time.Duration `mapstructure:"timeout"`
}

type serverConfigResolverTLS struct {
	Addr     string        `mapstructure:"addr"`
	Timeout  time.Duration `mapstructure:"timeout"`
	SNI      string        `mapstructure:"sni"`
	Insecure bool          `mapstructure:"insecure"`
}

type serverConfigResolverHTTPS struct {
	Addr     string        `mapstructure:"addr"`
	Timeout  time.Duration `mapstructure:"timeout"`
	SNI      string        `mapstructure:"sni"`
	Insecure bool          `mapstructure:"insecure"`
}

type serverConfigResolver struct {
	Type  string                    `mapstructure:"type"`
	TCP   serverConfigResolverTCP   `mapstructure:"tcp"`
	UDP   serverConfigResolverUDP   `mapstructure:"udp"`
	TLS   serverConfigResolverTLS   `mapstructure:"tls"`
	HTTPS serverConfigResolverHTTPS `mapstructure:"https"`
}

type serverConfigSniff struct {
	Enable        bool          `mapstructure:"enable"`
	Timeout       time.Duration `mapstructure:"timeout"`
	RewriteDomain bool          `mapstructure:"rewriteDomain"`
	TCPPorts      string        `mapstructure:"tcpPorts"`
	UDPPorts      string        `mapstructure:"udpPorts"`
}

type serverConfigACL struct {
	File              string        `mapstructure:"file"`
	Inline            []string      `mapstructure:"inline"`
	GeoIP             string        `mapstructure:"geoip"`
	GeoSite           string        `mapstructure:"geosite"`
	GeoUpdateInterval time.Duration `mapstructure:"geoUpdateInterval"`
}

type serverConfigOutboundDirect struct {
	Mode       string `mapstructure:"mode"`
	BindIPv4   string `mapstructure:"bindIPv4"`
	BindIPv6   string `mapstructure:"bindIPv6"`
	BindDevice string `mapstructure:"bindDevice"`
	FastOpen   bool   `mapstructure:"fastOpen"`
}

type serverConfigOutboundSOCKS5 struct {
	Addr     string `mapstructure:"addr"`
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
}

type serverConfigOutboundHTTP struct {
	URL      string `mapstructure:"url"`
	Insecure bool   `mapstructure:"insecure"`
}

type serverConfigOutboundEntry struct {
	Name   string                     `mapstructure:"name"`
	Type   string                     `mapstructure:"type"`
	Direct serverConfigOutboundDirect `mapstructure:"direct"`
	SOCKS5 serverConfigOutboundSOCKS5 `mapstructure:"socks5"`
	HTTP   serverConfigOutboundHTTP   `mapstructure:"http"`
}

type serverConfigTrafficStats struct {
	Listen string `mapstructure:"listen"`
	Secret string `mapstructure:"secret"`
}

type serverConfigMasqueradeFile struct {
	Dir string `mapstructure:"dir"`
}

type serverConfigMasqueradeProxy struct {
	URL           string        `mapstructure:"url"`
	RewriteHost   bool          `mapstructure:"rewriteHost"`
	XForwarded    bool          `mapstructure:"xForwarded"`
	Insecure      bool          `mapstructure:"insecure"`
	FlushInterval time.Duration `mapstructure:"flushInterval"`
}

type serverConfigMasqueradeString struct {
	Content    string            `mapstructure:"content"`
	Headers    map[string]string `mapstructure:"headers"`
	StatusCode int               `mapstructure:"statusCode"`
}

type serverConfigMasquerade struct {
	Type               string                       `mapstructure:"type"`
	File               serverConfigMasqueradeFile   `mapstructure:"file"`
	Proxy              serverConfigMasqueradeProxy  `mapstructure:"proxy"`
	String             serverConfigMasqueradeString `mapstructure:"string"`
	ListenHTTP         string                       `mapstructure:"listenHTTP"`
	ListenHTTPS        string                       `mapstructure:"listenHTTPS"`
	ForceHTTPS         bool                         `mapstructure:"forceHTTPS"`
	AdvertisedQUICPort int                          `mapstructure:"advertisedQUICPort"`
}

func (c *serverConfig) fillConn(hyConfig *server.Config) error {
	if realmAddr, ok, err := parseServerRealmAddr(c.Listen); ok || err != nil {
		if err != nil {
			return configError{Field: "listen", Err: err}
		}
		return c.fillRealmConn(hyConfig, realmAddr)
	}
	listenAddr := c.Listen
	if listenAddr == "" {
		listenAddr = defaultListenAddr
	}
	uAddr, portUnion, err := resolveServerListenAddr(listenAddr)
	if err != nil {
		return configError{Field: "listen", Err: err}
	}
	conn, err := correctnet.ListenUDP("udp", uAddr)
	if err != nil {
		return configError{Field: "listen", Err: err}
	}
	var packetConn net.PacketConn = conn
	var cleanup io.Closer
	if len(portUnion) > 0 {
		cleanup, err = firewall.SetupUDPPortRedirect(uAddr, portUnion)
		if err != nil {
			_ = conn.Close()
			return configError{Field: "listen", Err: err}
		}
	}
	wrapped, err := c.wrapObfs(packetConn)
	if err != nil {
		_ = conn.Close()
		if cleanup != nil {
			_ = cleanup.Close()
		}
		return err
	}
	hyConfig.Conn = wrapped
	hyConfig.Cleanup = cleanup
	return nil
}

func parseServerRealmAddr(listen string) (*realm.Addr, bool, error) {
	addr, err := realm.ParseAddr(listen)
	if err == nil {
		return addr, true, nil
	}
	if strings.HasPrefix(listen, realm.SchemeHTTPS+":") || strings.HasPrefix(listen, realm.SchemeHTTP+":") {
		return nil, true, err
	}
	return nil, false, nil
}

func (c *serverConfig) fillRealmConn(hyConfig *server.Config, addr *realm.Addr) error {
	logger.Debug("realm server mode detected",
		zap.String("realm", addr.RealmID),
		zap.String("realmServer", addr.HostPort),
		zap.String("scheme", addr.RendezvousScheme))
	family, network, err := realmIPMode(c.Realm.IPMode)
	if err != nil {
		return configError{Field: "realm.ipMode", Err: err}
	}
	listenAddr := &net.UDPAddr{}
	if addr.LocalPort != 0 {
		listenAddr.Port = addr.LocalPort
	}
	conn, err := correctnet.ListenUDP(network, listenAddr)
	if err != nil {
		return configError{Field: "listen", Err: err}
	}
	logger.Debug("realm server UDP socket opened",
		zap.String("realm", addr.RealmID),
		zap.String("local", conn.LocalAddr().String()))

	punchConn, err := realm.NewPunchPacketConn(conn, 0)
	if err != nil {
		_ = conn.Close()
		return configError{Field: "realm", Err: err}
	}
	packetConn, err := c.wrapObfs(punchConn)
	if err != nil {
		_ = conn.Close()
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	runtime, err := c.startRealmServerRuntime(ctx, cancel, addr, punchConn, family)
	if err != nil {
		cancel()
		_ = packetConn.Close()
		return err
	}
	hyConfig.Conn = packetConn
	hyConfig.Cleanup = runtime
	return nil
}

func (c *serverConfig) wrapObfs(conn net.PacketConn) (net.PacketConn, error) {
	switch strings.ToLower(c.Obfs.Type) {
	case "", "plain":
		return conn, nil
	case "salamander":
		wrapped, err := obfs.WrapPacketConnSalamander(conn, []byte(c.Obfs.Salamander.Password))
		if err != nil {
			return nil, configError{Field: "obfs.salamander.password", Err: err}
		}
		return wrapped, nil
	case "gecko":
		wrapped, err := obfs.WrapPacketConnGecko(conn, obfs.GeckoOptions{
			Password:      []byte(c.Obfs.Gecko.Password),
			MinPacketSize: c.Obfs.Gecko.MinPacketSize,
			MaxPacketSize: c.Obfs.Gecko.MaxPacketSize,
		})
		if err != nil {
			return nil, configError{Field: "obfs.gecko", Err: err}
		}
		return wrapped, nil
	default:
		return nil, configError{Field: "obfs.type", Err: errors.New("unsupported obfuscation type")}
	}
}

func resolveServerListenAddr(listenAddr string) (*net.UDPAddr, eUtils.PortUnion, error) {
	host, portStr, err := net.SplitHostPort(listenAddr)
	if err != nil {
		uAddr, resolveErr := net.ResolveUDPAddr("udp", listenAddr)
		return uAddr, nil, resolveErr
	}
	if !strings.ContainsAny(portStr, "-,") {
		uAddr, resolveErr := net.ResolveUDPAddr("udp", listenAddr)
		return uAddr, nil, resolveErr
	}
	portUnion := eUtils.ParsePortUnion(portStr)
	if portUnion == nil {
		return nil, nil, fmt.Errorf("%s is not a valid port number or range", portStr)
	}
	firstListenAddr := net.JoinHostPort(host, strconv.Itoa(int(portUnion[0].Start)))
	uAddr, err := net.ResolveUDPAddr("udp", firstListenAddr)
	return uAddr, portUnion, err
}

func (c *serverConfig) startRealmServerRuntime(ctx context.Context, cancel context.CancelFunc, addr *realm.Addr, punchConn *realm.PunchPacketConn, family realm.AddrFamily) (*realmServerRuntime, error) {
	stunServers := c.realmSTUNServers(addr)
	rClient, err := realm.NewClientFromAddr(addr, c.realmHTTPClient())
	if err != nil {
		return nil, configError{Field: "realm", Err: err}
	}
	puncher, err := realm.NewServerPuncher(ctx, punchConn)
	if err != nil {
		return nil, configError{Field: "realm", Err: err}
	}
	rt := &realmServerRuntime{
		cancel:      cancel,
		client:      rClient,
		realmID:     addr.RealmID,
		punchConn:   punchConn,
		stunServers: stunServers,
		puncher:     puncher,
		config:      c.Realm,
		family:      family,
	}
	// Gateway port mapping (UPnP/NAT-PMP) runs before STUN.
	// With the pinhole in place, in a double-NAT setup,
	// the address STUN observes corresponds to a path whose inner leg
	// goes through the static mapping rather than a filtered dynamic one.
	if c.Realm.PortMapping.Enabled {
		localPort := 0
		if udpAddr, ok := punchConn.LocalAddr().(*net.UDPAddr); ok {
			localPort = udpAddr.Port
		}
		rt.mapper = newRealmPortMapper(ctx, addr.RealmID, localPort, c.Realm.PortMapping)
	}
	cleanupMapper := func() {
		if rt.mapper != nil {
			_ = rt.mapper.Close()
		}
	}
	if _, _, err := rt.refreshAddrsDirect(ctx); err != nil {
		cleanupMapper()
		return nil, configError{Field: "realm.stun", Err: err}
	}
	initialSession, err := rt.register(ctx)
	if err != nil {
		cleanupMapper()
		return nil, configError{Field: "realm.register", Err: err}
	}
	rt.setSession(initialSession)
	if rt.mapper != nil {
		go realmPortMapLoop(ctx, addr.RealmID, rt.mapper)
	}
	go rt.run(ctx, initialSession)
	return rt, nil
}

func (c *serverConfig) realmSTUNServers(addr *realm.Addr) []string {
	if stunServers := addr.Params["stun"]; len(stunServers) > 0 {
		return append([]string(nil), stunServers...)
	}
	if len(c.Realm.STUNServers) > 0 {
		return append([]string(nil), c.Realm.STUNServers...)
	}
	return append([]string(nil), defaultRealmSTUNServers...)
}

func (c *serverConfig) realmHTTPClient() *http.Client {
	if !c.Realm.Insecure {
		return nil
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	return &http.Client{Transport: tr}
}

const realmConnectSTUNCacheTTL = 10 * time.Second

type realmServerRuntime struct {
	cancel      context.CancelFunc
	client      *realm.Client
	realmID     string
	punchConn   *realm.PunchPacketConn
	stunServers []string
	puncher     *realm.ServerPuncher
	config      serverConfigRealm
	family      realm.AddrFamily
	mapper      *realm.PortMapper // nil if port mapping is disabled or failed

	mu      sync.Mutex
	session realmSession
	addrs   []netip.AddrPort
	addrsAt time.Time

	connectSF singleflight.Group
}

type realmSession struct {
	id  string
	ttl int
}

var (
	errRealmSessionInvalid = errors.New("realm session invalid")
	errRealmSessionLost    = errors.New("realm session lost")
)

func (r *realmServerRuntime) run(ctx context.Context, sess realmSession) {
	for ctx.Err() == nil {
		if err := r.runSession(ctx, sess); err != nil && ctx.Err() == nil {
			logger.Warn("realm session lost", zap.String("realm", r.realmID), zap.Error(err))
		}
		sess = r.registerWithBackoff(ctx)
		if sess.id == "" {
			return
		}
	}
}

func (r *realmServerRuntime) registerWithBackoff(ctx context.Context) realmSession {
	backoff := time.Second
	for ctx.Err() == nil {
		if _, _, err := r.refreshAddrs(ctx); err != nil {
			logger.Warn("realm STUN refresh before re-register failed", zap.String("realm", r.realmID), zap.Error(err))
		}
		sess, err := r.register(ctx)
		if err == nil {
			r.setSession(sess)
			return sess
		}
		if isRealmRegisterFatal(err) {
			logger.Error("realm re-register rejected; giving up", zap.String("realm", r.realmID), zap.Error(err))
			return realmSession{}
		}
		logger.Warn("realm re-register failed", zap.String("realm", r.realmID), zap.Error(err))
		logger.Debug("realm re-register scheduled", zap.String("realm", r.realmID), zap.String("backoff", formatLogDuration(backoff)))
		if !sleepContext(ctx, backoff) {
			return realmSession{}
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
	return realmSession{}
}

func (r *realmServerRuntime) register(ctx context.Context) (realmSession, error) {
	localAddrs := r.currentAddrs()
	logger.Debug("realm registration started",
		zap.String("realm", r.realmID),
		zap.Strings("addresses", addrPortStrings(localAddrs)))
	start := time.Now()
	registerResp, err := r.client.Register(ctx, r.realmID, addrPortStrings(localAddrs))
	if err != nil {
		return realmSession{}, err
	}
	sess := realmSession{id: registerResp.SessionID, ttl: registerResp.TTL}
	logger.Debug("realm registration completed",
		zap.String("realm", r.realmID),
		zap.Int("ttl", sess.ttl),
		zap.String("duration", formatLogDuration(time.Since(start))))
	logger.Info("realm registered",
		zap.String("realm", r.realmID),
		zap.Strings("addresses", addrPortStrings(localAddrs)),
		zap.Int("ttl", sess.ttl))
	return sess, nil
}

func (r *realmServerRuntime) runSession(ctx context.Context, sess realmSession) error {
	sessionCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	errCh := make(chan error, 2)
	go func() { errCh <- r.heartbeatLoop(sessionCtx, sess) }()
	go func() { errCh <- r.eventsLoop(sessionCtx, sess) }()
	err := <-errCh
	cancel()
	return err
}

func (r *realmServerRuntime) heartbeatLoop(ctx context.Context, sess realmSession) error {
	interval := r.config.HeartbeatInterval
	if interval == 0 {
		interval = sessionTTLDuration(sess.ttl) / 2
		if interval <= 0 {
			interval = 15 * time.Second
		}
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	lastOK := time.Now()
	lastPublished := r.currentAddrs()
	for {
		select {
		case <-ctx.Done():
			logger.Debug("realm heartbeat loop stopped", zap.String("realm", r.realmID))
			return ctx.Err()
		case <-t.C:
			logger.Debug("realm heartbeat started", zap.String("realm", r.realmID))
			start := time.Now()
			req := realm.HeartbeatRequest{}
			if current := r.currentAddrs(); !slices.Equal(current, lastPublished) {
				req.Addresses = addrPortStrings(current)
				lastPublished = current
				logger.Debug("realm addresses changed", zap.String("realm", r.realmID), zap.Strings("addresses", req.Addresses))
			}
			resp, err := r.client.Heartbeat(ctx, r.realmID, sess.id, req)
			if err != nil {
				if isRealmSessionInvalid(err) {
					return errRealmSessionInvalid
				}
				logger.Warn("realm heartbeat failed", zap.String("realm", r.realmID), zap.Error(err))
				if time.Since(lastOK) > sessionTTLDuration(sess.ttl) {
					return errRealmSessionLost
				}
				continue
			}
			lastOK = time.Now()
			logger.Debug("realm heartbeat completed",
				zap.String("realm", r.realmID),
				zap.Int("ttl", resp.TTL),
				zap.Bool("addressesUpdated", len(req.Addresses) > 0),
				zap.String("duration", formatLogDuration(time.Since(start))))
			if r.config.HeartbeatInterval == 0 && resp.TTL > 0 {
				next := time.Duration(resp.TTL) * time.Second / 2
				if next > 0 && next != interval {
					interval = next
					t.Reset(interval)
				}
			}
		}
	}
}

func (r *realmServerRuntime) eventsLoop(ctx context.Context, sess realmSession) error {
	backoff := time.Second
	lastOK := time.Now()
	for {
		if ctx.Err() != nil {
			logger.Debug("realm events loop stopped", zap.String("realm", r.realmID))
			return ctx.Err()
		}
		logger.Debug("realm events stream connecting", zap.String("realm", r.realmID))
		stream, err := r.client.Events(ctx, r.realmID, sess.id)
		if err != nil {
			if isRealmSessionInvalid(err) {
				return errRealmSessionInvalid
			}
			logger.Warn("realm events stream failed", zap.String("realm", r.realmID), zap.Error(err))
			if time.Since(lastOK) > sessionTTLDuration(sess.ttl) {
				return errRealmSessionLost
			}
			logger.Debug("realm events stream reconnect scheduled",
				zap.String("realm", r.realmID),
				zap.String("backoff", formatLogDuration(backoff)))
			if !sleepContext(ctx, backoff) {
				return ctx.Err()
			}
			if backoff < 30*time.Second {
				backoff *= 2
			}
			continue
		}
		lastOK = time.Now()
		logger.Debug("realm events stream connected", zap.String("realm", r.realmID))
		backoff = time.Second
		for {
			ev, err := stream.Next()
			if err != nil {
				_ = stream.Close()
				if ctx.Err() == nil {
					logger.Warn("realm events stream dropped", zap.String("realm", r.realmID), zap.Error(err))
				}
				break
			}
			lastOK = time.Now()
			logger.Debug("realm punch event received",
				zap.String("realm", r.realmID),
				zap.String("attempt", shortAttempt(ev.Nonce)),
				zap.Strings("addresses", ev.Addresses))
			go r.respond(ctx, ev)
		}
	}
}

func (r *realmServerRuntime) connectAddrs(ctx context.Context) ([]netip.AddrPort, error) {
	if cached := r.cachedAddrs(); cached != nil {
		return cached, nil
	}
	v, err, _ := r.connectSF.Do("stun", func() (any, error) {
		if cached := r.cachedAddrs(); cached != nil {
			return cached, nil
		}
		addrs, _, err := r.refreshAddrs(ctx)
		if err != nil {
			return nil, err
		}
		return addrs, nil
	})
	if err != nil {
		if fallback := r.currentAddrs(); len(fallback) > 0 {
			return fallback, err
		}
		return nil, err
	}
	return v.([]netip.AddrPort), nil
}

func (r *realmServerRuntime) cachedAddrs() []netip.AddrPort {
	r.mu.Lock()
	if r.addrs == nil || time.Since(r.addrsAt) >= realmConnectSTUNCacheTTL {
		r.mu.Unlock()
		return nil
	}
	addrs := append([]netip.AddrPort(nil), r.addrs...)
	r.mu.Unlock()
	return r.withMappedAddr(addrs)
}

func (r *realmServerRuntime) withMappedAddr(addrs []netip.AddrPort) []netip.AddrPort {
	if r.mapper == nil {
		return addrs
	}
	return mergeMappedAddr(addrs, r.mapper.ExternalAddr())
}

func (r *realmServerRuntime) respond(ctx context.Context, ev *realm.PunchEvent) {
	attempt := shortAttempt(ev.Nonce)
	peerAddrs, err := parseAddrPorts(ev.Addresses)
	if err != nil {
		logger.Warn("invalid realm punch addresses", zap.String("realm", r.realmID), zap.String("attempt", attempt), zap.Error(err))
		return
	}

	freshAddrs, stunErr := r.connectAddrs(ctx)
	if stunErr != nil {
		logger.Warn("realm connect STUN failed; using last-known addresses",
			zap.String("realm", r.realmID),
			zap.String("attempt", attempt),
			zap.Error(stunErr))
	}

	if sess := r.currentSession(); sess.id != "" && len(freshAddrs) > 0 {
		postCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
		err := r.client.ConnectResponse(postCtx, r.realmID, sess.id, ev.Nonce, addrPortStrings(freshAddrs))
		cancel()
		if err != nil {
			logger.Warn("realm connect-response post failed",
				zap.String("realm", r.realmID),
				zap.String("attempt", attempt),
				zap.Error(err))
		}
	}

	logger.Debug("realm punch response started",
		zap.String("realm", r.realmID),
		zap.String("attempt", attempt),
		zap.Strings("candidates", ev.Addresses))
	start := time.Now()
	result, err := r.puncher.Respond(ctx, ev.Nonce, freshAddrs, peerAddrs, ev.PunchMetadata, realm.PunchConfig{
		Timeout: r.config.PunchTimeout,
		Family:  r.family,
	})
	if err != nil {
		logger.Warn("realm punch failed", zap.String("realm", r.realmID), zap.String("attempt", attempt), zap.Error(err))
		return
	}
	logger.Debug("realm punch completed",
		zap.String("realm", r.realmID),
		zap.String("attempt", attempt),
		zap.String("peer", result.PeerAddr.String()),
		zap.String("packet", punchPacketTypeString(result.Packet.Type)),
		zap.String("duration", formatLogDuration(time.Since(start))))
}

func (r *realmServerRuntime) Close() error {
	r.cancel()
	sess := r.currentSession()
	if sess.id == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	logger.Debug("realm deregister started", zap.String("realm", r.realmID))
	if err := r.client.Deregister(ctx, r.realmID, sess.id); err != nil {
		return err
	}
	logger.Info("realm deregistered", zap.String("realm", r.realmID))
	return nil
}

func (r *realmServerRuntime) setSession(sess realmSession) {
	r.mu.Lock()
	r.session = sess
	r.mu.Unlock()
}

func (r *realmServerRuntime) currentSession() realmSession {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.session
}

func (r *realmServerRuntime) refreshAddrs(ctx context.Context) ([]netip.AddrPort, bool, error) {
	return r.refreshAddrsWith(ctx, func(ctx context.Context, config realm.STUNConfig) ([]netip.AddrPort, error) {
		return realm.DiscoverWithDemux(ctx, r.punchConn, config)
	})
}

func (r *realmServerRuntime) refreshAddrsDirect(ctx context.Context) ([]netip.AddrPort, bool, error) {
	return r.refreshAddrsWith(ctx, func(ctx context.Context, config realm.STUNConfig) ([]netip.AddrPort, error) {
		return realm.Discover(ctx, r.punchConn.PacketConn, config)
	})
}

func (r *realmServerRuntime) refreshAddrsWith(ctx context.Context, discover func(context.Context, realm.STUNConfig) ([]netip.AddrPort, error)) ([]netip.AddrPort, bool, error) {
	logger.Debug("realm server STUN discovery started",
		zap.String("realm", r.realmID),
		zap.Strings("stunServers", r.stunServers))
	start := time.Now()
	addrs, err := discover(ctx, realm.STUNConfig{
		Servers: r.stunServers,
		Timeout: r.config.STUNTimeout,
		Family:  r.family,
	})
	if err != nil {
		return nil, false, err
	}
	r.mu.Lock()
	changed := !slices.Equal(r.addrs, addrs)
	if changed {
		r.addrs = append([]netip.AddrPort(nil), addrs...)
	}
	r.addrsAt = time.Now()
	current := append([]netip.AddrPort(nil), r.addrs...)
	r.mu.Unlock()
	logger.Debug("realm server STUN discovery completed",
		zap.String("realm", r.realmID),
		zap.Strings("addresses", addrPortStrings(current)),
		zap.Bool("changed", changed),
		zap.String("duration", formatLogDuration(time.Since(start))))
	return r.withMappedAddr(current), changed, nil
}

func (r *realmServerRuntime) currentAddrs() []netip.AddrPort {
	r.mu.Lock()
	addrs := append([]netip.AddrPort(nil), r.addrs...)
	r.mu.Unlock()
	return r.withMappedAddr(addrs)
}

func sessionTTLDuration(ttl int) time.Duration {
	if ttl <= 0 {
		return time.Minute
	}
	return time.Duration(ttl) * time.Second
}

func isRealmSessionInvalid(err error) bool {
	var statusErr *realm.StatusError
	return errors.As(err, &statusErr) &&
		(statusErr.StatusCode == http.StatusUnauthorized || statusErr.StatusCode == http.StatusNotFound)
}

func isRealmRegisterFatal(err error) bool {
	var statusErr *realm.StatusError
	return errors.As(err, &statusErr) && statusErr.StatusCode == http.StatusBadRequest
}

func sleepContext(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func (c *serverConfig) fillTLSConfig(hyConfig *server.Config) error {
	if c.TLS == nil && c.ACME == nil {
		return configError{Field: "tls", Err: errors.New("must set either tls or acme")}
	}
	if c.TLS != nil && c.ACME != nil {
		return configError{Field: "tls", Err: errors.New("cannot set both tls and acme")}
	}
	if c.TLS != nil {
		// SNI guard
		var sniGuard utils.SNIGuardFunc
		switch strings.ToLower(c.TLS.SNIGuard) {
		case "", "dns-san":
			sniGuard = utils.SNIGuardDNSSAN
		case "strict":
			sniGuard = utils.SNIGuardStrict
		case "disable":
			sniGuard = nil
		default:
			return configError{Field: "tls.sniGuard", Err: errors.New("unsupported SNI guard")}
		}
		// Local TLS cert
		if c.TLS.Cert == "" || c.TLS.Key == "" {
			return configError{Field: "tls", Err: errors.New("empty cert or key path")}
		}
		certLoader := &utils.LocalCertificateLoader{
			CertFile: c.TLS.Cert,
			KeyFile:  c.TLS.Key,
			SNIGuard: sniGuard,
		}
		// Try loading the cert-key pair here to catch errors early
		// (e.g. invalid files or insufficient permissions)
		err := certLoader.InitializeCache()
		if err != nil {
			var pathErr *os.PathError
			if errors.As(err, &pathErr) {
				if pathErr.Path == c.TLS.Cert {
					return configError{Field: "tls.cert", Err: pathErr}
				}
				if pathErr.Path == c.TLS.Key {
					return configError{Field: "tls.key", Err: pathErr}
				}
			}
			return configError{Field: "tls", Err: err}
		}
		// Use GetCertificate instead of Certificates so that
		// users can update the cert without restarting the server.
		hyConfig.TLSConfig.GetCertificate = certLoader.GetCertificate
		// Client CA
		if c.TLS.ClientCA != "" {
			ca, err := os.ReadFile(c.TLS.ClientCA)
			if err != nil {
				return configError{Field: "tls.clientCA", Err: err}
			}
			cPool := x509.NewCertPool()
			if !cPool.AppendCertsFromPEM(ca) {
				return configError{Field: "tls.clientCA", Err: errors.New("failed to parse client CA certificate")}
			}
			hyConfig.TLSConfig.ClientCAs = cPool
		}
	} else {
		// ACME
		dataDir := c.ACME.Dir
		if dataDir == "" {
			// If not specified in the config, check the environment variable
			// before resorting to the default "acme" value. The main reason
			// we have this is so that our setup script can set it to the
			// user's home directory.
			dataDir = envOrDefaultString(appACMEDirEnv, "acme")
		}
		cmCfg := &certmagic.Config{
			RenewalWindowRatio: certmagic.DefaultRenewalWindowRatio,
			KeySource:          certmagic.DefaultKeyGenerator,
			Storage:            &certmagic.FileStorage{Path: dataDir},
			Logger:             logger,
		}
		cmIssuer := certmagic.NewACMEIssuer(cmCfg, certmagic.ACMEIssuer{
			Email:      c.ACME.Email,
			Agreed:     true,
			ListenHost: c.ACME.ListenHost,
			Logger:     logger,
		})
		switch strings.ToLower(c.ACME.CA) {
		case "letsencrypt", "le", "":
			// Default to Let's Encrypt
			cmIssuer.CA = certmagic.LetsEncryptProductionCA
		case "zerossl", "zero":
			cmIssuer.CA = certmagic.ZeroSSLProductionCA
			eab, err := genZeroSSLEAB(c.ACME.Email)
			if err != nil {
				return configError{Field: "acme.ca", Err: err}
			}
			cmIssuer.ExternalAccount = eab
		default:
			return configError{Field: "acme.ca", Err: errors.New("unsupported CA")}
		}

		switch strings.ToLower(c.ACME.Type) {
		case "http":
			cmIssuer.DisableHTTPChallenge = false
			cmIssuer.DisableTLSALPNChallenge = true
			cmIssuer.DNS01Solver = nil
			cmIssuer.AltHTTPPort = c.ACME.HTTP.AltPort
		case "tls":
			cmIssuer.DisableHTTPChallenge = true
			cmIssuer.DisableTLSALPNChallenge = false
			cmIssuer.DNS01Solver = nil
			cmIssuer.AltTLSALPNPort = c.ACME.TLS.AltPort
		case "dns":
			cmIssuer.DisableHTTPChallenge = true
			cmIssuer.DisableTLSALPNChallenge = true
			if c.ACME.DNS.Name == "" {
				return configError{Field: "acme.dns.name", Err: errors.New("empty DNS provider name")}
			}
			if c.ACME.DNS.Config == nil {
				return configError{Field: "acme.dns.config", Err: errors.New("empty DNS provider config")}
			}
			var dnsProvider certmagic.DNSProvider
			switch strings.ToLower(c.ACME.DNS.Name) {
			case "cloudflare":
				dnsProvider = &cloudflare.Provider{
					APIToken: c.ACME.DNS.Config["cloudflare_api_token"],
				}
			case "duckdns":
				dnsProvider = &duckdns.Provider{
					APIToken:       c.ACME.DNS.Config["duckdns_api_token"],
					OverrideDomain: c.ACME.DNS.Config["duckdns_override_domain"],
				}
			case "gandi":
				dnsProvider = &gandi.Provider{
					BearerToken: c.ACME.DNS.Config["gandi_api_token"],
				}
			case "godaddy":
				dnsProvider = &godaddy.Provider{
					APIToken: c.ACME.DNS.Config["godaddy_api_token"],
				}
			case "namecheap":
				dnsProvider = &namecheap.Provider{
					APIKey:      c.ACME.DNS.Config["namecheap_api_key"],
					User:        c.ACME.DNS.Config["namecheap_api_user"],
					APIEndpoint: c.ACME.DNS.Config["namecheap_api_endpoint"],
					ClientIP:    c.ACME.DNS.Config["namecheap_client_ip"],
				}
			case "njalla":
				dnsProvider = &njalla.Provider{
					APIToken: c.ACME.DNS.Config["njalla_api_token"],
				}
			case "porkbun":
				dnsProvider = &porkbun.Provider{
					APIKey:       c.ACME.DNS.Config["porkbun_api_key"],
					APISecretKey: c.ACME.DNS.Config["porkbun_api_secret_key"],
				}
			case "vultr":
				dnsProvider = &vultr.Provider{
					APIToken: c.ACME.DNS.Config["vultr_api_token"],
				}
			case "namedotcom":
				// Dropped: upstream never released a libdns v1 compatible version,
				// which the current certmagic requires.
				return configError{Field: "acme.dns.name", Err: errors.New("namedotcom is no longer supported")}
			default:
				return configError{Field: "acme.dns.name", Err: errors.New("unsupported DNS provider")}
			}
			cmIssuer.DNS01Solver = &certmagic.DNS01Solver{
				DNSManager: certmagic.DNSManager{
					DNSProvider: dnsProvider,
				},
			}
		case "":
			// Legacy compatibility mode
			cmIssuer.DisableHTTPChallenge = c.ACME.DisableHTTP
			cmIssuer.DisableTLSALPNChallenge = c.ACME.DisableTLSALPN
			cmIssuer.AltHTTPPort = c.ACME.AltHTTPPort
			cmIssuer.AltTLSALPNPort = c.ACME.AltTLSALPNPort
		default:
			return configError{Field: "acme.type", Err: errors.New("unsupported ACME type")}
		}

		cmCfg.Issuers = []certmagic.Issuer{cmIssuer}
		cmCache := certmagic.NewCache(certmagic.CacheOptions{
			GetConfigForCert: func(cert certmagic.Certificate) (*certmagic.Config, error) {
				return cmCfg, nil
			},
			Logger: logger,
		})
		cmCfg = certmagic.New(cmCache, *cmCfg)

		if len(c.ACME.Domains) == 0 {
			return configError{Field: "acme.domains", Err: errors.New("empty domains")}
		}
		err := cmCfg.ManageSync(context.Background(), c.ACME.Domains)
		if err != nil {
			return configError{Field: "acme.domains", Err: err}
		}
		hyConfig.TLSConfig.GetCertificate = cmCfg.GetCertificate
	}
	if c.ECH != nil {
		if c.ECH.KeyPath == "" {
			return configError{Field: "ech.keyPath", Err: errors.New("empty ECH key path")}
		}
		keys, configList, err := utils.LoadECHKeys(c.ECH.KeyPath)
		if err != nil {
			return configError{Field: "ech.keyPath", Err: err}
		}
		hyConfig.TLSConfig.ECHKeys = keys
		logger.Info("ECH enabled, set the following config list on clients (tls.ech)",
			zap.String("configList", base64.StdEncoding.EncodeToString(configList)))
	}
	return nil
}

func genZeroSSLEAB(email string) (*acme.EAB, error) {
	req, err := http.NewRequest(
		http.MethodPost,
		"https://api.zerossl.com/acme/eab-credentials-email",
		strings.NewReader(url.Values{"email": []string{email}}.Encode()),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to creare ZeroSSL EAB request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", certmagic.UserAgent)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send ZeroSSL EAB request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var result struct {
		Success bool `json:"success"`
		Error   struct {
			Code int    `json:"code"`
			Type string `json:"type"`
		} `json:"error"`
		EABKID     string `json:"eab_kid"`
		EABHMACKey string `json:"eab_hmac_key"`
	}
	if err = json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed decoding ZeroSSL EAB API response: %w", err)
	}
	if result.Error.Code != 0 {
		return nil, fmt.Errorf("failed getting ZeroSSL EAB credentials: HTTP %d: %s (code %d)", resp.StatusCode, result.Error.Type, result.Error.Code)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed getting EAB credentials: HTTP %d", resp.StatusCode)
	}

	return &acme.EAB{
		KeyID:  result.EABKID,
		MACKey: result.EABHMACKey,
	}, nil
}

func (c *serverConfig) fillQUICConfig(hyConfig *server.Config) error {
	hyConfig.QUICConfig = server.QUICConfig{
		InitialStreamReceiveWindow:     c.QUIC.InitStreamReceiveWindow,
		MaxStreamReceiveWindow:         c.QUIC.MaxStreamReceiveWindow,
		InitialConnectionReceiveWindow: c.QUIC.InitConnectionReceiveWindow,
		MaxConnectionReceiveWindow:     c.QUIC.MaxConnectionReceiveWindow,
		MaxIdleTimeout:                 c.QUIC.MaxIdleTimeout,
		MaxIncomingStreams:             c.QUIC.MaxIncomingStreams,
		DisablePathMTUDiscovery:        c.QUIC.DisablePathMTUDiscovery,
		DisableStatelessReset:          c.QUIC.DisableStatelessReset,
		// See the client side: Mimic and GSO are mutually exclusive.
		DisableGSO: c.Mimic.Enabled,
	}
	return nil
}

func serverConfigOutboundDirectToOutbound(c serverConfigOutboundDirect) (outbounds.PluggableOutbound, error) {
	opts := outbounds.DirectOutboundOptions{}
	switch strings.ToLower(c.Mode) {
	case "", "auto":
		opts.Mode = outbounds.DirectOutboundModeAuto
	case "64":
		opts.Mode = outbounds.DirectOutboundMode64
	case "46":
		opts.Mode = outbounds.DirectOutboundMode46
	case "6":
		opts.Mode = outbounds.DirectOutboundMode6
	case "4":
		opts.Mode = outbounds.DirectOutboundMode4
	default:
		return nil, configError{Field: "outbounds.direct.mode", Err: errors.New("unsupported mode")}
	}
	bindIP := len(c.BindIPv4) > 0 || len(c.BindIPv6) > 0
	bindDevice := len(c.BindDevice) > 0
	if bindIP && bindDevice {
		return nil, configError{Field: "outbounds.direct", Err: errors.New("cannot bind both IP and device")}
	}
	if bindIP {
		ip4, ip6 := net.ParseIP(c.BindIPv4), net.ParseIP(c.BindIPv6)
		if len(c.BindIPv4) > 0 && ip4 == nil {
			return nil, configError{Field: "outbounds.direct.bindIPv4", Err: errors.New("invalid IPv4 address")}
		}
		if len(c.BindIPv6) > 0 && ip6 == nil {
			return nil, configError{Field: "outbounds.direct.bindIPv6", Err: errors.New("invalid IPv6 address")}
		}
		opts.BindIP4 = ip4
		opts.BindIP6 = ip6
	}
	if bindDevice {
		opts.DeviceName = c.BindDevice
	}
	opts.FastOpen = c.FastOpen
	return outbounds.NewDirectOutboundWithOptions(opts)
}

func serverConfigOutboundSOCKS5ToOutbound(c serverConfigOutboundSOCKS5) (outbounds.PluggableOutbound, error) {
	if c.Addr == "" {
		return nil, configError{Field: "outbounds.socks5.addr", Err: errors.New("empty socks5 address")}
	}
	return outbounds.NewSOCKS5Outbound(c.Addr, c.Username, c.Password), nil
}

func serverConfigOutboundHTTPToOutbound(c serverConfigOutboundHTTP) (outbounds.PluggableOutbound, error) {
	if c.URL == "" {
		return nil, configError{Field: "outbounds.http.url", Err: errors.New("empty http address")}
	}
	return outbounds.NewHTTPOutbound(c.URL, c.Insecure)
}

func (c *serverConfig) fillRequestHook(hyConfig *server.Config) error {
	if c.Sniff.Enable {
		s := &sniff.Sniffer{
			Timeout:       c.Sniff.Timeout,
			RewriteDomain: c.Sniff.RewriteDomain,
		}
		if c.Sniff.TCPPorts != "" {
			s.TCPPorts = eUtils.ParsePortUnion(c.Sniff.TCPPorts)
			if s.TCPPorts == nil {
				return configError{Field: "sniff.tcpPorts", Err: errors.New("invalid port union")}
			}
		}
		if c.Sniff.UDPPorts != "" {
			s.UDPPorts = eUtils.ParsePortUnion(c.Sniff.UDPPorts)
			if s.UDPPorts == nil {
				return configError{Field: "sniff.udpPorts", Err: errors.New("invalid port union")}
			}
		}
		hyConfig.RequestHook = s
	}
	return nil
}

func (c *serverConfig) fillOutboundConfig(hyConfig *server.Config) error {
	// Resolver, ACL, actual outbound are all implemented through the Outbound interface.
	// Depending on the config, we build a chain like this:
	// Resolver(ACL(Outbounds...))

	// Outbounds
	var obs []outbounds.OutboundEntry
	if len(c.Outbounds) == 0 {
		// Guarantee we have at least one outbound
		obs = []outbounds.OutboundEntry{{
			Name:     "default",
			Outbound: outbounds.NewDirectOutboundSimple(outbounds.DirectOutboundModeAuto),
		}}
	} else {
		obs = make([]outbounds.OutboundEntry, len(c.Outbounds))
		for i, entry := range c.Outbounds {
			if entry.Name == "" {
				return configError{Field: "outbounds.name", Err: errors.New("empty outbound name")}
			}
			var ob outbounds.PluggableOutbound
			var err error
			switch strings.ToLower(entry.Type) {
			case "direct":
				ob, err = serverConfigOutboundDirectToOutbound(entry.Direct)
			case "socks5":
				ob, err = serverConfigOutboundSOCKS5ToOutbound(entry.SOCKS5)
			case "http":
				ob, err = serverConfigOutboundHTTPToOutbound(entry.HTTP)
			default:
				err = configError{Field: "outbounds.type", Err: errors.New("unsupported outbound type")}
			}
			if err != nil {
				return err
			}
			obs[i] = outbounds.OutboundEntry{Name: entry.Name, Outbound: ob}
		}
	}

	var uOb outbounds.PluggableOutbound // "unified" outbound

	// ACL
	hasACL := false
	if c.ACL.File != "" && len(c.ACL.Inline) > 0 {
		return configError{Field: "acl", Err: errors.New("cannot set both acl.file and acl.inline")}
	}
	gLoader := &utils.GeoLoader{
		GeoIPFilename:   c.ACL.GeoIP,
		GeoSiteFilename: c.ACL.GeoSite,
		UpdateInterval:  c.ACL.GeoUpdateInterval,
		DownloadFunc:    geoDownloadFunc,
		DownloadErrFunc: geoDownloadErrFunc,
	}
	if c.ACL.File != "" {
		hasACL = true
		acl, err := outbounds.NewACLEngineFromFile(c.ACL.File, obs, gLoader)
		if err != nil {
			return configError{Field: "acl.file", Err: err}
		}
		uOb = acl
	} else if len(c.ACL.Inline) > 0 {
		hasACL = true
		acl, err := outbounds.NewACLEngineFromString(strings.Join(c.ACL.Inline, "\n"), obs, gLoader)
		if err != nil {
			return configError{Field: "acl.inline", Err: err}
		}
		uOb = acl
	} else {
		// No ACL, use the first outbound
		uOb = obs[0].Outbound
	}

	// Resolver
	switch strings.ToLower(c.Resolver.Type) {
	case "", "system":
		if hasACL {
			// If the user uses ACL, we must put a resolver in front of it,
			// for IP rules to work on domain requests.
			uOb = outbounds.NewSystemResolver(uOb)
		}
		// Otherwise we can just rely on outbound handling on its own.
	case "tcp":
		if c.Resolver.TCP.Addr == "" {
			return configError{Field: "resolver.tcp.addr", Err: errors.New("empty resolver address")}
		}
		uOb = outbounds.NewStandardResolverTCP(c.Resolver.TCP.Addr, c.Resolver.TCP.Timeout, uOb)
	case "udp":
		if c.Resolver.UDP.Addr == "" {
			return configError{Field: "resolver.udp.addr", Err: errors.New("empty resolver address")}
		}
		uOb = outbounds.NewStandardResolverUDP(c.Resolver.UDP.Addr, c.Resolver.UDP.Timeout, uOb)
	case "tls", "tcp-tls":
		if c.Resolver.TLS.Addr == "" {
			return configError{Field: "resolver.tls.addr", Err: errors.New("empty resolver address")}
		}
		uOb = outbounds.NewStandardResolverTLS(c.Resolver.TLS.Addr, c.Resolver.TLS.Timeout, c.Resolver.TLS.SNI, c.Resolver.TLS.Insecure, uOb)
	case "https", "http":
		if c.Resolver.HTTPS.Addr == "" {
			return configError{Field: "resolver.https.addr", Err: errors.New("empty resolver address")}
		}
		uOb = outbounds.NewDoHResolver(c.Resolver.HTTPS.Addr, c.Resolver.HTTPS.Timeout, c.Resolver.HTTPS.SNI, c.Resolver.HTTPS.Insecure, uOb)
	default:
		return configError{Field: "resolver.type", Err: errors.New("unsupported resolver type")}
	}

	// Speed test
	if c.SpeedTest {
		uOb = outbounds.NewSpeedtestHandler(uOb)
	}

	hyConfig.Outbound = &outbounds.PluggableOutboundAdapter{PluggableOutbound: uOb}
	return nil
}

func (c *serverConfig) fillBandwidthConfig(hyConfig *server.Config) error {
	var err error
	if c.Bandwidth.Up != "" {
		hyConfig.BandwidthConfig.MaxTx, err = utils.ConvBandwidth(c.Bandwidth.Up)
		if err != nil {
			return configError{Field: "bandwidth.up", Err: err}
		}
	}
	if c.Bandwidth.Down != "" {
		hyConfig.BandwidthConfig.MaxRx, err = utils.ConvBandwidth(c.Bandwidth.Down)
		if err != nil {
			return configError{Field: "bandwidth.down", Err: err}
		}
	}
	hyConfig.BandwidthConfig.DisableLossCompensation = c.Bandwidth.DisableLossCompensation
	return nil
}

func (c *serverConfig) fillCongestionConfig(hyConfig *server.Config) error {
	normalizedType, err := normalizeCongestionType(c.Congestion.Type)
	if err != nil {
		return configError{Field: "congestion.type", Err: err}
	}
	hyConfig.CongestionConfig.Type = normalizedType
	if normalizedType == congestionTypeBBR {
		normalizedProfile, err := normalizeBBRProfile(c.Congestion.BBRProfile)
		if err != nil {
			return configError{Field: "congestion.bbrProfile", Err: err}
		}
		hyConfig.CongestionConfig.BBRProfile = normalizedProfile
	}
	return nil
}

func (c *serverConfig) fillIgnoreClientBandwidth(hyConfig *server.Config) error {
	hyConfig.IgnoreClientBandwidth = c.IgnoreClientBandwidth
	return nil
}

func (c *serverConfig) fillDisableUDP(hyConfig *server.Config) error {
	hyConfig.DisableUDP = c.DisableUDP
	return nil
}

func (c *serverConfig) fillUDPIdleTimeout(hyConfig *server.Config) error {
	hyConfig.UDPIdleTimeout = c.UDPIdleTimeout
	return nil
}

func (c *serverConfig) fillAuthenticator(hyConfig *server.Config) error {
	if c.Auth.Type == "" {
		return configError{Field: "auth.type", Err: errors.New("empty auth type")}
	}
	switch strings.ToLower(c.Auth.Type) {
	case "password":
		if c.Auth.Password == "" {
			return configError{Field: "auth.password", Err: errors.New("empty auth password")}
		}
		hyConfig.Authenticator = &auth.PasswordAuthenticator{Password: c.Auth.Password}
		return nil
	case "userpass":
		if len(c.Auth.UserPass) == 0 {
			return configError{Field: "auth.userpass", Err: errors.New("empty auth userpass")}
		}
		hyConfig.Authenticator = auth.NewUserPassAuthenticator(c.Auth.UserPass)
		return nil
	case "http", "https":
		if c.Auth.HTTP.URL == "" {
			return configError{Field: "auth.http.url", Err: errors.New("empty auth http url")}
		}
		hyConfig.Authenticator = auth.NewHTTPAuthenticator(c.Auth.HTTP.URL, c.Auth.HTTP.Insecure)
		return nil
	case "command", "cmd":
		if c.Auth.Command == "" {
			return configError{Field: "auth.command", Err: errors.New("empty auth command")}
		}
		hyConfig.Authenticator = &auth.CommandAuthenticator{Cmd: c.Auth.Command}
		return nil
	default:
		return configError{Field: "auth.type", Err: errors.New("unsupported auth type")}
	}
}

func (c *serverConfig) fillEventLogger(hyConfig *server.Config) error {
	hyConfig.EventLogger = &serverLogger{}
	return nil
}

func (c *serverConfig) fillTrafficLogger(hyConfig *server.Config) error {
	if c.TrafficStats.Listen != "" {
		tss := trafficlogger.NewTrafficStatsServer(c.TrafficStats.Secret)
		hyConfig.TrafficLogger = tss
		go runTrafficStatsServer(c.TrafficStats.Listen, tss)
	}
	return nil
}

func newMasqueradeProxyHandler(config serverConfigMasqueradeProxy) (http.Handler, error) {
	if config.URL == "" {
		return nil, errors.New("empty proxy url")
	}
	return masq.NewProxyHandler(masq.ProxyOptions{
		URL:           config.URL,
		RewriteHost:   config.RewriteHost,
		XForwarded:    config.XForwarded,
		Insecure:      config.Insecure,
		FlushInterval: config.FlushInterval,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			logger.Error("HTTP reverse proxy error", zap.Error(err))
			w.WriteHeader(http.StatusBadGateway)
		},
	})
}

// fillMasqHandler must be called after fillConn, as we may need to extract the QUIC
// port number from Conn for MasqTCPServer.
func (c *serverConfig) fillMasqHandler(hyConfig *server.Config) error {
	var handler http.Handler
	switch strings.ToLower(c.Masquerade.Type) {
	case "", "404":
		handler = http.NotFoundHandler()
	case "file":
		if c.Masquerade.File.Dir == "" {
			return configError{Field: "masquerade.file.dir", Err: errors.New("empty file directory")}
		}
		handler = http.FileServer(http.Dir(c.Masquerade.File.Dir))
	case "proxy":
		var err error
		handler, err = newMasqueradeProxyHandler(c.Masquerade.Proxy)
		if err != nil {
			return configError{Field: "masquerade.proxy.url", Err: err}
		}
	case "string":
		if c.Masquerade.String.Content == "" {
			return configError{Field: "masquerade.string.content", Err: errors.New("empty string content")}
		}
		if c.Masquerade.String.StatusCode != 0 &&
			(c.Masquerade.String.StatusCode < 200 ||
				c.Masquerade.String.StatusCode > 599 ||
				c.Masquerade.String.StatusCode == 233) {
			// 233 is reserved for Hysteria authentication
			return configError{Field: "masquerade.string.statusCode", Err: errors.New("invalid status code (must be 200-599, except 233)")}
		}
		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			for k, v := range c.Masquerade.String.Headers {
				w.Header().Set(k, v)
			}
			if c.Masquerade.String.StatusCode != 0 {
				w.WriteHeader(c.Masquerade.String.StatusCode)
			} else {
				w.WriteHeader(http.StatusOK) // Use 200 OK by default
			}
			_, _ = w.Write([]byte(c.Masquerade.String.Content))
		})
	default:
		return configError{Field: "masquerade.type", Err: errors.New("unsupported masquerade type")}
	}
	hyConfig.MasqHandler = &masqHandlerLogWrapper{H: handler, QUIC: true}

	var tcpServer *masq.MasqTCPServer
	if c.Masquerade.ListenHTTP != "" || c.Masquerade.ListenHTTPS != "" {
		if c.Masquerade.ListenHTTP != "" && c.Masquerade.ListenHTTPS == "" {
			return configError{Field: "masquerade.listenHTTPS", Err: errors.New("having only HTTP server without HTTPS is not supported")}
		}
		quicPort, err := advertisedQUICPort(c.Masquerade.AdvertisedQUICPort, hyConfig.Conn.LocalAddr().String())
		if err != nil {
			return configError{Field: "masquerade.advertisedQUICPort", Err: err}
		}
		tcpServer = &masq.MasqTCPServer{
			QUICPort:  quicPort,
			HTTPSPort: extractPortFromAddr(c.Masquerade.ListenHTTPS),
			Handler:   &masqHandlerLogWrapper{H: handler, QUIC: false},
			TLSConfig: &tls.Config{
				Certificates:             hyConfig.TLSConfig.Certificates,
				GetCertificate:           hyConfig.TLSConfig.GetCertificate,
				EncryptedClientHelloKeys: hyConfig.TLSConfig.ECHKeys,
			},
			ForceHTTPS: c.Masquerade.ForceHTTPS,
		}
	}

	closers := make(orderedClosers, 0, 3)
	if tcpServer != nil {
		closers = append(closers, tcpServer)
	}
	if closer, ok := handler.(io.Closer); ok {
		closers = append(closers, closer)
	}
	if len(closers) > 0 {
		if hyConfig.Cleanup != nil {
			closers = append(closers, hyConfig.Cleanup)
		}
		hyConfig.Cleanup = closers
	}
	if tcpServer != nil {
		go runMasqTCPServer(tcpServer, c.Masquerade.ListenHTTP, c.Masquerade.ListenHTTPS)
	}
	return nil
}

// orderedClosers shuts down dependants before the resources they use. In the
// masquerade case this means listeners first, the upstream transport second,
// and the pre-existing packet-connection runtime last.
type orderedClosers []io.Closer

func (c orderedClosers) Close() error {
	var err error
	for _, closer := range c {
		err = errors.Join(err, closer.Close())
	}
	return err
}

// Config validates the fields and returns a ready-to-use Hysteria server config
func (c *serverConfig) Config() (*server.Config, error) {
	hyConfig := &server.Config{}
	fillers := []func(*server.Config) error{
		c.fillConn,
		c.fillTLSConfig,
		c.fillQUICConfig,
		c.fillRequestHook,
		c.fillOutboundConfig,
		c.fillCongestionConfig,
		c.fillBandwidthConfig,
		c.fillIgnoreClientBandwidth,
		c.fillDisableUDP,
		c.fillUDPIdleTimeout,
		c.fillAuthenticator,
		c.fillEventLogger,
		c.fillTrafficLogger,
		c.fillMasqHandler,
	}
	for _, f := range fillers {
		if err := f(hyConfig); err != nil {
			return nil, err
		}
	}

	return hyConfig, nil
}

func runServerCmd(cmd *cobra.Command, args []string) {
	logger.Info("server mode")
	runServer(defaultViper)
}

func runServer(v *viper.Viper) {
	if err := v.ReadInConfig(); err != nil {
		logger.Fatal("failed to read server config", zap.Error(err))
	}
	var config serverConfig
	if err := v.Unmarshal(&config); err != nil {
		logger.Fatal("failed to parse server config", zap.Error(err))
	}
	hyConfig, err := config.Config()
	if err != nil {
		logger.Fatal("failed to load server config", zap.Error(err))
	}

	mimicInst, err := mimic.Start(
		mimic.Config{
			Enabled:   config.Mimic.Enabled,
			Interface: config.Mimic.Interface,
			XDPMode:   config.Mimic.XDPMode,
			Path:      config.Mimic.Path,
			ExtraArgs: config.Mimic.ExtraArgs,
		},
		mimic.RoleServer, []*net.UDPAddr{listenUDPAddr(config.Listen)}, logger,
		func(err error) { logger.Fatal("mimic stopped", zap.Error(err)) },
	)
	if err != nil {
		logger.Fatal("failed to start mimic", zap.Error(err))
	}
	defer mimicInst.Close()

	s, err := server.NewServer(hyConfig)
	if err != nil {
		logger.Fatal("failed to initialize server", zap.Error(err))
	}
	if config.Listen != "" {
		logger.Info("server up and running", zap.String("listen", config.Listen))
	} else {
		logger.Info("server up and running", zap.String("listen", defaultListenAddr))
	}

	if !disableUpdateCheck {
		go runCheckUpdateServer()
	}

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signalChan)

	serveErrChan := make(chan error, 1)
	go func() {
		serveErrChan <- s.Serve()
	}()

	select {
	case <-signalChan:
		logger.Info("received signal, shutting down gracefully")
		if err := s.Close(); err != nil {
			logger.Error("failed to shut down server cleanly", zap.Error(err))
		}
		if err := <-serveErrChan; err != nil {
			logger.Info("server stopped", zap.Error(err))
		}
	case err := <-serveErrChan:
		if err != nil {
			logger.Fatal("failed to serve", zap.Error(err))
		}
	}
}

func runTrafficStatsServer(listen string, handler http.Handler) {
	logger.Info("traffic stats server up and running", zap.String("listen", listen))
	if err := correctnet.HTTPListenAndServe(listen, handler); err != nil {
		logger.Fatal("failed to serve traffic stats", zap.Error(err))
	}
}

func runMasqTCPServer(s *masq.MasqTCPServer, httpAddr, httpsAddr string) {
	errChan := make(chan error, 2)
	if httpAddr != "" {
		go func() {
			logger.Info("masquerade HTTP server up and running", zap.String("listen", httpAddr))
			errChan <- s.ListenAndServeHTTP(httpAddr)
		}()
	}
	if httpsAddr != "" {
		go func() {
			logger.Info("masquerade HTTPS server up and running", zap.String("listen", httpsAddr))
			errChan <- s.ListenAndServeHTTPS(httpsAddr)
		}()
	}
	err := <-errChan
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Fatal("failed to serve masquerade HTTP(S)", zap.Error(err))
	}
}

func geoDownloadFunc(filename, url string) {
	logger.Info("downloading database", zap.String("filename", filename), zap.String("url", url))
}

func geoDownloadErrFunc(err error) {
	if err != nil {
		logger.Error("failed to download database", zap.Error(err))
	}
}

type serverLogger struct{}

func (l *serverLogger) Connect(addr net.Addr, id string, tx uint64) {
	logger.Info("client connected", zap.String("addr", addr.String()), zap.String("id", id), zap.Uint64("tx", tx))
}

func (l *serverLogger) Disconnect(addr net.Addr, id string, err error) {
	logger.Info("client disconnected", zap.String("addr", addr.String()), zap.String("id", id), zap.Error(err))
}

func (l *serverLogger) TCPRequest(addr net.Addr, id, reqAddr string) {
	logger.Debug("TCP request", zap.String("addr", addr.String()), zap.String("id", id), zap.String("reqAddr", reqAddr))
}

func (l *serverLogger) TCPError(addr net.Addr, id, reqAddr string, err error) {
	if err == nil {
		logger.Debug("TCP closed", zap.String("addr", addr.String()), zap.String("id", id), zap.String("reqAddr", reqAddr))
	} else {
		logger.Warn("TCP error", zap.String("addr", addr.String()), zap.String("id", id), zap.String("reqAddr", reqAddr), zap.Error(err))
	}
}

func (l *serverLogger) UDPRequest(addr net.Addr, id string, sessionID uint32, reqAddr string) {
	logger.Debug("UDP request", zap.String("addr", addr.String()), zap.String("id", id), zap.Uint32("sessionID", sessionID), zap.String("reqAddr", reqAddr))
}

func (l *serverLogger) UDPError(addr net.Addr, id string, sessionID uint32, err error) {
	if err == nil {
		logger.Debug("UDP closed", zap.String("addr", addr.String()), zap.String("id", id), zap.Uint32("sessionID", sessionID))
	} else {
		logger.Warn("UDP error", zap.String("addr", addr.String()), zap.String("id", id), zap.Uint32("sessionID", sessionID), zap.Error(err))
	}
}

type masqHandlerLogWrapper struct {
	H    http.Handler
	QUIC bool
}

func (m *masqHandlerLogWrapper) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	logger.Debug("masquerade request",
		zap.String("addr", r.RemoteAddr),
		zap.String("method", r.Method),
		zap.String("host", r.Host),
		zap.String("url", r.URL.String()),
		zap.Bool("quic", m.QUIC))
	m.H.ServeHTTP(w, r)
}

func extractPortFromAddr(addr string) int {
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return 0
	}
	return port
}

func advertisedQUICPort(configuredPort int, listenerAddr string) (int, error) {
	if configuredPort == 0 {
		return extractPortFromAddr(listenerAddr), nil
	}
	if configuredPort < 1 || configuredPort > 65535 {
		return 0, errors.New("port must be between 1 and 65535")
	}
	return configuredPort, nil
}

// listenUDPAddr resolves the listen string for Mimic's filter. A wildcard host
// stays wildcard: Mimic accepts one for a local filter.
func listenUDPAddr(listen string) *net.UDPAddr {
	if listen == "" {
		listen = defaultListenAddr
	}
	addr, err := net.ResolveUDPAddr("udp", listen)
	if err != nil {
		return &net.UDPAddr{}
	}
	return addr
}
