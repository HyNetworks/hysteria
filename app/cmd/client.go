package cmd

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	stdHTTP "net/http"
	"net/netip"
	"os"
	"os/signal"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"

	"github.com/apernet/hysteria/app/v2/internal/forwarding"
	"github.com/apernet/hysteria/app/v2/internal/http"
	"github.com/apernet/hysteria/app/v2/internal/mimic"
	"github.com/apernet/hysteria/app/v2/internal/proxymux"
	"github.com/apernet/hysteria/app/v2/internal/redirect"
	"github.com/apernet/hysteria/app/v2/internal/sockopts"
	"github.com/apernet/hysteria/app/v2/internal/socks5"
	"github.com/apernet/hysteria/app/v2/internal/tproxy"
	"github.com/apernet/hysteria/app/v2/internal/tun"
	"github.com/apernet/hysteria/app/v2/internal/url"
	"github.com/apernet/hysteria/app/v2/internal/utils"
	"github.com/apernet/hysteria/core/v2/client"
	coreErrs "github.com/apernet/hysteria/core/v2/errors"
	"github.com/apernet/hysteria/extras/v2/correctnet"
	"github.com/apernet/hysteria/extras/v2/obfs"
	"github.com/apernet/hysteria/extras/v2/realm"
	"github.com/apernet/hysteria/extras/v2/transport/udphop"
)

// Ref: https://ip.skk.moe/stun
var defaultRealmSTUNServers = []string{
	"stun.nextcloud.com:3478",
	"stun.sip.us:3478",
	"global.stun.twilio.com:3478",
}

// Client flags
var (
	showQR bool
)

var clientCmd = &cobra.Command{
	Use:   "client",
	Short: "Client mode",
	Run:   runClientCmd,
}

func init() {
	initClientFlags()
	rootCmd.AddCommand(clientCmd)
}

func initClientFlags() {
	clientCmd.Flags().BoolVar(&showQR, "qr", false, "show QR code for server config sharing")
}

type clientConfig struct {
	Server        string                 `mapstructure:"server"`
	Auth          string                 `mapstructure:"auth"`
	Realm         clientConfigRealm      `mapstructure:"realm"`
	Transport     clientConfigTransport  `mapstructure:"transport"`
	Obfs          clientConfigObfs       `mapstructure:"obfs"`
	TLS           clientConfigTLS        `mapstructure:"tls"`
	QUIC          clientConfigQUIC       `mapstructure:"quic"`
	Mimic         mimicConfig            `mapstructure:"mimic"`
	Congestion    clientConfigCongestion `mapstructure:"congestion"`
	Bandwidth     clientConfigBandwidth  `mapstructure:"bandwidth"`
	FastOpen      bool                   `mapstructure:"fastOpen"`
	Lazy          bool                   `mapstructure:"lazy"`
	SOCKS5        *socks5Config          `mapstructure:"socks5"`
	HTTP          *httpConfig            `mapstructure:"http"`
	TCPForwarding []tcpForwardingEntry   `mapstructure:"tcpForwarding"`
	UDPForwarding []udpForwardingEntry   `mapstructure:"udpForwarding"`
	TCPTProxy     *tcpTProxyConfig       `mapstructure:"tcpTProxy"`
	UDPTProxy     *udpTProxyConfig       `mapstructure:"udpTProxy"`
	TCPRedirect   *tcpRedirectConfig     `mapstructure:"tcpRedirect"`
	TUN           *tunConfig             `mapstructure:"tun"`
	PPP           *pppConfig             `mapstructure:"ppp"`
}

type pppSSTPConfig struct {
	BinaryPath  string `mapstructure:"binaryPath"`
	Listen      string `mapstructure:"listen"`
	CertDir     string `mapstructure:"certDir"`
	Endpoint    string `mapstructure:"endpoint"`
	User        string `mapstructure:"user"`
	Password    string `mapstructure:"password"`
	MSSClamp    *int   `mapstructure:"mssClamp"` // nil=auto, 0=off, >0=forced
	ServerRoute *bool  `mapstructure:"serverRoute"`
	LogLevel    string `mapstructure:"logLevel"`
}

type pppConfig struct {
	Mode        string         `mapstructure:"mode"`
	MTU         uint32         `mapstructure:"mtu"`
	PPPDPath    string         `mapstructure:"pppdPath"`
	PPPDArgs    []string       `mapstructure:"pppdArgs"`
	DataStreams int            `mapstructure:"dataStreams"`
	SSTP        *pppSSTPConfig `mapstructure:"sstp"`
}

type mimicConfig struct {
	Enabled   bool     `mapstructure:"enabled"`
	Interface string   `mapstructure:"interface"`
	XDPMode   string   `mapstructure:"xdpMode"`
	Path      string   `mapstructure:"path"`
	ExtraArgs []string `mapstructure:"extraArgs"`
}

type clientConfigRealm struct {
	STUNServers  []string               `mapstructure:"stunServers"`
	STUNTimeout  time.Duration          `mapstructure:"stunTimeout"`
	PunchTimeout time.Duration          `mapstructure:"punchTimeout"`
	Insecure     bool                   `mapstructure:"insecure"`
	IPMode       string                 `mapstructure:"ipMode"`
	PortMapping  realmPortMappingConfig `mapstructure:"portMapping"`
}

func realmIPMode(mode string) (realm.AddrFamily, string, error) {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", "dual":
		return realm.AddrFamilyAny, "udp", nil
	case "v4":
		return realm.AddrFamilyIPv4, "udp4", nil
	case "v6":
		return realm.AddrFamilyIPv6, "udp6", nil
	default:
		return realm.AddrFamilyAny, "", fmt.Errorf("invalid ipMode %q (expected v4, v6, or dual)", mode)
	}
}

type clientConfigTransportUDP struct {
	HopInterval    time.Duration `mapstructure:"hopInterval"`
	MinHopInterval time.Duration `mapstructure:"minHopInterval"`
	MaxHopInterval time.Duration `mapstructure:"maxHopInterval"`
}

type clientConfigTransport struct {
	Type string                   `mapstructure:"type"`
	UDP  clientConfigTransportUDP `mapstructure:"udp"`
}

type clientConfigObfsSalamander struct {
	Password string `mapstructure:"password"`
}

type clientConfigObfsGecko struct {
	Password      string `mapstructure:"password"`
	MinPacketSize int    `mapstructure:"minPacketSize"`
	MaxPacketSize int    `mapstructure:"maxPacketSize"`
}

type clientConfigObfs struct {
	Type       string                     `mapstructure:"type"`
	Salamander clientConfigObfsSalamander `mapstructure:"salamander"`
	Gecko      clientConfigObfsGecko      `mapstructure:"gecko"`
}

type clientConfigTLS struct {
	SNI               string `mapstructure:"sni"`
	Insecure          bool   `mapstructure:"insecure"`
	PinSHA256         string `mapstructure:"pinSHA256"`
	CA                string `mapstructure:"ca"`
	ClientCertificate string `mapstructure:"clientCertificate"`
	ClientKey         string `mapstructure:"clientKey"`
	ECH               string `mapstructure:"ech"`
}

type clientConfigQUIC struct {
	InitStreamReceiveWindow     uint64                   `mapstructure:"initStreamReceiveWindow"`
	MaxStreamReceiveWindow      uint64                   `mapstructure:"maxStreamReceiveWindow"`
	InitConnectionReceiveWindow uint64                   `mapstructure:"initConnReceiveWindow"`
	MaxConnectionReceiveWindow  uint64                   `mapstructure:"maxConnReceiveWindow"`
	MaxIdleTimeout              time.Duration            `mapstructure:"maxIdleTimeout"`
	KeepAlivePeriod             time.Duration            `mapstructure:"keepAlivePeriod"`
	DisablePathMTUDiscovery     bool                     `mapstructure:"disablePathMTUDiscovery"`
	DisableChromeParrot         bool                     `mapstructure:"disableChromeParrot"`
	Sockopts                    clientConfigQUICSockopts `mapstructure:"sockopts"`
}

type clientConfigQUICSockopts struct {
	BindInterface       *string `mapstructure:"bindInterface"`
	FirewallMark        *uint32 `mapstructure:"fwmark"`
	FdControlUnixSocket *string `mapstructure:"fdControlUnixSocket"`
}

type clientConfigBandwidth struct {
	Up                      string `mapstructure:"up"`
	Down                    string `mapstructure:"down"`
	DisableLossCompensation bool   `mapstructure:"disableLossCompensation"`
}

type clientConfigCongestion struct {
	Type       string `mapstructure:"type"`
	BBRProfile string `mapstructure:"bbrProfile"`
}

type socks5Config struct {
	Listen     string `mapstructure:"listen"`
	Username   string `mapstructure:"username"`
	Password   string `mapstructure:"password"`
	DisableUDP bool   `mapstructure:"disableUDP"`
}

type httpConfig struct {
	Listen   string `mapstructure:"listen"`
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
	Realm    string `mapstructure:"realm"`
}

type tcpForwardingEntry struct {
	Listen string `mapstructure:"listen"`
	Remote string `mapstructure:"remote"`
}

type udpForwardingEntry struct {
	Listen  string        `mapstructure:"listen"`
	Remote  string        `mapstructure:"remote"`
	Timeout time.Duration `mapstructure:"timeout"`
}

type tcpTProxyConfig struct {
	Listen string `mapstructure:"listen"`
}

type udpTProxyConfig struct {
	Listen  string        `mapstructure:"listen"`
	Timeout time.Duration `mapstructure:"timeout"`
}

type tcpRedirectConfig struct {
	Listen string `mapstructure:"listen"`
}

type tunConfig struct {
	Name    string        `mapstructure:"name"`
	MTU     uint32        `mapstructure:"mtu"`
	Timeout time.Duration `mapstructure:"timeout"`
	Address struct {
		IPv4 string `mapstructure:"ipv4"`
		IPv6 string `mapstructure:"ipv6"`
	} `mapstructure:"address"`
	Route *struct {
		Strict      bool     `mapstructure:"strict"`
		IPv4        []string `mapstructure:"ipv4"`
		IPv6        []string `mapstructure:"ipv6"`
		IPv4Exclude []string `mapstructure:"ipv4Exclude"`
		IPv6Exclude []string `mapstructure:"ipv6Exclude"`
	} `mapstructure:"route"`
}

func (c *clientConfig) fillServerAddr(hyConfig *client.Config) error {
	if c.Server == "" {
		return configError{Field: "server", Err: errors.New("server address is empty")}
	}
	var addr net.Addr
	var err error
	host, port, hostPort := parseServerAddrString(c.Server)
	if !isPortHoppingPort(port) {
		addr, err = net.ResolveUDPAddr("udp", hostPort)
	} else {
		addr, err = udphop.ResolveUDPHopAddr(hostPort)
	}
	if err != nil {
		return configError{Field: "server", Err: err}
	}
	hyConfig.ServerAddr = addr
	// Special handling for SNI
	if c.TLS.SNI == "" {
		// Use server hostname as SNI
		hyConfig.TLSConfig.ServerName = host
	}
	return nil
}

// fillConnFactory must be called after fillServerAddr, since the right kind
// of inner conn (plain vs port-hopping) depends on the resolved server addr.
func (c *clientConfig) fillConnFactory(hyConfig *client.Config) error {
	so, err := c.socketOptions()
	if err != nil {
		return err
	}
	hopInterval, err := c.Transport.UDP.hopIntervalConfig()
	if err != nil {
		return configError{Field: "transport.udp", Err: err}
	}
	var openInner func() (net.PacketConn, error)
	switch strings.ToLower(c.Transport.Type) {
	case "", "udp":
		if hyConfig.ServerAddr.Network() == "udphop" {
			hopAddr := hyConfig.ServerAddr.(*udphop.UDPHopAddr)
			openInner = func() (net.PacketConn, error) {
				return udphop.NewUDPHopPacketConn(hopAddr, hopInterval, so.ListenUDP)
			}
		} else {
			openInner = func() (net.PacketConn, error) {
				return so.ListenUDP()
			}
		}
	default:
		return configError{Field: "transport.type", Err: errors.New("unsupported transport type")}
	}
	hyConfig.ConnFactory = &singleUseConnFactory{
		Open: func() (net.PacketConn, error) {
			conn, err := openInner()
			if err != nil {
				return nil, err
			}
			wrapped, err := c.wrapObfs(conn)
			if err != nil {
				_ = conn.Close()
				return nil, err
			}
			return wrapped, nil
		},
	}
	return nil
}

func (c *clientConfig) socketOptions() (*sockopts.SocketOptions, error) {
	so := &sockopts.SocketOptions{
		BindInterface:       c.QUIC.Sockopts.BindInterface,
		FirewallMark:        c.QUIC.Sockopts.FirewallMark,
		FdControlUnixSocket: c.QUIC.Sockopts.FdControlUnixSocket,
	}
	if err := so.CheckSupported(); err != nil {
		var unsupportedErr *sockopts.UnsupportedError
		if errors.As(err, &unsupportedErr) {
			return nil, configError{
				Field: "quic.sockopts." + unsupportedErr.Field,
				Err:   errors.New("unsupported on this platform"),
			}
		}
		return nil, configError{Field: "quic.sockopts", Err: err}
	}
	return so, nil
}

func (c *clientConfig) wrapObfs(conn net.PacketConn) (net.PacketConn, error) {
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

func (c clientConfigTransportUDP) hopIntervalConfig() (udphop.HopIntervalConfig, error) {
	if c.HopInterval != 0 && (c.MinHopInterval != 0 || c.MaxHopInterval != 0) {
		return udphop.HopIntervalConfig{}, errors.New("hopInterval cannot be used together with minHopInterval or maxHopInterval")
	}
	if c.MinHopInterval == 0 && c.MaxHopInterval == 0 {
		if c.HopInterval == 0 {
			return udphop.HopIntervalConfig{}, nil
		}
		return udphop.HopIntervalConfig{Min: c.HopInterval, Max: c.HopInterval}, nil
	}
	if c.MinHopInterval == 0 || c.MaxHopInterval == 0 {
		return udphop.HopIntervalConfig{}, errors.New("minHopInterval and maxHopInterval must both be set")
	}
	return udphop.HopIntervalConfig{
		Min: c.MinHopInterval,
		Max: c.MaxHopInterval,
	}, nil
}

func (c *clientConfig) fillAuth(hyConfig *client.Config) error {
	hyConfig.Auth = c.Auth
	return nil
}

func (c *clientConfig) fillTLSConfig(hyConfig *client.Config) error {
	if c.TLS.SNI != "" {
		hyConfig.TLSConfig.ServerName = c.TLS.SNI
	}
	hyConfig.TLSConfig.InsecureSkipVerify = c.TLS.Insecure
	if c.TLS.PinSHA256 != "" {
		nHash := normalizeCertHash(c.TLS.PinSHA256)
		hyConfig.TLSConfig.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			cert := rawCerts[0] // only check the end-entity cert hash in the chain of trust
			hash := sha256.Sum256(cert)
			hashHex := hex.EncodeToString(hash[:])
			if hashHex == nHash {
				return nil
			}
			// No match
			return errors.New("no certificate matches the pinned hash")
		}
	}
	if c.TLS.CA != "" {
		ca, err := os.ReadFile(c.TLS.CA)
		if err != nil {
			return configError{Field: "tls.ca", Err: err}
		}
		cPool := x509.NewCertPool()
		if !cPool.AppendCertsFromPEM(ca) {
			return configError{Field: "tls.ca", Err: errors.New("failed to parse CA certificate")}
		}
		hyConfig.TLSConfig.RootCAs = cPool
	}
	if c.TLS.ClientCertificate != "" && c.TLS.ClientKey != "" {
		certLoader := &utils.LocalCertificateLoader{
			CertFile: c.TLS.ClientCertificate,
			KeyFile:  c.TLS.ClientKey,
		}
		// Try loading the cert-key pair here to catch errors early
		err := certLoader.InitializeCache()
		if err != nil {
			var pathErr *os.PathError
			if errors.As(err, &pathErr) {
				if pathErr.Path == c.TLS.ClientCertificate {
					return configError{Field: "tls.clientCertificate", Err: pathErr}
				}
				if pathErr.Path == c.TLS.ClientKey {
					return configError{Field: "tls.clientKey", Err: pathErr}
				}
			}
			return configError{Field: "tls.clientCertificate", Err: err}
		}
		// Use GetClientCertificates so that users can update the cert without restarting the client.
		hyConfig.TLSConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			// For simplicity, always respond with the configured client certs, regardless of server requests.
			return certLoader.GetCertificate(nil)
		}
	}
	if c.TLS.ECH != "" {
		configList, err := utils.ParseECHConfigList(c.TLS.ECH)
		if err != nil {
			return configError{Field: "tls.ech", Err: err}
		}
		hyConfig.TLSConfig.ECHConfigList = configList
	}
	return nil
}

func (c *clientConfig) validateMimic() error {
	if !c.Mimic.Enabled {
		return nil
	}
	// Mimic matches traffic by a single ip:port. Port hopping moves the server
	// port over a range, which would need one filter per port.
	_, port, _ := parseServerAddrString(c.Server)
	if isPortHoppingPort(port) {
		return configError{Field: "mimic", Err: errors.New("cannot be used with port hopping")}
	}
	return nil
}

func (c *clientConfig) fillQUICConfig(hyConfig *client.Config) error {
	hyConfig.QUICConfig = client.QUICConfig{
		InitialStreamReceiveWindow:     c.QUIC.InitStreamReceiveWindow,
		MaxStreamReceiveWindow:         c.QUIC.MaxStreamReceiveWindow,
		InitialConnectionReceiveWindow: c.QUIC.InitConnectionReceiveWindow,
		MaxConnectionReceiveWindow:     c.QUIC.MaxConnectionReceiveWindow,
		MaxIdleTimeout:                 c.QUIC.MaxIdleTimeout,
		KeepAlivePeriod:                c.QUIC.KeepAlivePeriod,
		DisablePathMTUDiscovery:        c.QUIC.DisablePathMTUDiscovery,
		DisableChromeParrot:            c.QUIC.DisableChromeParrot,
		// Mimic rewrites packets after they leave the socket, which corrupts
		// every segment but the first of a GSO batch.
		DisableGSO: c.Mimic.Enabled,
	}
	return nil
}

func (c *clientConfig) fillBandwidthConfig(hyConfig *client.Config) error {
	// New core now allows users to omit bandwidth values and use built-in congestion control
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

func (c *clientConfig) fillCongestionConfig(hyConfig *client.Config) error {
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

func (c *clientConfig) fillFastOpen(hyConfig *client.Config) error {
	hyConfig.FastOpen = c.FastOpen
	return nil
}

// URI generates a URI for sharing the config with others.
// Note that only the bare minimum of information required to
// connect to the server is included in the URI, specifically:
// - server address
// - authentication
// - obfuscation type
// - obfuscation password
// - TLS SNI
// - TLS insecure
// - TLS pinned SHA256 hash (normalized)
func (c *clientConfig) URI() string {
	q := url.Values{}
	switch strings.ToLower(c.Obfs.Type) {
	case "salamander":
		q.Set("obfs", "salamander")
		q.Set("obfs-password", c.Obfs.Salamander.Password)
	case "gecko":
		q.Set("obfs", "gecko")
		q.Set("obfs-password", c.Obfs.Gecko.Password)
	}
	if c.TLS.SNI != "" {
		q.Set("sni", c.TLS.SNI)
	}
	if c.TLS.Insecure {
		q.Set("insecure", "1")
	}
	if c.TLS.PinSHA256 != "" {
		q.Set("pinSHA256", normalizeCertHash(c.TLS.PinSHA256))
	}
	if c.TLS.ECH != "" {
		// Resolve to the raw config list so the URI is self-contained
		// (the source may be a file path, which is not portable).
		if configList, err := utils.ParseECHConfigList(c.TLS.ECH); err == nil {
			q.Set("ech", base64.StdEncoding.EncodeToString(configList))
		}
	}
	var user *url.Userinfo
	if c.Auth != "" {
		// We need to handle the special case of user:pass pairs
		rs := strings.SplitN(c.Auth, ":", 2)
		if len(rs) == 2 {
			user = url.UserPassword(rs[0], rs[1])
		} else {
			user = url.User(c.Auth)
		}
	}
	u := url.URL{
		Scheme:   "hysteria2",
		User:     user,
		Host:     c.Server,
		Path:     "/",
		RawQuery: q.Encode(),
	}
	return u.String()
}

// parseURI tries to parse the server address field as a URI,
// and fills the config with the information contained in the URI.
// Returns whether the server address field is a valid URI.
// This allows a user to use put a URI as the server address and
// omit the fields that are already contained in the URI.
func (c *clientConfig) parseURI() bool {
	u, err := url.Parse(c.Server)
	if err != nil {
		return false
	}
	if u.Scheme != "hysteria2" && u.Scheme != "hy2" {
		return false
	}
	if u.User != nil {
		username := u.User.Username()
		password, hasPassword := u.User.Password()
		if hasPassword {
			c.Auth = username + ":" + password
		} else {
			c.Auth = username
		}
	}
	c.Server = u.Host
	q := u.Query()
	if obfsType := q.Get("obfs"); obfsType != "" {
		c.Obfs.Type = obfsType
		switch strings.ToLower(obfsType) {
		case "salamander":
			c.Obfs.Salamander.Password = q.Get("obfs-password")
		case "gecko":
			c.Obfs.Gecko.Password = q.Get("obfs-password")
		}
	}
	if sni := q.Get("sni"); sni != "" {
		c.TLS.SNI = sni
	}
	if insecure, err := strconv.ParseBool(q.Get("insecure")); err == nil {
		c.TLS.Insecure = insecure
	}
	if pinSHA256 := q.Get("pinSHA256"); pinSHA256 != "" {
		c.TLS.PinSHA256 = pinSHA256
	}
	if ech := q.Get("ech"); ech != "" {
		c.TLS.ECH = ech
	}
	return true
}

// Config validates the fields and returns a ready-to-use Hysteria client config
func (c *clientConfig) Config() (*client.Config, error) {
	if realmAddr, ok, err := c.parseRealmAddr(); ok || err != nil {
		if err != nil {
			return nil, configError{Field: "server", Err: err}
		}
		return c.realmConfig(realmAddr)
	}
	c.parseURI()
	hyConfig := &client.Config{}
	fillers := []func(*client.Config) error{
		c.fillServerAddr,
		c.fillConnFactory,
		c.fillAuth,
		c.fillTLSConfig,
		c.fillQUICConfig,
		c.fillCongestionConfig,
		c.fillBandwidthConfig,
		c.fillFastOpen,
	}
	for _, f := range fillers {
		if err := f(hyConfig); err != nil {
			return nil, err
		}
	}
	if c.PPP != nil && c.PPP.DataStreams == 0 {
		hyConfig.PPPMode = true
	}
	return hyConfig, nil
}

func (c *clientConfig) parseRealmAddr() (*realm.Addr, bool, error) {
	addr, err := realm.ParseAddr(c.Server)
	if err == nil {
		return addr, true, nil
	}
	if strings.HasPrefix(c.Server, realm.SchemeHTTPS+":") || strings.HasPrefix(c.Server, realm.SchemeHTTP+":") {
		return nil, true, err
	}
	return nil, false, nil
}

func (c *clientConfig) realmConfig(addr *realm.Addr) (*client.Config, error) {
	logger.Debug("realm client mode detected",
		zap.String("realm", addr.RealmID),
		zap.String("realmServer", addr.HostPort),
		zap.String("scheme", addr.RendezvousScheme))
	hyConfig := &client.Config{}
	fillers := []func(*client.Config) error{
		c.fillAuth,
		c.fillTLSConfig,
		c.fillQUICConfig,
		c.fillCongestionConfig,
		c.fillBandwidthConfig,
		c.fillFastOpen,
	}
	for _, f := range fillers {
		if err := f(hyConfig); err != nil {
			return nil, err
		}
	}
	if c.TLS.SNI == "" {
		hyConfig.TLSConfig.ServerName = addr.Host
	}
	family, network, err := realmIPMode(c.Realm.IPMode)
	if err != nil {
		return nil, configError{Field: "realm.ipMode", Err: err}
	}
	so, err := c.socketOptions()
	if err != nil {
		return nil, err
	}
	var listenAddr *net.UDPAddr
	if addr.LocalPort != 0 {
		listenAddr = &net.UDPAddr{Port: addr.LocalPort}
	}
	baseConn, err := so.ListenUDPAddrNetwork(network, listenAddr)
	if err != nil {
		return nil, configError{Field: "realm", Err: err}
	}
	logger.Debug("realm client UDP socket opened",
		zap.String("realm", addr.RealmID),
		zap.String("local", baseConn.LocalAddr().String()))
	success := false
	defer func() {
		if !success {
			_ = baseConn.Close()
		}
	}()

	ctx := context.Background()
	// Gateway port mapping (UPnP/NAT-PMP) runs before STUN.
	// With the pinhole in place, in a double-NAT setup,
	// the address STUN observes corresponds to a path whose inner leg
	// goes through the static mapping rather than a filtered dynamic one.
	var mapper *realm.PortMapper
	if c.Realm.PortMapping.Enabled {
		localPort := baseConn.LocalAddr().(*net.UDPAddr).Port
		mapper = newRealmPortMapper(ctx, addr.RealmID, localPort, c.Realm.PortMapping)
		if mapper != nil {
			defer func() {
				if !success {
					_ = mapper.Close()
				}
			}()
		}
	}
	stunServers := c.realmSTUNServers(addr)
	logger.Debug("realm client STUN discovery started",
		zap.String("realm", addr.RealmID),
		zap.Strings("stunServers", stunServers))
	stunStart := time.Now()
	localAddrs, err := realm.Discover(ctx, baseConn, realm.STUNConfig{
		Servers: stunServers,
		Timeout: c.Realm.STUNTimeout,
		Family:  family,
	})
	if err != nil {
		return nil, configError{Field: "realm.stun", Err: err}
	}
	logger.Debug("realm client STUN discovery completed",
		zap.String("realm", addr.RealmID),
		zap.Strings("addresses", addrPortStrings(localAddrs)),
		zap.String("duration", formatLogDuration(time.Since(stunStart))))
	if mapper != nil {
		localAddrs = mergeMappedAddr(localAddrs, mapper.ExternalAddr())
	}
	meta, err := realm.NewPunchMetadata()
	if err != nil {
		return nil, configError{Field: "realm", Err: err}
	}
	attempt := shortAttempt(meta.Nonce)
	rClient, err := realm.NewClientFromAddr(addr, c.realmHTTPClient())
	if err != nil {
		return nil, configError{Field: "realm", Err: err}
	}
	logger.Debug("realm client connect request started",
		zap.String("realm", addr.RealmID),
		zap.String("attempt", attempt),
		zap.Strings("addresses", addrPortStrings(localAddrs)))
	connectStart := time.Now()
	connectResp, err := rClient.Connect(ctx, addr.RealmID, realm.ConnectRequest{
		Addresses:     addrPortStrings(localAddrs),
		PunchMetadata: meta,
	})
	if err != nil {
		return nil, configError{Field: "realm.connect", Err: err}
	}
	logger.Debug("realm client connect response received",
		zap.String("realm", addr.RealmID),
		zap.String("attempt", attempt),
		zap.Strings("serverAddresses", connectResp.Addresses),
		zap.String("duration", formatLogDuration(time.Since(connectStart))))
	peerAddrs, err := parseAddrPorts(connectResp.Addresses)
	if err != nil {
		return nil, configError{Field: "realm.connect.addresses", Err: err}
	}
	logger.Debug("realm client punch started",
		zap.String("realm", addr.RealmID),
		zap.String("attempt", attempt),
		zap.Strings("candidates", connectResp.Addresses))
	punchStart := time.Now()
	result, err := realm.Punch(ctx, baseConn, localAddrs, peerAddrs, connectResp.PunchMetadata, realm.PunchConfig{
		Timeout: c.Realm.PunchTimeout,
		Family:  family,
	})
	if err != nil {
		return nil, configError{Field: "realm.punch", Err: err}
	}
	logger.Debug("realm client punch completed",
		zap.String("realm", addr.RealmID),
		zap.String("attempt", attempt),
		zap.String("peer", result.PeerAddr.String()),
		zap.String("packet", punchPacketTypeString(result.Packet.Type)),
		zap.String("duration", formatLogDuration(time.Since(punchStart))))
	hyConfig.ServerAddr = udpAddrFromAddrPort(result.PeerAddr)
	logger.Debug("realm client handing socket to QUIC",
		zap.String("realm", addr.RealmID),
		zap.String("peer", result.PeerAddr.String()))

	finalConn, err := c.wrapObfs(baseConn)
	if err != nil {
		return nil, err
	}
	if mapper != nil {
		mapCtx, mapCancel := context.WithCancel(context.Background())
		go realmPortMapLoop(mapCtx, addr.RealmID, mapper)
		finalConn = &cleanupPacketConn{PacketConn: finalConn, cleanup: mapCancel}
	}
	hyConfig.ConnFactory = &singleUseConnFactory{
		Open: func() (net.PacketConn, error) { return finalConn, nil },
	}
	success = true
	return hyConfig, nil
}

func (c *clientConfig) realmSTUNServers(addr *realm.Addr) []string {
	if stunServers := addr.Params["stun"]; len(stunServers) > 0 {
		return append([]string(nil), stunServers...)
	}
	if len(c.Realm.STUNServers) > 0 {
		return append([]string(nil), c.Realm.STUNServers...)
	}
	return append([]string(nil), defaultRealmSTUNServers...)
}

func (c *clientConfig) realmHTTPClient() *stdHTTP.Client {
	if !c.Realm.Insecure {
		return nil
	}
	tr := stdHTTP.DefaultTransport.(*stdHTTP.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	return &stdHTTP.Client{Transport: tr}
}

func runClientCmd(cmd *cobra.Command, args []string) {
	logger.Info("client mode")
	runClient(defaultViper)
}

// authRetryDelay is how long to wait before asking a second time about a refused
// password. Short enough to stay inside the restart floor that is being spent
// anyway, long enough to outlast the momentary gap it exists to tolerate.
const authRetryDelay = 2 * time.Second

// connectClient builds the client, and when the server refuses the password asks
// once more before believing it.
//
// AuthError carries no more meaning than "the server answered with something
// other than 233". A server whose auth backend is momentarily unavailable serves
// the request through its masquerade handler instead -- a 404 -- which is the
// same answer a genuinely wrong password gets, and the client cannot tell them
// apart. With lazy off this handshake is a single un-retried attempt, and the
// caller turns an AuthError into a status file that makes the netifd handler
// call proto_block_restart. One unlucky moment would then hold the WAN down
// until somebody logged in and ran ifup, where before it recovered by itself.
//
// Asking twice separates the two: a wrong password is refused both times, a gap
// almost never lasts across the delay. Only an auth failure is retried -- every
// other error is already treated as retryable and is left to netifd.
func connectClient(config clientConfig, connected func(client.Client, *client.HandshakeInfo, int)) (client.Client, error) {
	c, err := client.NewReconnectableClient(config.Config, connected, config.Lazy)
	var authErr coreErrs.AuthError
	if err == nil || !errors.As(err, &authErr) {
		return c, err
	}
	logger.Warn("server refused the password, confirming before reporting it as final",
		zap.Int("status", authErr.StatusCode))
	time.Sleep(authRetryDelay)
	return client.NewReconnectableClient(config.Config, connected, config.Lazy)
}

func runClient(v *viper.Viper) {
	if err := v.ReadInConfig(); err != nil {
		holdPPPRestart()
		logger.Fatal("failed to read client config", zap.Error(err))
	}
	var config clientConfig
	if err := v.Unmarshal(&config); err != nil {
		holdPPPRestart()
		logger.Fatal("failed to parse client config", zap.Error(err))
	}

	if err := config.validateMimic(); err != nil {
		logger.Fatal("failed to load client config", zap.Error(err))
	}
	mimicInst := config.startMimic()
	defer mimicInst.Close()

	connected := func(c client.Client, info *client.HandshakeInfo, count int) {
		connectLog(info, count)
		// On the client side, we start checking for updates after we successfully connect
		// to the server, which, depending on whether lazy mode is enabled, may or may not
		// be immediately after the client starts. We don't want the update check request
		// to interfere with the lazy mode option.
		if count == 1 && !disableUpdateCheck {
			go runCheckUpdateClient(c)
		}
	}

	c, err := connectClient(config, connected)
	if err != nil {
		// Two unrelated things share this line. The status write is where a
		// refused Hysteria2 password is reported from: with lazy off the
		// handshake has already happened here, so it never reaches the runner
		// below. The hold is for the opposite case -- a dropped upstream fails
		// this dial in microseconds, and without it that becomes a restart loop.
		writePPPStatus(err)
		// And the state file, which reports every failure rather than only the
		// permanent ones. A handshake refused here never reaches PPP mode, so
		// without this the link's last published state is whatever it was before
		// the interface was rebuilt -- which for a link that was working a moment
		// ago is "connected".
		writePPPStateDown(err)
		holdPPPRestart()
		logger.Fatal("failed to initialize client", zap.Error(err))
	}
	defer c.Close()

	uri := config.URI()
	if showQR {
		logger.Warn("--qr flag is deprecated and will be removed in future release, " +
			"please use `share` subcommand to generate share URI and QR code")
		logger.Info("use this URI to share your server", zap.String("uri", uri))
		utils.PrintQR(uri)
	}

	// Register modes
	var runner clientModeRunner
	if config.SOCKS5 != nil {
		runner.Add("SOCKS5 server", func() error {
			return clientSOCKS5(*config.SOCKS5, c)
		})
	}
	if config.HTTP != nil {
		runner.Add("HTTP proxy server", func() error {
			return clientHTTP(*config.HTTP, c)
		})
	}
	if len(config.TCPForwarding) > 0 {
		runner.Add("TCP forwarding", func() error {
			return clientTCPForwarding(config.TCPForwarding, c)
		})
	}
	if len(config.UDPForwarding) > 0 {
		runner.Add("UDP forwarding", func() error {
			return clientUDPForwarding(config.UDPForwarding, c)
		})
	}
	if config.TCPTProxy != nil {
		runner.Add("TCP transparent proxy", func() error {
			return clientTCPTProxy(*config.TCPTProxy, c)
		})
	}
	if config.UDPTProxy != nil {
		runner.Add("UDP transparent proxy", func() error {
			return clientUDPTProxy(*config.UDPTProxy, c)
		})
	}
	if config.TCPRedirect != nil {
		runner.Add("TCP redirect", func() error {
			return clientTCPRedirect(*config.TCPRedirect, c)
		})
	}
	if config.TUN != nil {
		runner.Add("TUN", func() error {
			return clientTUN(*config.TUN, c)
		})
	}
	if config.PPP != nil {
		runner.Add("PPP", func() error {
			return clientPPP(*config.PPP, c, strings.EqualFold(config.Obfs.Type, "salamander"))
		})
	}

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signalChan)

	runnerChan := make(chan clientModeRunnerResult, 1)
	go func() {
		runnerChan <- runner.Run()
	}()

	select {
	case <-signalChan:
		logger.Info("received signal, shutting down gracefully")
	case r := <-runnerChan:
		if r.OK {
			logger.Info(r.Msg)
		} else {
			// A connect that fails only reaches here in lazy mode, where the
			// handshake is deferred until PPP mode asks for the conn. With lazy
			// off -- which is what the OpenWrt handler generates, since it never
			// writes the key -- the handshake has already happened above, and a
			// refused password fails there instead. Both sites write the status.
			writePPPStatus(r.Err)
			writePPPStateDown(r.Err)
			_ = c.Close() // Close the client here as Fatal will exit the program without running defer
			// Hand SIGTERM back to the runtime before holding. The deferred Stop
			// never runs -- Fatal exits -- so without this an ifdown arriving
			// during the hold would sit unread in signalChan and be ignored for
			// the length of it, keeping netifd waiting on a process that has
			// already decided to die.
			signal.Stop(signalChan)
			// Stop only restores the default disposition for signals still to
			// come. One that arrived while this select was being decided is
			// already buffered, and the select is free to have picked the runner
			// case instead -- so it has to be looked for, not waited for. Finding
			// one means an ifdown is in progress and nothing is going to restart
			// us, which is exactly when holding is pure delay.
			select {
			case <-signalChan:
			default:
				holdPPPRestart()
			}
			if r.Err != nil {
				logger.Fatal(r.Msg, zap.Error(r.Err))
			} else {
				logger.Fatal(r.Msg)
			}
		}
	}
}

type clientModeRunner struct {
	ModeMap map[string]func() error
}

type clientModeRunnerResult struct {
	OK  bool
	Msg string
	Err error
}

func (r *clientModeRunner) Add(name string, f func() error) {
	if r.ModeMap == nil {
		r.ModeMap = make(map[string]func() error)
	}
	r.ModeMap[name] = f
}

func (r *clientModeRunner) Run() clientModeRunnerResult {
	if len(r.ModeMap) == 0 {
		return clientModeRunnerResult{OK: false, Msg: "no mode specified"}
	}

	type modeError struct {
		Name string
		Err  error
	}
	errChan := make(chan modeError, len(r.ModeMap))
	for name, f := range r.ModeMap {
		go func(name string, f func() error) {
			err := f()
			errChan <- modeError{name, err}
		}(name, f)
	}
	// Fatal if any one of the modes fails
	for i := 0; i < len(r.ModeMap); i++ {
		e := <-errChan
		if e.Err != nil {
			return clientModeRunnerResult{OK: false, Msg: "failed to run " + e.Name, Err: e.Err}
		}
	}

	// We don't really have any such cases, as currently none of our modes would stop on themselves without error.
	// But we leave the possibility here for future expansion.
	return clientModeRunnerResult{OK: true, Msg: "finished without error"}
}

func clientSOCKS5(config socks5Config, c client.Client) error {
	if config.Listen == "" {
		return configError{Field: "listen", Err: errors.New("listen address is empty")}
	}
	l, err := proxymux.ListenSOCKS(config.Listen)
	if err != nil {
		return configError{Field: "listen", Err: err}
	}
	var authFunc func(username, password string) bool
	username, password := config.Username, config.Password
	if username != "" && password != "" {
		authFunc = func(u, p string) bool {
			return u == username && p == password
		}
	}
	s := socks5.Server{
		HyClient:    c,
		AuthFunc:    authFunc,
		DisableUDP:  config.DisableUDP,
		EventLogger: &socks5Logger{},
	}
	logger.Info("SOCKS5 server listening", zap.String("addr", config.Listen))
	return s.Serve(l)
}

func clientHTTP(config httpConfig, c client.Client) error {
	if config.Listen == "" {
		return configError{Field: "listen", Err: errors.New("listen address is empty")}
	}
	l, err := proxymux.ListenHTTP(config.Listen)
	if err != nil {
		return configError{Field: "listen", Err: err}
	}
	var authFunc func(username, password string) bool
	username, password := config.Username, config.Password
	if username != "" && password != "" {
		authFunc = func(u, p string) bool {
			return u == username && p == password
		}
	}
	if config.Realm == "" {
		config.Realm = "Hysteria"
	}
	h := http.Server{
		HyClient:    c,
		AuthFunc:    authFunc,
		AuthRealm:   config.Realm,
		EventLogger: &httpLogger{},
	}
	logger.Info("HTTP proxy server listening", zap.String("addr", config.Listen))
	return h.Serve(l)
}

func clientTCPForwarding(entries []tcpForwardingEntry, c client.Client) error {
	errChan := make(chan error, len(entries))
	for _, e := range entries {
		if e.Listen == "" {
			return configError{Field: "listen", Err: errors.New("listen address is empty")}
		}
		if e.Remote == "" {
			return configError{Field: "remote", Err: errors.New("remote address is empty")}
		}
		l, err := correctnet.Listen("tcp", e.Listen)
		if err != nil {
			return configError{Field: "listen", Err: err}
		}
		logger.Info("TCP forwarding listening", zap.String("addr", e.Listen), zap.String("remote", e.Remote))
		go func(remote string) {
			t := &forwarding.TCPTunnel{
				HyClient:    c,
				Remote:      remote,
				EventLogger: &tcpLogger{},
			}
			errChan <- t.Serve(l)
		}(e.Remote)
	}
	// Return if any one of the forwarding fails
	return <-errChan
}

func clientUDPForwarding(entries []udpForwardingEntry, c client.Client) error {
	errChan := make(chan error, len(entries))
	for _, e := range entries {
		if e.Listen == "" {
			return configError{Field: "listen", Err: errors.New("listen address is empty")}
		}
		if e.Remote == "" {
			return configError{Field: "remote", Err: errors.New("remote address is empty")}
		}
		l, err := correctnet.ListenPacket("udp", e.Listen)
		if err != nil {
			return configError{Field: "listen", Err: err}
		}
		logger.Info("UDP forwarding listening", zap.String("addr", e.Listen), zap.String("remote", e.Remote))
		go func(remote string, timeout time.Duration) {
			u := &forwarding.UDPTunnel{
				HyClient:    c,
				Remote:      remote,
				Timeout:     timeout,
				EventLogger: &udpLogger{},
			}
			errChan <- u.Serve(l)
		}(e.Remote, e.Timeout)
	}
	// Return if any one of the forwarding fails
	return <-errChan
}

func clientTCPTProxy(config tcpTProxyConfig, c client.Client) error {
	if config.Listen == "" {
		return configError{Field: "listen", Err: errors.New("listen address is empty")}
	}
	laddr, err := net.ResolveTCPAddr("tcp", config.Listen)
	if err != nil {
		return configError{Field: "listen", Err: err}
	}
	p := &tproxy.TCPTProxy{
		HyClient:    c,
		EventLogger: &tcpTProxyLogger{},
	}
	logger.Info("TCP transparent proxy listening", zap.String("addr", config.Listen))
	return p.ListenAndServe(laddr)
}

func clientUDPTProxy(config udpTProxyConfig, c client.Client) error {
	if config.Listen == "" {
		return configError{Field: "listen", Err: errors.New("listen address is empty")}
	}
	laddr, err := net.ResolveUDPAddr("udp", config.Listen)
	if err != nil {
		return configError{Field: "listen", Err: err}
	}
	p := &tproxy.UDPTProxy{
		HyClient:    c,
		Timeout:     config.Timeout,
		EventLogger: &udpTProxyLogger{},
	}
	logger.Info("UDP transparent proxy listening", zap.String("addr", config.Listen))
	return p.ListenAndServe(laddr)
}

func clientTCPRedirect(config tcpRedirectConfig, c client.Client) error {
	if config.Listen == "" {
		return configError{Field: "listen", Err: errors.New("listen address is empty")}
	}
	laddr, err := net.ResolveTCPAddr("tcp", config.Listen)
	if err != nil {
		return configError{Field: "listen", Err: err}
	}
	p := &redirect.TCPRedirect{
		HyClient:    c,
		EventLogger: &tcpRedirectLogger{},
	}
	logger.Info("TCP redirect listening", zap.String("addr", config.Listen))
	return p.ListenAndServe(laddr)
}

func clientTUN(config tunConfig, c client.Client) error {
	supportedPlatforms := []string{"linux", "darwin", "windows", "android"}
	if !slices.Contains(supportedPlatforms, runtime.GOOS) {
		logger.Error("TUN is not supported on this platform", zap.String("platform", runtime.GOOS))
	}
	if config.Name == "" {
		return configError{Field: "name", Err: errors.New("name is empty")}
	}
	if config.MTU == 0 {
		config.MTU = 1500
	}
	timeout := int64(config.Timeout.Seconds())
	if timeout == 0 {
		timeout = 300
	}
	if config.Address.IPv4 == "" {
		config.Address.IPv4 = "100.100.100.101/30"
	}
	prefix4, err := netip.ParsePrefix(config.Address.IPv4)
	if err != nil {
		return configError{Field: "address.ipv4", Err: err}
	}
	if config.Address.IPv6 == "" {
		config.Address.IPv6 = "2001::ffff:ffff:ffff:fff1/126"
	}
	prefix6, err := netip.ParsePrefix(config.Address.IPv6)
	if err != nil {
		return configError{Field: "address.ipv6", Err: err}
	}
	server := &tun.Server{
		HyClient:     c,
		EventLogger:  &tunLogger{},
		Logger:       logger,
		IfName:       config.Name,
		MTU:          config.MTU,
		Timeout:      timeout,
		Inet4Address: []netip.Prefix{prefix4},
		Inet6Address: []netip.Prefix{prefix6},
	}
	if config.Route != nil {
		server.AutoRoute = true
		server.StructRoute = config.Route.Strict

		parsePrefixes := func(field string, ss []string) ([]netip.Prefix, error) {
			var prefixes []netip.Prefix
			for i, s := range ss {
				var p netip.Prefix
				if strings.Contains(s, "/") {
					var err error
					p, err = netip.ParsePrefix(s)
					if err != nil {
						return nil, configError{Field: fmt.Sprintf("%s[%d]", field, i), Err: err}
					}
				} else {
					pa, err := netip.ParseAddr(s)
					if err != nil {
						return nil, configError{Field: fmt.Sprintf("%s[%d]", field, i), Err: err}
					}
					p = netip.PrefixFrom(pa, pa.BitLen())
				}
				prefixes = append(prefixes, p)
			}
			return prefixes, nil
		}

		server.Inet4RouteAddress, err = parsePrefixes("route.ipv4", config.Route.IPv4)
		if err != nil {
			return err
		}
		server.Inet6RouteAddress, err = parsePrefixes("route.ipv6", config.Route.IPv6)
		if err != nil {
			return err
		}
		server.Inet4RouteExcludeAddress, err = parsePrefixes("route.ipv4Exclude", config.Route.IPv4Exclude)
		if err != nil {
			return err
		}
		server.Inet6RouteExcludeAddress, err = parsePrefixes("route.ipv6Exclude", config.Route.IPv6Exclude)
		if err != nil {
			return err
		}
	}
	logger.Info("TUN listening", zap.String("interface", config.Name))
	return server.Serve()
}

// parseServerAddrString parses server address string.
// Server address can be in either "host:port" or "host" format (in which case we assume port 443).
func parseServerAddrString(addrStr string) (host, port, hostPort string) {
	h, p, err := net.SplitHostPort(addrStr)
	if err != nil {
		return addrStr, "443", net.JoinHostPort(addrStr, "443")
	}
	return h, p, addrStr
}

// isPortHoppingPort returns whether the port string is a port hopping port.
// We consider a port string to be a port hopping port if it contains "-" or ",".
func isPortHoppingPort(port string) bool {
	return strings.Contains(port, "-") || strings.Contains(port, ",")
}

// normalizeCertHash normalizes a certificate hash string.
// It converts all characters to lowercase and removes possible separators such as ":" and "-".
func normalizeCertHash(hash string) string {
	r := strings.ToLower(hash)
	r = strings.ReplaceAll(r, ":", "")
	r = strings.ReplaceAll(r, "-", "")
	return r
}

// singleUseConnFactory invokes Open exactly once to produce the underlying
// conn. It defers any allocation to the moment core/client.connect() actually
// asks for the conn, so config-validation failures inside NewClient (e.g.
// verifyAndFill rejecting a value) don't leak a socket. For the realm path
// the conn is already open by the time we reach the factory, so Open just
// returns it; for the regular path Open opens the UDP socket fresh.
type singleUseConnFactory struct {
	Open func() (net.PacketConn, error)

	mu   sync.Mutex
	used bool
}

func (f *singleUseConnFactory) New(net.Addr) (net.PacketConn, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.used {
		return nil, errors.New("connection factory already used")
	}
	f.used = true
	return f.Open()
}

func addrPortStrings(addrs []netip.AddrPort) []string {
	out := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		out = append(out, addr.String())
	}
	return out
}

func parseAddrPorts(addrs []string) ([]netip.AddrPort, error) {
	out := make([]netip.AddrPort, 0, len(addrs))
	for _, s := range addrs {
		addr, err := netip.ParseAddrPort(s)
		if err != nil {
			return nil, err
		}
		out = append(out, addr)
	}
	return out, nil
}

func udpAddrFromAddrPort(addr netip.AddrPort) *net.UDPAddr {
	return &net.UDPAddr{
		IP:   net.IP(addr.Addr().AsSlice()),
		Port: int(addr.Port()),
	}
}

func shortAttempt(nonce string) string {
	if len(nonce) <= 8 {
		return nonce
	}
	return nonce[:8]
}

func punchPacketTypeString(t realm.PunchPacketType) string {
	switch t {
	case realm.PunchPacketHello:
		return "hello"
	case realm.PunchPacketAck:
		return "ack"
	default:
		return "unknown"
	}
}

func formatLogDuration(d time.Duration) string {
	return d.Round(time.Millisecond).String()
}

func connectLog(info *client.HandshakeInfo, count int) {
	logger.Info("connected to server",
		zap.String("addr", info.ServerAddr.String()),
		zap.Bool("udpEnabled", info.UDPEnabled),
		zap.Uint64("tx", info.Tx),
		zap.Bool("ech", info.ECHAccepted),
		zap.Int("count", count))
}

type socks5Logger struct{}

func (l *socks5Logger) TCPRequest(addr net.Addr, reqAddr string) {
	logger.Debug("SOCKS5 TCP request", zap.String("addr", addr.String()), zap.String("reqAddr", reqAddr))
}

func (l *socks5Logger) TCPError(addr net.Addr, reqAddr string, err error) {
	if err == nil {
		logger.Debug("SOCKS5 TCP closed", zap.String("addr", addr.String()), zap.String("reqAddr", reqAddr))
	} else {
		logger.Warn("SOCKS5 TCP error", zap.String("addr", addr.String()), zap.String("reqAddr", reqAddr), zap.Error(err))
	}
}

func (l *socks5Logger) UDPRequest(addr net.Addr) {
	logger.Debug("SOCKS5 UDP request", zap.String("addr", addr.String()))
}

func (l *socks5Logger) UDPError(addr net.Addr, err error) {
	if err == nil {
		logger.Debug("SOCKS5 UDP closed", zap.String("addr", addr.String()))
	} else {
		logger.Warn("SOCKS5 UDP error", zap.String("addr", addr.String()), zap.Error(err))
	}
}

type httpLogger struct{}

func (l *httpLogger) ConnectRequest(addr net.Addr, reqAddr string) {
	logger.Debug("HTTP CONNECT request", zap.String("addr", addr.String()), zap.String("reqAddr", reqAddr))
}

func (l *httpLogger) ConnectError(addr net.Addr, reqAddr string, err error) {
	if err == nil {
		logger.Debug("HTTP CONNECT closed", zap.String("addr", addr.String()), zap.String("reqAddr", reqAddr))
	} else {
		logger.Warn("HTTP CONNECT error", zap.String("addr", addr.String()), zap.String("reqAddr", reqAddr), zap.Error(err))
	}
}

func (l *httpLogger) HTTPRequest(addr net.Addr, reqURL string) {
	logger.Debug("HTTP request", zap.String("addr", addr.String()), zap.String("reqURL", reqURL))
}

func (l *httpLogger) HTTPError(addr net.Addr, reqURL string, err error) {
	if err == nil {
		logger.Debug("HTTP closed", zap.String("addr", addr.String()), zap.String("reqURL", reqURL))
	} else {
		logger.Warn("HTTP error", zap.String("addr", addr.String()), zap.String("reqURL", reqURL), zap.Error(err))
	}
}

type tcpLogger struct{}

func (l *tcpLogger) Connect(addr net.Addr) {
	logger.Debug("TCP forwarding connect", zap.String("addr", addr.String()))
}

func (l *tcpLogger) Error(addr net.Addr, err error) {
	if err == nil {
		logger.Debug("TCP forwarding closed", zap.String("addr", addr.String()))
	} else {
		logger.Warn("TCP forwarding error", zap.String("addr", addr.String()), zap.Error(err))
	}
}

type udpLogger struct{}

func (l *udpLogger) Connect(addr net.Addr) {
	logger.Debug("UDP forwarding connect", zap.String("addr", addr.String()))
}

func (l *udpLogger) Error(addr net.Addr, err error) {
	if err == nil {
		logger.Debug("UDP forwarding closed", zap.String("addr", addr.String()))
	} else {
		logger.Warn("UDP forwarding error", zap.String("addr", addr.String()), zap.Error(err))
	}
}

type tcpTProxyLogger struct{}

func (l *tcpTProxyLogger) Connect(addr, reqAddr net.Addr) {
	logger.Debug("TCP transparent proxy connect", zap.String("addr", addr.String()), zap.String("reqAddr", reqAddr.String()))
}

func (l *tcpTProxyLogger) Error(addr, reqAddr net.Addr, err error) {
	if err == nil {
		logger.Debug("TCP transparent proxy closed", zap.String("addr", addr.String()), zap.String("reqAddr", reqAddr.String()))
	} else {
		logger.Warn("TCP transparent proxy error", zap.String("addr", addr.String()), zap.String("reqAddr", reqAddr.String()), zap.Error(err))
	}
}

type udpTProxyLogger struct{}

func (l *udpTProxyLogger) Connect(addr, reqAddr net.Addr) {
	logger.Debug("UDP transparent proxy connect", zap.String("addr", addr.String()), zap.String("reqAddr", reqAddr.String()))
}

func (l *udpTProxyLogger) Error(addr, reqAddr net.Addr, err error) {
	if err == nil {
		logger.Debug("UDP transparent proxy closed", zap.String("addr", addr.String()), zap.String("reqAddr", reqAddr.String()))
	} else {
		logger.Warn("UDP transparent proxy error", zap.String("addr", addr.String()), zap.String("reqAddr", reqAddr.String()), zap.Error(err))
	}
}

type tcpRedirectLogger struct{}

func (l *tcpRedirectLogger) Connect(addr, reqAddr net.Addr) {
	logger.Debug("TCP redirect connect", zap.String("addr", addr.String()), zap.String("reqAddr", reqAddr.String()))
}

func (l *tcpRedirectLogger) Error(addr, reqAddr net.Addr, err error) {
	if err == nil {
		logger.Debug("TCP redirect closed", zap.String("addr", addr.String()), zap.String("reqAddr", reqAddr.String()))
	} else {
		logger.Warn("TCP redirect error", zap.String("addr", addr.String()), zap.String("reqAddr", reqAddr.String()), zap.Error(err))
	}
}

type tunLogger struct{}

func (l *tunLogger) TCPRequest(addr, reqAddr string) {
	logger.Debug("TUN TCP request", zap.String("addr", addr), zap.String("reqAddr", reqAddr))
}

func (l *tunLogger) TCPError(addr, reqAddr string, err error) {
	if err == nil {
		logger.Debug("TUN TCP closed", zap.String("addr", addr), zap.String("reqAddr", reqAddr))
	} else {
		logger.Warn("TUN TCP error", zap.String("addr", addr), zap.String("reqAddr", reqAddr), zap.Error(err))
	}
}

func (l *tunLogger) UDPRequest(addr string) {
	logger.Debug("TUN UDP request", zap.String("addr", addr))
}

func (l *tunLogger) UDPError(addr string, err error) {
	if err == nil {
		logger.Debug("TUN UDP closed", zap.String("addr", addr))
	} else {
		logger.Warn("TUN UDP error", zap.String("addr", addr), zap.Error(err))
	}
}

// startMimic brings Mimic up for this client, if enabled. Every command that
// opens a connection needs this, not just "client": Mimic has to be attached
// before the first packet, or the server sees plain UDP and drops it.
func (c *clientConfig) startMimic() *mimic.Instance {
	if err := c.validateMimic(); err != nil {
		logger.Fatal("failed to load client config", zap.Error(err))
	}
	if !c.Mimic.Enabled {
		return nil
	}
	addrs, err := c.mimicServerAddrs()
	if err != nil {
		logger.Fatal("failed to resolve server address for mimic", zap.Error(err))
	}
	inst, err := mimic.Start(
		mimic.Config{
			Enabled:   c.Mimic.Enabled,
			Interface: c.Mimic.Interface,
			XDPMode:   c.Mimic.XDPMode,
			Path:      c.Mimic.Path,
			ExtraArgs: c.Mimic.ExtraArgs,
		},
		mimic.RoleClient, addrs, logger,
		func(err error) { logger.Fatal("mimic stopped", zap.Error(err)) },
	)
	if err != nil {
		logger.Fatal("failed to start mimic", zap.Error(err))
	}
	return inst
}

// mimicServerAddrs resolves the server address for Mimic's filters. Mimic needs
// literal ip:port, and a name can resolve to several addresses across both
// families, so every one of them gets a filter: the client re-resolves on each
// reconnect and may pick a different one than it did at startup.
func (c *clientConfig) mimicServerAddrs() ([]*net.UDPAddr, error) {
	host, portStr, hostPort := parseServerAddrString(c.Server)
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("invalid server port %q: %w", portStr, err)
	}
	if ip := net.ParseIP(host); ip != nil {
		return []*net.UDPAddr{{IP: ip, Port: port}}, nil
	}
	ips, err := net.DefaultResolver.LookupIP(context.Background(), "ip", host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no addresses for %s", hostPort)
	}
	addrs := make([]*net.UDPAddr, 0, len(ips))
	for _, ip := range ips {
		addrs = append(addrs, &net.UDPAddr{IP: ip, Port: port})
	}
	return addrs, nil
}
