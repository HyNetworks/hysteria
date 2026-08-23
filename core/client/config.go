package client

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"time"

	"github.com/apernet/hysteria/core/v2/errors"
	"github.com/apernet/hysteria/core/v2/internal/congestion"
	"github.com/apernet/hysteria/core/v2/internal/pmtud"
)

const (
	defaultStreamReceiveWindow = 8388608                            // 8MB
	defaultConnReceiveWindow   = defaultStreamReceiveWindow * 5 / 2 // 20MB
	defaultMaxIdleTimeout      = 30 * time.Second
	defaultKeepAlivePeriod     = 10 * time.Second
)

type Config struct {
	ConnFactory      ConnFactory
	ServerAddr       net.Addr
	Auth             string
	TLSConfig        TLSConfig
	QUICConfig       QUICConfig
	CongestionConfig CongestionConfig
	BandwidthConfig  BandwidthConfig
	FastOpen         bool
	PPPMode          bool // Enable datagram dispatcher for PPP datagram mode (dataStreams=0)

	filled bool // whether the fields have been verified and filled
}

// verifyAndFill fills the fields that are not set by the user with default values when possible,
// and returns an error if the user has not set a required field or has set an invalid value.
func (c *Config) verifyAndFill() error {
	if c.filled {
		return nil
	}
	if c.ConnFactory == nil {
		c.ConnFactory = &udpConnFactory{}
	}
	if c.ServerAddr == nil {
		return errors.ConfigError{Field: "ServerAddr", Reason: "must be set"}
	}
	if c.QUICConfig.InitialStreamReceiveWindow == 0 {
		c.QUICConfig.InitialStreamReceiveWindow = defaultStreamReceiveWindow
	} else if c.QUICConfig.InitialStreamReceiveWindow < 16384 {
		return errors.ConfigError{Field: "QUICConfig.InitialStreamReceiveWindow", Reason: "must be at least 16384"}
	}
	if c.QUICConfig.MaxStreamReceiveWindow == 0 {
		c.QUICConfig.MaxStreamReceiveWindow = defaultStreamReceiveWindow
	} else if c.QUICConfig.MaxStreamReceiveWindow < 16384 {
		return errors.ConfigError{Field: "QUICConfig.MaxStreamReceiveWindow", Reason: "must be at least 16384"}
	}
	if c.QUICConfig.InitialConnectionReceiveWindow == 0 {
		c.QUICConfig.InitialConnectionReceiveWindow = defaultConnReceiveWindow
	} else if c.QUICConfig.InitialConnectionReceiveWindow < 16384 {
		return errors.ConfigError{Field: "QUICConfig.InitialConnectionReceiveWindow", Reason: "must be at least 16384"}
	}
	if c.QUICConfig.MaxConnectionReceiveWindow == 0 {
		c.QUICConfig.MaxConnectionReceiveWindow = defaultConnReceiveWindow
	} else if c.QUICConfig.MaxConnectionReceiveWindow < 16384 {
		return errors.ConfigError{Field: "QUICConfig.MaxConnectionReceiveWindow", Reason: "must be at least 16384"}
	}
	if c.QUICConfig.MaxIdleTimeout == 0 {
		c.QUICConfig.MaxIdleTimeout = defaultMaxIdleTimeout
	} else if c.QUICConfig.MaxIdleTimeout < 4*time.Second || c.QUICConfig.MaxIdleTimeout > 120*time.Second {
		return errors.ConfigError{Field: "QUICConfig.MaxIdleTimeout", Reason: "must be between 4s and 120s"}
	}
	if c.QUICConfig.KeepAlivePeriod == 0 {
		c.QUICConfig.KeepAlivePeriod = defaultKeepAlivePeriod
	} else if c.QUICConfig.KeepAlivePeriod < 2*time.Second || c.QUICConfig.KeepAlivePeriod > 60*time.Second {
		return errors.ConfigError{Field: "QUICConfig.KeepAlivePeriod", Reason: "must be between 2s and 60s"}
	}
	c.QUICConfig.DisablePathMTUDiscovery = c.QUICConfig.DisablePathMTUDiscovery || pmtud.DisablePathMTUDiscovery
	var err error
	c.CongestionConfig.Type, err = congestion.NormalizeType(c.CongestionConfig.Type)
	if err != nil {
		return errors.ConfigError{Field: "CongestionConfig.Type", Reason: err.Error()}
	}
	if c.CongestionConfig.Type == congestion.TypeBBR {
		c.CongestionConfig.BBRProfile, err = congestion.NormalizeBBRProfile(c.CongestionConfig.BBRProfile)
		if err != nil {
			return errors.ConfigError{Field: "CongestionConfig.BBRProfile", Reason: err.Error()}
		}
	}

	c.filled = true
	return nil
}

type ConnFactory interface {
	New(net.Addr) (net.PacketConn, error)
}

type udpConnFactory struct{}

func (f *udpConnFactory) New(addr net.Addr) (net.PacketConn, error) {
	return net.ListenUDP("udp", nil)
}

// TLSConfig contains the TLS configuration fields that we want to expose to the user.
type TLSConfig struct {
	ServerName            string
	InsecureSkipVerify    bool
	VerifyPeerCertificate func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error
	RootCAs               *x509.CertPool
	GetClientCertificate  func(*tls.CertificateRequestInfo) (*tls.Certificate, error)
	ECHConfigList         []byte
}

// QUICConfig contains the QUIC configuration fields that we want to expose to the user.
type QUICConfig struct {
	InitialStreamReceiveWindow     uint64
	MaxStreamReceiveWindow         uint64
	InitialConnectionReceiveWindow uint64
	MaxConnectionReceiveWindow     uint64
	MaxIdleTimeout                 time.Duration
	KeepAlivePeriod                time.Duration
	DisablePathMTUDiscovery        bool // The server may still override this to true on unsupported platforms.
	DisableGSO                     bool
	DisableChromeParrot            bool // Chrome QUIC fingerprint parroting is on by default.
}

type CongestionConfig struct {
	Type       string
	BBRProfile string
}

// BandwidthConfig describes the maximum bandwidth that the server can use, in bytes per second.
type BandwidthConfig struct {
	MaxTx                   uint64
	MaxRx                   uint64
	DisableLossCompensation bool
}
