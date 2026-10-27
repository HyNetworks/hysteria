package client

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/url"
	"time"

	coreErrs "github.com/apernet/hysteria/core/v2/errors"
	"github.com/apernet/hysteria/core/v2/internal/congestion"
	"github.com/apernet/hysteria/core/v2/internal/protocol"
	"github.com/apernet/hysteria/core/v2/internal/utils"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
)

const (
	closeErrCodeOK            = 0x100 // HTTP3 ErrCodeNoError
	closeErrCodeProtocolError = 0x101 // HTTP3 ErrCodeGeneralProtocolError
)

type Client interface {
	TCP(addr string) (net.Conn, error)
	UDP() (HyUDPConn, error)
	L3() (HyL3Conn, error)
	Close() error
}

// HyL3Conn carries whole IP packets across the QUIC connection.
// Send does not keep ipPkt after it returns, so the caller may reuse it.
type HyL3Conn interface {
	Send(ipPkt []byte) error
	Receive() ([]byte, error)
}

type HyUDPConn interface {
	Receive() ([]byte, string, error)
	Send([]byte, string) error
	Close() error
}

type HandshakeInfo struct {
	UDPEnabled  bool
	L3          bool
	L3Mode      string
	Tx          uint64 // 0 if using BBR
	ServerAddr  net.Addr
	ECHAccepted bool
}

func NewClient(config *Config) (Client, *HandshakeInfo, error) {
	if err := config.verifyAndFill(); err != nil {
		return nil, nil, err
	}
	c := &clientImpl{
		config: config,
	}
	info, err := c.connect()
	if err != nil {
		return nil, nil, err
	}
	return c, info, nil
}

type clientImpl struct {
	config *Config

	pktConn net.PacketConn
	tr      *quic.Transport
	conn    *quic.Conn

	udpSM *udpSessionManager
	l3    l3Session
}

// l3Session is the datagram or stream endpoint behind L3().
type l3Session interface {
	HyL3Conn
	close()
}

func (c *clientImpl) connect() (*HandshakeInfo, error) {
	pktConn, err := c.config.ConnFactory.New(c.config.ServerAddr)
	if err != nil {
		return nil, err
	}
	// Convert config to TLS config & QUIC config
	tlsConfig := &tls.Config{
		ServerName:                     c.config.TLSConfig.ServerName,
		InsecureSkipVerify:             c.config.TLSConfig.InsecureSkipVerify,
		VerifyPeerCertificate:          c.config.TLSConfig.VerifyPeerCertificate,
		RootCAs:                        c.config.TLSConfig.RootCAs,
		GetClientCertificate:           c.config.TLSConfig.GetClientCertificate,
		EncryptedClientHelloConfigList: c.config.TLSConfig.ECHConfigList,
	}
	quicConfig := &quic.Config{
		InitialStreamReceiveWindow:     c.config.QUICConfig.InitialStreamReceiveWindow,
		MaxStreamReceiveWindow:         c.config.QUICConfig.MaxStreamReceiveWindow,
		InitialConnectionReceiveWindow: c.config.QUICConfig.InitialConnectionReceiveWindow,
		MaxConnectionReceiveWindow:     c.config.QUICConfig.MaxConnectionReceiveWindow,
		MaxIdleTimeout:                 c.config.QUICConfig.MaxIdleTimeout,
		KeepAlivePeriod:                c.config.QUICConfig.KeepAlivePeriod,
		DisablePathMTUDiscovery:        c.config.QUICConfig.DisablePathMTUDiscovery,
		EnableDatagrams:                true,
		MaxDatagramFrameSize:           protocol.MaxDatagramFrameSize,
		OmitMaxDatagramFrameSize:       true,
		DisablePathManager:             true,
		ChromeParrot:                   !c.config.QUICConfig.DisableChromeParrot,
	}
	tr := &quic.Transport{Conn: pktConn, DisableGSO: c.config.QUICConfig.DisableGSO}
	if !c.config.QUICConfig.DisableChromeParrot {
		// Chrome uses a zero-length source connection ID. This has to be set on the
		// Transport, since it fixes the length at which incoming packets' connection
		// IDs are parsed; leaving it default yields 4-byte IDs, visible on the wire.
		tr.ConnectionIDGenerator = quic.ZeroLengthConnectionIDGenerator{}
	}
	// Prepare RoundTripper
	var conn *quic.Conn
	rt := &http3.Transport{
		TLSClientConfig: tlsConfig,
		QUICConfig:      quicConfig,
		Dial: func(ctx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			qc, err := tr.DialEarly(ctx, c.config.ServerAddr, tlsCfg, cfg)
			if err != nil {
				return nil, err
			}
			conn = qc
			return qc, nil
		},
	}
	// Send auth HTTP request
	req := &http.Request{
		Method: http.MethodPost,
		URL: &url.URL{
			Scheme: "https",
			Host:   protocol.URLHost,
			Path:   protocol.URLPath,
		},
		Header: make(http.Header),
	}
	authReq := protocol.AuthRequest{
		Auth: c.config.Auth,
		Rx:   c.config.BandwidthConfig.MaxRx,
		L3:   c.config.RequestL3,
	}
	if c.config.RequestL3 && protocol.L3UsesStreams(c.config.L3Mode) {
		authReq.L3Mode = protocol.L3ModeStream
		authReq.L3Lanes = protocol.NormalizeL3Lanes(c.config.L3Lanes)
	}
	protocol.AuthRequestToHeader(req.Header, authReq)
	resp, err := rt.RoundTrip(req)
	if err != nil {
		if conn != nil {
			_ = conn.CloseWithError(closeErrCodeProtocolError, "")
		}
		_ = tr.Close()
		_ = pktConn.Close()
		return nil, coreErrs.ConnectError{Err: err}
	}
	if resp.StatusCode != protocol.StatusAuthOK {
		_ = conn.CloseWithError(closeErrCodeProtocolError, "")
		_ = tr.Close()
		_ = pktConn.Close()
		return nil, coreErrs.AuthError{StatusCode: resp.StatusCode}
	}
	// Auth OK
	authResp := protocol.AuthResponseFromHeader(resp.Header)
	var actualTx uint64
	if authResp.RxAuto {
		// Server asks client to use bandwidth detection,
		// ignore local bandwidth config and use the configured congestion controller.
		congestion.UseConfigured(conn, c.config.CongestionConfig.Type, c.config.CongestionConfig.BBRProfile)
	} else {
		// actualTx = min(serverRx, clientTx)
		actualTx = authResp.Rx
		if actualTx == 0 || actualTx > c.config.BandwidthConfig.MaxTx {
			// Server doesn't have a limit, or our clientTx is smaller than serverRx
			actualTx = c.config.BandwidthConfig.MaxTx
		}
		if actualTx > 0 {
			congestion.UseBrutal(conn, actualTx, c.config.BandwidthConfig.DisableLossCompensation)
		} else {
			// We don't know our own bandwidth either, use the configured congestion controller.
			congestion.UseConfigured(conn, c.config.CongestionConfig.Type, c.config.CongestionConfig.BBRProfile)
		}
	}
	_ = resp.Body.Close()

	c.pktConn = pktConn
	c.tr = tr
	c.conn = conn
	if authResp.UDPEnabled || authResp.L3 {
		// One ReceiveDatagram loop. UDP sessions are fed from it; L3 uses the same read.
		if authResp.UDPEnabled {
			c.udpSM = newFedUDPSessionManager(&udpIOImpl{Conn: conn})
		}
		if authResp.L3 {
			if protocol.L3UsesStreams(c.config.L3Mode) && authResp.L3Mode == protocol.L3ModeStream {
				ep, err := openL3Streams(conn, c.config.L3Mode == protocol.L3ModeHybrid)
				if err != nil {
					_ = conn.CloseWithError(closeErrCodeProtocolError, "")
					_ = tr.Close()
					_ = pktConn.Close()
					return nil, err
				}
				c.l3 = ep
			} else {
				c.l3 = newL3Endpoint(conn)
			}
		}
		go c.datagramLoop()
	}
	mode := ""
	if c.l3 != nil {
		if ep, stream := c.l3.(*l3StreamEndpoint); stream {
			mode = protocol.L3ModeStream
			if ep.hybrid {
				mode = protocol.L3ModeHybrid
			}
		} else {
			mode = protocol.L3ModeDatagram
		}
	}
	return &HandshakeInfo{
		UDPEnabled:  authResp.UDPEnabled,
		L3:          authResp.L3,
		L3Mode:      mode,
		Tx:          actualTx,
		ServerAddr:  c.config.ServerAddr,
		ECHAccepted: conn.ConnectionState().TLS.ECHAccepted,
	}, nil
}

func (c *clientImpl) datagramLoop() {
	defer func() {
		if c.udpSM != nil {
			c.udpSM.Stop()
		}
		if c.l3 != nil {
			c.l3.close()
		}
	}()
	for {
		raw, err := c.conn.ReceiveDatagram(context.Background())
		if err != nil {
			return
		}
		if frag, ok := protocol.ParseL3Fragment(raw); ok {
			switch ep := c.l3.(type) {
			case *l3Endpoint:
				if pkt := ep.asm.Feed(frag.PacketID, frag.FragID, frag.FragCount, frag.Data); pkt != nil {
					ep.push(pkt)
				}
			case *l3StreamEndpoint:
				ep.feedDatagram(frag)
			}
			continue
		}
		if c.udpSM == nil {
			continue
		}
		msg, err := protocol.ParseUDPMessage(raw)
		if err != nil {
			continue
		}
		c.udpSM.feed(msg)
	}
}

// openStream wraps the stream with QStream, which handles Close() properly
func (c *clientImpl) openStream() (*utils.QStream, error) {
	stream, err := c.conn.OpenStream()
	if err != nil {
		return nil, err
	}
	return &utils.QStream{Stream: stream}, nil
}

func (c *clientImpl) TCP(addr string) (net.Conn, error) {
	stream, err := c.openStream()
	if err != nil {
		return nil, wrapIfConnectionClosed(err)
	}
	// Send request
	err = protocol.WriteTCPRequest(stream, addr)
	if err != nil {
		_ = stream.Close()
		return nil, wrapIfConnectionClosed(err)
	}
	if c.config.FastOpen {
		// Don't wait for the response when fast open is enabled.
		// Return the connection immediately, defer the response handling
		// to the first Read() call.
		return &tcpConn{
			Orig:             stream,
			PseudoLocalAddr:  c.conn.LocalAddr(),
			PseudoRemoteAddr: c.conn.RemoteAddr(),
			Established:      false,
		}, nil
	}
	// Read response
	ok, msg, err := protocol.ReadTCPResponse(stream)
	if err != nil {
		_ = stream.Close()
		return nil, wrapIfConnectionClosed(err)
	}
	if !ok {
		_ = stream.Close()
		return nil, coreErrs.DialError{Message: msg}
	}
	return &tcpConn{
		Orig:             stream,
		PseudoLocalAddr:  c.conn.LocalAddr(),
		PseudoRemoteAddr: c.conn.RemoteAddr(),
		Established:      true,
	}, nil
}

func (c *clientImpl) UDP() (HyUDPConn, error) {
	if c.udpSM == nil {
		return nil, coreErrs.DialError{Message: "UDP not enabled"}
	}
	return c.udpSM.NewUDP()
}

func (c *clientImpl) L3() (HyL3Conn, error) {
	if c.l3 == nil {
		// The server has no l3tun, does not list this user, or another user holds the tunnel.
		return nil, coreErrs.DialError{Message: "server did not grant L3"}
	}
	return c.l3, nil
}

func (c *clientImpl) Close() error {
	_ = c.conn.CloseWithError(closeErrCodeOK, "")
	_ = c.tr.Close()
	_ = c.pktConn.Close()
	return nil
}

var nonPermanentErrors = []error{
	quic.StreamLimitReachedError{},
}

// wrapIfConnectionClosed checks if the error returned by quic-go
// is recoverable (listed in nonPermanentErrors) or permanent.
// Recoverable errors are returned as-is,
// permanent ones are wrapped as ClosedError.
func wrapIfConnectionClosed(err error) error {
	for _, e := range nonPermanentErrors {
		if errors.Is(err, e) {
			return err
		}
	}
	return coreErrs.ClosedError{Err: err}
}

type tcpConn struct {
	Orig             *utils.QStream
	PseudoLocalAddr  net.Addr
	PseudoRemoteAddr net.Addr
	Established      bool
}

func (c *tcpConn) Read(b []byte) (n int, err error) {
	if !c.Established {
		// Read response
		ok, msg, err := protocol.ReadTCPResponse(c.Orig)
		if err != nil {
			return 0, err
		}
		if !ok {
			return 0, coreErrs.DialError{Message: msg}
		}
		c.Established = true
	}
	return c.Orig.Read(b)
}

func (c *tcpConn) Write(b []byte) (n int, err error) {
	return c.Orig.Write(b)
}

func (c *tcpConn) Close() error {
	return c.Orig.Close()
}

func (c *tcpConn) LocalAddr() net.Addr {
	return c.PseudoLocalAddr
}

func (c *tcpConn) RemoteAddr() net.Addr {
	return c.PseudoRemoteAddr
}

func (c *tcpConn) SetDeadline(t time.Time) error {
	return c.Orig.SetDeadline(t)
}

func (c *tcpConn) SetReadDeadline(t time.Time) error {
	return c.Orig.SetReadDeadline(t)
}

func (c *tcpConn) SetWriteDeadline(t time.Time) error {
	return c.Orig.SetWriteDeadline(t)
}

type udpIOImpl struct {
	Conn *quic.Conn
}

func (io *udpIOImpl) ReceiveMessage() (*protocol.UDPMessage, error) {
	for {
		msg, err := io.Conn.ReceiveDatagram(context.Background())
		if err != nil {
			// Connection error, this will stop the session manager
			return nil, err
		}
		udpMsg, err := protocol.ParseUDPMessage(msg)
		if err != nil {
			// Invalid message, this is fine - just wait for the next
			continue
		}
		return udpMsg, nil
	}
}

func (io *udpIOImpl) SendMessage(buf []byte, msg *protocol.UDPMessage) error {
	msgN := msg.Serialize(buf)
	if msgN < 0 {
		// Message larger than buffer, silent drop
		return nil
	}
	return io.Conn.SendDatagram(buf[:msgN])
}
