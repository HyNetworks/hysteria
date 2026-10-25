package server

import (
	"context"
	crand "crypto/rand"
	"crypto/tls"
	"errors"
	"io"
	"math/rand"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	"github.com/apernet/quic-go/quicvarint"

	"github.com/apernet/hysteria/core/v2/internal/congestion"
	"github.com/apernet/hysteria/core/v2/internal/protocol"
	"github.com/apernet/hysteria/core/v2/internal/utils"
)

const (
	closeErrCodeOK                  = 0x100 // HTTP3 ErrCodeNoError
	closeErrCodeTrafficLimitReached = 0x107 // HTTP3 ErrCodeExcessiveLoad
	closeErrCodeL3Replaced          = 0x10b // HTTP3 ErrCodeRequestRejected
)

type Server interface {
	Serve() error
	Close() error
	L3() (HyL3Conn, error)
}

func convertToStdTLSConfig(config *Config) *tls.Config {
	var clientAuth tls.ClientAuthType
	if config.TLSConfig.ClientCAs != nil {
		clientAuth = tls.RequireAndVerifyClientCert
	} else {
		clientAuth = tls.NoClientCert
	}
	return http3.ConfigureTLSConfig(&tls.Config{
		Certificates:                config.TLSConfig.Certificates,
		GetCertificate:              config.TLSConfig.GetCertificate,
		ClientCAs:                   config.TLSConfig.ClientCAs,
		ClientAuth:                  clientAuth,
		EncryptedClientHelloKeys:    config.TLSConfig.ECHKeys,
		GetEncryptedClientHelloKeys: config.TLSConfig.GetECHKeys,
	})
}

func NewServer(config *Config) (Server, error) {
	if err := config.fill(); err != nil {
		return nil, err
	}
	tlsConfig := convertToStdTLSConfig(config)
	quicConfig := &quic.Config{
		InitialStreamReceiveWindow:     config.QUICConfig.InitialStreamReceiveWindow,
		MaxStreamReceiveWindow:         config.QUICConfig.MaxStreamReceiveWindow,
		InitialConnectionReceiveWindow: config.QUICConfig.InitialConnectionReceiveWindow,
		MaxConnectionReceiveWindow:     config.QUICConfig.MaxConnectionReceiveWindow,
		MaxIdleTimeout:                 config.QUICConfig.MaxIdleTimeout,
		MaxIncomingStreams:             config.QUICConfig.MaxIncomingStreams,
		DisablePathMTUDiscovery:        config.QUICConfig.DisablePathMTUDiscovery,
		EnableDatagrams:                true,
		MaxDatagramFrameSize:           protocol.MaxDatagramFrameSize,
		AssumePeerMaxDatagramFrameSize: protocol.MaxDatagramFrameSize,
		DisablePathManager:             true,
	}
	tr := &quic.Transport{
		Conn:       config.Conn,
		DisableGSO: config.QUICConfig.DisableGSO,
	}
	// A nil key means quic-go never sends stateless resets. Clients then have to
	// wait for the idle timeout to notice the server is gone, so keep them on
	// unless the user explicitly asks otherwise.
	if !config.QUICConfig.DisableStatelessReset {
		srk := config.StatelessResetKey
		if srk == nil {
			var k quic.StatelessResetKey
			if _, err := crand.Read(k[:]); err != nil {
				return nil, err
			}
			srk = &k
		}
		tr.StatelessResetKey = srk
	}
	listener, err := tr.Listen(tlsConfig, quicConfig)
	if err != nil {
		err = errors.Join(err, tr.Close(), config.Conn.Close())
		if config.Cleanup != nil {
			err = errors.Join(err, config.Cleanup.Close())
		}
		return nil, err
	}
	s := &serverImpl{
		config:   config,
		tr:       tr,
		listener: listener,
	}
	if config.EnableL3 {
		s.l3 = newL3Hub()
	}
	return s, nil
}

type serverImpl struct {
	config   *Config
	tr       *quic.Transport
	listener *quic.Listener
	l3       *l3Hub
}

func (s *serverImpl) L3() (HyL3Conn, error) {
	if s.l3 == nil {
		return nil, errors.New("L3 not enabled")
	}
	return s.l3, nil
}

func (s *serverImpl) Serve() error {
	for {
		conn, err := s.listener.Accept(context.Background())
		if err != nil {
			return err
		}
		go s.handleClient(conn)
	}
}

func (s *serverImpl) Close() error {
	if s.l3 != nil {
		s.l3.close()
	}
	err := errors.Join(s.listener.Close(), s.tr.Close(), s.config.Conn.Close())
	if s.config.Cleanup != nil {
		err = errors.Join(err, s.config.Cleanup.Close())
	}
	return err
}

func (s *serverImpl) handleClient(conn *quic.Conn) {
	handler := newH3sHandler(s.config, conn, s.l3)
	h3s := http3.Server{
		Handler:          handler,
		StreamDispatcher: handler.ProxyStreamHijacker,
	}
	err := h3s.ServeQUICConn(conn)
	// If the client is authenticated, we need to log the disconnect event
	if handler.authenticated {
		if tl := s.config.TrafficLogger; tl != nil {
			tl.LogOnlineState(handler.authID, false)
		}
		if el := s.config.EventLogger; el != nil {
			el.Disconnect(conn.RemoteAddr(), handler.authID, err)
		}
	}
	_ = conn.CloseWithError(closeErrCodeOK, "")
}

type h3sHandler struct {
	config *Config
	conn   *quic.Conn

	authenticated bool
	authMutex     sync.Mutex
	authID        string
	connID        uint32 // a random id for dump streams

	udpSM *udpSessionManager // Only set after authentication

	l3     *l3Hub
	l3Peer atomic.Pointer[l3Peer] // read by stream handlers, set once at auth
}

func newH3sHandler(config *Config, conn *quic.Conn, l3 *l3Hub) *h3sHandler {
	return &h3sHandler{
		config: config,
		conn:   conn,
		connID: rand.Uint32(),
		l3:     l3,
	}
}

func (h *h3sHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost && r.Host == protocol.URLHost && r.URL.Path == protocol.URLPath {
		h.authMutex.Lock()
		defer h.authMutex.Unlock()
		if h.authenticated {
			// Already authenticated
			protocol.AuthResponseToHeader(w.Header(), protocol.AuthResponse{
				UDPEnabled: !h.config.DisableUDP,
				Rx:         h.config.BandwidthConfig.MaxRx,
				RxAuto:     h.config.IgnoreClientBandwidth,
				L3:         h.l3Peer.Load() != nil,
			})
			w.WriteHeader(protocol.StatusAuthOK)
			return
		}
		authReq := protocol.AuthRequestFromHeader(r.Header)
		actualTx := authReq.Rx
		ok, id := h.config.Authenticator.Authenticate(h.conn.RemoteAddr(), authReq.Auth, actualTx)
		if ok {
			// Set authenticated flag
			h.authenticated = true
			h.authID = id
			if h.config.IgnoreClientBandwidth {
				// Ignore client bandwidth and use the configured congestion controller.
				congestion.UseConfigured(h.conn, h.config.CongestionConfig.Type, h.config.CongestionConfig.BBRProfile)
				actualTx = 0
			} else {
				// actualTx = min(serverTx, clientRx)
				if h.config.BandwidthConfig.MaxTx > 0 && actualTx > h.config.BandwidthConfig.MaxTx {
					// We have a maxTx limit and the client is asking for more than that,
					// return and use the limit instead
					actualTx = h.config.BandwidthConfig.MaxTx
				}
				if actualTx > 0 {
					congestion.UseBrutal(h.conn, actualTx, h.config.BandwidthConfig.DisableLossCompensation)
				} else {
					// Client doesn't know its own bandwidth, use the configured congestion controller.
					congestion.UseConfigured(h.conn, h.config.CongestionConfig.Type, h.config.CongestionConfig.BBRProfile)
				}
			}
			// Auth OK, send response
			grantL3 := authReq.L3 && h.l3 != nil && h.config.l3Allowed(id)
			l3Mode := ""
			l3Lanes := 0
			if grantL3 {
				l3Mode = protocol.L3ModeDatagram
				if protocol.L3UsesStreams(h.config.L3Mode) && authReq.L3Mode == protocol.L3ModeStream {
					l3Mode = protocol.L3ModeStream
					l3Lanes = protocol.NormalizeL3Lanes(authReq.L3Lanes)
				}
			}
			var peer *l3Peer
			if grantL3 {
				// The wire says stream. Whether to split by inner protocol is this end's choice.
				policy := l3Mode
				if l3Mode == protocol.L3ModeStream {
					policy = h.config.L3Mode
				}
				peer = h.l3.adopt(h.conn, id, h.config.TrafficLogger, policy)
				grantL3 = peer != nil
			}
			if !grantL3 {
				l3Mode = ""
				l3Lanes = 0
			}
			h.l3Peer.Store(peer)
			protocol.AuthResponseToHeader(w.Header(), protocol.AuthResponse{
				UDPEnabled: !h.config.DisableUDP,
				Rx:         h.config.BandwidthConfig.MaxRx,
				RxAuto:     h.config.IgnoreClientBandwidth,
				L3:         grantL3,
				L3Mode:     l3Mode,
				L3Lanes:    l3Lanes,
			})
			w.WriteHeader(protocol.StatusAuthOK)
			// Call event logger
			if tl := h.config.TrafficLogger; tl != nil {
				tl.LogOnlineState(id, true)
			}
			if el := h.config.EventLogger; el != nil {
				el.Connect(h.conn.RemoteAddr(), id, actualTx)
			}
			// One datagram reader for this connection. UDP sessions and L3 share it.
			if !h.config.DisableUDP || peer != nil {
				var sm *udpSessionManager
				if !h.config.DisableUDP {
					sm = newUDPSessionManager(
						&udpIOImpl{h.conn, id, h.config.TrafficLogger, h.config.RequestHook, h.config.Outbound},
						&udpEventLoggerImpl{h.conn, id, h.config.EventLogger},
						h.config.UDPIdleTimeout,
					)
					h.udpSM = sm
				}
				go h.serveDatagrams(sm, peer)
			}
		} else {
			// Auth failed, pretend to be a normal HTTP server
			h.masqHandler(w, r)
		}
	} else {
		// Not an auth request, pretend to be a normal HTTP server
		h.masqHandler(w, r)
	}
}

// serveDatagrams is the only ReceiveDatagram loop for this QUIC connection.
// SessionID 0 is L3. Every other datagram is a UDP session message.
func (h *h3sHandler) serveDatagrams(sm *udpSessionManager, peer *l3Peer) {
	if peer != nil {
		defer h.l3.clear(peer)
	}
	if sm != nil {
		stopCh := make(chan struct{})
		go sm.idleCleanupLoop(stopCh)
		defer close(stopCh)
		defer sm.cleanup(false)
	}
	for {
		raw, err := h.conn.ReceiveDatagram(context.Background())
		if err != nil {
			return
		}
		if frag, ok := protocol.ParseL3Fragment(raw); ok {
			if peer != nil {
				peer.accept(frag)
			}
			continue
		}
		if sm == nil {
			continue
		}
		msg, err := protocol.ParseUDPMessage(raw)
		if err != nil {
			continue
		}
		// Inbound UDP bytes used to be counted in ReceiveMessage. The shared
		// reader feeds sessions directly, so the count stays here.
		if h.config.TrafficLogger != nil {
			if !h.config.TrafficLogger.LogTraffic(h.authID, uint64(len(msg.Data)), 0) {
				_ = h.conn.CloseWithError(closeErrCodeTrafficLimitReached, "")
				return
			}
		}
		sm.feed(msg)
	}
}

func (h *h3sHandler) ProxyStreamHijacker(ft http3.FrameType, stream *quic.Stream, err error) (bool, error) {
	if err != nil || !h.authenticated {
		return false, nil
	}

	switch ft {
	case protocol.FrameTypeL3Stream:
		if _, err := quicvarint.Read(quicvarint.NewReader(stream)); err != nil {
			return false, err
		}
		var hdr [2]byte
		if _, err := io.ReadFull(stream, hdr[:]); err != nil {
			return false, err
		}
		peer := h.l3Peer.Load()
		if peer == nil {
			stream.CancelRead(0)
			stream.CancelWrite(0)
			return true, nil
		}
		if hdr[0] == protocol.L3StreamDownlink {
			if peer.down == nil {
				stream.CancelRead(0)
				stream.CancelWrite(0)
				return true, nil
			}
			peer.down.add(int(hdr[1]), stream)
			return true, nil
		}
		go readL3Uplink(stream, peer)
		return true, nil
	case protocol.FrameTypeTCPRequest:
		// StreamDispatcher only peeks the frame type. Consume it so ReadTCPRequest
		// starts at address length, matching pre-upgrade StreamHijacker behavior.
		if _, err := quicvarint.Read(quicvarint.NewReader(stream)); err != nil {
			return false, err
		}
		// Wraps the stream with QStream, which handles Close() properly
		qStream := &utils.QStream{Stream: stream}
		go h.handleTCPRequest(qStream)
		return true, nil
	default:
		return false, nil
	}
}

func readL3Uplink(stream *quic.Stream, peer *l3Peer) {
	for {
		pkt, err := protocol.ReadL3Frame(stream)
		if err != nil {
			stream.CancelRead(0)
			return
		}
		peer.deliverUplink(pkt)
	}
}

func (h *h3sHandler) handleTCPRequest(stream *utils.QStream) {
	trafficLogger := h.config.TrafficLogger
	streamStats := &StreamStats{
		AuthID:      h.authID,
		ConnID:      h.connID,
		InitialTime: time.Now(),
	}
	streamStats.State.Store(StreamStateInitial)
	streamStats.LastActiveTime.Store(time.Now())
	defer func() {
		streamStats.State.Store(StreamStateClosed)
	}()
	if trafficLogger != nil {
		trafficLogger.TraceStream(stream, streamStats)
		defer trafficLogger.UntraceStream(stream)
	}

	// Read request
	reqAddr, err := protocol.ReadTCPRequest(stream)
	if err != nil {
		_ = stream.Close()
		return
	}
	streamStats.ReqAddr.Store(reqAddr)
	// Call the hook if set
	var putback []byte
	var hooked bool
	if h.config.RequestHook != nil {
		hooked = h.config.RequestHook.Check(false, reqAddr)
		// When the hook is enabled, the server should always accept a connection
		// so that the client will send whatever request the hook wants to see.
		// This is essentially a server-side fast-open.
		if hooked {
			streamStats.State.Store(StreamStateHooking)
			_ = protocol.WriteTCPResponse(stream, true, "RequestHook enabled")
			putback, err = h.config.RequestHook.TCP(stream, &reqAddr)
			if err != nil {
				_ = stream.Close()
				return
			}
			streamStats.setHookedReqAddr(reqAddr)
		}
	}
	// Log the event
	if h.config.EventLogger != nil {
		h.config.EventLogger.TCPRequest(h.conn.RemoteAddr(), h.authID, reqAddr)
	}
	// Dial target
	streamStats.State.Store(StreamStateConnecting)
	tConn, err := h.config.Outbound.TCP(reqAddr)
	if err != nil {
		if !hooked {
			_ = protocol.WriteTCPResponse(stream, false, err.Error())
		}
		_ = stream.Close()
		// Log the error
		if h.config.EventLogger != nil {
			h.config.EventLogger.TCPError(h.conn.RemoteAddr(), h.authID, reqAddr, err)
		}
		return
	}
	if !hooked {
		_ = protocol.WriteTCPResponse(stream, true, "Connected")
	}
	streamStats.State.Store(StreamStateEstablished)
	// Put back the data if the hook requested
	if len(putback) > 0 {
		n, _ := tConn.Write(putback)
		streamStats.Tx.Add(uint64(n))
	}
	// Start proxying
	if trafficLogger != nil {
		err = copyTwoWayEx(h.authID, stream, tConn, trafficLogger, streamStats)
	} else {
		// Use the fast path if no traffic logger is set
		err = copyTwoWay(stream, tConn)
	}
	if h.config.EventLogger != nil {
		h.config.EventLogger.TCPError(h.conn.RemoteAddr(), h.authID, reqAddr, err)
	}
	// Cleanup
	_ = tConn.Close()
	_ = stream.Close()
	// Disconnect the client if TrafficLogger requested
	if err == errDisconnect {
		_ = h.conn.CloseWithError(closeErrCodeTrafficLimitReached, "")
	}
}

func (h *h3sHandler) masqHandler(w http.ResponseWriter, r *http.Request) {
	if h.config.MasqHandler != nil {
		h.config.MasqHandler.ServeHTTP(w, r)
	} else {
		// Return 404 for everything
		http.NotFound(w, r)
	}
}

// udpIOImpl is the IO implementation for udpSessionManager with TrafficLogger support
type udpIOImpl struct {
	Conn          *quic.Conn
	AuthID        string
	TrafficLogger TrafficLogger
	RequestHook   RequestHook
	Outbound      Outbound
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
		if io.TrafficLogger != nil {
			ok := io.TrafficLogger.LogTraffic(io.AuthID, uint64(len(udpMsg.Data)), 0)
			if !ok {
				// TrafficLogger requested to disconnect the client
				_ = io.Conn.CloseWithError(closeErrCodeTrafficLimitReached, "")
				return nil, errDisconnect
			}
		}
		return udpMsg, nil
	}
}

func (io *udpIOImpl) SendMessage(buf []byte, msg *protocol.UDPMessage) error {
	if io.TrafficLogger != nil {
		ok := io.TrafficLogger.LogTraffic(io.AuthID, 0, uint64(len(msg.Data)))
		if !ok {
			// TrafficLogger requested to disconnect the client
			_ = io.Conn.CloseWithError(closeErrCodeTrafficLimitReached, "")
			return errDisconnect
		}
	}
	msgN := msg.Serialize(buf)
	if msgN < 0 {
		// Message larger than buffer, silent drop
		return nil
	}
	return io.Conn.SendDatagram(buf[:msgN])
}

func (io *udpIOImpl) Hook(packets [][]byte, reqAddr *string) (bool, error) {
	if io.RequestHook != nil && io.RequestHook.Check(true, *reqAddr) {
		return io.RequestHook.UDP(packets, reqAddr)
	} else {
		return true, nil
	}
}

func (io *udpIOImpl) UDP(reqAddr string) (UDPConn, error) {
	return io.Outbound.UDP(reqAddr)
}

func (io *udpIOImpl) CheckUDP(reqAddr string) error {
	return io.Outbound.CheckUDP(reqAddr)
}

type udpEventLoggerImpl struct {
	Conn        *quic.Conn
	AuthID      string
	EventLogger EventLogger
}

func (l *udpEventLoggerImpl) New(sessionID uint32, reqAddr string) {
	if l.EventLogger != nil {
		l.EventLogger.UDPRequest(l.Conn.RemoteAddr(), l.AuthID, sessionID, reqAddr)
	}
}

func (l *udpEventLoggerImpl) Close(sessionID uint32, err error) {
	if l.EventLogger != nil {
		l.EventLogger.UDPError(l.Conn.RemoteAddr(), l.AuthID, sessionID, err)
	}
}
