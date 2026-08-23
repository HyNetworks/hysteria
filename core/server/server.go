package server

import (
	"context"
	crand "crypto/rand"
	"crypto/tls"
	"errors"
	"math/rand"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	"github.com/apernet/quic-go/quicvarint"

	"github.com/apernet/hysteria/core/v2/internal/congestion"
	internalppp "github.com/apernet/hysteria/core/v2/internal/ppp"
	"github.com/apernet/hysteria/core/v2/internal/protocol"
	"github.com/apernet/hysteria/core/v2/internal/utils"
	"github.com/apernet/hysteria/core/v2/ppp"
)

const (
	closeErrCodeOK                  = 0x100 // HTTP3 ErrCodeNoError
	closeErrCodeTrafficLimitReached = 0x107 // HTTP3 ErrCodeExcessiveLoad
)

// datagramDispatcher routes incoming QUIC datagrams to either
// the UDP session manager or the PPP data handler, depending on
// whether PPP mode is active for this connection.
type datagramDispatcher struct {
	conn      *quic.Conn
	udpSM     *udpSessionManager
	udpCh     chan []byte
	pppCh     chan []byte
	pppActive atomic.Bool
	once      sync.Once
}

func (d *datagramDispatcher) start() {
	d.once.Do(func() {
		go d.run()
	})
}

func newDatagramDispatcher(conn *quic.Conn) *datagramDispatcher {
	return &datagramDispatcher{
		conn:  conn,
		udpCh: make(chan []byte, 256),
	}
}

func (d *datagramDispatcher) run() {
	for {
		msg, err := d.conn.ReceiveDatagram(context.Background())
		if err != nil {
			close(d.udpCh)
			if d.pppCh != nil {
				close(d.pppCh)
			}
			return
		}
		if d.pppActive.Load() && d.pppCh != nil {
			d.pppCh <- msg
		} else {
			d.udpCh <- msg
		}
	}
}

type Server interface {
	Serve() error
	Close() error
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
	return &serverImpl{
		config:   config,
		tr:       tr,
		listener: listener,
	}, nil
}

type serverImpl struct {
	config   *Config
	tr       *quic.Transport
	listener *quic.Listener
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
	err := errors.Join(s.listener.Close(), s.tr.Close(), s.config.Conn.Close())
	if s.config.Cleanup != nil {
		err = errors.Join(err, s.config.Cleanup.Close())
	}
	return err
}

func (s *serverImpl) handleClient(conn *quic.Conn) {
	handler := newH3sHandler(s.config, conn)
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

	dispatcher *datagramDispatcher

	pppMu           sync.Mutex
	pppActive       bool
	pppDone         chan struct{}
	pppDataStreamCh chan *quic.Stream
}

func newH3sHandler(config *Config, conn *quic.Conn) *h3sHandler {
	return &h3sHandler{
		config:     config,
		conn:       conn,
		connID:     rand.Uint32(),
		dispatcher: newDatagramDispatcher(conn),
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
			protocol.AuthResponseToHeader(w.Header(), protocol.AuthResponse{
				UDPEnabled: !h.config.DisableUDP,
				Rx:         h.config.BandwidthConfig.MaxRx,
				RxAuto:     h.config.IgnoreClientBandwidth,
			})
			w.WriteHeader(protocol.StatusAuthOK)
			// Call event logger
			if tl := h.config.TrafficLogger; tl != nil {
				tl.LogOnlineState(id, true)
			}
			if el := h.config.EventLogger; el != nil {
				el.Connect(h.conn.RemoteAddr(), id, actualTx)
			}
			// Start datagram dispatcher and UDP session manager (if UDP is enabled)
			if !h.config.DisableUDP {
				h.dispatcher.start()
				go func() {
					sm := newUDPSessionManager(
						&udpIOImpl{
							Conn:          h.conn,
							DatagramCh:    h.dispatcher.udpCh,
							AuthID:        id,
							TrafficLogger: h.config.TrafficLogger,
							RequestHook:   h.config.RequestHook,
							Outbound:      h.config.Outbound,
						},
						&udpEventLoggerImpl{h.conn, id, h.config.EventLogger},
						h.config.UDPIdleTimeout,
					)
					h.dispatcher.udpSM = sm
					go sm.Run()
				}()
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

func (h *h3sHandler) ProxyStreamHijacker(ft http3.FrameType, stream *quic.Stream, err error) (bool, error) {
	if err != nil || !h.authenticated {
		return false, nil
	}

	switch ft {
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
	case protocol.FrameTypePPPRequest:
		// Consume the frame type varint
		if _, err := quicvarint.Read(quicvarint.NewReader(stream)); err != nil {
			return false, err
		}
		dataStreams, clientMaxFrame, err := protocol.ReadPPPRequest(stream)
		if err != nil {
			return false, err
		}
		qStream := &utils.QStream{Stream: stream}
		if h.config.PPPRequestHandler == nil {
			_ = protocol.WritePPPResponse(qStream, false, "PPP not enabled on server", 0, 0)
			_ = qStream.Close()
			return true, nil
		}
		h.pppMu.Lock()
		if h.pppActive {
			done := h.pppDone
			h.pppMu.Unlock()
			select {
			case <-done:
				h.pppMu.Lock()
			case <-time.After(5 * time.Second):
				_ = protocol.WritePPPResponse(qStream, false, "PPP session already active", 0, 0)
				_ = qStream.Close()
				return true, nil
			}
		}
		h.pppActive = true
		h.pppDone = make(chan struct{})
		h.pppMu.Unlock()

		// Measure only now that the request is definitely being served: this waits
		// on Path MTU discovery, and the rejection paths above must not pay for it.
		// Discovery is still climbing at this point -- it advances on acknowledged
		// traffic, not elapsed time -- so StableDatagramBudget drives its own.
		//
		// Both figures are floors, not caps. Discovery is paced entirely in round
		// trips, so a constant chosen here cannot say how long it needs; it is
		// widened from the connection's own RTT, up to a bound the callee holds.
		// Sizing a session against a figure discovery had not reached yet is what
		// this used to do, and it cost every link on a WAN path a sixth of its MTU
		// for the life of the session.
		serverMaxFrame := protocol.MaxPPPFrameSize
		if dataStreams == 0 {
			serverMaxFrame = internalppp.StableDatagramBudget(h.conn, 400*time.Millisecond, 3*time.Second)
		}
		pppParams := ppp.SessionParams{
			DataStreams:    dataStreams,
			ClientMaxFrame: clientMaxFrame,
			ServerMaxFrame: serverMaxFrame,
		}

		if dataStreams > 0 {
			h.pppDataStreamCh = make(chan *quic.Stream, dataStreams)
		}

		createDataIO := func() (ppp.PPPDataIO, error) {
			if dataStreams == 0 {
				h.dispatcher.pppCh = make(chan []byte, 256)
				h.dispatcher.pppActive.Store(true)
				h.dispatcher.start()
				return internalppp.NewDatagramIO(h.conn, h.dispatcher.pppCh), nil
			}
			return internalppp.CollectDataStreams(h.pppDataStreamCh, dataStreams, 10*time.Second, nil)
		}

		go func() {
			h.config.PPPRequestHandler.HandlePPP(qStream, pppParams, createDataIO, h.conn.RemoteAddr(), h.authID)
			h.pppMu.Lock()
			h.dispatcher.pppActive.Store(false)
			oldCh := h.pppDataStreamCh
			h.pppDataStreamCh = nil
			h.pppActive = false
			close(h.pppDone)
			h.pppMu.Unlock()
			if oldCh != nil {
				for {
					select {
					case s := <-oldCh:
						_ = s.Close()
					default:
						return
					}
				}
			}
		}()
		return true, nil
	case protocol.FrameTypePPPData:
		h.pppMu.Lock()
		ch := h.pppDataStreamCh
		h.pppMu.Unlock()
		if ch == nil {
			return false, nil
		}
		if _, err := quicvarint.Read(quicvarint.NewReader(stream)); err != nil {
			return false, err
		}
		// Read and discard stream_index varint
		if _, err := quicvarint.Read(quicvarint.NewReader(stream)); err != nil {
			return false, err
		}
		select {
		case ch <- stream:
		default:
			_ = stream.Close()
		}
		return true, nil
	default:
		return false, nil
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
	DatagramCh    <-chan []byte
	AuthID        string
	TrafficLogger TrafficLogger
	RequestHook   RequestHook
	Outbound      Outbound
}

func (io *udpIOImpl) ReceiveMessage() (*protocol.UDPMessage, error) {
	for {
		msg, ok := <-io.DatagramCh
		if !ok {
			return nil, errors.New("connection closed")
		}
		udpMsg, err := protocol.ParseUDPMessage(msg)
		if err != nil {
			continue
		}
		if io.TrafficLogger != nil {
			ok := io.TrafficLogger.LogTraffic(io.AuthID, uint64(len(udpMsg.Data)), 0)
			if !ok {
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

func (io *udpIOImpl) Hook(data []byte, reqAddr *string) error {
	if io.RequestHook != nil && io.RequestHook.Check(true, *reqAddr) {
		return io.RequestHook.UDP(data, reqAddr)
	} else {
		return nil
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
