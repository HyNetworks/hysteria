package l2tp

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	"go.uber.org/zap"
)

const (
	maxPacketSize        = 4096
	defaultRecvWindow    = 4
	tunnelSetupTimeout   = 10 * time.Second
	maxCtrlRetries       = 5
	ctrlRetryBaseTimeout = 1 * time.Second
)

var (
	errTunnelClosed   = errors.New("l2tp: tunnel closed")
	errControlTimeout = errors.New("l2tp: control response timeout")
)

// Tunnel represents an L2TPv2 tunnel to a single LNS.
type Tunnel struct {
	conn   net.Conn // UDP connection to LNS
	logger *zap.Logger

	localTunnelID  uint16
	remoteTunnelID uint16
	hostname       string
	secret         []byte
	helloInterval  time.Duration

	// Control retransmission schedule (RFC 2661 s5.8), held per tunnel rather
	// than read from the package constants so that tests can drive the
	// retransmit and give-up paths in milliseconds. Production never changes
	// them; newTunnel seeds them from the constants.
	ctrlBase    time.Duration
	ctrlCap     time.Duration
	ctrlRetries int

	// Sequence numbers for reliable control delivery
	ns atomic.Uint32 // next send sequence number
	nr atomic.Uint32 // next expected receive sequence number

	// Session registry
	mu       sync.RWMutex
	sessions map[uint16]*Session
	nextSID  uint16

	// Serializes all packet writes to prevent interleaving
	writeMu sync.Mutex

	// Peer Nr tracking for reliable delivery of SCCCN/ICCN.
	// peerNrCh is closed-and-recreated each time the peer advances Nr.
	peerNrMu sync.Mutex
	peerNr   uint16
	peerNrCh chan struct{}

	// Channels for routing control responses (ICRP/CDN) from recvLoop
	// to session establishment goroutines, keyed by local session ID.
	pendingCtrlMu sync.Mutex
	pendingCtrls  map[uint16]chan controlMsg

	// Lifecycle
	closed    chan struct{}
	closeOnce sync.Once
	onClose   func() // callback to manager when tunnel dies
}

type controlMsg struct {
	avps    []AVP
	msgType uint16
}

func newTunnel(conn net.Conn, localTID uint16, hostname string, secret []byte, helloInterval time.Duration, logger *zap.Logger) *Tunnel {
	return &Tunnel{
		conn:          conn,
		logger:        logger,
		localTunnelID: localTID,
		hostname:      hostname,
		secret:        secret,
		helloInterval: helloInterval,
		ctrlBase:      ctrlRetryBaseTimeout,
		ctrlCap:       tunnelSetupTimeout,
		ctrlRetries:   maxCtrlRetries,
		sessions:      make(map[uint16]*Session),
		nextSID:       1,
		peerNrCh:      make(chan struct{}),
		pendingCtrls:  make(map[uint16]chan controlMsg),
		closed:        make(chan struct{}),
	}
}

// Establish performs the tunnel setup handshake (SCCRQ -> SCCRP -> SCCCN).
//
// A tunnel that fails to establish is closed before the error is returned, so
// Alive() is never true for one that never came up. That matters because Alive()
// is what decides whether a cached tunnel can carry another call: a half-open
// one that still claimed to be alive would be handed to the next subscriber.
func (t *Tunnel) Establish() (err error) {
	defer func() {
		if err != nil {
			// Best effort, and it doubles as telling the LNS: a peer that refused
			// us, or that we refused, is otherwise left holding a control
			// connection until its own timeout expires.
			t.Close()
		}
	}()

	var challenge []byte
	if len(t.secret) > 0 {
		challenge = make([]byte, 16)
		if _, err := rand.Read(challenge); err != nil {
			return fmt.Errorf("generate challenge: %w", err)
		}
	}

	payload := BuildSCCRQ(t.hostname, t.localTunnelID, defaultRecvWindow, challenge)
	pkt := t.buildControl(0, 0, payload)
	t.logger.Debug("sending SCCRQ",
		zap.Uint16("tunnelID", t.localTunnelID),
		zap.String("hostname", t.hostname),
		zap.String("remoteAddr", t.conn.RemoteAddr().String()))

	var avps []AVP
	timeout := t.ctrlBase
	for attempt := 0; ; attempt++ {
		if err := t.resendControl(pkt); err != nil {
			return fmt.Errorf("send SCCRQ: %w", err)
		}
		var err error
		avps, err = t.recvControlDirect(timeout)
		if err == nil {
			break
		}
		if attempt >= t.ctrlRetries {
			return fmt.Errorf("recv SCCRP: %w (after %d retries)", err, t.ctrlRetries)
		}
		var netErr net.Error
		if !errors.As(err, &netErr) || !netErr.Timeout() {
			return fmt.Errorf("recv SCCRP: %w", err)
		}
		timeout = min(timeout*2, t.ctrlCap)
		t.logger.Debug("SCCRQ timeout, retransmitting", zap.Int("attempt", attempt+1))
	}

	msgType, err := GetMessageType(avps)
	if err != nil {
		return err
	}
	if msgType == MsgTypeStopCCN {
		// The Result Code is the whole content of a refusal. Without it an
		// operator whose hostname or secret does not match what the LNS expects
		// gets "rejected" and nothing else, and the two look identical.
		return fmt.Errorf("LNS rejected tunnel with StopCCN: %s", describeResultCode(avps))
	}
	if msgType != MsgTypeSCCRP {
		return fmt.Errorf("expected SCCRP, got msg type %d", msgType)
	}

	// Extract Assigned Tunnel ID from SCCRP
	tidAVP := FindAVP(avps, 0, AVPAssignedTunnelID)
	if tidAVP == nil {
		return fmt.Errorf("%w: Assigned Tunnel ID in SCCRP", ErrMissingAVP)
	}
	remoteTID, err := AVPUint16(tidAVP)
	if err != nil {
		return err
	}
	t.remoteTunnelID = remoteTID

	t.logger.Debug("received SCCRP",
		zap.Uint16("remoteTunnelID", remoteTID))

	// Handle tunnel authentication
	var challengeResponse []byte
	if len(t.secret) > 0 {
		// Check for Challenge in SCCRP (LNS may challenge us)
		lnsChallenge := FindAVP(avps, 0, AVPChallenge)
		if lnsChallenge != nil {
			// Respond with MD5(SCCCN_type + secret + LNS_challenge)
			challengeResponse = ComputeChallengeResponse(byte(MsgTypeSCCCN), t.secret, lnsChallenge.Value)
		}

		// Verify LNS's Challenge Response if we sent a challenge
		lnsCR := FindAVP(avps, 0, AVPChallengeResponse)
		if lnsCR == nil {
			return fmt.Errorf("LNS did not respond to our challenge")
		}
		expected := ComputeChallengeResponse(byte(MsgTypeSCCRP), t.secret, challenge)
		if len(lnsCR.Value) != len(expected) {
			return fmt.Errorf("invalid challenge response from LNS")
		}
		for i := range expected {
			if lnsCR.Value[i] != expected[i] {
				return fmt.Errorf("invalid challenge response from LNS")
			}
		}
	}

	// Start recvLoop before sending SCCCN so any piggybacked control
	// payload on the ack packet is properly processed (not dropped).
	go t.recvLoop()
	if t.helloInterval > 0 {
		go t.helloLoop()
	}

	// Send SCCCN reliably: retry until the LNS acknowledges via Nr advance.
	t.logger.Debug("sending SCCCN",
		zap.Uint16("remoteTunnelID", t.remoteTunnelID))
	scccnPayload := BuildSCCCN(challengeResponse)
	scccnPkt := t.buildControl(t.remoteTunnelID, 0, scccnPayload)
	scccnNs := uint16(t.ns.Load() - 1)
	{
		timeout := t.ctrlBase
		for attempt := 0; ; attempt++ {
			if err := t.resendControl(scccnPkt); err != nil {
				t.Close()
				return fmt.Errorf("send SCCCN: %w", err)
			}
			err := t.waitForPeerAck(scccnNs, timeout)
			if err == nil {
				break
			}
			if attempt >= t.ctrlRetries || !errors.Is(err, errControlTimeout) {
				t.Close()
				return fmt.Errorf("SCCCN ack: %w", err)
			}
			timeout = min(timeout*2, t.ctrlCap)
			t.logger.Debug("SCCCN ack timeout, retransmitting", zap.Int("attempt", attempt+1))
		}
	}

	t.logger.Debug("tunnel handshake complete")
	return nil
}

// CreateSession creates a new L2TP session on this tunnel.
func (t *Tunnel) CreateSession(subscriber, callingNumber string) (*Session, error) {
	t.mu.Lock()
	// Session ID 0 addresses the tunnel itself, and handing out an ID that is
	// still in use would make the peer's replies ambiguous. A tunnel lives as
	// long as it has calls, so a busy LAC does come round again.
	sid, ok := t.allocSessionID()
	if !ok {
		t.mu.Unlock()
		return nil, errors.New("l2tp: no free session ID in this tunnel")
	}
	s := newSession(t, sid, subscriber, callingNumber)
	t.sessions[sid] = s
	t.mu.Unlock()

	if err := s.establish(); err != nil {
		t.mu.Lock()
		delete(t.sessions, sid)
		t.mu.Unlock()
		return nil, err
	}
	return s, nil
}

// removeSession removes a session from the registry.
// Returns the number of remaining sessions.
// allocSessionID returns an unused non-zero session ID. Caller holds t.mu.
func (t *Tunnel) allocSessionID() (uint16, bool) {
	for i := 0; i < 0x10000; i++ {
		t.nextSID++
		if t.nextSID == 0 {
			t.nextSID = 1
		}
		if _, taken := t.sessions[t.nextSID]; !taken {
			return t.nextSID, true
		}
	}
	return 0, false
}

func (t *Tunnel) removeSession(sid uint16) int {
	t.mu.Lock()
	delete(t.sessions, sid)
	remaining := len(t.sessions)
	t.mu.Unlock()
	return remaining
}

// SessionCount returns the number of active sessions.
func (t *Tunnel) SessionCount() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.sessions)
}

// Close sends StopCCN and tears down the tunnel.
func (t *Tunnel) Close() {
	t.closeOnce.Do(func() {
		// StopCCN has to leave before the tunnel is marked closed. writePacket
		// short-circuits on t.closed, so closing first would discard it silently,
		// and a peer that is never told the control connection is going away has
		// nothing to act on until its own liveness timer expires. Hello is optional
		// (RFC 2661 s5.5), so how long that takes is the peer's business and may be
		// a long time; every session in the tunnel stays up meanwhile.
		//
		// RFC 2661 s3.3: StopCCN implicitly terminates every session in the tunnel,
		// so the sessions are torn down locally afterwards rather than each sending
		// its own CDN.
		payload := BuildStopCCN(t.localTunnelID, 1, 0, "LAC shutting down")
		if err := t.sendControl(t.remoteTunnelID, 0, payload); err != nil {
			t.logger.Debug("could not send StopCCN",
				zap.Uint16("tunnelID", t.localTunnelID), zap.Error(err))
		}
		close(t.closed)
		t.conn.Close()
		t.closeAllSessions()
		if t.onClose != nil {
			t.onClose()
		}
	})
}

// Alive returns true if the tunnel has not been closed.
func (t *Tunnel) Alive() bool {
	select {
	case <-t.closed:
		return false
	default:
		return true
	}
}

func (t *Tunnel) closeAllSessions() {
	t.mu.Lock()
	sessions := make([]*Session, 0, len(t.sessions))
	for _, s := range t.sessions {
		sessions = append(sessions, s)
	}
	t.mu.Unlock()
	for _, s := range sessions {
		s.closeDueToTunnel()
	}
}

// buildControl allocates the next Ns and returns the serialized control packet.
func (t *Tunnel) buildControl(tunnelID, sessionID uint16, payload []byte) []byte {
	ns := uint16(t.ns.Add(1) - 1)
	nr := uint16(t.nr.Load())
	hdr := EncodeControlHeader(tunnelID, sessionID, ns, nr, len(payload))
	return append(hdr, payload...)
}

// resendControl retransmits a previously built control packet with an updated Nr.
func (t *Tunnel) resendControl(pkt []byte) error {
	if len(pkt) >= 12 {
		nr := uint16(t.nr.Load())
		binary.BigEndian.PutUint16(pkt[10:12], nr)
	}
	return t.writePacket(pkt)
}

// sendControl allocates the next Ns and writes the message while holding the
// write lock, so the sequence numbers reach the wire in the order they were
// issued. Allocating first and locking afterwards let a second sender take Ns+1
// and win the lock ahead of the holder of Ns, which the peer sees as a gap.
func (t *Tunnel) sendControl(tunnelID, sessionID uint16, payload []byte) error {
	select {
	case <-t.closed:
		return errTunnelClosed
	default:
	}
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	pkt := t.buildControl(tunnelID, sessionID, payload)
	_, err := t.conn.Write(pkt)
	return err
}

// sendZLB sends a Zero-Length Body acknowledgment.
func (t *Tunnel) sendZLB() {
	nr := uint16(t.nr.Load())
	ns := uint16(t.ns.Load())
	hdr := EncodeControlHeader(t.remoteTunnelID, 0, ns, nr, 0)
	_ = t.writePacket(hdr)
}

// updatePeerNr advances the tracked peer Nr and signals any waiters.
func (t *Tunnel) updatePeerNr(nr uint16) {
	t.peerNrMu.Lock()
	defer t.peerNrMu.Unlock()
	if nr != t.peerNr && int16(nr-t.peerNr) > 0 {
		t.peerNr = nr
		close(t.peerNrCh)
		t.peerNrCh = make(chan struct{})
	}
}

// waitForPeerAck waits for recvLoop to observe the peer advancing Nr past sentNs.
// Used after recvLoop has started (i.e., for ICCN during session setup).
func (t *Tunnel) waitForPeerAck(sentNs uint16, timeout time.Duration) error {
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	for {
		t.peerNrMu.Lock()
		if int16(t.peerNr-(sentNs+1)) >= 0 {
			t.peerNrMu.Unlock()
			return nil
		}
		ch := t.peerNrCh
		t.peerNrMu.Unlock()

		select {
		case <-ch:
		case <-deadline.C:
			return errControlTimeout
		case <-t.closed:
			return errTunnelClosed
		}
	}
}

func (t *Tunnel) writePacket(pkt []byte) error {
	select {
	case <-t.closed:
		return errTunnelClosed
	default:
	}
	t.writeMu.Lock()
	_, err := t.conn.Write(pkt)
	t.writeMu.Unlock()
	return err
}

// SendData sends one PPP frame for a session.
//
// The frame is written exactly as given. RFC 2661 s4.1 makes the information
// field of a data message the PPP frame with its HDLC framing removed, which is
// precisely what the caller already holds -- so there is nothing to add and
// nothing to take away.
func (t *Tunnel) SendData(sessionID uint16, frame []byte) error {
	hdr := EncodeDataHeader(t.remoteTunnelID, sessionID)
	pkt := make([]byte, 0, len(hdr)+len(frame))
	pkt = append(pkt, hdr...)
	pkt = append(pkt, frame...)
	return t.writePacket(pkt)
}

// recvControlDirect reads one control message with a deadline.
// Used ONLY during tunnel handshake before recvLoop starts.
func (t *Tunnel) recvControlDirect(timeout time.Duration) ([]AVP, error) {
	buf := make([]byte, maxPacketSize)
	t.conn.SetReadDeadline(time.Now().Add(timeout))
	defer t.conn.SetReadDeadline(time.Time{})

	for {
		n, err := t.conn.Read(buf)
		if err != nil {
			return nil, err
		}
		hdr, off, err := DecodeHeader(buf[:n])
		if err != nil {
			continue
		}
		if !hdr.IsControl {
			continue
		}
		t.updatePeerNr(hdr.Nr)
		expectedNr := uint16(t.nr.Load())
		if hdr.Ns != expectedNr {
			t.sendZLB()
			continue
		}
		t.nr.Store(uint32(hdr.Ns + 1))
		t.sendZLB()

		if off >= n {
			continue
		}
		avps, err := DecodeAVPs(buf[off:n])
		if err != nil {
			return nil, fmt.Errorf("decode AVPs: %w", err)
		}
		return avps, nil
	}
}

// registerPendingCtrl creates a buffered channel for receiving control
// responses routed by recvLoop for the given local session ID.
// Must be called before sending the request that triggers the response.
func (t *Tunnel) registerPendingCtrl(sid uint16) chan controlMsg {
	ch := make(chan controlMsg, 1)
	t.pendingCtrlMu.Lock()
	t.pendingCtrls[sid] = ch
	t.pendingCtrlMu.Unlock()
	return ch
}

func (t *Tunnel) unregisterPendingCtrl(sid uint16) {
	t.pendingCtrlMu.Lock()
	delete(t.pendingCtrls, sid)
	t.pendingCtrlMu.Unlock()
}

func (t *Tunnel) waitForControl(ch chan controlMsg, timeout time.Duration) ([]AVP, uint16, error) {
	select {
	case msg := <-ch:
		return msg.avps, msg.msgType, nil
	case <-time.After(timeout):
		return nil, 0, errControlTimeout
	case <-t.closed:
		return nil, 0, errTunnelClosed
	}
}

// recvLoop is the main receive loop for the tunnel.
// It demuxes packets to sessions and handles control messages.
func (t *Tunnel) recvLoop() {
	buf := make([]byte, maxPacketSize)
	for {
		select {
		case <-t.closed:
			return
		default:
		}
		if t.helloInterval > 0 {
			t.conn.SetReadDeadline(time.Now().Add(t.helloInterval * 3))
		}
		n, err := t.conn.Read(buf)
		if err != nil {
			select {
			case <-t.closed:
				return
			default:
			}
			t.logger.Warn("tunnel read error, closing",
				zap.Uint16("tunnelID", t.localTunnelID),
				zap.Error(err))
			t.die()
			return
		}
		hdr, off, err := DecodeHeader(buf[:n])
		if err != nil {
			continue
		}
		// DecodeHeader already bounds off, so this never fires today. It stays
		// because everything below slices buf[off:n]: a decoder that ever got
		// this wrong would panic the whole tunnel rather than drop one packet.
		if off > n {
			continue
		}

		if hdr.IsControl {
			t.handleControl(hdr, buf[off:n])
		} else {
			t.handleData(hdr, buf[off:n])
		}
	}
}

func (t *Tunnel) handleControl(hdr Header, payload []byte) {
	if len(payload) == 0 {
		t.updatePeerNr(hdr.Nr)
		return // ZLB ack
	}

	expectedNr := uint16(t.nr.Load())
	if hdr.Ns != expectedNr {
		t.sendZLB()
		return
	}
	t.nr.Store(uint32(hdr.Ns + 1))
	t.sendZLB()
	t.updatePeerNr(hdr.Nr)

	avps, err := DecodeAVPs(payload)
	if err != nil {
		t.logger.Debug("failed to decode control AVPs", zap.Error(err))
		return
	}
	msgType, err := GetMessageType(avps)
	if err != nil {
		t.logger.Debug("failed to get message type", zap.Error(err))
		return
	}

	if hdr.Session != 0 {
		t.mu.RLock()
		s := t.sessions[hdr.Session]
		t.mu.RUnlock()
		if s != nil {
			s.noteInboundControl(msgType, avps)
		}
	}

	// Route ICRP/CDN to the session that is waiting for it, keyed by
	// the header Session field (which is our local session ID per RFC 2661).
	if msgType == MsgTypeICRP || msgType == MsgTypeCDN {
		t.pendingCtrlMu.Lock()
		ch := t.pendingCtrls[hdr.Session]
		t.pendingCtrlMu.Unlock()
		if ch != nil {
			select {
			case ch <- controlMsg{avps: avps, msgType: msgType}:
				if msgType == MsgTypeICRP {
					return
				}
			default:
			}
		}
	}

	switch msgType {
	case MsgTypeStopCCN:
		logFields := []zap.Field{zap.Uint16("tunnelID", t.localTunnelID)}
		if rcAVP := FindAVP(avps, 0, AVPResultCode); rcAVP != nil && len(rcAVP.Value) >= 2 {
			resultCode := binary.BigEndian.Uint16(rcAVP.Value[0:2])
			logFields = append(logFields, zap.Uint16("resultCode", resultCode))
			if len(rcAVP.Value) >= 4 {
				errorCode := binary.BigEndian.Uint16(rcAVP.Value[2:4])
				logFields = append(logFields, zap.Uint16("errorCode", errorCode))
			}
			if len(rcAVP.Value) > 4 {
				logFields = append(logFields, zap.String("errorMsg", string(rcAVP.Value[4:])))
			}
		}
		t.logger.Warn("received StopCCN from LNS", logFields...)
		// StopCCN implicitly terminates every session (RFC 2661 s3.3), so give
		// each one the reason before they are closed -- otherwise a session torn
		// down this way reports CloseReason() == (0,0,"") and the LAC has nothing
		// to tell its client.
		result, errCode, msg := parseResultCode(avps)
		t.mu.RLock()
		victims := make([]*Session, 0, len(t.sessions))
		for _, sess := range t.sessions {
			victims = append(victims, sess)
		}
		t.mu.RUnlock()
		for _, sess := range victims {
			sess.noteCloseReason(result, errCode, msg)
		}
		t.die()
	case MsgTypeHello:
		// Hello is just acknowledged (ZLB already sent above)
	case MsgTypeCDN:
		t.handleCDN(hdr, avps)
	default:
		t.logger.Debug("unhandled control message",
			zap.Uint16("type", msgType),
			zap.Uint16("tunnelID", t.localTunnelID))
	}
}

func (t *Tunnel) handleCDN(hdr Header, avps []AVP) {
	// The Result Code says why. Keep it: it is the only thing that lets the LAC
	// tell its client whether this was worth retrying (RFC 2661 s4.4.2).
	result, errCode, msg := parseResultCode(avps)

	// RFC 2661 s3.1 makes the header's Session field the authoritative identifier
	// of the local session, and it is this map's key -- so the common path needs
	// no read of a session's own fields. The Assigned Session ID AVP is a fallback
	// for peers that leave the header zero.
	var target *Session
	t.mu.RLock()
	if hdr.Session != 0 {
		target = t.sessions[hdr.Session]
	}
	if target == nil {
		if avp := FindAVP(avps, 0, AVPAssignedSessionID); avp != nil {
			if remoteSID, err := AVPUint16(avp); err == nil {
				for _, s := range t.sessions {
					if s.remoteSID() == remoteSID {
						target = s
						break
					}
				}
			}
		}
	}
	t.mu.RUnlock()

	if target == nil {
		t.logger.Debug("CDN for an unknown session",
			zap.Uint16("tunnelID", t.localTunnelID), zap.Uint16("headerSession", hdr.Session))
		return
	}
	target.noteCloseReason(result, errCode, msg)
	target.closeDueToLNS()
}

// maxResultMessage bounds the peer-controlled text that reaches our logs and the
// SessionReason sent to the client. The AVP length field is 10 bits, so a single
// Result Code can carry a kilobyte of anything.
const maxResultMessage = 256

// sanitiseResultMessage makes peer text safe to log and forward: valid UTF-8,
// bounded, and free of control characters that would corrupt a log line.
func sanitiseResultMessage(b []byte) string {
	if len(b) > maxResultMessage {
		b = b[:maxResultMessage]
	}
	out := make([]rune, 0, len(b))
	for _, r := range string(b) {
		if r == utf8.RuneError || unicode.IsControl(r) {
			r = ' '
		}
		out = append(out, r)
	}
	return strings.TrimSpace(string(out))
}

// parseResultCode pulls the Result Code AVP apart: result(2) + error(2) +
// optional message, per RFC 2661 s4.4.2. Missing or short values report zeroes
// rather than failing, since a peer is free to omit them.
func parseResultCode(avps []AVP) (result, errCode uint16, msg string) {
	avp := FindAVP(avps, 0, AVPResultCode)
	if avp == nil {
		return 0, 0, ""
	}
	v := avp.Value
	if len(v) >= 2 {
		result = binary.BigEndian.Uint16(v[0:2])
	}
	if len(v) >= 4 {
		errCode = binary.BigEndian.Uint16(v[2:4])
	}
	if len(v) > 4 {
		msg = sanitiseResultMessage(v[4:])
	}
	return result, errCode, msg
}

// frameProtocol names a frame's PPP protocol for a log line, and is the only
// place in this package that looks inside one.
//
// It is best-effort on purpose. RFC 1661 s2 makes the two forms of the Protocol
// field self-describing -- an odd leading octet is a Protocol-Field-Compressed
// single octet, an even one begins the full pair -- but whether compression is
// in use was agreed between the subscriber's pppd and the LNS without telling
// the LAC. Being wrong here costs a misleading debug field and nothing more,
// which is exactly why the relay path stopped doing this.
func frameProtocol(frame []byte) uint16 {
	b := frame
	if len(b) >= 3 && b[0] == 0xFF && b[1] == 0x03 {
		b = b[2:]
	}
	if len(b) == 0 {
		return 0
	}
	if b[0]&1 == 1 {
		return uint16(b[0])
	}
	if len(b) < 2 {
		return 0
	}
	return uint16(b[0])<<8 | uint16(b[1])
}

// describeResultCode renders a Result Code AVP for an error message, naming the
// StopCCN result codes of RFC 2661 s4.4.2.
//
// The peer's own message is included because the Result Code alone is coarse:
// several quite different configuration mistakes share one code, and the text is
// the only thing that separates them.
func describeResultCode(avps []AVP) string {
	result, errCode, msg := parseResultCode(avps)
	if result == 0 && errCode == 0 && msg == "" {
		return "no Result Code given"
	}
	out := fmt.Sprintf("result=%d", result)
	switch result {
	case 2:
		out += " (general error)"
	case 4:
		out += " (not authorized)"
	case 5:
		out += " (unsupported protocol version)"
	}
	if errCode != 0 {
		out += fmt.Sprintf(" error=%d", errCode)
	}
	if msg != "" {
		out += fmt.Sprintf(" message=%q", msg)
	}
	return out
}

func (t *Tunnel) handleData(hdr Header, payload []byte) {
	if len(payload) == 0 {
		return
	}
	t.mu.RLock()
	s, ok := t.sessions[hdr.Session]
	t.mu.RUnlock()
	if !ok {
		return
	}
	// Verbatim, deliberately.
	//
	// Whether this frame carries a leading FF 03, and whether its protocol field
	// is one octet or two, was settled between the subscriber's pppd and the LNS
	// end to end through this tunnel. The LAC was not part of that negotiation and
	// is never told its result.
	//
	// This used to split the protocol field out and the endpoint glued it back on.
	// That was not wrong -- it wrote back the same octets it had skipped, so a
	// misread of a compressed field cancelled itself out -- but it was a round
	// trip whose result nothing used, resting on an invariant nobody had stated.
	// Not interpreting the frame is shorter and true by construction.
	s.deliverPPP(payload)
}

func (t *Tunnel) helloLoop() {
	ticker := time.NewTicker(t.helloInterval)
	defer ticker.Stop()
	for {
		select {
		case <-t.closed:
			return
		case <-ticker.C:
			payload := BuildHello()
			if err := t.sendControl(t.remoteTunnelID, 0, payload); err != nil {
				return
			}
		}
	}
}

func (t *Tunnel) die() {
	t.closeOnce.Do(func() {
		close(t.closed)
		t.conn.Close()
		count := t.SessionCount()
		t.logger.Warn("tunnel died",
			zap.Uint16("tunnelID", t.localTunnelID),
			zap.Int("sessionCount", count))
		t.closeAllSessions()
		if t.onClose != nil {
			t.onClose()
		}
	})
}
