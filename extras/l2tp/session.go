package l2tp

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"

	"go.uber.org/zap"
)

var errSessionClosed = errors.New("l2tp: session closed")

// Who ended a session, in the order the session learns it.
type closeCause uint32

const (
	// closeCauseLocal: we closed it, so there is nothing to report.
	closeCauseLocal closeCause = iota
	// closeCauseLNS: the LNS sent a CDN. This is the only cause that carries a
	// verdict about the subscriber.
	closeCauseLNS
	// closeCauseTunnel: the control connection died underneath us. Says nothing
	// about the credentials.
	closeCauseTunnel
)

// Session represents an L2TP session within a tunnel.
type Session struct {
	tunnel *Tunnel
	logger *zap.Logger

	localSessionID uint16
	// remoteSessionID is written by establish on the creating goroutine while
	// recvLoop may already be scanning the tunnel's session map -- CreateSession
	// registers the session before establishing it -- so it is not a plain field.
	remoteSessionID atomic.Uint32
	callSerial      uint32
	callingNumber   string
	// subscriber identifies whose call this is, for logs. It is the Hysteria2
	// authentication identity, not a PPP username: this LAC never sees one,
	// because the LNS runs authentication itself.
	subscriber string

	// Channel for receiving whole PPP frames from the tunnel's demux loop
	recvCh chan []byte

	closed    chan struct{}
	closeOnce sync.Once
	// cause records who ended the session. Written before closed is closed, so
	// anyone woken by that channel sees it.
	cause atomic.Uint32

	// closeResult/closeError/closeMessage hold the Result Code AVP from the CDN
	// that ended this session, so the LAC can tell its client why rather than
	// reporting a bare disconnect.
	closeMu      sync.Mutex
	closeResult  uint16
	closeError   uint16
	closeMessage string

	established            atomic.Bool
	firstInboundDataLogged atomic.Bool
	firstInboundCtrlLogged atomic.Bool

	// dropped counts inbound frames discarded because recvCh was full. Non-zero
	// means the PPP reader fell behind the LNS.
	dropped atomic.Uint64
}

var callSerialCounter atomic.Uint32

func newSession(t *Tunnel, localSID uint16, subscriber, callingNumber string) *Session {
	return &Session{
		tunnel:         t,
		logger:         t.logger,
		localSessionID: localSID,
		callSerial:     callSerialCounter.Add(1),
		callingNumber:  callingNumber,
		subscriber:     subscriber,
		recvCh:         make(chan []byte, 256),
		closed:         make(chan struct{}),
	}
}

// establish performs the ICRQ -> ICRP -> ICCN handshake.
// The pending-control waiter is registered BEFORE sending ICRQ so that
// a fast LNS reply cannot be lost, and each session has its own channel
// so concurrent session setups on the same tunnel don't interfere.
func (s *Session) establish() error {
	ch := s.tunnel.registerPendingCtrl(s.localSessionID)
	defer s.tunnel.unregisterPendingCtrl(s.localSessionID)

	s.logger.Debug("sending ICRQ",
		zap.Uint16("localSessionID", s.localSessionID),
		zap.Uint32("callSerial", s.callSerial),
		zap.String("callingNumber", s.callingNumber))

	icrqPayload := BuildICRQ(s.localSessionID, s.callSerial, s.callingNumber)
	pkt := s.tunnel.buildControl(s.tunnel.remoteTunnelID, 0, icrqPayload)

	var avps []AVP
	var msgType uint16
	timeout := s.tunnel.ctrlBase
	for attempt := 0; ; attempt++ {
		if err := s.tunnel.resendControl(pkt); err != nil {
			return fmt.Errorf("send ICRQ: %w", err)
		}
		var err error
		avps, msgType, err = s.tunnel.waitForControl(ch, timeout)
		if err == nil {
			break
		}
		if attempt >= s.tunnel.ctrlRetries || !errors.Is(err, errControlTimeout) {
			return fmt.Errorf("recv ICRP: %w", err)
		}
		timeout = min(timeout*2, s.tunnel.ctrlCap)
		s.logger.Debug("ICRQ timeout, retransmitting", zap.Int("attempt", attempt+1))
	}

	if msgType == MsgTypeCDN {
		return fmt.Errorf("LNS rejected session with CDN")
	}
	// Unreachable while handleControl routes only ICRP and CDN to this channel,
	// and kept so that widening that filter cannot silently turn some other
	// message into an established call.
	if msgType != MsgTypeICRP {
		return fmt.Errorf("expected ICRP, got msg type %d", msgType)
	}

	sidAVP := FindAVP(avps, 0, AVPAssignedSessionID)
	if sidAVP == nil {
		return fmt.Errorf("%w: Assigned Session ID in ICRP", ErrMissingAVP)
	}
	remoteSID, err := AVPUint16(sidAVP)
	if err != nil {
		return err
	}
	s.remoteSessionID.Store(uint32(remoteSID))

	s.logger.Debug("received ICRP",
		zap.Uint16("remoteSessionID", remoteSID))

	iccnPayload := BuildICCN()
	s.logger.Debug("sending ICCN",
		zap.Uint16("remoteSessionID", s.remoteSID()),
		zap.String("subscriber", s.subscriber))
	iccnPkt := s.tunnel.buildControl(s.tunnel.remoteTunnelID, s.remoteSID(), iccnPayload)
	iccnNs := uint16(s.tunnel.ns.Load() - 1)
	{
		ackTimeout := s.tunnel.ctrlBase
		for attempt := 0; ; attempt++ {
			if err := s.tunnel.resendControl(iccnPkt); err != nil {
				return fmt.Errorf("send ICCN: %w", err)
			}
			err := s.tunnel.waitForPeerAck(iccnNs, ackTimeout)
			if err == nil {
				break
			}
			if attempt >= s.tunnel.ctrlRetries || !errors.Is(err, errControlTimeout) {
				return fmt.Errorf("ICCN ack: %w", err)
			}
			ackTimeout = min(ackTimeout*2, s.tunnel.ctrlCap)
			s.logger.Debug("ICCN ack timeout, retransmitting", zap.Int("attempt", attempt+1))
		}
	}

	s.logger.Debug("session handshake complete",
		zap.Uint16("localSessionID", s.localSessionID),
		zap.Uint16("remoteSessionID", s.remoteSID()))
	s.established.Store(true)
	return nil
}

// SendPPP sends one PPP frame to the LNS, exactly as given.
//
// The frame is opaque here. What is inside it -- which protocol, whether the
// address and control octets are present, whether the protocol field was
// compressed -- is between the subscriber and the LNS, and this session carries
// their conversation without joining it.
func (s *Session) SendPPP(frame []byte) error {
	select {
	case <-s.closed:
		return errSessionClosed
	default:
	}
	return s.tunnel.SendData(s.remoteSID(), frame)
}

// RecvPPP receives one PPP frame from the LNS, exactly as it arrived.
func (s *Session) RecvPPP() ([]byte, error) {
	// recvCh is never closed -- s.closed is the end-of-session signal, and the
	// demux loop keeps the queue alive so a frame in flight has somewhere to go.
	// With both ready, which one wins is arbitrary, so a reader draining a closed
	// session gets the frames that did arrive before it sees the error.
	select {
	case <-s.closed:
		return nil, errSessionClosed
	case frame := <-s.recvCh:
		return frame, nil
	}
}

// deliverPPP is called by the tunnel's demux loop to deliver a PPP frame.
// remoteSID is the session ID the LNS assigned, or 0 before ICRP.
func (s *Session) remoteSID() uint16 { return uint16(s.remoteSessionID.Load()) }

func (s *Session) deliverPPP(payload []byte) {
	if s.established.Load() && s.firstInboundDataLogged.CompareAndSwap(false, true) {
		s.logger.Debug("first inbound PPP data after ICCN",
			zap.Uint16("sessionID", s.localSessionID),
			zap.Uint16("proto", frameProtocol(payload)),
			zap.Int("len", len(payload)),
			zap.String("hex", hex.EncodeToString(payload)))
	}
	frame := make([]byte, len(payload))
	copy(frame, payload)
	select {
	case s.recvCh <- frame:
	case <-s.closed:
	default:
		// The queue belongs to this session but the goroutine does not: this runs
		// on the tunnel's single demux loop, which also carries every other
		// session's frames and all of the control traffic. Waiting for one stalled
		// subscriber here would stop ICRP, CDN and HELLO for the whole tunnel, so
		// a session whose reader has fallen behind takes every other session on
		// that LNS down with it.
		//
		// Dropping is what the link does anyway. PPP runs over lossy media by
		// design and the upper layers retransmit; 256 frames of slack is already
		// far more than a link that is keeping up ever needs.
		n := s.dropped.Add(1)
		if n == 1 {
			s.logger.Warn("L2TP session queue full, dropping frames; the PPP reader is not keeping up",
				zap.Uint16("sessionID", s.localSessionID))
		} else if ce := s.logger.Check(zap.DebugLevel, "L2TP session frame dropped"); ce != nil {
			ce.Write(zap.Uint16("sessionID", s.localSessionID), zap.Uint64("count", n))
		}
	}
}

// Dropped reports how many inbound frames were discarded because the session's
// reader could not keep up.
func (s *Session) Dropped() uint64 { return s.dropped.Load() }

func (s *Session) noteInboundControl(msgType uint16, avps []AVP) {
	if !s.established.Load() || !s.firstInboundCtrlLogged.CompareAndSwap(false, true) {
		return
	}
	s.logger.Debug("first inbound control after ICCN",
		zap.Uint16("sessionID", s.localSessionID),
		zap.Uint16("msgType", msgType),
		zap.String("avps", summarizeAVPs(avps)))
}

func summarizeAVPs(avps []AVP) string {
	parts := make([]string, 0, len(avps))
	for _, avp := range avps {
		parts = append(parts, fmt.Sprintf("type=%d,len=%d,m=%t", avp.Type, len(avp.Value), avp.Mandatory))
	}
	return strings.Join(parts, "; ")
}

// Close sends CDN and cleans up the session.
func (s *Session) Close() {
	last := false
	s.closeOnce.Do(func() {
		s.cause.Store(uint32(closeCauseLocal))
		close(s.closed)
		// Best-effort CDN
		cdnPayload := BuildCDN(s.localSessionID, 2, 0, "LAC disconnect")
		_ = s.tunnel.sendControl(s.tunnel.remoteTunnelID, s.remoteSID(), cdnPayload)
		remaining := s.tunnel.removeSession(s.localSessionID)
		s.logger.Info("session closed",
			zap.Uint16("tunnelID", s.tunnel.localTunnelID),
			zap.Uint16("sessionID", s.localSessionID),
			zap.String("subscriber", s.subscriber))
		last = remaining == 0
	})
	// Tearing the tunnel down happens outside the Once, and it has to:
	// Tunnel.Close closes every session it still holds, so a Tunnel.Close racing
	// this one would sit inside the tunnel's Once waiting on this session's Once
	// while this goroutine waited on the tunnel's. Both are reachable at once --
	// TunnelManager.Close during a server shutdown is the other side. Releasing
	// this session's Once first means one of them simply waits for the other.
	if last {
		s.logger.Info("last session ended, closing tunnel",
			zap.Uint16("tunnelID", s.tunnel.localTunnelID))
		s.tunnel.Close()
	}
}

// closeDueToTunnel is called when the tunnel dies.
func (s *Session) closeDueToTunnel() {
	s.closeOnce.Do(func() {
		s.cause.Store(uint32(closeCauseTunnel))
		close(s.closed)
		s.tunnel.removeSession(s.localSessionID)
		s.logger.Warn("session died due to tunnel death",
			zap.Uint16("tunnelID", s.tunnel.localTunnelID),
			zap.Uint16("sessionID", s.localSessionID),
			zap.String("subscriber", s.subscriber))
	})
}

// closeDueToLNS is called when the LNS sends CDN.
// noteCloseReason records the Result Code the LNS sent with its CDN.
func (s *Session) noteCloseReason(result, errCode uint16, msg string) {
	s.closeMu.Lock()
	s.closeResult, s.closeError, s.closeMessage = result, errCode, msg
	s.closeMu.Unlock()
}

// CloseReason returns the Result Code, Error Code and message from the CDN that
// ended this session. A zero result means it was not the LNS that ended it.
func (s *Session) CloseReason() (result, errCode uint16, msg string) {
	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	return s.closeResult, s.closeError, s.closeMessage
}

func (s *Session) closeDueToLNS() {
	s.closeOnce.Do(func() {
		s.cause.Store(uint32(closeCauseLNS))
		close(s.closed)
		s.tunnel.removeSession(s.localSessionID)
		s.logger.Warn("session CDN received from LNS",
			zap.Uint16("tunnelID", s.tunnel.localTunnelID),
			zap.Uint16("sessionID", s.localSessionID),
			zap.String("subscriber", s.subscriber))
	})
}

// EndedByLNS reports whether the LNS disconnected this session with a CDN, as
// opposed to the tunnel dying underneath it or the LAC closing it. It is the
// difference between "the far end hung up on you" and "the path to the far end
// broke", which is all the LAC can honestly tell its client now that the LNS
// owns authentication.
func (s *Session) EndedByLNS() bool {
	return closeCause(s.cause.Load()) == closeCauseLNS
}
