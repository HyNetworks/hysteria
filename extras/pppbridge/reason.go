package pppbridge

import (
	"io"
	"time"

	"github.com/apernet/quic-go/quicvarint"
)

// Why a PPP session ended, carried from the server to the client.
//
// Without this the client only ever sees its transport go quiet, and a rejected
// password is indistinguishable from a flapping uplink -- so netifd retries a
// credential that can never work, forever, showing a generic pppd exit code. The
// control stream is free for this now that every PPP frame rides the data
// transport, so it becomes the signalling channel it was already shaped like.
//
// Wire format, written once as the session ends:
//
//	reason code (varint) | LNS result (varint) | LNS error (varint) | message (varint len + bytes)
type ReasonCode uint64

const (
	// ReasonUnknown is the zero value: no reason was reported.
	ReasonUnknown ReasonCode = 0
	// ReasonLinkDown means the session ended without a specific cause.
	ReasonLinkDown ReasonCode = 1
	// ReasonAuthFailed means credentials were refused. Retrying will not help.
	ReasonAuthFailed ReasonCode = 2
	// ReasonNoRoute means no configured rule matched the subscriber's identity,
	// so there is no LNS group to send them to.
	ReasonNoRoute ReasonCode = 3
	// ReasonNoLNS means the realm's group had no usable LNS.
	ReasonNoLNS ReasonCode = 4
	// ReasonLNSUnreachable means the L2TP session could not be established.
	ReasonLNSUnreachable ReasonCode = 5
	// ReasonLNSDisconnected means the LNS tore the session down afterwards.
	ReasonLNSDisconnected ReasonCode = 6
	// ReasonPathNarrowed means full-size frames stopped getting through.
	ReasonPathNarrowed ReasonCode = 7
)

func (c ReasonCode) String() string {
	switch c {
	case ReasonLinkDown:
		return "LINK_DOWN"
	case ReasonAuthFailed:
		return "AUTH_FAILED"
	case ReasonNoRoute:
		return "NO_ROUTE"
	case ReasonNoLNS:
		return "NO_LNS"
	case ReasonLNSUnreachable:
		return "LNS_UNREACHABLE"
	case ReasonLNSDisconnected:
		return "LNS_DISCONNECTED"
	case ReasonPathNarrowed:
		return "PATH_NARROWED"
	default:
		return "UNKNOWN"
	}
}

// Permanent reports whether retrying could ever succeed. Only reasons that are
// definitionally not transient qualify: a refused Hysteria2 credential stays
// refused, and an identity with no configured route will not acquire one by
// waiting. Everything else -- including an unreachable LNS -- is worth another
// attempt.
func (c ReasonCode) Permanent() bool {
	switch c {
	case ReasonAuthFailed, ReasonNoRoute:
		return true
	default:
		return false
	}
}

// SessionReason is a reason plus whatever the LNS said about it. Result and Error
// are the RFC 2661 s4.4.2 Result Code AVP fields, passed through rather than
// interpreted, because the message text is often the only specific thing an LNS
// gives.
type SessionReason struct {
	Code    ReasonCode
	Result  uint16
	Error   uint16
	Message string
}

// maxReasonMessage bounds the text an untrusted peer can make us buffer.
const maxReasonMessage = 512

// reasonFromCDN maps an L2TP CDN Result Code onto a reason.
//
// The result code is only trusted for what it genuinely distinguishes: 5 is the
// permanent "facilities unavailable". Everything else is reported as an LNS
// disconnect with the result, error and message passed through for a human to
// read. The LAC deliberately does not try to infer "the credential was refused"
// from a CDN: it no longer authenticates anyone, and the subscriber's pppd has
// already seen the LNS's own CHAP-Failure or PAP-Nak directly.
func reasonFromCDN(result, errCode uint16, msg string) SessionReason {
	r := SessionReason{Code: ReasonLNSDisconnected, Result: result, Error: errCode, Message: msg}
	if result == 5 {
		// Permanently unavailable, so there is nothing to retry into.
		r.Code = ReasonNoLNS
	}
	return r
}

// reasonWriteTimeout bounds how long the teardown path will wait for the client
// to take the reason. A client that has already gone -- which is the common way a
// session ends -- would otherwise leave the handler blocked on a stream nobody is
// reading, holding its IP lease and its L2TP session open.
const reasonWriteTimeout = 2 * time.Second

// writeSessionReason emits the reason on the control stream. Best effort: the
// stream may already be gone, and if it is, the client falls back to reporting a
// plain link loss, which is the behaviour without any of this.
func writeSessionReason(w io.Writer, r SessionReason) {
	if c, ok := w.(interface{ SetWriteDeadline(time.Time) error }); ok {
		_ = c.SetWriteDeadline(time.Now().Add(reasonWriteTimeout))
		defer func() { _ = c.SetWriteDeadline(time.Time{}) }()
	}
	msg := r.Message
	if len(msg) > maxReasonMessage {
		msg = msg[:maxReasonMessage]
	}
	buf := quicvarint.Append(nil, uint64(r.Code))
	buf = quicvarint.Append(buf, uint64(r.Result))
	buf = quicvarint.Append(buf, uint64(r.Error))
	buf = quicvarint.Append(buf, uint64(len(msg)))
	buf = append(buf, msg...)
	_, _ = w.Write(buf)
}

// ReadSessionReason reads a reason written by writeSessionReason. It is the
// client's side of the channel; an error means nothing usable arrived, which the
// caller should treat as an unexplained link loss rather than a failure.
func ReadSessionReason(r io.Reader) (SessionReason, error) {
	br := quicvarint.NewReader(r)
	code, err := quicvarint.Read(br)
	if err != nil {
		return SessionReason{}, err
	}
	result, err := quicvarint.Read(br)
	if err != nil {
		return SessionReason{}, err
	}
	errCode, err := quicvarint.Read(br)
	if err != nil {
		return SessionReason{}, err
	}
	msgLen, err := quicvarint.Read(br)
	if err != nil {
		return SessionReason{}, err
	}
	if msgLen > maxReasonMessage {
		return SessionReason{}, io.ErrUnexpectedEOF
	}
	var msg []byte
	if msgLen > 0 {
		msg = make([]byte, msgLen)
		if _, err := io.ReadFull(r, msg); err != nil {
			return SessionReason{}, err
		}
	}
	return SessionReason{
		Code:    ReasonCode(code),
		Result:  uint16(result),
		Error:   uint16(errCode),
		Message: string(msg),
	}, nil
}
