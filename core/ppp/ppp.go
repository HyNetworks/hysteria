package ppp

import (
	"errors"
	"fmt"
)

// PPPDataIO abstracts PPP data frame transport.
// Two implementations exist: datagram-based (QUIC datagrams) and
// multi-stream-based (N parallel QUIC streams with per-flow hashing).
type PPPDataIO interface {
	SendData(frame []byte) error
	ReceiveData() ([]byte, error)
	Close() error
}

// MaxFrameSizer is implemented by transports that can report the largest frame
// they will currently accept. For QUIC datagrams this tracks Path MTU discovery,
// so it starts small and grows as the path is probed.
type MaxFrameSizer interface {
	// MaxFrameSize returns the current per-frame ceiling, or 0 if unknown.
	MaxFrameSize() int
}

// FrameTooLargeError reports that one frame exceeded what the transport can
// carry right now. It means "drop this frame" -- the transport is healthy and
// smaller frames still go through -- and must not be treated as session failure.
// MaxSize is the largest frame that would currently fit.
type FrameTooLargeError struct {
	FrameSize int
	MaxSize   int
}

func (e *FrameTooLargeError) Error() string {
	return fmt.Sprintf("ppp: frame of %d bytes exceeds the transport limit of %d", e.FrameSize, e.MaxSize)
}

func (e *FrameTooLargeError) Is(target error) bool {
	_, ok := target.(*FrameTooLargeError)
	return ok
}

// IsFrameTooLarge reports whether err means a single frame did not fit, as
// opposed to the transport being gone.
func IsFrameTooLarge(err error) bool {
	var e *FrameTooLargeError
	return errors.As(err, &e)
}

// SessionParams describes a requested PPP session. It travels from the server's
// stream handler to whichever PPPRequestHandler is configured.
type SessionParams struct {
	// DataStreams is 0 for datagram mode, or the number of reliable streams.
	DataStreams int
	// ClientMaxFrame is the largest frame the client's transport reported it can
	// carry, measured after Path MTU discovery settled. 0 when unknown.
	ClientMaxFrame int
	// ServerMaxFrame is the same figure for this server's transport.
	ServerMaxFrame int
}

// EffectiveMTU returns the PPP MTU that fits both directions, or 0 when neither
// side reported a figure. The PPP header (address, control and protocol) rides
// inside every frame, so it comes off the top.
func (p SessionParams) EffectiveMTU(pppHeader int) int {
	budget := p.ClientMaxFrame
	if p.ServerMaxFrame > 0 && (budget == 0 || p.ServerMaxFrame < budget) {
		budget = p.ServerMaxFrame
	}
	if budget <= pppHeader {
		return 0
	}
	return budget - pppHeader
}
