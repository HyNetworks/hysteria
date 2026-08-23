package pppbridge

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"time"

	"github.com/apernet/hysteria/core/v2/ppp"
	"go.uber.org/zap"
)

// ServerPPPHandler implements server.PPPRequestHandler.
// It manages pppd sessions with IP allocation and proper lifecycle logging.
type ServerPPPHandler struct {
	PPPDPath   string
	PPPDArgs   []string // Extra args appended to auto-generated ones
	Sudo       bool
	IPv4Pool   *IPPool
	DNS        []string
	MTU        int
	Salamander bool
	Logger     *zap.Logger
}

func (h *ServerPPPHandler) HandlePPP(control io.ReadWriteCloser, params ppp.SessionParams, createDataIO func() (ppp.PPPDataIO, error), addr net.Addr, id string) {
	defer control.Close()
	dataStreams := params.DataStreams

	// The PPP link can only be as wide as the narrower of the two transports.
	// Both figures were measured after Path MTU discovery settled, so this is
	// what the path actually carries rather than what the interface claims.
	transportMTU := params.EffectiveMTU(PPPHeaderLen)
	if transportMTU > 0 {
		h.Logger.Debug("PPP transport MTU negotiated",
			zap.String("id", id),
			zap.Int("clientMaxFrame", params.ClientMaxFrame),
			zap.Int("serverMaxFrame", params.ServerMaxFrame),
			zap.Int("mtu", transportMTU))
	}

	var clientIP, gatewayIP string
	if h.IPv4Pool != nil {
		var err error
		clientIP, err = h.IPv4Pool.Allocate()
		if err != nil {
			h.Logger.Error("PPP request rejected",
				zap.String("addr", addr.String()),
				zap.String("reason", "pool exhausted"))
			_ = writePPPResponse(control, false, "IP pool exhausted", dataStreams, 0)
			return
		}
		defer func() {
			h.IPv4Pool.Release(clientIP)
			h.Logger.Debug("PPP IPv4 released", zap.String("clientIP", clientIP))
		}()
		gatewayIP = h.IPv4Pool.Gateway()
		h.Logger.Debug("PPP IPv4 allocated",
			zap.String("addr", addr.String()),
			zap.String("id", id),
			zap.String("clientIP", clientIP),
			zap.String("gatewayIP", gatewayIP))
	} else {
		h.Logger.Debug("PPP IPv6-only (no IPv4 pool)",
			zap.String("addr", addr.String()),
			zap.String("id", id))
	}

	if err := writePPPResponse(control, true, "OK", dataStreams, transportMTU); err != nil {
		h.Logger.Error("PPP request rejected",
			zap.String("addr", addr.String()),
			zap.String("reason", "failed to write response: "+err.Error()))
		return
	}

	dataIO, err := createDataIO()
	if err != nil {
		h.Logger.Error("PPP data transport setup failed",
			zap.String("addr", addr.String()),
			zap.String("id", id),
			zap.Error(err))
		return
	}
	defer dataIO.Close()

	pppdArgs, mtu := h.buildPPPDArgs(gatewayIP, clientIP, id, addr, dataStreams, transportMTU)
	h.Logger.Debug("PPP spawning pppd",
		zap.String("addr", addr.String()),
		zap.String("id", id),
		zap.String("pppdPath", h.PPPDPath),
		zap.Strings("pppdArgs", pppdArgs),
		zap.Int("dataStreams", dataStreams))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	start := time.Now()
	bridge := &Bridge{
		PPPDPath: h.PPPDPath,
		PPPDArgs: pppdArgs,
		Sudo:     h.Sudo,
		Logger:   h.Logger,
	}

	logFields := []zap.Field{
		zap.String("addr", addr.String()),
		zap.String("id", id),
		zap.Int("dataStreams", dataStreams),
	}
	if clientIP != "" {
		logFields = append(logFields, zap.String("clientIP", clientIP))
	} else {
		logFields = append(logFields, zap.String("mode", "IPv6-only"))
	}
	if mtu > 0 {
		logFields = append(logFields, zap.Int("mtu", mtu))
	}
	h.Logger.Info("PPP session started", logFields...)

	runErr := bridge.Run(ctx, oneShotDial(control, dataIO, cancel))

	// Tell the client why, the same as the LAC does. Local mode has no LNS to
	// quote, so the reason is only ever "this ended" -- but saying so beats the
	// client inferring a bare link loss from silence, and it keeps both server
	// modes speaking the same protocol on the control stream.
	writeSessionReason(control, SessionReason{
		Code:    ReasonLinkDown,
		Message: "server-side PPP session ended",
	})

	duration := time.Since(start)
	if runErr != nil {
		h.Logger.Error("PPP pppd exited with error",
			zap.String("addr", addr.String()),
			zap.String("id", id),
			zap.Error(runErr))
	}
	h.Logger.Info("PPP session ended",
		zap.String("addr", addr.String()),
		zap.String("id", id),
		zap.Duration("duration", duration))
}

// oneShotDial hands the already-established control stream and data transport to
// a Bridge exactly once.
//
// The server side does not dial anything: the client did, and these are the ends
// of that connection. Bridge.dialWithRetry would happily call a DialFn again
// after a transient failure, and handing out the same single-use streams a second
// time would relay a new session into a transport the old one still owns -- so
// the second attempt is refused permanently instead.
func oneShotDial(control io.ReadWriteCloser, dataIO ppp.PPPDataIO, cancel func()) DialFn {
	var called atomic.Bool
	return func() (io.ReadWriteCloser, ppp.PPPDataIO, func(), error) {
		if !called.CompareAndSwap(false, true) {
			return nil, nil, nil, permanentDialError{errors.New("the server side has only one connection to give")}
		}
		return control, dataIO, cancel, nil
	}
}

func (h *ServerPPPHandler) buildPPPDArgs(gatewayIP, clientIP, remoteName string, addr net.Addr, dataStreams, transportMTU int) ([]string, int) {
	var args []string
	var computedMTU int
	if len(h.PPPDArgs) > 0 {
		args = append(args, h.PPPDArgs...)
	} else {
		// See the note in app/cmd/client_ppp.go: echoes share the data transport,
		// so they are what detects a link that is up but dropping frames.
		//
		// mpshortseq asks the peer to send short sequence numbers; it says nothing
		// about what we send, and it does not make the multilink header any
		// cheaper for us. Against another pppd it is refused outright, because
		// pppd never sets lcp_allowoptions[0].neg_ssnhf. It is kept because a peer
		// that does support it costs us two fewer octets per received frame, and
		// it is called out here so it is not mistaken for a reason to budget four
		// octets of overhead instead of six -- see MLPPPOverhead.
		args = []string{
			"nodetach", "local", "+ipv6", "require-pap", "multilink", "mpshortseq",
			"lcp-echo-interval", "5", "lcp-echo-failure", "3", "lcp-echo-adaptive",
		}
		if gatewayIP != "" {
			args = append(args, fmt.Sprintf("%s:%s", gatewayIP, clientIP))
		}
		for _, dns := range h.DNS {
			args = append(args, "ms-dns", dns)
		}
		if h.MTU > 0 {
			// An explicit operator setting is used verbatim for both.
			s := fmt.Sprintf("%d", h.MTU)
			args = append(args, "mtu", s, "mru", s)
			computedMTU = h.MTU
		} else {
			// Prefer the measured transport ceiling over the calculation: it
			// reflects the path both endpoints actually share, after discovery
			// settled, whereas AutoPPPMTU only ever sees this host's egress
			// interface and has to guess the rest.
			linkMRU := transportMTU
			if linkMRU <= 0 {
				linkMRU = AutoPPPMTU(MTUParams{
					RemoteAddr:  addr,
					Salamander:  h.Salamander,
					DataStreams: dataStreams,
				})
			}
			linkMRU = ClampPPPMTU(linkMRU)
			vpnMTU := linkMRU - MLPPPOverhead
			args = append(args, "mtu", fmt.Sprintf("%d", vpnMTU), "mru", fmt.Sprintf("%d", linkMRU))
			computedMTU = vpnMTU
		}
	}
	if remoteName != "" {
		args = append(args, "remotename", remoteName)
	}
	return args, computedMTU
}
