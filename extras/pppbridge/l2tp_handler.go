package pppbridge

import (
	"context"
	"io"
	"net"
	"sync/atomic"
	"time"

	"github.com/apernet/hysteria/core/v2/ppp"
	"github.com/apernet/hysteria/extras/v2/l2tp"

	"go.uber.org/zap"
)

// L2TPPPPHandler implements server.PPPRequestHandler for L2TP mode.
//
// The LAC is a data-plane bridge and nothing more. It picks an LNS from the
// subscriber's Hysteria2 identity, opens an L2TP session, and relays PPP frames
// verbatim in both directions. It never runs LCP, never authenticates anybody,
// and sends no proxy AVPs -- the LNS negotiates LCP and authentication directly
// with the subscriber's pppd, end to end through the tunnel.
//
// That is a deliberate choice, and RFC 2661 s4.4.5 is explicit that it is a
// supported one: an ICCN without Proxy Authen Type means "this peer cannot
// perform proxy authentication, requiring a restart of the authentication phase
// at the LNS". Most LNS deployments renegotiate regardless of what a LAC
// proxies, so proxying bought little and cost a great deal: a full LCP state
// machine, a CHAP/PAP implementation, verbatim capture of three CONFREQs, and
// the standing problem that the LAC had to tell the subscriber "you are
// authenticated" before the LNS had ruled.
//
// It also means no subscriber credential ever crosses the LAC. A proxied PAP
// password travels the L2TP control connection in the clear unless AVP hiding is
// in use; with nothing proxied there is nothing to hide.
type L2TPPPPHandler struct {
	TunnelManager *l2tp.TunnelManager
	IDRouter      *l2tp.IDRouter
	LoadBalancer  *l2tp.LoadBalancer
	Logger        *zap.Logger

	// MTU probe schedule, shared with the relay. Zero selects the defaults.
	ProbeInterval time.Duration
	ProbeGrace    time.Duration
	ProbeFailures int
}

func (h *L2TPPPPHandler) HandlePPP(
	control io.ReadWriteCloser,
	params ppp.SessionParams,
	createDataIO func() (ppp.PPPDataIO, error),
	addr net.Addr,
	id string,
) {
	defer control.Close()
	dataStreams := params.DataStreams
	transportMTU := params.EffectiveMTU(PPPHeaderLen)

	h.Logger.Debug("PPP request received",
		zap.String("addr", addr.String()),
		zap.String("id", id),
		zap.Int("dataStreams", dataStreams),
		zap.Int("transportMTU", transportMTU))

	if err := writePPPResponse(control, true, "OK", dataStreams, transportMTU); err != nil {
		h.Logger.Error("failed to write PPP response", zap.Error(err))
		return
	}

	// The data transport is created before the routing decision so that every
	// path out of here closes it. A refusal that left it open would leave the
	// client's relay pumping into a transport nobody is serving, and the session
	// would hang until the QUIC connection idled out rather than ending with the
	// reason we just wrote.
	dataIO, err := createDataIO()
	if err != nil {
		h.Logger.Error("failed to create data IO", zap.Error(err))
		return
	}
	defer dataIO.Close()

	// Routing needs no PPP at all, because the subscriber is already known: they
	// authenticated to Hysteria2 to get here. A classic LAC has to terminate PPP
	// just to learn who is calling; this one does not.
	group := h.IDRouter.Match(id)
	if group == "" {
		h.Logger.Warn("no LNS group configured for this identity",
			zap.String("addr", addr.String()), zap.String("id", id))
		writeSessionReason(control, SessionReason{
			Code:    ReasonNoRoute,
			Message: "no LNS group is configured for identity " + id,
		})
		return
	}
	lnsConfig, ok := h.LoadBalancer.PickSticky(group, id)
	if !ok {
		h.Logger.Warn("no LNS available in group",
			zap.String("group", group), zap.String("id", id))
		writeSessionReason(control, SessionReason{
			Code:    ReasonNoLNS,
			Message: "no LNS available in group " + group,
		})
		return
	}

	h.Logger.Debug("LNS selection",
		zap.String("id", id), zap.String("group", group),
		zap.String("selectedLNS", lnsConfig.Address))

	// The identity is also the Calling Number, which is what an LNS records as
	// the Calling-Station-Id. BuildICRQ bounds its length, because with an
	// external authenticator this string is not one the LAC chose.
	session, err := h.TunnelManager.CreateSession(lnsConfig.Address, lnsConfig.Secret, id, id)
	if err != nil {
		h.Logger.Warn("L2TP session creation failed",
			zap.String("lns", lnsConfig.Address), zap.String("id", id), zap.Error(err))
		writeSessionReason(control, SessionReason{
			Code:    ReasonLNSUnreachable,
			Message: "L2TP session to " + lnsConfig.Address + " could not be established: " + err.Error(),
		})
		return
	}
	defer session.Close()

	h.Logger.Info("PPP L2TP session active",
		zap.String("addr", addr.String()), zap.String("id", id),
		zap.String("group", group), zap.String("lns", lnsConfig.Address))

	// From here the LAC has no opinion about what crosses it. LCP, authentication
	// and NCP all run between the subscriber's pppd and the LNS.
	//
	// The relay runs against a background context on purpose: HandlePPP has no
	// context of its own, and what ends this session is the transport dying or
	// the session closing, both of which the relay already sees.
	// Every other line HandlePPP writes carries addr and id; the relay's did not,
	// so one subscriber's oversize warning was indistinguishable from another's in
	// a server log carrying hundreds of sessions.
	relayLog := h.Logger.With(zap.String("addr", addr.String()), zap.String("id", id))

	// Counted rather than discarded. newRelay allocates its own when passed nil,
	// which made the count unreachable: the relay's warning fires once per session
	// and every drop after it is Debug, so a link losing every full-size packet
	// and a link that lost one look identical.
	var oversize atomic.Uint64

	r := newRelay(dataIO, newL2TPEndpoint(session), relayLog, &oversize)
	r.ProbeInterval, r.ProbeGrace, r.ProbeFailures = h.ProbeInterval, h.ProbeGrace, h.ProbeFailures
	// The LAC does not choose this link's MTU. The subscriber's pppd negotiated it
	// with the LNS end to end, past a bridge that never sees LCP -- so a teardown
	// cannot come back smaller: the rebuilt session negotiates the identical
	// number, and all the round trip achieves is dropping a subscriber whose path
	// was never the problem. Exactly the reasoning MTUFixed carries for nospawn,
	// where pppd is likewise not this process's to configure.
	r.MTUFixed = true
	runErr := r.run(context.Background())

	if dropped := oversize.Load(); dropped > 0 {
		relayLog.Warn("frames were dropped over this session for exceeding the transport limit; "+
			"the MTU the subscriber negotiated with the LNS is larger than this path carries",
			zap.Uint64("count", dropped))
	}

	reason := h.endReason(session)
	writeSessionReason(control, reason)

	h.Logger.Debug("PPP L2TP session ended",
		zap.String("addr", addr.String()), zap.String("id", id),
		zap.String("lns", lnsConfig.Address),
		zap.String("reason", reason.Code.String()), zap.Error(runErr))
}

// endReason turns however the L2TP session ended into something the client can
// act on.
//
// The LAC no longer knows whether a credential was refused -- that conversation
// is between the subscriber's pppd and the LNS, and pppd sees the CHAP-Failure
// itself. What the LAC can still say is whether the far end hung up and what
// Result Code it gave, which is what distinguishes an LNS that disconnected this
// call from a path that broke.
func (h *L2TPPPPHandler) endReason(session *l2tp.Session) SessionReason {
	res, code, msg := session.CloseReason()
	if res != 0 {
		return reasonFromCDN(res, code, msg)
	}
	if session.EndedByLNS() {
		return SessionReason{Code: ReasonLNSDisconnected, Message: "the LNS disconnected the session"}
	}
	return SessionReason{Code: ReasonLinkDown, Message: "session ended"}
}
