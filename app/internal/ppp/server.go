package ppp

import (
	"context"
	"io"
	"net"
	"time"

	"github.com/apernet/hysteria/core/v2/client"
	"github.com/apernet/hysteria/core/v2/ppp"
	"github.com/apernet/hysteria/extras/v2/pppbridge"
	"go.uber.org/zap"
)

type Server struct {
	HyClient    client.Client
	Logger      *zap.Logger
	PPPDPath    string
	PPPDArgs    []string
	DataStreams int  // 0 = datagram (default), >0 = N parallel streams
	ServerRoute bool // when true, inject server-route <ip> arg for the child
	NoSpawn     bool // when true, bridge stdin/stdout instead of spawning pppd

	// LinkMRU is the MRU pppd was configured with, when this process did not
	// choose it. Only nospawn sets it, and there it is not optional: pppd fixed
	// its MRU before this process existed, so measuring the path would cost a
	// dial's worth of latency to learn a number that cannot be applied. Zero
	// means "measure it", which is what spawn mode wants.
	LinkMRU int

	// MTUArgs, when non-nil, builds the mtu and mru arguments for a link of the
	// given MRU, and is what carries the negotiated figure to pppd. Spawn mode
	// sets it whenever this process is the one choosing those numbers, and leaves
	// it nil when the operator pinned an MTU or supplied their own pppd arguments
	// -- those are not ours to move.
	//
	// A function rather than a number because the number does not exist yet when
	// the Server is built. The Bridge calls it after the session is established.
	MTUArgs func(linkMRU int) []string

	// FallbackMRU is what MTUArgs is called with when the server reports no
	// negotiated MTU. It is the pre-connection estimate, which is what every link
	// used to run on unconditionally.
	FallbackMRU int

	// OnSessionUp is called once the server has accepted a PPP session, which is
	// the moment this link starts being worth something, and is given the MTU the
	// session settled on. The OpenWrt handler uses it to publish "this server is
	// connected", and the MTU with it, for its status page; left nil nothing
	// happens.
	//
	// Deliberately not "once the Hysteria2 connection is up". A reachable server
	// that refuses the session leaves a perfectly healthy connection carrying
	// nothing, and reporting that as connected is how a bundle comes to show
	// three live links and one link's throughput.
	OnSessionUp func(linkMRU int)

	// Counters, when set, accumulate the PPP traffic every link this Server
	// carries. Handed to each Bridge in turn rather than to one of them, so the
	// figure spans the rebuilds Serve does after a link failure instead of
	// restarting with each of them.
	//
	// One Server is one link. That is not a property of this type but of how the
	// OpenWrt handler runs it -- a process per server slot, each pppd's pty child
	// -- and it is the reason these numbers can be attributed to a server at all.
	Counters *pppbridge.Counters
}

func (s *Server) Serve() error {
	const (
		minBackoff     = 1 * time.Second
		maxBackoff     = 30 * time.Second
		resetThreshold = 5 * time.Second
	)
	var backoff time.Duration

	for {
		// Written by dialFn, read by the argument builder below. Not a race and not
		// ordering by luck: setting PPPDArgsFn is what makes the Bridge establish
		// the session before it starts the child, so the dial has already returned
		// by the time the arguments are built.
		sessionMRU := 0

		dialFn := func() (io.ReadWriteCloser, ppp.PPPDataIO, func(), error) {
			// The transport ceiling is the frame, not the packet: pppd hands the
			// bridge address, control and protocol octets ahead of the payload.
			maxFrameSize := 0
			if s.LinkMRU > 0 {
				maxFrameSize = s.LinkMRU + pppbridge.PPPHeaderLen
			}
			conn, err := s.HyClient.PPP(s.DataStreams, maxFrameSize)
			if err != nil {
				return nil, nil, nil, err
			}
			// The server sizes the link to whichever direction's transport carries
			// less, measured after Path MTU discovery settled on both sides. Logged
			// because in nospawn it is the only place an operator watching this
			// session sees it: pppd's MRU was fixed before this process started, so
			// the number cannot be applied here and only reaches the next link, via
			// the file OnSessionUp writes.
			if conn.MTU > 0 {
				sessionMRU = conn.MTU
				s.Logger.Info("PPP link MTU negotiated", zap.Int("mtu", conn.MTU))
				// Only nospawn can be told this and do nothing about it. pppd fixed
				// its MRU before this process started and cannot be given another
				// one, so the far end will keep sending frames sized to a number the
				// path does not carry, and the relay will keep dropping them. Name
				// both figures: the fix is to configure the smaller one, and an
				// operator cannot do that without being told what it is.
				if s.NoSpawn && s.LinkMRU > 0 && conn.MTU < s.LinkMRU {
					s.Logger.Warn("configured PPP MRU exceeds what this path carries; "+
						"large frames will be dropped until it is lowered",
						zap.Int("configuredMRU", s.LinkMRU),
						zap.Int("negotiatedMRU", conn.MTU))
				}
			} else {
				s.Logger.Warn("server did not report a PPP MTU; " +
					"pppd will use whatever its own configuration says")
			}
			if s.OnSessionUp != nil {
				s.OnSessionUp(sessionMRU)
			}
			return conn.ControlStream, conn.Data, func() { conn.Close() }, nil
		}

		args := s.PPPDArgs
		if s.ServerRoute {
			if ip := addrIP(s.HyClient.RemoteAddr()); ip != "" {
				args = append(append([]string{}, s.PPPDArgs...), "server-route", ip)
			}
		}

		bridge := &pppbridge.Bridge{
			// In nospawn the MTU arrived with pppd and a rebuild would ask for the
			// same one, so a narrowed path is reported rather than acted on.
			MTUFixed: s.NoSpawn,
			// Without this the reason the server sends as it tears a session down
			// is never read, so Run can only ever report a plain link loss --
			// making AUTH_FAILED and NO_ROUTE unreachable, and leaving netifd to
			// redial a configuration that can never work.
			ReadReason: true,
			PPPDPath:   s.PPPDPath,
			PPPDArgs:   args,
			NoSpawn:    s.NoSpawn,
			Logger:     s.Logger,
			Counters:   s.Counters,
		}

		// The whole point of the exercise: pppd is handed the MTU the two ends
		// agreed on rather than the estimate this process made before it had a
		// connection to measure. Falling back to that estimate keeps a server that
		// reports nothing working exactly as it did.
		if s.MTUArgs != nil && !s.NoSpawn {
			base := args
			bridge.PPPDArgsFn = func() []string {
				linkMRU := sessionMRU
				if linkMRU <= 0 {
					linkMRU = s.FallbackMRU
				}
				return append(append([]string{}, base...), s.MTUArgs(pppbridge.ClampPPPMTU(linkMRU))...)
			}
		}

		start := time.Now()
		runErr := bridge.Run(context.Background(), dialFn)
		elapsed := time.Since(start)

		if s.NoSpawn {
			return runErr
		}

		// The link and the PPP session live and die together, so a restart here
		// rebuilds both: a fresh pppd and a fresh Hysteria2 connection. Nothing
		// is carried across, which is why there is no state to reconcile.
		if runErr != nil {
			s.Logger.Warn("PPP link down, rebuilding", zap.Error(runErr))
		} else {
			s.Logger.Info("PPP child exited, restarting")
		}

		if elapsed < resetThreshold {
			if backoff == 0 {
				backoff = minBackoff
			} else {
				backoff *= 2
				if backoff > maxBackoff {
					backoff = maxBackoff
				}
			}
			s.Logger.Warn("PPP child exited too quickly, backing off",
				zap.Duration("elapsed", elapsed),
				zap.Duration("backoff", backoff))
			time.Sleep(backoff)
		} else {
			backoff = 0
		}
	}
}

func addrToIP(addr net.Addr) net.IP {
	if addr == nil {
		return nil
	}
	if u, ok := addr.(*net.UDPAddr); ok {
		return u.IP
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return nil
	}
	return net.ParseIP(host)
}

func addrIP(addr net.Addr) string {
	if ip := addrToIP(addr); ip != nil {
		return ip.String()
	}
	return ""
}
