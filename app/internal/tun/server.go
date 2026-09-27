package tun

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/control"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"go.uber.org/zap"

	"github.com/apernet/hysteria/core/v2/client"
)

// Server captures TCP and UDP traffic from a TUN interface with sing-tun's
// "system" stack and forwards it through HyClient.
type Server struct {
	HyClient    client.Client
	EventLogger EventLogger

	// for debugging
	Logger *zap.Logger

	IfName string
	MTU    uint32
	// Timeout is the idle timeout of UDP sessions. The system stack also
	// uses it for its TCP NAT entries. Must be positive.
	Timeout time.Duration

	// The system stack uses the next address of the first prefix in each
	// family, so the prefixes must hold at least two addresses.
	Inet4Address []netip.Prefix
	Inet6Address []netip.Prefix

	// auto route
	AutoRoute                bool
	StrictRoute              bool
	Inet4RouteAddress        []netip.Prefix
	Inet6RouteAddress        []netip.Prefix
	Inet4RouteExcludeAddress []netip.Prefix
	Inet6RouteExcludeAddress []netip.Prefix

	mu      sync.Mutex
	closed  bool
	done    chan struct{}
	closers []io.Closer // closed in reverse order
}

type EventLogger interface {
	TCPRequest(addr, reqAddr string)
	TCPError(addr, reqAddr string, err error)
	UDPRequest(addr string)
	UDPError(addr string, err error)
}

// Serve sets up the TUN interface (and its routes, if AutoRoute is set),
// then forwards traffic until Close is called.
func (s *Server) Serve() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return net.ErrClosed
	}
	s.done = make(chan struct{})
	if err := s.start(); err != nil {
		_ = s.closeLocked()
		s.mu.Unlock()
		return err
	}
	done := s.done
	s.mu.Unlock()
	<-done
	return nil
}

// Close removes the TUN interface along with the routes and rules it added,
// and aborts the connections it is forwarding.
func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	return s.closeLocked()
}

func (s *Server) closeLocked() error {
	s.closed = true
	var errs []error
	for _, c := range slices.Backward(s.closers) {
		errs = append(errs, c.Close())
	}
	s.closers = nil
	if s.done != nil {
		close(s.done)
	}
	return errors.Join(errs...)
}

func (s *Server) start() error {
	logger := s.Logger
	if logger == nil {
		logger = zap.NewNop()
	}
	inet6Address := s.Inet6Address
	if !isIPv6Supported() {
		logger.Warn("IPv6 is not supported or enabled on this system, TUN device is created without IPv6 support")
		inet6Address = nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	s.closers = append(s.closers, closerFunc(func() error {
		cancel()
		return nil
	}))

	// sing-tun needs the interface monitor on every platform that has a TUN
	// implementation: it registers the TUN interface with it, and on Android
	// it re-applies the rules when the default interface changes.
	interfaceFinder := control.NewDefaultInterfaceFinder()
	networkMonitor, err := tun.NewNetworkUpdateMonitor(&singLogger{"tun-monitor", logger})
	if err != nil {
		return fmt.Errorf("failed to create network monitor: %w", err)
	}
	if err := networkMonitor.Start(); err != nil {
		return fmt.Errorf("failed to start network monitor: %w", err)
	}
	s.closers = append(s.closers, networkMonitor)
	interfaceMonitor, err := tun.NewDefaultInterfaceMonitor(networkMonitor, &singLogger{"tun-monitor", logger}, tun.DefaultInterfaceMonitorOptions{
		InterfaceFinder: interfaceFinder,
	})
	if err != nil {
		return fmt.Errorf("failed to create interface monitor: %w", err)
	}
	if err := interfaceMonitor.Start(); err != nil {
		return fmt.Errorf("failed to start interface monitor: %w", err)
	}
	s.closers = append(s.closers, interfaceMonitor)

	tunOpts := tun.Options{
		Name:         s.IfName,
		Inet4Address: s.Inet4Address,
		Inet6Address: inet6Address,
		MTU:          s.MTU,
		GSO:          true,
		AutoRoute:    s.AutoRoute,
		// Leave the system DNS configuration alone: the default would point
		// it to the TUN's own next address, which nothing answers.
		DNSMode: tun.DNSModeDisabled,
		// sing-tun owns the rule priorities [9000, 9010] and flushes the
		// whole range on setup and teardown, so this must never be 0.
		IPRoute2RuleIndex:        tun.DefaultIPRoute2RuleIndex,
		StrictRoute:              s.StrictRoute,
		Inet4RouteAddress:        s.Inet4RouteAddress,
		Inet6RouteAddress:        s.Inet6RouteAddress,
		Inet4RouteExcludeAddress: s.Inet4RouteExcludeAddress,
		Inet6RouteExcludeAddress: s.Inet6RouteExcludeAddress,
		InterfaceFinder:          interfaceFinder,
		InterfaceMonitor:         interfaceMonitor,
		Logger:                   &singLogger{"tun", logger},
	}
	tunIf, err := tun.New(tunOpts)
	if err != nil {
		return fmt.Errorf("failed to create tun interface: %w", err)
	}
	s.closers = append(s.closers, tunIf)

	tunStack, err := tun.NewSystem(tun.StackOptions{
		Context:                ctx,
		Tun:                    tunIf,
		TunOptions:             tunOpts,
		UDPTimeout:             s.Timeout,
		Handler:                &tunHandler{s},
		Logger:                 &singLogger{"tun-stack", logger},
		ForwarderBindInterface: true,
		InterfaceFinder:        interfaceFinder,
	})
	if err != nil {
		return fmt.Errorf("failed to create tun stack: %w", err)
	}
	s.closers = append(s.closers, tunStack)
	// The stack must be listening before the interface comes up.
	if err := tunStack.Start(); err != nil {
		return fmt.Errorf("failed to start tun stack: %w", err)
	}
	if err := tunIf.Start(); err != nil {
		return fmt.Errorf("failed to start tun interface: %w", err)
	}
	return nil
}

type closerFunc func() error

func (f closerFunc) Close() error {
	return f()
}

type tunHandler struct {
	*Server
}

var _ tun.Handler = (*tunHandler)(nil)

// JudgeFlow lets every flow through to the system stack, which hands TCP and
// UDP to the methods below and answers ICMP echo requests itself.
func (t *tunHandler) JudgeFlow(network uint8, source, destination netip.AddrPort, firstPacket []byte) tun.FlowVerdict {
	return tun.FlowVerdict{Action: tun.ActionAccept}
}

// NewDNSPacket is only called for flows judged as tun.ActionHijackDNS,
// which JudgeFlow never returns.
func (t *tunHandler) NewDNSPacket(payload []byte, source, destination M.Socksaddr, writer N.PacketWriter) {
}

func (t *tunHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	addr := source.String()
	reqAddr := destination.String()
	if t.EventLogger != nil {
		t.EventLogger.TCPRequest(addr, reqAddr)
	}
	err := t.forwardTCP(ctx, conn, reqAddr)
	if onClose != nil {
		onClose(err)
	}
	if t.EventLogger != nil {
		t.EventLogger.TCPError(addr, reqAddr, err)
	}
}

func (t *tunHandler) forwardTCP(ctx context.Context, conn net.Conn, reqAddr string) error {
	defer conn.Close()
	rc, err := t.HyClient.TCP(reqAddr)
	if err != nil {
		return err
	}
	defer rc.Close()

	copyErrChan := make(chan error, 2)
	go func() {
		_, copyErr := io.Copy(rc, conn)
		copyErrChan <- copyErr
	}()
	go func() {
		_, copyErr := io.Copy(conn, rc)
		copyErrChan <- copyErr
	}()
	select {
	case err = <-copyErrChan:
		return err
	case <-ctx.Done():
		// Server closed
		return nil
	}
}

func (t *tunHandler) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	addr := source.String()
	if t.EventLogger != nil {
		t.EventLogger.UDPRequest(addr)
	}
	err := t.forwardUDP(ctx, conn)
	if onClose != nil {
		onClose(err)
	}
	if t.EventLogger != nil {
		t.EventLogger.UDPError(addr, err)
	}
}

func (t *tunHandler) forwardUDP(ctx context.Context, conn N.PacketConn) error {
	defer conn.Close()
	rc, err := t.HyClient.UDP()
	if err != nil {
		return err
	}
	defer rc.Close()

	copyErrChan := make(chan error, 2)
	// local <- remote
	go func() {
		for {
			bs, from, err := rc.Receive()
			if err != nil {
				copyErrChan <- err
				return
			}
			fromAddr, err := netip.ParseAddrPort(from)
			if err != nil {
				// A packet written to the TUN needs an IP source address.
				continue
			}
			err = conn.WritePacket(buf.As(bs), M.SocksaddrFromNetIP(fromAddr))
			if err != nil {
				copyErrChan <- err
				return
			}
		}
	}()
	// local -> remote
	go func() {
		buffer := buf.NewPacket()
		defer buffer.Release()

		for {
			buffer.Reset()
			reqAddr, err := conn.ReadPacket(buffer)
			if err != nil {
				if errors.Is(err, io.ErrClosedPipe) {
					// The stack closed the session after Timeout without traffic
					err = nil
				}
				copyErrChan <- err
				return
			}
			err = rc.Send(buffer.Bytes(), reqAddr.String())
			if err != nil {
				copyErrChan <- err
				return
			}
		}
	}()
	select {
	case err = <-copyErrChan:
		return err
	case <-ctx.Done():
		// Server closed
		return nil
	}
}
