package tun

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"

	tun "github.com/apernet/sing-tun"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/network"
	"go.uber.org/zap"

	"github.com/apernet/hysteria/core/v2/client"
)

type Server struct {
	HyClient    client.Client
	EventLogger EventLogger

	// for debugging
	Logger *zap.Logger

	IfName  string
	MTU     uint32
	Timeout int64 // in seconds, also applied to TCP in system stack

	// required by system stack
	Inet4Address []netip.Prefix
	Inet6Address []netip.Prefix

	// auto route
	AutoRoute                bool
	StructRoute              bool
	Inet4RouteAddress        []netip.Prefix
	Inet6RouteAddress        []netip.Prefix
	Inet4RouteExcludeAddress []netip.Prefix
	Inet6RouteExcludeAddress []netip.Prefix
}

type EventLogger interface {
	TCPRequest(addr, reqAddr string)
	TCPError(addr, reqAddr string, err error)
	UDPRequest(addr string)
	UDPError(addr string, err error)
}

func (s *Server) Serve(ctx context.Context) error {
	if !isIPv6Supported() {
		s.Logger.Warn("tun-pre-check", zap.String("msg", "IPv6 is not supported or enabled on this system, TUN device is created without IPv6 support."))
		s.Inet6Address = nil
	}
	tunOpts := tun.Options{
		Name:                     s.IfName,
		Inet4Address:             s.Inet4Address,
		Inet6Address:             s.Inet6Address,
		MTU:                      s.MTU,
		GSO:                      true,
		AutoRoute:                s.AutoRoute,
		StrictRoute:              s.StructRoute,
		Inet4RouteAddress:        s.Inet4RouteAddress,
		Inet6RouteAddress:        s.Inet6RouteAddress,
		Inet4RouteExcludeAddress: s.Inet4RouteExcludeAddress,
		Inet6RouteExcludeAddress: s.Inet6RouteExcludeAddress,
		Logger: &singLogger{
			tag:       "tun",
			zapLogger: s.Logger,
		},
	}
	tunIf, err := tun.New(tunOpts)
	if err != nil {
		return fmt.Errorf("failed to create tun interface: %w", err)
	}
	var closeTunOnce sync.Once

	closeTun := func() {
		closeTunOnce.Do(func() {
			_ = tunIf.Close()
		})
	}
	defer closeTun()
	tunStack, err := tun.NewSystem(tun.StackOptions{
		Context:    ctx,
		Tun:        tunIf,
		TunOptions: tunOpts,
		UDPTimeout: s.Timeout,
		Handler: &tunHandler{
			Server:      s,
			shutdownCtx: ctx,
		},
		Logger: &singLogger{
			tag:       "tun-stack",
			zapLogger: s.Logger,
		},
		ForwarderBindInterface: true,
		InterfaceFinder:        &interfaceFinder{},
	})
	if err != nil {
		return fmt.Errorf("failed to create tun stack: %w", err)
	}
	defer tunStack.Close()

	stopClose := context.AfterFunc(ctx, closeTun)
	defer stopClose()
	err = tunStack.(tun.StackRunner).Run()
	if ctx.Err() != nil {
		return nil
	}

	return err
}

type tunHandler struct {
	*Server
	shutdownCtx context.Context
}

func (t *tunHandler) isShutdownCancellation(err error) bool {
	return errors.Is(err, context.Canceled) &&
		errors.Is(t.shutdownCtx.Err(), context.Canceled)
}

var _ tun.Handler = (*tunHandler)(nil)

func (t *tunHandler) NewConnection(ctx context.Context, conn net.Conn, m metadata.Metadata) error {
	addr := m.Source.String()
	reqAddr := m.Destination.String()
	if t.EventLogger != nil {
		t.EventLogger.TCPRequest(addr, reqAddr)
	}
	var closeErr error
	defer func() {
		if t.EventLogger != nil && !t.isShutdownCancellation(closeErr) {
			t.EventLogger.TCPError(addr, reqAddr, closeErr)
		}
	}()

	rc, err := t.HyClient.TCP(reqAddr)
	if err != nil {
		closeErr = err
		// the returned err is ignored by caller
		return nil
	}
	defer rc.Close()

	// start forwarding
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
	case <-ctx.Done():
		closeErr = ctx.Err()
	case closeErr = <-copyErrChan:
	}
	return nil
}

func (t *tunHandler) NewPacketConnection(ctx context.Context, conn network.PacketConn, m metadata.Metadata) error {
	addr := m.Source.String()
	if t.EventLogger != nil {
		t.EventLogger.UDPRequest(addr)
	}
	var closeErr error
	defer func() {
		if t.EventLogger != nil && !t.isShutdownCancellation(closeErr) {
			t.EventLogger.UDPError(addr, closeErr)
		}
	}()

	rc, err := t.HyClient.UDP()
	if err != nil {
		closeErr = err
		// the returned err is simply called into NewError again
		return nil
	}
	defer rc.Close()

	// start forwarding
	copyErrChan := make(chan error, 2)
	// local <- remote
	go func() {
		for {
			bs, from, err := rc.Receive()
			if err != nil {
				copyErrChan <- err
				return
			}
			var fromAddr metadata.Socksaddr
			if ap, perr := netip.ParseAddrPort(from); perr == nil {
				fromAddr = metadata.SocksaddrFromNetIP(ap)
			} else {
				fromAddr.Fqdn = from
			}
			err = conn.WritePacket(buf.As(bs), fromAddr)
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
			addr, err := conn.ReadPacket(buffer)
			if err != nil {
				copyErrChan <- err
				return
			}
			err = rc.Send(buffer.Bytes(), addr.String())
			if err != nil {
				copyErrChan <- err
				return
			}
		}
	}()
	select {
	case <-ctx.Done():
		closeErr = ctx.Err()
	case closeErr = <-copyErrChan:
	}
	return nil
}

func (t *tunHandler) NewError(ctx context.Context, err error) {
	// unused
}

type interfaceFinder struct{}

var _ control.InterfaceFinder = (*interfaceFinder)(nil)

func (f *interfaceFinder) InterfaceIndexByName(name string) (int, error) {
	ifce, err := net.InterfaceByName(name)
	if err != nil {
		return -1, err
	}
	return ifce.Index, nil
}

func (f *interfaceFinder) InterfaceNameByIndex(index int) (string, error) {
	ifce, err := net.InterfaceByIndex(index)
	if err != nil {
		return "", err
	}
	return ifce.Name, nil
}
