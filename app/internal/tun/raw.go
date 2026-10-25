package tun

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"runtime"
	"slices"
	"sync"

	stun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"
	"go.uber.org/zap"
)

const (
	defaultL3MTU = 1600
	vxlanPort    = 4789
)

// L3Conn is the QUIC side of a raw IP tunnel.
type L3Conn interface {
	Send(ipPkt []byte) error
	Receive() ([]byte, error)
}

// Raw is a TUN device that copies IP packets to and from an L3 connection.
// It does not terminate TCP or UDP.
type Raw struct {
	Name    string
	MTU     uint32
	Address netip.Prefix
	Peer    netip.Addr
	Logger  *zap.Logger
	// VXLANOnly writes only UDP to Address port 4789 into the TUN. Without it,
	// the peer can reach anything this host routes to once it forwards packets.
	VXLANOnly bool

	mu      sync.Mutex
	closed  bool
	done    chan struct{}
	closers []io.Closer
}

// NewRaw checks the tunnel addresses. The device itself is created in Serve.
func NewRaw(name string, mtu uint32, address netip.Prefix, peer netip.Addr) (*Raw, error) {
	supported := []string{"linux", "darwin", "windows", "android"}
	if !slices.Contains(supported, runtime.GOOS) {
		return nil, fmt.Errorf("L3 TUN is not supported on %s", runtime.GOOS)
	}
	if name == "" {
		return nil, errors.New("name is empty")
	}
	if !address.IsValid() || !address.Addr().IsValid() {
		return nil, errors.New("address is empty")
	}
	if !peer.IsValid() {
		return nil, errors.New("peer is empty")
	}
	if address.Addr().Is4() != peer.Is4() {
		return nil, errors.New("address and peer are different IP versions")
	}
	if mtu == 0 {
		mtu = defaultL3MTU
	}
	if mtu > defaultL3MTU {
		return nil, fmt.Errorf("mtu %d is above %d", mtu, defaultL3MTU)
	}
	return &Raw{Name: name, MTU: mtu, Address: address, Peer: peer, VXLANOnly: true}, nil
}

// Serve creates the TUN and copies packets until Close.
// Packets read from the tunnel are sent as-is. Packets received from conn
// are written only when their source address is the peer and, with VXLANOnly,
// they are VXLAN addressed to this end.
func (r *Raw) Serve(conn L3Conn) error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return net.ErrClosed
	}
	r.done = make(chan struct{})
	if err := r.open(); err != nil {
		_ = r.closeLocked()
		r.mu.Unlock()
		return err
	}
	dev := r.closers[len(r.closers)-1].(stun.Tun)
	done := r.done
	r.mu.Unlock()

	errCh := make(chan error, 2)
	go func() { errCh <- r.readLoop(dev, conn) }()
	go func() { errCh <- r.writeLoop(dev, conn) }()
	select {
	case err := <-errCh:
		_ = r.Close()
		return err
	case <-done:
		return nil
	}
}

// Close removes the TUN device and unblocks Serve.
func (r *Raw) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	return r.closeLocked()
}

func (r *Raw) closeLocked() error {
	r.closed = true
	var errs []error
	for _, c := range slices.Backward(r.closers) {
		errs = append(errs, c.Close())
	}
	r.closers = nil
	if r.done != nil {
		select {
		case <-r.done:
		default:
			close(r.done)
		}
	}
	return errors.Join(errs...)
}

func (r *Raw) open() error {
	logger := r.Logger
	if logger == nil {
		logger = zap.NewNop()
	}
	interfaceFinder := control.NewDefaultInterfaceFinder()
	networkMonitor, err := stun.NewNetworkUpdateMonitor(&singLogger{"l3tun-monitor", logger})
	if err != nil {
		return fmt.Errorf("failed to create network monitor: %w", err)
	}
	if err := networkMonitor.Start(); err != nil {
		return fmt.Errorf("failed to start network monitor: %w", err)
	}
	r.closers = append(r.closers, networkMonitor)
	interfaceMonitor, err := stun.NewDefaultInterfaceMonitor(networkMonitor, &singLogger{"l3tun-monitor", logger}, stun.DefaultInterfaceMonitorOptions{
		InterfaceFinder: interfaceFinder,
	})
	if err != nil {
		return fmt.Errorf("failed to create interface monitor: %w", err)
	}
	if err := interfaceMonitor.Start(); err != nil {
		return fmt.Errorf("failed to start interface monitor: %w", err)
	}
	r.closers = append(r.closers, interfaceMonitor)

	opts := stun.Options{
		Name:              r.Name,
		MTU:               r.MTU,
		GSO:               false,
		AutoRoute:         false,
		DNSMode:           stun.DNSModeDisabled,
		IPRoute2RuleIndex: stun.DefaultIPRoute2RuleIndex,
		InterfaceFinder:   interfaceFinder,
		InterfaceMonitor:  interfaceMonitor,
		Logger:            &singLogger{"l3tun", logger},
	}
	if r.Address.Addr().Is4() {
		opts.Inet4Address = []netip.Prefix{r.Address}
	} else if isIPv6Supported() {
		opts.Inet6Address = []netip.Prefix{r.Address}
	} else {
		return errors.New("IPv6 is not supported or enabled on this system")
	}
	dev, err := stun.New(opts)
	if err != nil {
		return fmt.Errorf("failed to create tun interface: %w", err)
	}
	r.closers = append(r.closers, dev)
	if err := dev.Start(); err != nil {
		return fmt.Errorf("failed to start tun interface: %w", err)
	}
	return nil
}

func (r *Raw) readLoop(dev stun.Tun, conn L3Conn) error {
	buf := make([]byte, int(r.MTU)+stun.PacketOffset)
	for {
		n, err := dev.Read(buf)
		if err != nil {
			if r.isClosed() {
				return nil
			}
			return err
		}
		if n <= stun.PacketOffset {
			continue
		}
		ip := buf[stun.PacketOffset:n]
		if len(ip) > int(r.MTU) {
			continue
		}
		pkt := append([]byte(nil), ip...)
		if err := conn.Send(pkt); err != nil {
			if r.isClosed() {
				return nil
			}
			return err
		}
	}
}

func (r *Raw) writeLoop(dev stun.Tun, conn L3Conn) error {
	for {
		pkt, err := conn.Receive()
		if err != nil {
			if r.isClosed() {
				return nil
			}
			return err
		}
		if len(pkt) > int(r.MTU) || !r.accepts(pkt) {
			continue
		}
		if err := writeIP(dev, pkt); err != nil {
			// A failed write must not stall the QUIC reader. Drop the packet.
			if r.isClosed() || errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) {
				return nil
			}
			if r.Logger != nil {
				r.Logger.Debug("L3 TUN write dropped packet", zap.Error(err))
			}
			continue
		}
	}
}

func (r *Raw) isClosed() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.closed
}

func (r *Raw) accepts(pkt []byte) bool {
	src, ok := packetSource(pkt)
	if !ok || src != r.Peer {
		return false
	}
	return !r.VXLANOnly || isVXLANTo(pkt, r.Address.Addr())
}

// isVXLANTo reports whether pkt is UDP to dst port 4789. A later IPv4 fragment
// has no UDP header; it passes on the address and protocol, and the kernel
// drops it unless the first fragment, which carries the port, arrived too.
// IPv6 extension headers are not followed, so an IPv6 fragment is refused.
func isVXLANTo(pkt []byte, dst netip.Addr) bool {
	switch pkt[0] >> 4 {
	case 4:
		ihl := int(pkt[0]&0x0f) * 4
		if len(pkt) < 20 || ihl < 20 || len(pkt) < ihl || pkt[9] != 17 {
			return false
		}
		if netip.AddrFrom4(([4]byte)(pkt[16:20])) != dst {
			return false
		}
		if binary.BigEndian.Uint16(pkt[6:8])&0x1fff != 0 {
			return true
		}
		return len(pkt) >= ihl+8 && binary.BigEndian.Uint16(pkt[ihl+2:ihl+4]) == vxlanPort
	case 6:
		if len(pkt) < 40+8 || pkt[6] != 17 {
			return false
		}
		if netip.AddrFrom16(([16]byte)(pkt[24:40])) != dst {
			return false
		}
		return binary.BigEndian.Uint16(pkt[42:44]) == vxlanPort
	default:
		return false
	}
}

func writeIP(dev stun.Tun, ip []byte) error {
	if stun.PacketOffset == 0 {
		_, err := dev.Write(ip)
		return err
	}
	buf := make([]byte, stun.PacketOffset+len(ip))
	stun.PacketFillHeader(buf[:stun.PacketOffset], int(ip[0]>>4))
	copy(buf[stun.PacketOffset:], ip)
	_, err := dev.Write(buf)
	return err
}

func packetSource(pkt []byte) (netip.Addr, bool) {
	if len(pkt) < 1 {
		return netip.Addr{}, false
	}
	switch pkt[0] >> 4 {
	case 4:
		if len(pkt) < 20 {
			return netip.Addr{}, false
		}
		ihl := int(pkt[0]&0x0f) * 4
		if ihl < 20 || len(pkt) < ihl {
			return netip.Addr{}, false
		}
		return netip.AddrFrom4(([4]byte)(pkt[12:16])), true
	case 6:
		if len(pkt) < 40 {
			return netip.Addr{}, false
		}
		return netip.AddrFrom16(([16]byte)(pkt[8:24])), true
	default:
		return netip.Addr{}, false
	}
}
