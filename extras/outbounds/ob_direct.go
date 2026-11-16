package outbounds

import (
	"errors"
	"net"
	"net/netip"
	"strconv"
	"sync/atomic"
	"time"
)

type DirectOutboundMode int

type udpConnState int

const (
	DirectOutboundModeAuto DirectOutboundMode = iota // Dual-stack "happy eyeballs"-like mode
	DirectOutboundMode64                             // Use IPv6 address when available, otherwise IPv4
	DirectOutboundMode46                             // Use IPv4 address when available, otherwise IPv6
	DirectOutboundMode6                              // Use IPv6 only, fail if not available
	DirectOutboundMode4                              // Use IPv4 only, fail if not available

	defaultDialerTimeout = 10 * time.Second
)

const (
	udpConnStateDualStack udpConnState = iota
	udpConnStateIPv4
	udpConnStateIPv6
)

// directOutbound is a PluggableOutbound that connects directly to the target
// using the local network (as opposed to using a proxy, for example).
// It prefers to use ResolveInfo in AddrEx if available. But if it's nil,
// it will fall back to resolving Host using Go's built-in DNS resolver.
type directOutbound struct {
	Mode DirectOutboundMode

	// Dialer4 and Dialer6 are used for IPv4 and IPv6 TCP connections respectively.
	DialFunc4 func(network, address string) (net.Conn, error)
	DialFunc6 func(network, address string) (net.Conn, error)

	// DeviceName & BindIPs are for UDP connections. They don't use dialers, so we
	// need to bind them when creating the connection.
	DeviceName string
	BindIP4    net.IP
	BindIP6    net.IP
}

type DirectOutboundOptions struct {
	Mode DirectOutboundMode

	DeviceName string
	BindIP4    net.IP
	BindIP6    net.IP

	FastOpen bool
}

type noAddressError struct {
	IPv4 bool
	IPv6 bool
}

func (e noAddressError) Error() string {
	if e.IPv4 && e.IPv6 {
		return "no IPv4 or IPv6 address available"
	} else if e.IPv4 {
		return "no IPv4 address available"
	} else if e.IPv6 {
		return "no IPv6 address available"
	} else {
		return "no address available"
	}
}

type invalidOutboundModeError struct{}

func (e invalidOutboundModeError) Error() string {
	return "invalid outbound mode"
}

type resolveError struct {
	Err error
}

func (e resolveError) Error() string {
	if e.Err == nil {
		return "resolve error"
	} else {
		return "resolve error: " + e.Err.Error()
	}
}

func (e resolveError) Unwrap() error {
	return e.Err
}

func NewDirectOutboundWithOptions(opts DirectOutboundOptions) (PluggableOutbound, error) {
	dialer4 := &net.Dialer{
		Timeout: defaultDialerTimeout,
	}
	if opts.BindIP4 != nil {
		if opts.BindIP4.To4() == nil {
			return nil, errors.New("BindIP4 must be an IPv4 address")
		}
		dialer4.LocalAddr = &net.TCPAddr{
			IP: opts.BindIP4,
		}
	}
	dialer6 := &net.Dialer{
		Timeout: defaultDialerTimeout,
	}
	if opts.BindIP6 != nil {
		if opts.BindIP6.To4() != nil {
			return nil, errors.New("BindIP6 must be an IPv6 address")
		}
		dialer6.LocalAddr = &net.TCPAddr{
			IP: opts.BindIP6,
		}
	}
	if opts.DeviceName != "" {
		err := dialerBindToDevice(dialer4, opts.DeviceName)
		if err != nil {
			return nil, err
		}
		err = dialerBindToDevice(dialer6, opts.DeviceName)
		if err != nil {
			return nil, err
		}
	}

	dialFunc4 := dialer4.Dial
	dialFunc6 := dialer6.Dial
	if opts.FastOpen {
		dialFunc4 = newFastOpenDialer(dialer4).Dial
		dialFunc6 = newFastOpenDialer(dialer6).Dial
	}

	return &directOutbound{
		Mode:       opts.Mode,
		DialFunc4:  dialFunc4,
		DialFunc6:  dialFunc6,
		DeviceName: opts.DeviceName,
		BindIP4:    opts.BindIP4,
		BindIP6:    opts.BindIP6,
	}, nil
}

// NewDirectOutboundSimple creates a new directOutbound with the given mode,
// without binding to a specific device. Works on all platforms.
func NewDirectOutboundSimple(mode DirectOutboundMode) PluggableOutbound {
	d := &net.Dialer{
		Timeout: defaultDialerTimeout,
	}
	return &directOutbound{
		Mode:      mode,
		DialFunc4: d.Dial,
		DialFunc6: d.Dial,
	}
}

// NewDirectOutboundBindToIPs creates a new directOutbound with the given mode,
// and binds to the given IPv4 and IPv6 addresses. Either or both of the addresses
// can be nil, in which case the directOutbound will not bind to a specific address
// for that family.
func NewDirectOutboundBindToIPs(mode DirectOutboundMode, bindIP4, bindIP6 net.IP) (PluggableOutbound, error) {
	return NewDirectOutboundWithOptions(DirectOutboundOptions{
		Mode:    mode,
		BindIP4: bindIP4,
		BindIP6: bindIP6,
	})
}

// NewDirectOutboundBindToDevice creates a new directOutbound with the given mode,
// and binds to the given device. Only works on Linux.
func NewDirectOutboundBindToDevice(mode DirectOutboundMode, deviceName string) (PluggableOutbound, error) {
	return NewDirectOutboundWithOptions(DirectOutboundOptions{
		Mode:       mode,
		DeviceName: deviceName,
	})
}

// resolve is our built-in DNS resolver for handling the case when
// AddrEx.ResolveInfo is nil.
func (d *directOutbound) resolve(reqAddr *AddrEx) {
	ips, err := net.LookupIP(reqAddr.Host)
	if err != nil {
		reqAddr.ResolveInfo = &ResolveInfo{Err: err}
		return
	}
	r := &ResolveInfo{}
	r.IPv4, r.IPv6 = splitIPv4IPv6(ips)
	if r.IPv4 == nil && r.IPv6 == nil {
		r.Err = noAddressError{IPv4: true, IPv6: true}
	}
	reqAddr.ResolveInfo = r
}

func (d *directOutbound) TCP(reqAddr *AddrEx) (net.Conn, error) {
	if reqAddr.ResolveInfo == nil {
		// AddrEx.ResolveInfo is nil (no resolver in the pipeline),
		// we need to resolve the address ourselves.
		d.resolve(reqAddr)
	}
	r := reqAddr.ResolveInfo
	if r.IPv4 == nil && r.IPv6 == nil {
		// ResolveInfo not nil but no address available,
		// this can only mean that the resolver failed.
		// Return the error from the resolver.
		return nil, resolveError{Err: r.Err}
	}
	switch d.Mode {
	case DirectOutboundModeAuto:
		if r.IPv4 != nil && r.IPv6 != nil {
			return d.dualStackDialTCP(r.IPv4, r.IPv6, reqAddr.Port)
		} else if r.IPv4 != nil {
			return d.dialTCP(r.IPv4, reqAddr.Port)
		} else {
			return d.dialTCP(r.IPv6, reqAddr.Port)
		}
	case DirectOutboundMode64:
		if r.IPv6 != nil {
			return d.dialTCP(r.IPv6, reqAddr.Port)
		} else {
			return d.dialTCP(r.IPv4, reqAddr.Port)
		}
	case DirectOutboundMode46:
		if r.IPv4 != nil {
			return d.dialTCP(r.IPv4, reqAddr.Port)
		} else {
			return d.dialTCP(r.IPv6, reqAddr.Port)
		}
	case DirectOutboundMode6:
		if r.IPv6 != nil {
			return d.dialTCP(r.IPv6, reqAddr.Port)
		} else {
			return nil, noAddressError{IPv6: true}
		}
	case DirectOutboundMode4:
		if r.IPv4 != nil {
			return d.dialTCP(r.IPv4, reqAddr.Port)
		} else {
			return nil, noAddressError{IPv4: true}
		}
	default:
		return nil, invalidOutboundModeError{}
	}
}

func (d *directOutbound) dialTCP(ip net.IP, port uint16) (net.Conn, error) {
	if ip.To4() != nil {
		return d.DialFunc4("tcp4", net.JoinHostPort(ip.String(), strconv.Itoa(int(port))))
	} else {
		return d.DialFunc6("tcp6", net.JoinHostPort(ip.String(), strconv.Itoa(int(port))))
	}
}

type dialResult struct {
	Conn net.Conn
	Err  error
}

// dualStackDialTCP dials the target using both IPv4 and IPv6 addresses simultaneously.
// It returns the first successful connection and drops the other one.
// If both connections fail, it returns the last error.
func (d *directOutbound) dualStackDialTCP(ipv4, ipv6 net.IP, port uint16) (net.Conn, error) {
	ch := make(chan dialResult, 2)
	go func() {
		conn, err := d.dialTCP(ipv4, port)
		ch <- dialResult{Conn: conn, Err: err}
	}()
	go func() {
		conn, err := d.dialTCP(ipv6, port)
		ch <- dialResult{Conn: conn, Err: err}
	}()
	// Get the first result, check if it's successful
	if r := <-ch; r.Err == nil {
		// Yes. Return this and close the other connection when it's done
		go func() {
			r2 := <-ch
			if r2.Conn != nil {
				_ = r2.Conn.Close()
			}
		}()
		return r.Conn, nil
	} else {
		// No. Return the other result, which may or may not be successful
		r2 := <-ch
		return r2.Conn, r2.Err
	}
}

type directOutboundUDPConn struct {
	*directOutbound
	*net.UDPConn
	State udpConnState

	// The last address converted in each direction, as it rarely changes between packets
	lastRead  atomic.Pointer[directOutboundUDPRead]
	lastWrite atomic.Pointer[directOutboundUDPWrite]
}

type directOutboundUDPRead struct {
	AddrPort netip.AddrPort
	Host     string
}

type directOutboundUDPWrite struct {
	Host     string
	Port     uint16
	AddrPort netip.AddrPort
}

func (u *directOutboundUDPConn) ReadFrom(b []byte) (int, *AddrEx, error) {
	n, addrPort, err := u.UDPConn.ReadFromUDPAddrPort(b)
	if !addrPort.IsValid() {
		return n, nil, err
	}
	last := u.lastRead.Load()
	if last == nil || last.AddrPort != addrPort {
		last = &directOutboundUDPRead{
			AddrPort: addrPort,
			// Same string as net.IP.String()
			Host: addrPort.Addr().Unmap().WithZone("").String(),
		}
		u.lastRead.Store(last)
	}
	return n, &AddrEx{
		Host: last.Host,
		Port: addrPort.Port(),
	}, err
}

func (u *directOutboundUDPConn) WriteTo(b []byte, addr *AddrEx) (int, error) {
	// Only IP literals are cached, host names are resolved every time
	isLiteral := false
	if addr.ResolveInfo == nil {
		last := u.lastWrite.Load()
		if last != nil && last.Host == addr.Host && last.Port == addr.Port {
			return u.UDPConn.WriteToUDPAddrPort(b, last.AddrPort)
		}
		isLiteral = tryParseIP(addr)
		if !isLiteral {
			u.directOutbound.resolve(addr)
		}
	}
	ip, err := u.selectIP(addr.ResolveInfo)
	if err != nil {
		return 0, err
	}
	addrPort := netip.AddrPortFrom(ipToNetipAddr(ip), addr.Port)
	if isLiteral {
		u.lastWrite.Store(&directOutboundUDPWrite{
			Host:     addr.Host,
			Port:     addr.Port,
			AddrPort: addrPort,
		})
	}
	return u.UDPConn.WriteToUDPAddrPort(b, addrPort)
}

// selectIP picks the resolved IP to send to, based on the socket's address family and the outbound mode.
func (u *directOutboundUDPConn) selectIP(r *ResolveInfo) (net.IP, error) {
	if r.IPv4 == nil && r.IPv6 == nil {
		return nil, resolveError{Err: r.Err}
	}
	if u.State == udpConnStateIPv4 {
		if r.IPv4 != nil {
			return r.IPv4, nil
		} else {
			return nil, noAddressError{IPv4: true}
		}
	} else if u.State == udpConnStateIPv6 {
		if r.IPv6 != nil {
			return r.IPv6, nil
		} else {
			return nil, noAddressError{IPv6: true}
		}
	} else {
		// Dual stack
		switch u.directOutbound.Mode {
		case DirectOutboundModeAuto:
			// This is a special case.
			// We must make a decision here, so we prefer IPv4 for maximum compatibility.
			if r.IPv4 != nil {
				return r.IPv4, nil
			} else {
				return r.IPv6, nil
			}
		case DirectOutboundMode64:
			if r.IPv6 != nil {
				return r.IPv6, nil
			} else {
				return r.IPv4, nil
			}
		case DirectOutboundMode46:
			if r.IPv4 != nil {
				return r.IPv4, nil
			} else {
				return r.IPv6, nil
			}
		case DirectOutboundMode6:
			if r.IPv6 != nil {
				return r.IPv6, nil
			} else {
				return nil, noAddressError{IPv6: true}
			}
		case DirectOutboundMode4:
			if r.IPv4 != nil {
				return r.IPv4, nil
			} else {
				return nil, noAddressError{IPv4: true}
			}
		default:
			return nil, invalidOutboundModeError{}
		}
	}
}

func ipToNetipAddr(ip net.IP) netip.Addr {
	if ip4 := ip.To4(); ip4 != nil {
		return netip.AddrFrom4([4]byte(ip4))
	}
	addr, _ := netip.AddrFromSlice(ip)
	return addr
}

func (u *directOutboundUDPConn) Close() error {
	return u.UDPConn.Close()
}

func (d *directOutbound) CheckUDP(reqAddr *AddrEx) error {
	return nil
}

func (d *directOutbound) UDP(reqAddr *AddrEx) (UDPConn, error) {
	if d.BindIP4 == nil && d.BindIP6 == nil {
		// No bind address specified, use default dual stack implementation
		c, err := net.ListenUDP("udp", nil)
		if err != nil {
			return nil, err
		}
		if d.DeviceName != "" {
			if err := udpConnBindToDevice(c, d.DeviceName); err != nil {
				// Don't forget to close the UDPConn if binding fails
				_ = c.Close()
				return nil, err
			}
		}
		return &directOutboundUDPConn{
			directOutbound: d,
			UDPConn:        c,
			State:          udpConnStateDualStack,
		}, nil
	} else {
		// Bind address specified,
		// need to check what kind of address is in reqAddr
		// to determine which address family to bind to
		if reqAddr.ResolveInfo == nil {
			d.resolve(reqAddr)
		}
		r := reqAddr.ResolveInfo
		if r.IPv4 == nil && r.IPv6 == nil {
			return nil, resolveError{Err: r.Err}
		}
		var bindIP net.IP      // can be nil, in which case we still lock the address family but don't bind to any address
		var state udpConnState // either IPv4 or IPv6
		switch d.Mode {
		case DirectOutboundModeAuto:
			// This is a special case.
			// We must make a decision here, so we prefer IPv4 for maximum compatibility.
			if r.IPv4 != nil {
				bindIP = d.BindIP4
				state = udpConnStateIPv4
			} else {
				bindIP = d.BindIP6
				state = udpConnStateIPv6
			}
		case DirectOutboundMode64:
			if r.IPv6 != nil {
				bindIP = d.BindIP6
				state = udpConnStateIPv6
			} else {
				bindIP = d.BindIP4
				state = udpConnStateIPv4
			}
		case DirectOutboundMode46:
			if r.IPv4 != nil {
				bindIP = d.BindIP4
				state = udpConnStateIPv4
			} else {
				bindIP = d.BindIP6
				state = udpConnStateIPv6
			}
		case DirectOutboundMode6:
			if r.IPv6 != nil {
				bindIP = d.BindIP6
				state = udpConnStateIPv6
			} else {
				return nil, noAddressError{IPv6: true}
			}
		case DirectOutboundMode4:
			if r.IPv4 != nil {
				bindIP = d.BindIP4
				state = udpConnStateIPv4
			} else {
				return nil, noAddressError{IPv4: true}
			}
		default:
			return nil, invalidOutboundModeError{}
		}
		var network string
		var c *net.UDPConn
		var err error
		if state == udpConnStateIPv4 {
			network = "udp4"
		} else {
			network = "udp6"
		}
		if bindIP != nil {
			c, err = net.ListenUDP(network, &net.UDPAddr{
				IP: bindIP,
			})
		} else {
			c, err = net.ListenUDP(network, nil)
		}
		if err != nil {
			return nil, err
		}
		// We don't support binding to both device & address at the same time,
		// so d.DeviceName is ignored in this case.
		return &directOutboundUDPConn{
			directOutbound: d,
			UDPConn:        c,
			State:          state,
		}, nil
	}
}
