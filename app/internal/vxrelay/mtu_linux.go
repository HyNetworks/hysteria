//go:build linux

package vxrelay

import (
	"errors"
	"net"

	"golang.org/x/sys/unix"
)

// allowFragmentation lets the kernel fragment a VXLAN datagram that does not
// fit the LAN MTU. The default discovery setting sets DF and then returns
// EMSGSIZE instead of sending the packet.
func allowFragmentation(conn *net.UDPConn) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var sockErr error
	ctrlErr := raw.Control(func(fd uintptr) {
		sockErr = errors.Join(
			setOptional(int(fd), unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DONT),
			setOptional(int(fd), unix.IPPROTO_IPV6, unix.IPV6_MTU_DISCOVER, unix.IPV6_PMTUDISC_DONT),
		)
	})
	return errors.Join(ctrlErr, sockErr)
}

func setOptional(fd, proto, opt, value int) error {
	err := unix.SetsockoptInt(fd, proto, opt, value)
	if err == nil || errors.Is(err, unix.ENOPROTOOPT) || errors.Is(err, unix.EINVAL) || errors.Is(err, unix.EOPNOTSUPP) {
		return nil
	}
	return err
}

// growBuffers raises the socket buffers so a burst from a VTEP, which a fast
// LAN or cloud network delivers at line rate, is queued instead of dropped
// while the relay is busy. SO_*BUFFORCE ignores net.core.rmem_max and needs
// CAP_NET_ADMIN; without it the plain option is capped by the sysctl.
func growBuffers(conn *net.UDPConn, size int) {
	raw, err := conn.SyscallConn()
	if err == nil {
		var rerr, werr error
		_ = raw.Control(func(fd uintptr) {
			rerr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, size)
			werr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUFFORCE, size)
		})
		if rerr == nil && werr == nil {
			return
		}
	}
	_ = conn.SetReadBuffer(size)
	_ = conn.SetWriteBuffer(size)
}
