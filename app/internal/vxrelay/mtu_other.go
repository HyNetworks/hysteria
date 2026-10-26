//go:build !linux

package vxrelay

import "net"

func allowFragmentation(*net.UDPConn) error { return nil }

func growBuffers(conn *net.UDPConn, size int) {
	_ = conn.SetReadBuffer(size)
	_ = conn.SetWriteBuffer(size)
}
