package tproxy

import (
	"errors"
	"net"
	"sync"
	"time"

	"github.com/apernet/go-tproxy"
	"github.com/apernet/hysteria/core/v2/client"
)

const (
	udpBufferSize  = 4096
	defaultTimeout = 60 * time.Second
)

type UDPTProxy struct {
	HyClient    client.Client
	Timeout     time.Duration
	EventLogger UDPEventLogger
}

// udpPair is the hysteria session of one src/dst pair. Sends are serialized
// because HyUDPConn.Send is not thread-safe, and both the pair's forwarding
// goroutine and the listener (for packets that raced the pair's socket) send.
type udpPair struct {
	hyConn client.HyUDPConn
	sendMu sync.Mutex
}

func (p *udpPair) send(data []byte, dst string) error {
	p.sendMu.Lock()
	defer p.sendMu.Unlock()
	return p.hyConn.Send(data, dst)
}

type UDPEventLogger interface {
	Connect(addr, reqAddr net.Addr)
	Error(addr, reqAddr net.Addr, err error)
}

func (r *UDPTProxy) ListenAndServe(laddr *net.UDPAddr) error {
	conn, err := tproxy.ListenUDP("udp", laddr)
	if err != nil {
		return err
	}
	defer conn.Close()
	buf := make([]byte, udpBufferSize)
	var pairs sync.Map // src/dst key -> *udpPair
	for {
		// We will mostly get only the first packet of each src/dst pair here,
		// because newPair will create a TProxy connection and take over
		// the src/dst pair. Later packets will be sent there instead of here.
		// Packets that arrive before that connection exists (e.g. a QUIC
		// ClientHello split over two datagrams) still land here and must go
		// through the existing pair, not a second hysteria session.
		n, srcAddr, dstAddr, err := tproxy.ReadFromUDP(conn, buf)
		if err != nil {
			return err
		}
		key := srcAddr.String() + " " + dstAddr.String()
		if p, ok := pairs.Load(key); ok {
			_ = p.(*udpPair).send(buf[:n], dstAddr.String())
			continue
		}
		r.newPair(srcAddr, dstAddr, buf[:n], key, &pairs)
	}
}

func (r *UDPTProxy) newPair(srcAddr, dstAddr *net.UDPAddr, initPkt []byte, key string, pairs *sync.Map) {
	if r.EventLogger != nil {
		r.EventLogger.Connect(srcAddr, dstAddr)
	}
	var closeErr error
	defer func() {
		// If closeErr is nil, it means we at least successfully sent the first packet
		// and started forwarding, in which case we don't call the error logger.
		if r.EventLogger != nil && closeErr != nil {
			r.EventLogger.Error(srcAddr, dstAddr, closeErr)
		}
	}()
	conn, err := tproxy.DialUDP("udp", dstAddr, srcAddr)
	if err != nil {
		closeErr = err
		return
	}
	hyConn, err := r.HyClient.UDP()
	if err != nil {
		_ = conn.Close()
		closeErr = err
		return
	}
	pair := &udpPair{hyConn: hyConn}
	// Send the first packet
	err = pair.send(initPkt, dstAddr.String())
	if err != nil {
		_ = conn.Close()
		_ = hyConn.Close()
		closeErr = err
		return
	}
	pairs.Store(key, pair)
	// Start forwarding
	go func() {
		err := r.forwarding(conn, pair, dstAddr.String())
		pairs.CompareAndDelete(key, pair)
		_ = conn.Close()
		_ = hyConn.Close()
		if r.EventLogger != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				// We don't consider deadline exceeded (timeout) an error
				err = nil
			}
			r.EventLogger.Error(srcAddr, dstAddr, err)
		}
	}()
}

func (r *UDPTProxy) forwarding(conn *net.UDPConn, pair *udpPair, dst string) error {
	errChan := make(chan error, 2)
	// Local <- Remote
	go func() {
		for {
			bs, _, err := pair.hyConn.Receive()
			if err != nil {
				errChan <- err
				return
			}
			_, err = conn.Write(bs)
			if err != nil {
				errChan <- err
				return
			}
			_ = r.updateConnDeadline(conn)
		}
	}()
	// Local -> Remote
	go func() {
		buf := make([]byte, udpBufferSize)
		for {
			_ = r.updateConnDeadline(conn)
			n, err := conn.Read(buf)
			if n > 0 {
				err := pair.send(buf[:n], dst)
				if err != nil {
					errChan <- err
					return
				}
			}
			if err != nil {
				errChan <- err
				return
			}
		}
	}()
	return <-errChan
}

func (r *UDPTProxy) updateConnDeadline(conn *net.UDPConn) error {
	if r.Timeout == 0 {
		return conn.SetReadDeadline(time.Now().Add(defaultTimeout))
	} else {
		return conn.SetReadDeadline(time.Now().Add(r.Timeout))
	}
}
