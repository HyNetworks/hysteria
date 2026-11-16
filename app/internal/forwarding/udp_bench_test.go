//go:build unix

package forwarding

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"fmt"
	"math/big"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/apernet/hysteria/core/v2/client"
	"github.com/apernet/hysteria/core/v2/server"
	"github.com/apernet/hysteria/extras/v2/outbounds"
)

// End-to-end UDP forwarding benchmark:
//
//	load generator <-> UDPTunnel <-> client <-> QUIC <-> server <-> direct outbound <-> target
//
// Each case runs for a fixed time and ignores b.N:
//
//	go test -run '^$' -bench UDPForward -benchtime 1x ./internal/forwarding/
//
// The throughput cases overload the tunnel and report what arrives.
// HY_UDP_BENCH_DURATION and HY_UDP_BENCH_SIZES override the defaults.
//
// 127.0.0.1 must be a real loopback. WSL2 in mirrored networking mode routes it
// through the host; there, run the test binary under "unshare -Urn" with lo up.

const (
	benchWarmup     = 500 * time.Millisecond
	benchSockBuffer = 4 << 20
	benchBandwidth  = 1250000000 // 10 Gbps, so that Brutal is never the limit
)

func benchDuration() time.Duration {
	if s := os.Getenv("HY_UDP_BENCH_DURATION"); s != "" {
		if d, err := time.ParseDuration(s); err == nil {
			return d
		}
	}
	return 3 * time.Second
}

// benchSizes are the payload sizes of the throughput cases.
// 1100 still fits in one QUIC datagram, 1400 is fragmented.
func benchSizes() []int {
	var sizes []int
	for _, s := range strings.Split(os.Getenv("HY_UDP_BENCH_SIZES"), ",") {
		if size, err := strconv.Atoi(s); err == nil && size > 0 {
			sizes = append(sizes, size)
		}
	}
	if len(sizes) == 0 {
		return []int{100, 1100, 1400}
	}
	return sizes
}

type benchAuthenticator struct{}

func (benchAuthenticator) Authenticate(addr net.Addr, auth string, tx uint64) (bool, string) {
	return true, "bench"
}

func benchTLSConfig(tb testing.TB) server.TLSConfig {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "bench"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		tb.Fatal(err)
	}
	return server.TLSConfig{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
	}
}

func benchListenUDP(tb testing.TB) *net.UDPConn {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		tb.Fatal(err)
	}
	_ = conn.SetReadBuffer(benchSockBuffer)
	_ = conn.SetWriteBuffer(benchSockBuffer)
	return conn
}

type benchEnv struct {
	Target     *net.UDPConn
	TunnelAddr *net.UDPAddr

	closers []func()
}

func (e *benchEnv) Close() {
	for i := len(e.closers) - 1; i >= 0; i-- {
		e.closers[i]()
	}
}

func newBenchEnv(tb testing.TB, brutal bool) *benchEnv {
	e := &benchEnv{}

	e.Target = benchListenUDP(tb)
	e.closers = append(e.closers, func() { _ = e.Target.Close() })

	serverConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		tb.Fatal(err)
	}
	serverConfig := &server.Config{
		TLSConfig:     benchTLSConfig(tb),
		Conn:          serverConn,
		Authenticator: benchAuthenticator{},
		// The default outbound of the app
		Outbound: &outbounds.PluggableOutboundAdapter{
			PluggableOutbound: outbounds.NewDirectOutboundSimple(outbounds.DirectOutboundModeAuto),
		},
	}
	clientConfig := &client.Config{
		ServerAddr: serverConn.LocalAddr(),
		TLSConfig:  client.TLSConfig{InsecureSkipVerify: true},
	}
	if brutal {
		serverConfig.BandwidthConfig = server.BandwidthConfig{MaxTx: benchBandwidth, MaxRx: benchBandwidth}
		clientConfig.BandwidthConfig = client.BandwidthConfig{MaxTx: benchBandwidth, MaxRx: benchBandwidth}
	}
	s, err := server.NewServer(serverConfig)
	if err != nil {
		tb.Fatal(err)
	}
	go s.Serve()
	e.closers = append(e.closers, func() { _ = s.Close() })

	c, _, err := client.NewClient(clientConfig)
	if err != nil {
		e.Close()
		tb.Fatal(err)
	}
	e.closers = append(e.closers, func() { _ = c.Close() })

	tunnelConn := benchListenUDP(tb)
	e.TunnelAddr = tunnelConn.LocalAddr().(*net.UDPAddr)
	tunnel := &UDPTunnel{HyClient: c, Remote: e.Target.LocalAddr().String()}
	go tunnel.Serve(tunnelConn)
	e.closers = append(e.closers, func() { _ = tunnelConn.Close() })

	return e
}

// dialTunnel opens the sockets of the load generator, one UDP session each.
func (e *benchEnv) dialTunnel(tb testing.TB, flows int) []*net.UDPConn {
	conns := make([]*net.UDPConn, flows)
	for i := range conns {
		conn, err := net.DialUDP("udp", nil, e.TunnelAddr)
		if err != nil {
			tb.Fatal(err)
		}
		_ = conn.SetReadBuffer(benchSockBuffer)
		_ = conn.SetWriteBuffer(benchSockBuffer)
		conns[i] = conn
		e.closers = append(e.closers, func() { _ = conn.Close() })
	}
	return conns
}

type benchCounter struct {
	packets atomic.Uint64
	bytes   atomic.Uint64
}

func (c *benchCounter) count(conn *net.UDPConn) {
	buf := make([]byte, 65536)
	for {
		n, _, err := conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		c.packets.Add(1)
		c.bytes.Add(uint64(n))
	}
}

func benchCPUTime() time.Duration {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		return 0
	}
	return time.Duration(ru.Utime.Nano() + ru.Stime.Nano())
}

func (c *benchCounter) measure(b *testing.B) {
	time.Sleep(benchWarmup)
	d := benchDuration()
	p0, b0, cpu0, t0 := c.packets.Load(), c.bytes.Load(), benchCPUTime(), time.Now()
	b.ResetTimer()
	time.Sleep(d)
	b.StopTimer()
	elapsed := time.Since(t0).Seconds()
	packets, bytes, cpu := c.packets.Load()-p0, c.bytes.Load()-b0, benchCPUTime()-cpu0
	if packets == 0 {
		b.Fatal("nothing arrived")
	}
	b.ReportMetric(0, "ns/op")
	b.ReportMetric(float64(packets)/elapsed, "pps")
	b.ReportMetric(float64(bytes)*8/1e6/elapsed, "Mbps")
	// Whole process, load generator and target included
	b.ReportMetric(float64(cpu.Nanoseconds())/float64(packets), "cpu-ns/pkt")
}

func benchUpload(b *testing.B, brutal bool, flows, size int) {
	e := newBenchEnv(b, brutal)
	defer e.Close()

	var received benchCounter
	go received.count(e.Target)

	// One writer for all sessions. A writer per session mostly measures
	// their contention for the tunnel's socket.
	conns := e.dialTunnel(b, flows)
	var stop atomic.Bool
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		payload := make([]byte, size)
		for i := 0; !stop.Load(); i++ {
			_, _ = conns[i%len(conns)].Write(payload)
		}
	}()
	received.measure(b)
	stop.Store(true)
	wg.Wait()
}

func benchDownload(b *testing.B, brutal bool, flows, size int) {
	e := newBenchEnv(b, brutal)
	defer e.Close()

	// The target floods every address it hears from.
	var stop atomic.Bool
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		seen := make(map[string]bool)
		buf := make([]byte, 65536)
		for {
			_, addr, err := e.Target.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if seen[addr.String()] {
				continue
			}
			seen[addr.String()] = true
			wg.Add(1)
			go func() {
				defer wg.Done()
				payload := make([]byte, size)
				for !stop.Load() {
					_, _ = e.Target.WriteToUDP(payload, addr)
				}
			}()
		}
	}()

	var received benchCounter
	for _, conn := range e.dialTunnel(b, flows) {
		if _, err := conn.Write([]byte("start")); err != nil {
			b.Fatal(err)
		}
		go received.count(conn)
	}
	received.measure(b)
	stop.Store(true)
	_ = e.Target.Close()
	wg.Wait()
}

// benchLatency reports round trip times at a fixed rate well below capacity.
func benchLatency(b *testing.B, brutal bool, pps, size int) {
	e := newBenchEnv(b, brutal)
	defer e.Close()

	go func() {
		buf := make([]byte, 65536)
		for {
			n, addr, err := e.Target.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			_, _ = e.Target.WriteToUDPAddrPort(buf[:n], addr)
		}
	}()

	conn := e.dialTunnel(b, 1)[0]
	d := benchDuration()
	total := int(d.Seconds() * float64(pps))
	rtts := make([]time.Duration, 0, total)
	start := time.Now()
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 65536)
		for len(rtts) < total {
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			if n < 8 {
				continue
			}
			sent := time.Duration(binary.BigEndian.Uint64(buf))
			rtts = append(rtts, time.Since(start)-sent)
		}
	}()

	payload := make([]byte, size)
	interval := time.Second / time.Duration(pps)
	b.ResetTimer()
	for i := 0; i < total; i++ {
		// Spin, timers are too coarse for this
		for time.Since(start) < time.Duration(i)*interval {
		}
		binary.BigEndian.PutUint64(payload, uint64(time.Since(start)))
		_, _ = conn.Write(payload)
	}
	b.StopTimer()
	select {
	case <-done:
	case <-time.After(time.Second):
	}
	_ = conn.SetReadDeadline(time.Now())
	<-done

	if len(rtts) == 0 {
		b.Fatal("nothing came back")
	}
	sort.Slice(rtts, func(i, j int) bool { return rtts[i] < rtts[j] })
	quantile := func(q float64) float64 {
		return float64(rtts[int(q*float64(len(rtts)-1))].Microseconds())
	}
	b.ReportMetric(0, "ns/op")
	b.ReportMetric(quantile(0.5), "p50-µs")
	b.ReportMetric(quantile(0.99), "p99-µs")
	b.ReportMetric(float64(total-len(rtts))*100/float64(total), "loss-%")
}

func BenchmarkUDPForward(b *testing.B) {
	for _, cc := range []string{"bbr", "brutal"} {
		brutal := cc == "brutal"
		for _, size := range benchSizes() {
			for _, flows := range []int{1, 8} {
				name := fmt.Sprintf("cc=%s/size=%d/flows=%d", cc, size, flows)
				b.Run("dir=up/"+name, func(b *testing.B) { benchUpload(b, brutal, flows, size) })
				b.Run("dir=down/"+name, func(b *testing.B) { benchDownload(b, brutal, flows, size) })
			}
		}
		b.Run(fmt.Sprintf("dir=echo/cc=%s/size=200/pps=5000", cc), func(b *testing.B) {
			benchLatency(b, brutal, 5000, 200)
		})
	}
}
