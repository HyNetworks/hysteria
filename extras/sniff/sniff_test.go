package sniff

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/apernet/hysteria/extras/v2/utils"
)

func TestSnifferCheck(t *testing.T) {
	sniffer := &Sniffer{
		Timeout:       1 * time.Second,
		RewriteDomain: false,
		TCPPorts:      nil, // nil = all
		UDPPorts:      nil, // nil = all
	}

	assert.True(t, sniffer.Check(false, "1.1.1.1:80"))
	assert.False(t, sniffer.Check(false, "example.com:443"))

	sniffer.RewriteDomain = true
	assert.True(t, sniffer.Check(false, "example.com:443"))

	sniffer.TCPPorts = []utils.PortRange{{80, 80}}
	assert.True(t, sniffer.Check(false, "google.com:80"))
	assert.False(t, sniffer.Check(false, "google.com:443"))

	sniffer.UDPPorts = []utils.PortRange{{443, 443}}
	assert.True(t, sniffer.Check(true, "google.com:443"))
	assert.False(t, sniffer.Check(true, "google.com:80"))
}

func TestSnifferTCP(t *testing.T) {
	goHello := goTLSClientHello(t, "go.sniff.test")
	chromeHello := readTestdata(t, "tls-chrome153.bin")

	tests := []struct {
		name     string
		data     []byte
		chunk    int // Write the data in chunks of this size, 0 = all at once
		reqAddr  string
		wantAddr string
	}{
		{
			name:     "HTTP",
			data:     []byte("POST /hello HTTP/1.1\r\nHost: example.com\r\nContent-Length: 27\r\n\r\nparam1=value1&param2=value2"),
			reqAddr:  "111.111.111.111:80",
			wantAddr: "example.com:80",
		},
		{
			name:     "HTTP host with port",
			data:     []byte("GET / HTTP/1.1\r\nHost: example.com:8080\r\nAccept: */*\r\n\r\n"),
			reqAddr:  "222.222.222.222:10086",
			wantAddr: "example.com:10086",
		},
		{
			name:     "HTTP absolute URI",
			data:     []byte("GET http://absolute.example.com/x HTTP/1.1\r\n\r\n"),
			reqAddr:  "1.2.3.4:80",
			wantAddr: "absolute.example.com:80",
		},
		{
			name:     "HTTP byte by byte",
			data:     []byte("GET / HTTP/1.1\r\nHost: slow.example.com\r\n\r\n"),
			chunk:    1,
			reqAddr:  "1.2.3.4:80",
			wantAddr: "slow.example.com:80",
		},
		{
			name:     "HTTP Chrome 153",
			data:     readTestdata(t, "http-chrome153.txt"),
			reqAddr:  "1.2.3.4:80",
			wantAddr: "chrome.sniff.test:80",
		},
		{
			name:     "HTTP IPv6 host",
			data:     []byte("GET / HTTP/1.1\r\nHost: [2001:db8::1]:8080\r\n\r\n"),
			reqAddr:  "1.2.3.4:80",
			wantAddr: "1.2.3.4:80",
		},
		{
			name:     "TLS Go",
			data:     goHello,
			reqAddr:  "1.2.3.4:443",
			wantAddr: "go.sniff.test:443",
		},
		{
			name:     "TLS Chrome 153",
			data:     chromeHello,
			reqAddr:  "1.2.3.4:443",
			wantAddr: "chrome.sniff.test:443",
		},
		{
			name:     "TLS Firefox 153 ESR",
			data:     readTestdata(t, "tls-firefox153esr.bin"),
			reqAddr:  "1.2.3.4:443",
			wantAddr: "firefox.sniff.test:443",
		},
		{
			name:     "TLS curl 8.18 (OpenSSL 3.5)",
			data:     readTestdata(t, "tls-curl8.18-openssl3.5.bin"),
			reqAddr:  "1.2.3.4:443",
			wantAddr: "curl.sniff.test:443",
		},
		{
			name:     "TLS byte by byte",
			data:     chromeHello,
			chunk:    1,
			reqAddr:  "1.2.3.4:443",
			wantAddr: "chrome.sniff.test:443",
		},
		{
			name:     "TLS ClientHello fragmented across records",
			data:     fragmentTLSRecords(chromeHello, 100),
			chunk:    333,
			reqAddr:  "1.2.3.4:443",
			wantAddr: "chrome.sniff.test:443",
		},
		{
			name:     "TLS ClientHello followed by other records",
			data:     append(slices.Clone(goHello), 0x14, 0x03, 0x03, 0x00, 0x01, 0x01),
			reqAddr:  "1.2.3.4:443",
			wantAddr: "go.sniff.test:443",
		},
		{
			name:     "TLS ClientHello interrupted by another record",
			data:     append(fragmentTLSRecords(goHello, 100)[:105], 0x14, 0x03, 0x03, 0x00, 0x01, 0x01),
			reqAddr:  "1.2.3.4:443",
			wantAddr: "1.2.3.4:443",
		},
		{
			name:     "Unrecognized text",
			data:     []byte("Wait It's All Ohio? Always Has Been."),
			reqAddr:  "123.123.123.123:123",
			wantAddr: "123.123.123.123:123",
		},
		{
			name:     "Unrecognized SSH",
			data:     []byte("SSH-2.0-OpenSSH_9.6\r\n"),
			reqAddr:  "123.123.123.123:22",
			wantAddr: "123.123.123.123:22",
		},
		{
			name:     "Unrecognized binary",
			data:     []byte("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a"),
			reqAddr:  "45.45.45.45:45",
			wantAddr: "45.45.45.45:45",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// The stream stays open, so the sniffer must stop as soon as it has seen enough,
			// or it times out and doesn't rewrite anything.
			stream, client := newPipeStream()
			defer client.Close()
			go writeChunks(client, tt.data, tt.chunk)

			reqAddr := tt.reqAddr
			putback, err := (&Sniffer{Timeout: 3 * time.Second}).TCP(stream, &reqAddr)
			require.NoError(t, err)
			assert.Equal(t, tt.wantAddr, reqAddr)

			// Nothing is lost: what's put back and what's left make up the whole data
			rest := make([]byte, len(tt.data)-len(putback))
			_, err = io.ReadFull(stream, rest)
			require.NoError(t, err)
			assert.Equal(t, tt.data, append(putback, rest...))
		})
	}
}

func TestSnifferTCPTimeout(t *testing.T) {
	stream, client := newPipeStream()
	defer client.Close()
	go client.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n"))

	reqAddr := "66.66.66.66:80"
	start := time.Now()
	putback, err := (&Sniffer{Timeout: 500 * time.Millisecond}).TCP(stream, &reqAddr)
	assert.NoError(t, err)
	assert.Less(t, time.Since(start), 2*time.Second)
	assert.Equal(t, []byte("GET / HTTP/1.1\r\nHost: example.com\r\n"), putback)
	assert.Equal(t, "66.66.66.66:80", reqAddr)
}

func TestSnifferTCPMaxBytes(t *testing.T) {
	stream, client := newPipeStream()
	defer client.Close()
	data := []byte("GET / HTTP/1.1\r\nX-Big: " + strings.Repeat("a", 2*sniffMaxTCPBytes) + "\r\nHost: example.com\r\n\r\n")
	go client.Write(data)

	reqAddr := "66.66.66.66:80"
	putback, err := (&Sniffer{Timeout: 3 * time.Second}).TCP(stream, &reqAddr)
	assert.NoError(t, err)
	assert.Equal(t, data[:sniffMaxTCPBytes], putback)
	assert.Equal(t, "66.66.66.66:80", reqAddr)
}

func TestSnifferUDP(t *testing.T) {
	chrome := readTestdataPackets(t, "quic-chrome153", 3)
	firefox := readTestdataPackets(t, "quic-firefox153esr", 2)
	curl := readTestdataPackets(t, "quic-curl8.14-openssl3.5", 2)

	tests := []struct {
		name     string
		packets  [][]byte
		wantAddr string
		wantN    int // Packets needed before the sniffer is done
	}{
		// Chrome shuffles the ClientHello fragments across two packets, and retransmits them split differently
		{"Chrome 153", chrome, "chrome.sniff.test:443", 2},
		{"Chrome 153 reordered", [][]byte{chrome[1], chrome[0]}, "chrome.sniff.test:443", 2},
		{"Chrome 153 retransmitted", [][]byte{chrome[1], chrome[2]}, "chrome.sniff.test:443", 2},
		{"Firefox 153 ESR", firefox, "firefox.sniff.test:443", 2},
		{"Firefox 153 ESR reordered", [][]byte{firefox[1], firefox[0]}, "firefox.sniff.test:443", 2},
		{"curl 8.14 (OpenSSL 3.5)", curl, "curl.sniff.test:443", 2},
		// quiche retransmits the first packet before sending the second
		{"quiche", readTestdataPackets(t, "quic-quiche", 3), "quiche.sniff.test:443", 3},
		{"ngtcp2 1.11", readTestdataPackets(t, "quic-ngtcp2-1.11", 1), "ngtcp2.sniff.test:443", 1},
		{"aioquic 1.2", readTestdataPackets(t, "quic-aioquic1.2", 1), "aioquic.sniff.test:443", 1},
		{"Not QUIC", [][]byte{[]byte("oh my sweet summer child")}, "1.2.3.4:443", 1},
		{"Unsupported version", [][]byte{append([]byte{0xc0, 0xff, 0x00, 0x00, 0x1d}, chrome[0][5:]...)}, "1.2.3.4:443", 1},
		{"Other connections ignored", [][]byte{chrome[0], firefox[1], curl[1], chrome[1]}, "chrome.sniff.test:443", 4},
		{"Gives up", slices.Repeat([][]byte{chrome[0]}, sniffMaxUDPPackets), "1.2.3.4:443", sniffMaxUDPPackets},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertSniffUDP(t, tt.packets, tt.wantAddr, tt.wantN)
		})
	}
}

// TestSnifferUDPQUICGo sniffs the first flight of live quic-go clients.
func TestSnifferUDPQUICGo(t *testing.T) {
	tests := []struct {
		name string
		conf *quic.Config
	}{
		{"v1", &quic.Config{}},
		{"v2", &quic.Config{Versions: []quic.Version{quic.Version2}}},
		{"Chrome parrot", &quic.Config{ChromeParrot: true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			packets := quicGoFirstFlight(t, tt.conf, "quic-go.sniff.test", 3)
			assertSniffUDP(t, packets, "quic-go.sniff.test:443", 2)
		})
	}
}

func TestRewrite(t *testing.T) {
	tests := []struct {
		host string
		want string
	}{
		{"example.com", "example.com:443"},
		{"example.com:8443", "example.com:443"},
		{"under_score.example.com.", "under_score.example.com.:443"},
		{"", "1.2.3.4:443"},
		{"5.6.7.8", "1.2.3.4:443"},
		{"[2001:db8::1]:80", "1.2.3.4:443"},
		{"evil.com/path", "1.2.3.4:443"},
		{"evil.com\x00", "1.2.3.4:443"},
		{strings.Repeat("a", 254), "1.2.3.4:443"},
	}
	for _, tt := range tests {
		reqAddr := "1.2.3.4:443"
		rewrite(&reqAddr, tt.host)
		assert.Equal(t, tt.want, reqAddr, "host %q", tt.host)
	}
}

// assertSniffUDP feeds packets to the sniffer one by one, and checks that it's done
// after exactly n packets, with the address rewritten to want.
func assertSniffUDP(t *testing.T, packets [][]byte, want string, n int) {
	t.Helper()
	sniffer := &Sniffer{}
	for i := 1; i <= n; i++ {
		held := make([][]byte, i)
		for j := range held {
			held[j] = slices.Clone(packets[j])
		}
		reqAddr := "1.2.3.4:443"
		done, err := sniffer.UDP(held, &reqAddr)
		require.NoError(t, err)
		if i < n {
			require.False(t, done, "done after %d packets", i)
			require.Equal(t, "1.2.3.4:443", reqAddr)
			continue
		}
		require.True(t, done, "not done after %d packets", i)
		require.Equal(t, want, reqAddr)
		for j := range held {
			require.Equal(t, packets[j], held[j], "packet %d was modified", j)
		}
	}
}

// quicGoFirstFlight returns the first n datagrams a quic-go client sends.
func quicGoFirstFlight(t *testing.T, conf *quic.Config, serverName string, n int) [][]byte {
	t.Helper()
	ln, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	dialDone := make(chan struct{})
	defer func() {
		cancel()
		<-dialDone
	}()
	go func() {
		defer close(dialDone)
		tlsConf := &tls.Config{ServerName: serverName, NextProtos: []string{"h3"}}
		_, _ = quic.DialAddr(ctx, ln.LocalAddr().String(), tlsConf, conf)
	}()

	var packets [][]byte
	buf := make([]byte, 2048)
	for len(packets) < n {
		require.NoError(t, ln.SetReadDeadline(time.Now().Add(5*time.Second)))
		l, _, err := ln.ReadFrom(buf)
		require.NoError(t, err)
		packets = append(packets, slices.Clone(buf[:l]))
	}
	return packets
}

// goTLSClientHello returns the TLS records carrying a crypto/tls ClientHello.
func goTLSClientHello(t *testing.T, serverName string) []byte {
	t.Helper()
	client, server := net.Pipe()
	defer server.Close()
	go func() {
		_ = tls.Client(client, &tls.Config{ServerName: serverName}).Handshake()
		client.Close()
	}()
	buf := make([]byte, 16384)
	n, err := server.Read(buf)
	require.NoError(t, err)
	return buf[:n]
}

// fragmentTLSRecords splits the handshake messages in a TLS record into records of size n.
func fragmentTLSRecords(record []byte, n int) []byte {
	var out []byte
	for p := range slices.Chunk(record[5:], n) {
		out = append(out, 0x16, 0x03, 0x01, byte(len(p)>>8), byte(len(p)))
		out = append(out, p...)
	}
	return out
}

func readTestdata(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	require.NoError(t, err)
	return b
}

func readTestdataPackets(t *testing.T, prefix string, n int) [][]byte {
	t.Helper()
	packets := make([][]byte, n)
	for i := range packets {
		packets[i] = readTestdata(t, prefix+"-"+string(rune('0'+i))+".bin")
	}
	return packets
}

// pipeStream is a server.HyStream backed by a net.Pipe.
type pipeStream struct {
	net.Conn
}

func (pipeStream) StreamID() quic.StreamID { return 0 }

func newPipeStream() (pipeStream, net.Conn) {
	s, c := net.Pipe()
	return pipeStream{s}, c
}

func writeChunks(w io.Writer, data []byte, chunk int) {
	if chunk == 0 {
		chunk = len(data)
	}
	for p := range slices.Chunk(data, chunk) {
		if _, err := w.Write(p); err != nil {
			return
		}
	}
}
