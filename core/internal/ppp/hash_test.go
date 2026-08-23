package ppp

import (
	"encoding/binary"
	"fmt"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Frame builders
//
// A PPP frame as handed to flowHash looks like:
//
//	[FF 03]? <protocol field: 1 or 2 octets> <payload>
//
// The leading FF 03 is the HDLC-like framing's Address (all-stations, 0xFF) and
// Control (UI, 0x03) pair; a peer that negotiated Address-and-Control-Field-
// Compression (RFC 1661 s6.6) omits it. The protocol field may likewise be
// compressed to a single octet when its value is below 0x100 (Protocol-Field-
// Compression, RFC 1661 s6.5), which is why flowHash tells the two apart by the
// low bit: a compressed protocol field is odd, whereas the first octet of an
// uncompressed one is even.
//
// These tests do not assert that flowHash *implements* either option - it is a
// load balancer, not a PPP receiver, and it only has to parse far enough to
// find the 5-tuple. They assert the consequence that matters here: both
// encodings of one flow must select the same stream.
// ---------------------------------------------------------------------------

const (
	pppProtoIPv4 = 0x0021
	pppProtoIPv6 = 0x0057
	pppProtoLCP  = 0xC021
	pppProtoIPCP = 0x8021
	pppProtoPAP  = 0xC023
)

type frameOpts struct {
	acfc bool // prepend the FF 03 address/control field
	pfc  bool // compress the protocol field to one octet
}

func pppFrame(proto uint16, opts frameOpts, payload []byte) []byte {
	var b []byte
	if opts.acfc {
		b = append(b, 0xFF, 0x03)
	}
	if opts.pfc {
		if proto > 0xFF {
			panic("cannot PFC-compress a protocol field >= 0x100")
		}
		b = append(b, byte(proto))
	} else {
		b = binary.BigEndian.AppendUint16(b, proto)
	}
	return append(b, payload...)
}

// ipv4Packet builds a minimal 20-octet-header IPv4 packet. ttl and id are
// deliberately parameterised so tests can prove they do not take part in the
// flow hash.
func ipv4Packet(src, dst string, ipProto uint8, sport, dport uint16, ttl uint8, id uint16, body []byte) []byte {
	transport := transportHeader(ipProto, sport, dport, body)
	hdr := make([]byte, 20)
	hdr[0] = 0x45 // version 4, IHL 5
	binary.BigEndian.PutUint16(hdr[2:4], uint16(20+len(transport)))
	binary.BigEndian.PutUint16(hdr[4:6], id)
	hdr[8] = ttl
	hdr[9] = ipProto
	copy(hdr[12:16], net.ParseIP(src).To4())
	copy(hdr[16:20], net.ParseIP(dst).To4())
	return append(hdr, transport...)
}

// ipv4PacketWithOptions builds an IPv4 packet with `optWords` 32-bit option
// words, i.e. an IHL of 5+optWords.
func ipv4PacketWithOptions(src, dst string, ipProto uint8, sport, dport uint16, optWords int, body []byte) []byte {
	transport := transportHeader(ipProto, sport, dport, body)
	hdrLen := 20 + optWords*4
	hdr := make([]byte, hdrLen)
	hdr[0] = byte(0x40 | (hdrLen / 4))
	binary.BigEndian.PutUint16(hdr[2:4], uint16(hdrLen+len(transport)))
	hdr[8] = 64
	hdr[9] = ipProto
	copy(hdr[12:16], net.ParseIP(src).To4())
	copy(hdr[16:20], net.ParseIP(dst).To4())
	for i := 20; i < hdrLen; i++ {
		hdr[i] = 0x01 // NOP options
	}
	return append(hdr, transport...)
}

func ipv6Packet(src, dst string, nextHdr uint8, sport, dport uint16, hopLimit uint8, body []byte) []byte {
	transport := transportHeader(nextHdr, sport, dport, body)
	hdr := make([]byte, 40)
	hdr[0] = 0x60 // version 6
	binary.BigEndian.PutUint16(hdr[4:6], uint16(len(transport)))
	hdr[6] = nextHdr
	hdr[7] = hopLimit
	copy(hdr[8:24], net.ParseIP(src).To16())
	copy(hdr[24:40], net.ParseIP(dst).To16())
	return append(hdr, transport...)
}

// transportHeader builds a stub L4 header. For TCP (6) and UDP (17) the first
// four octets are the source and destination ports; for anything else the
// ports are not encoded at all.
func transportHeader(ipProto uint8, sport, dport uint16, body []byte) []byte {
	switch ipProto {
	case 6, 17:
		h := make([]byte, 8)
		binary.BigEndian.PutUint16(h[0:2], sport)
		binary.BigEndian.PutUint16(h[2:4], dport)
		return append(h, body...)
	default:
		// e.g. ICMP: type/code/checksum, no ports.
		h := []byte{8, 0, 0, 0}
		return append(h, body...)
	}
}

func ipv4TCP(src, dst string, sport, dport uint16) []byte {
	return pppFrame(pppProtoIPv4, frameOpts{}, ipv4Packet(src, dst, 6, sport, dport, 64, 1, []byte("hello")))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// representativeFrames is the shared corpus used by the determinism and range
// tests. Every entry must be safe to hand to flowHash with any n.
func representativeFrames() []struct {
	name  string
	frame []byte
} {
	return []struct {
		name  string
		frame []byte
	}{
		{"ipv4 tcp", ipv4TCP("192.0.2.1", "198.51.100.7", 12345, 443)},
		{"ipv4 tcp with acfc", pppFrame(pppProtoIPv4, frameOpts{acfc: true}, ipv4Packet("192.0.2.1", "198.51.100.7", 6, 12345, 443, 64, 1, nil))},
		{"ipv4 tcp with pfc", pppFrame(pppProtoIPv4, frameOpts{pfc: true}, ipv4Packet("192.0.2.1", "198.51.100.7", 6, 12345, 443, 64, 1, nil))},
		{"ipv4 udp", pppFrame(pppProtoIPv4, frameOpts{}, ipv4Packet("10.0.0.1", "10.0.0.2", 17, 53, 5353, 64, 2, nil))},
		{"ipv4 icmp", pppFrame(pppProtoIPv4, frameOpts{}, ipv4Packet("10.0.0.1", "10.0.0.2", 1, 0, 0, 64, 3, []byte("ping")))},
		{"ipv4 with options", pppFrame(pppProtoIPv4, frameOpts{}, ipv4PacketWithOptions("10.0.0.1", "10.0.0.2", 6, 80, 8080, 3, nil))},
		{"ipv6 tcp", pppFrame(pppProtoIPv6, frameOpts{}, ipv6Packet("2001:db8::1", "2001:db8::2", 6, 12345, 443, 64, nil))},
		{"ipv6 udp with acfc", pppFrame(pppProtoIPv6, frameOpts{acfc: true}, ipv6Packet("fe80::1", "fe80::2", 17, 546, 547, 64, nil))},
		{"ipv6 icmpv6", pppFrame(pppProtoIPv6, frameOpts{}, ipv6Packet("2001:db8::1", "2001:db8::2", 58, 0, 0, 64, []byte("nd")))},
		{"lcp", pppFrame(pppProtoLCP, frameOpts{acfc: true}, []byte{0x01, 0x01, 0x00, 0x04})},
		{"ipcp", pppFrame(pppProtoIPCP, frameOpts{acfc: true}, []byte{0x01, 0x02, 0x00, 0x0a, 0x03, 0x06, 10, 0, 0, 1})},
		{"empty", nil},
		{"one octet", []byte{0x21}},
		{"acfc only", []byte{0xFF, 0x03}},
		{"acfc plus half a protocol field", []byte{0xFF, 0x03, 0x00}},
		{"truncated ipv4 mid address", pppFrame(pppProtoIPv4, frameOpts{}, []byte{0x45, 0, 0, 40, 0, 0, 0, 0, 64, 6, 0, 0, 192, 0})},
		{"bad ip version nibble", pppFrame(pppProtoIPv4, frameOpts{}, ipv6Packet("2001:db8::1", "2001:db8::2", 6, 1, 2, 64, nil))},
	}
}

func TestFlowHashIsDeterministicAndInRange(t *testing.T) {
	for _, n := range []int{1, 2, 3, 4, 7, 8, 16, 255, 256} {
		for _, tc := range representativeFrames() {
			t.Run(fmt.Sprintf("n=%d/%s", n, tc.name), func(t *testing.T) {
				first := flowHash(tc.frame, n, nil)
				assert.GreaterOrEqual(t, first, 0, "index must not be negative")
				assert.Less(t, first, n, "index must be < n")
				for i := 0; i < 20; i++ {
					assert.Equal(t, first, flowHash(tc.frame, n, nil), "flowHash must be deterministic")
				}
				// A copy of the same bytes must hash identically: nothing about
				// the backing array may leak into the hash.
				cp := append([]byte(nil), tc.frame...)
				assert.Equal(t, first, flowHash(cp, n, nil))
			})
		}
	}
}

func TestFlowHashDegenerateStreamCount(t *testing.T) {
	frame := ipv4TCP("192.0.2.1", "198.51.100.7", 1000, 80)
	tests := []struct {
		name string
		n    int
	}{
		{"single stream", 1},
		{"zero streams", 0},
		{"negative stream count", -1},
		{"very negative stream count", -1000},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// n <= 1 short-circuits before the modulo, so no division by zero
			// is possible here; the panic risk lives in the caller instead
			// (see TestSendDataPanicsWithNoStreams).
			assert.NotPanics(t, func() {
				assert.Equal(t, 0, flowHash(frame, tt.n, nil))
			})
		})
	}
}

func TestFlowHashSameFlowHashesTogether(t *testing.T) {
	const n = 16
	tests := []struct {
		name string
		a, b []byte
	}{
		{
			name: "ipv4 differing ttl, id and body",
			a:    pppFrame(pppProtoIPv4, frameOpts{}, ipv4Packet("192.0.2.1", "198.51.100.7", 6, 1234, 443, 64, 1, []byte("first"))),
			b:    pppFrame(pppProtoIPv4, frameOpts{}, ipv4Packet("192.0.2.1", "198.51.100.7", 6, 1234, 443, 1, 65535, []byte("a much longer second payload"))),
		},
		{
			name: "ipv4 with and without the FF 03 prefix",
			a:    pppFrame(pppProtoIPv4, frameOpts{}, ipv4Packet("192.0.2.1", "198.51.100.7", 6, 1234, 443, 64, 1, nil)),
			b:    pppFrame(pppProtoIPv4, frameOpts{acfc: true}, ipv4Packet("192.0.2.1", "198.51.100.7", 6, 1234, 443, 64, 1, nil)),
		},
		{
			name: "ipv4 with compressed and uncompressed protocol field",
			a:    pppFrame(pppProtoIPv4, frameOpts{}, ipv4Packet("192.0.2.1", "198.51.100.7", 6, 1234, 443, 64, 1, nil)),
			b:    pppFrame(pppProtoIPv4, frameOpts{pfc: true}, ipv4Packet("192.0.2.1", "198.51.100.7", 6, 1234, 443, 64, 1, nil)),
		},
		{
			name: "ipv6 with and without the FF 03 prefix",
			a:    pppFrame(pppProtoIPv6, frameOpts{}, ipv6Packet("2001:db8::1", "2001:db8::2", 17, 500, 4500, 64, nil)),
			b:    pppFrame(pppProtoIPv6, frameOpts{acfc: true}, ipv6Packet("2001:db8::1", "2001:db8::2", 17, 500, 4500, 1, nil)),
		},
		{
			name: "ipv6 with compressed and uncompressed protocol field",
			a:    pppFrame(pppProtoIPv6, frameOpts{}, ipv6Packet("2001:db8::1", "2001:db8::2", 6, 22, 33, 64, nil)),
			b:    pppFrame(pppProtoIPv6, frameOpts{pfc: true}, ipv6Packet("2001:db8::1", "2001:db8::2", 6, 22, 33, 64, nil)),
		},
		{
			name: "icmp ignores the body entirely",
			a:    pppFrame(pppProtoIPv4, frameOpts{}, ipv4Packet("10.0.0.1", "10.0.0.2", 1, 0, 0, 64, 1, []byte("echo request one"))),
			b:    pppFrame(pppProtoIPv4, frameOpts{}, ipv4Packet("10.0.0.1", "10.0.0.2", 1, 0, 0, 64, 2, []byte("a totally different body"))),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, flowHash(tt.a, n, nil), flowHash(tt.b, n, nil),
				"frames of the same flow must pin to the same stream")
		})
	}
}

func TestFlowHashDistinguishesFlows(t *testing.T) {
	const n = 64
	base := ipv4TCP("192.0.2.1", "198.51.100.7", 1234, 443)
	tests := []struct {
		name  string
		frame []byte
	}{
		{"different source port", ipv4TCP("192.0.2.1", "198.51.100.7", 1235, 443)},
		{"different destination port", ipv4TCP("192.0.2.1", "198.51.100.7", 1234, 444)},
		{"different source address", ipv4TCP("192.0.2.2", "198.51.100.7", 1234, 443)},
		{"different destination address", ipv4TCP("192.0.2.1", "198.51.100.8", 1234, 443)},
		{"reversed direction", ipv4TCP("198.51.100.7", "192.0.2.1", 443, 1234)},
		{"udp instead of tcp", pppFrame(pppProtoIPv4, frameOpts{}, ipv4Packet("192.0.2.1", "198.51.100.7", 17, 1234, 443, 64, 1, nil))},
	}
	baseIdx := flowHash(base, n, nil)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// With n = 64 a collision is possible in principle, but these are
			// fixed inputs against a fixed hash, so the outcome is stable.
			assert.NotEqual(t, baseIdx, flowHash(tt.frame, n, nil),
				"distinct flows should generally land on distinct streams")
		})
	}
}

func TestFlowHashSpreadsFlowsAcrossStreams(t *testing.T) {
	const n = 8
	counts := make([]int, n)
	const total = 512
	for port := 0; port < total; port++ {
		frame := ipv4TCP("192.0.2.1", "198.51.100.7", uint16(1024+port), 443)
		counts[flowHash(frame, n, nil)]++
	}
	for i, c := range counts {
		assert.NotZero(t, c, "stream %d received no flows at all", i)
		// A perfectly uniform split would be 64 per stream; allow a wide band
		// but still catch a hash that collapses onto a few streams.
		assert.Greater(t, c, total/n/4, "stream %d is starved (%d/%d)", i, c, total)
		assert.Less(t, c, total/n*4, "stream %d is overloaded (%d/%d)", i, c, total)
	}
}

func TestFlowHashRuntAndMalformedInput(t *testing.T) {
	const n = 4
	tests := []struct {
		name  string
		frame []byte
		want  int // pinned current behaviour where the code bails out early
		exact bool
	}{
		{name: "nil", frame: nil, want: 0, exact: true},
		{name: "empty", frame: []byte{}, want: 0, exact: true},
		{name: "single 0xFF", frame: []byte{0xFF}},
		{name: "address control field only", frame: []byte{0xFF, 0x03}, want: 0, exact: true},
		{name: "address control plus one even octet", frame: []byte{0xFF, 0x03, 0x00}, want: 0, exact: true},
		{name: "even octet only", frame: []byte{0x00}, want: 0, exact: true},
		{name: "ipv4 header truncated mid source address", frame: pppFrame(pppProtoIPv4, frameOpts{}, []byte{0x45, 0, 0, 40, 0, 0, 0, 0, 64, 6, 0, 0, 192, 0})},
		{name: "ipv4 header exactly 19 octets", frame: pppFrame(pppProtoIPv4, frameOpts{}, make([]byte, 19))},
		{name: "ipv4 header exactly 20 octets", frame: pppFrame(pppProtoIPv4, frameOpts{}, make([]byte, 20))},
		{name: "ipv6 header exactly 39 octets", frame: pppFrame(pppProtoIPv6, frameOpts{}, make([]byte, 39))},
		{name: "ipv6 header exactly 40 octets", frame: pppFrame(pppProtoIPv6, frameOpts{}, make([]byte, 40))},
		{name: "ipv6 tcp header truncated to 43 octets", frame: pppFrame(pppProtoIPv6, frameOpts{}, func() []byte { p := make([]byte, 43); p[6] = 6; return p }())},
		{name: "version nibble says 6 but ppp protocol says ipv4", frame: pppFrame(pppProtoIPv4, frameOpts{}, ipv6Packet("2001:db8::1", "2001:db8::2", 6, 1, 2, 64, nil))},
		{name: "version nibble says 4 but ppp protocol says ipv6", frame: pppFrame(pppProtoIPv6, frameOpts{}, ipv4Packet("10.0.0.1", "10.0.0.2", 6, 1, 2, 64, 1, make([]byte, 64)))},
		{name: "ihl smaller than 20 octets", frame: pppFrame(pppProtoIPv4, frameOpts{}, func() []byte {
			p := ipv4Packet("10.0.0.1", "10.0.0.2", 6, 1, 2, 64, 1, nil)
			p[0] = 0x43 // IHL 3 -> 12 octets, shorter than the fixed header
			return p
		}())},
		{name: "ihl larger than the packet", frame: pppFrame(pppProtoIPv4, frameOpts{}, func() []byte {
			p := ipv4Packet("10.0.0.1", "10.0.0.2", 6, 1, 2, 64, 1, nil)
			p[0] = 0x4F // IHL 15 -> 60 octets, longer than the packet
			return p
		}())},
		{name: "unknown ppp protocol with a one octet payload", frame: []byte{0x00, 0x2A, 0x01}},
		// No `want` here: the frame is long enough to be hashed for real, so the
		// only honest expectation is the range check below - pinning a specific
		// index would just be re-deriving the digest with the code under test.
		{name: "unknown ppp protocol with no payload", frame: []byte{0x00, 0x2A}},
		{name: "pfc protocol with no payload", frame: []byte{0x21}},
		{name: "all zeroes", frame: make([]byte, 128)},
		{name: "all ones", frame: func() []byte {
			b := make([]byte, 128)
			for i := range b {
				b[i] = 0xFF
			}
			return b
		}()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got int
			require.NotPanics(t, func() { got = flowHash(tt.frame, n, nil) })
			assert.GreaterOrEqual(t, got, 0)
			assert.Less(t, got, n)
			if tt.exact {
				assert.Equal(t, tt.want, got, "pinned early-bailout index")
			}
		})
	}
}

// A non-IP frame is keyed on its PPP protocol number and nothing else, so every
// frame of one control protocol lands on one stream and stays in order. This is
// the property the multi-stream transport depends on: an LCP exchange is a
// conversation, and MLPPP (0x003D) carries its own sequence space, so neither
// may be scattered across independent reliable streams.
func TestFlowHashNonIPProtocolsHashByProtocolAlone(t *testing.T) {
	const n = 16

	// Payloads that differ everywhere, including in their very first octet, must
	// still select the same stream.
	payloads := [][]byte{
		nil,
		{0x01},
		append([]byte{0xAB}, make([]byte, 15)...),
		append(make([]byte, 16), []byte("a completely different tail")...),
		[]byte("01 configure-request, or something else entirely"),
	}
	want := flowHash(pppFrame(pppProtoLCP, frameOpts{acfc: true}, payloads[0]), n, nil)
	for i, payload := range payloads {
		for _, opts := range []frameOpts{{}, {acfc: true}} {
			got := flowHash(pppFrame(pppProtoLCP, opts, payload), n, nil)
			assert.Equal(t, want, got,
				"LCP payload %d (acfc=%v) changed the stream; the payload must not take part in the non-IP hash",
				i, opts.acfc)
		}
	}

	// The same holds for MLPPP, the case that makes this contract load-bearing.
	const pppProtoMultilink = 0x003D
	mlWant := flowHash(pppFrame(pppProtoMultilink, frameOpts{}, []byte{0x40, 0x00, 0x00, 0x01}), n, nil)
	for seq := 2; seq < 64; seq++ {
		got := flowHash(pppFrame(pppProtoMultilink, frameOpts{}, []byte{0x00, 0x00, 0x00, byte(seq)}), n, nil)
		require.Equal(t, mlWant, got, "MLPPP fragment %d was striped onto another stream", seq)
	}

	// Different PPP protocols with the same payload land differently, as long as
	// the protocol numbers differ in their low bits (see
	// TestFlowHashCollidesOnHighBitOnlyDifferences for why that caveat exists).
	lcp := pppFrame(pppProtoLCP, frameOpts{}, []byte{1, 2, 3, 4})
	pap := pppFrame(pppProtoPAP, frameOpts{}, []byte{1, 2, 3, 4})
	assert.NotEqual(t, flowHash(lcp, n, nil), flowHash(pap, n, nil))
}

// CONFORMANCE GAP (n/a - plain bug): flowHash reduces the FNV-1a sum with
// `hash % n`, which for a power-of-two n keeps only the digest's low bits, and
// those are the weakest bits FNV-1a produces. Each FNV-1a step is
// h = (h XOR b) * prime mod 2^32; both XOR and a multiplication modulo 2^32
// carry information only upwards, so the low k bits of the digest are a
// function of the low k bits of the input octets alone. Reducing with % 2^k
// therefore throws away every input bit above bit k-1: two 5-tuples differing
// only in the high bits of an octet land on the same stream for EVERY
// power-of-two stream count up to 2^k, and 2/4/8 streams are exactly what an
// operator configures. (For a non-power-of-two n the reduction does mix in
// higher bits, so this is specifically a power-of-two defect.) The fix is to
// fold or finalise the digest before reducing. This test pins the current
// behaviour so a future fix is a deliberate change.
func TestFlowHashCollidesOnHighBitOnlyDifferences(t *testing.T) {
	tests := []struct {
		name string
		a, b []byte
		// bit is the (0-based) bit position, within the octet, of the single
		// difference between a and b. Everything below it is identical, so the
		// two frames collide for every power-of-two n up to 2^bit.
		bit int
	}{
		{
			// 192 = 0xC0 vs 64 = 0x40: only bit 7 of the first address octet.
			name: "ipv4 source addresses differing only in bit 7 of octet 0",
			a:    ipv4TCP("192.0.2.1", "198.51.100.7", 1234, 443),
			b:    ipv4TCP("64.0.2.1", "198.51.100.7", 1234, 443),
			bit:  7,
		},
		{
			// 0xC021 vs 0x8021: only bit 6 of the high protocol octet.
			name: "ppp protocol numbers differing only in bit 6",
			a:    pppFrame(pppProtoLCP, frameOpts{}, []byte{1, 2, 3, 4}),
			b:    pppFrame(pppProtoIPCP, frameOpts{}, []byte{1, 2, 3, 4}),
			bit:  6,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.NotEqual(t, tt.a, tt.b, "the two frames must actually differ")
			upTo := 1 << tt.bit
			for n := 2; n <= upTo; n *= 2 {
				assert.Equal(t, flowHash(tt.a, n, nil), flowHash(tt.b, n, nil),
					"n=%d: distinct flows currently collide because %% n keeps only the weak low FNV bits", n)
			}
		})
	}
}

func TestFlowHashDebugLogReceivesParsedFields(t *testing.T) {
	type record struct {
		msg    string
		fields map[string]any
	}
	var recs []record
	log := func(msg string, fields ...any) {
		m := make(map[string]any, len(fields)/2)
		for i := 0; i+1 < len(fields); i += 2 {
			m[fields[i].(string)] = fields[i+1]
		}
		recs = append(recs, record{msg: msg, fields: m})
	}

	frame := pppFrame(pppProtoIPv4, frameOpts{acfc: true}, ipv4Packet("192.0.2.1", "198.51.100.7", 6, 1234, 443, 64, 1, nil))
	idx := flowHash(frame, 4, log)
	require.Len(t, recs, 1)
	assert.Equal(t, "PPP flow hash", recs[0].msg)
	assert.Equal(t, uint16(pppProtoIPv4), recs[0].fields["pppProto"])
	assert.Equal(t, uint8(6), recs[0].fields["ipProto"])
	assert.Equal(t, uint16(1234), recs[0].fields["srcPort"])
	assert.Equal(t, uint16(443), recs[0].fields["dstPort"])
	assert.Equal(t, idx, recs[0].fields["streamIdx"])
	assert.Equal(t, "192.0.2.1", recs[0].fields["srcIP"].(net.IP).String())

	recs = nil
	flowHash(pppFrame(pppProtoLCP, frameOpts{}, []byte{1, 2, 3, 4}), 4, log)
	require.Len(t, recs, 1)
	assert.Equal(t, "PPP flow hash (non-IP)", recs[0].msg)
	assert.NotContains(t, recs[0].fields, "srcIP")

	// n <= 1 returns before any logging happens.
	recs = nil
	flowHash(frame, 1, log)
	assert.Empty(t, recs, "no debug log is emitted for the single-stream fast path")
}

// CONFORMANCE GAP (n/a - latent bug): the net.IP values handed to debugLog
// (hash.go:57-58 for IPv4, :72-73 for IPv6) are slices into the caller's frame
// rather than copies, so a logger that retains them or defers their formatting
// - an asynchronous or buffered logger, or anything that samples fields - will
// render whatever the caller later writes into that buffer. flowHash itself
// only reads the bytes, so the hash is unaffected, and both production call
// sites (core/server/server.go:339, core/client/ppp.go:57) pass a nil debugLog,
// so nothing reaches this today: it is a trap for the next caller that supplies
// one. This test pins the current aliasing so a future fix is a deliberate
// change.
func TestFlowHashDebugLogAliasesCallerBuffer(t *testing.T) {
	var captured net.IP
	log := func(msg string, fields ...any) {
		for i := 0; i+1 < len(fields); i += 2 {
			if fields[i] == "srcIP" {
				captured, _ = fields[i+1].(net.IP)
			}
		}
	}
	frame := pppFrame(pppProtoIPv4, frameOpts{}, ipv4Packet("192.0.2.1", "198.51.100.7", 6, 1234, 443, 64, 1, nil))
	flowHash(frame, 4, log)
	require.NotNil(t, captured)
	require.Equal(t, "192.0.2.1", captured.String())

	// Reuse the frame buffer, exactly as a packet-loop reading into a shared
	// scratch buffer would.
	copy(frame[2+12:2+16], []byte{203, 0, 113, 9})
	assert.Equal(t, "203.0.113.9", captured.String(),
		"the logged net.IP still points at the caller's buffer")
}

func FuzzFlowHash(f *testing.F) {
	for _, tc := range representativeFrames() {
		f.Add(tc.frame, 4)
		f.Add(tc.frame, 1)
	}
	f.Add([]byte(nil), 0)
	f.Add([]byte{0xFF, 0x03, 0x00, 0x21}, -3)
	f.Add([]byte{0x00, 0x21, 0x45}, 2)
	f.Add([]byte{0x00, 0x57}, 255)

	f.Fuzz(func(t *testing.T, frame []byte, rawN int) {
		// Keep n in a range a caller could plausibly reach (0..256), including
		// the degenerate values, without asking the fuzzer for a giant slice.
		n := rawN % 257
		idx := flowHash(frame, n, nil)
		if n <= 1 {
			if idx != 0 {
				t.Fatalf("flowHash(frame, %d) = %d, want 0 for the n <= 1 fast path", n, idx)
			}
			return
		}
		if idx < 0 || idx >= n {
			t.Fatalf("flowHash(frame, %d) = %d, out of range [0, %d)", n, idx, n)
		}
		// The hash must depend only on the frame contents, not on the backing
		// array, and must be stable across calls.
		cp := append([]byte(nil), frame...)
		if got := flowHash(cp, n, nil); got != idx {
			t.Fatalf("flowHash is not a pure function of the bytes: %d != %d", got, idx)
		}
		// Debug logging must not change the result or panic on any input.
		if got := flowHash(frame, n, func(string, ...any) {}); got != idx {
			t.Fatalf("debug logging changed the result: %d != %d", got, idx)
		}
	})
}
