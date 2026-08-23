package pppbridge

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCalculatePPPMTU(t *testing.T) {
	tests := []struct {
		name        string
		wanMTU      int
		outerIPv6   bool
		salamander  bool
		dataStreams int
		want        int
	}{
		// Datagram mode: framing = 41 (quic-go's per-packet reserve(37)+PPP(4)).
		// The reserve rather than the 28-octet wire header, because what refuses
		// an oversize datagram is quic-go's estimate; see quicDatagramReserve.
		// maxQUIC = min(WAN-outerIP-UDP[-sal], 1452) - 21
		// PPP MTU = maxQUIC - framing
		{"datagram IPv4 no sal", 1500, false, false, 0, 1390},
		{"datagram IPv4 with sal", 1500, false, true, 0, 1390},
		{"datagram IPv6 no sal", 1500, true, false, 0, 1390},
		{"datagram IPv6 with sal", 1500, true, true, 0, 1382},
		// Multi-stream: framing = 40 (QUIC(9)+AEAD(16)+STREAM(9)+LenPfx(2)+PPP(4))
		{"multistream IPv4 no sal", 1500, false, false, 20, 1391},
		{"multistream IPv4 with sal", 1500, false, true, 20, 1391},
		{"multistream IPv6 no sal", 1500, true, false, 20, 1391},
		{"multistream IPv6 with sal", 1500, true, true, 20, 1383},
		// Multilink adds 4 bytes overhead
		// Edge cases
		{"PPPoE WAN datagram", 1492, false, false, 0, 1390},
		{"tiny WAN clamp to min", 200, true, true, 0, 576},
		{"jumbo WAN clamp to max", 9000, false, false, 0, 1390},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CalculatePPPMTU(tt.wanMTU, tt.outerIPv6, tt.salamander, tt.dataStreams)
			assert.Equal(t, tt.want, got)
		})
	}
}

// AutoPPPMTU is what sizes a link that has not been measured. It no longer asks
// the host anything, so unlike the version that probed the egress interface its
// answer is fully determined by the arguments -- which is what makes it worth
// pinning exactly rather than by inequalities.
func TestAutoPPPMTUAssumesAnEthernetPath(t *testing.T) {
	v4 := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 443}
	v6 := &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 443}

	assert.Equal(t,
		CalculatePPPMTU(1500, false, false, 0),
		AutoPPPMTU(MTUParams{RemoteAddr: v4}),
		"an IPv4 peer is sized as a 1500-octet Ethernet path")

	assert.Equal(t,
		CalculatePPPMTU(1500, true, false, 0),
		AutoPPPMTU(MTUParams{RemoteAddr: v6}),
		"an IPv6 peer pays the larger outer header")
}

// With no destination at all the answer must be the smaller one. "We do not know"
// producing a larger MTU than a known path would size the link above something it
// then turns out not to fit.
func TestAutoPPPMTUFallsBackToTheWorstCase(t *testing.T) {
	known := AutoPPPMTU(MTUParams{
		RemoteAddr: &net.UDPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 443},
	})
	unknown := AutoPPPMTU(MTUParams{RemoteAddr: nil})

	assert.GreaterOrEqual(t, known, minPPPMTU)
	assert.LessOrEqual(t, known, maxPPPMTU)
	assert.Less(t, unknown, known,
		"not knowing the path must never produce a larger MTU than knowing it")

	// The unknown case is IPv6 plus Salamander, whatever the caller said about
	// obfuscation.
	assert.Equal(t, CalculatePPPMTU(1500, true, true, 0), unknown)
}

// A destination that is not a UDP address -- which is what the server side sees,
// since a client's remote address arrives as whatever the transport reports --
// is sized as IPv4 rather than treated as unknown.
func TestAutoPPPMTUHandlesANonUDPAddress(t *testing.T) {
	got := AutoPPPMTU(MTUParams{
		RemoteAddr:  &net.TCPAddr{IP: net.IPv4(198, 51, 100, 7), Port: 443},
		DataStreams: 4,
	})
	assert.Equal(t, CalculatePPPMTU(1500, false, false, 4), got)
}

// The one number in this file that cannot be derived from the others, pinned to
// its value rather than to a relationship. Every other multilink assertion is
// written as "ceiling minus MLPPPOverhead", so all of them would follow the
// constant quietly if it were changed back.
//
// Six is what pppd 2.5.2 can actually transmit: short sequence numbers on
// transmit need ho->neg_ssnhf, lcp.c:1784 refuses to set it unless
// ao->neg_ssnhf is set, and nothing in pppd ever sets that -- "mpshortseq"
// reaches lcp_wantoptions, which is the receive direction. See MLPPPOverhead.
//
// At 4 the bundle MTU is two octets too large. That is invisible while several
// links share the load and drops every full-size packet once one link is left,
// so it presents as the redundancy not working.
func TestMLPPPOverheadIsTheLongSequenceHeader(t *testing.T) {
	assert.Equal(t, 6, MLPPPOverhead,
		"pppd cannot negotiate short-sequence transmit, so the header is always 6 octets")
}

// The invariant the model owes quic-go, stated without a network so that no
// amount of probe luck can hide a violation.
//
// quic-go refuses a datagram above estimateMaxPayloadSize(CurrentSize), which is
// CurrentSize - 37, and done() lets CurrentSize settle as much as maxMTUDiff+1 =
// 21 below the true path -- which is what pmtudSafetyMargin covers. So the frame
// CalculatePPPMTU permits has to fit in (path - 21) - 37.
//
// Budgeting the real 28-octet wire header instead of the 37 quic-go enforces put
// this nine octets negative. The simulation could not see it: loss-free the
// ladder happens to converge one byte inside, and every case in this file was
// loss-free.
func TestCalculatePPPMTUFitsQUICsWorstCaseBudget(t *testing.T) {
	// estimateMaxPayloadSize: type byte + maximum connection ID + AEAD tag.
	const quicGoReserve = 37

	for _, wan := range []int{1500, 1492, 1480, 1420, 1360, 1300} {
		for _, v6 := range []bool{false, true} {
			for _, sal := range []bool{false, true} {
				mtu := CalculatePPPMTU(wan, v6, sal, 0)
				if mtu <= minPPPMTU {
					continue // clamped: the path is narrower than PPP allows anyway
				}

				outerIP := ipv4Header
				if v6 {
					outerIP = ipv6Header
				}
				packet := wan - outerIP - udpHeader
				if sal {
					packet -= salamanderCost
				}
				if packet > quicMaxPacketBufferSize {
					packet = quicMaxPacketBufferSize
				}
				// The smallest size discovery may settle on and still call itself done.
				settled := packet - pmtudSafetyMargin

				assert.LessOrEqual(t, mtu+PPPHeaderLen, settled-quicGoReserve,
					"wan=%d v6=%v sal=%v: an MTU of %d frames %d octets, which quic-go "+
						"refuses once discovery settles at %d", wan, v6, sal, mtu, mtu+PPPHeaderLen, settled)
			}
		}
	}
}

// AutoPPPMTU reports what one link carries. The bundle MTU is that minus the
// multilink header, and it is the caller that subtracts it -- keeping the two
// numbers distinct at the point where the difference is visible.
func TestAutoPPPMTUReportsTheLinkCeilingNotTheBundleMTU(t *testing.T) {
	addr := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 443}
	linkMRU := AutoPPPMTU(MTUParams{RemoteAddr: addr})

	assert.Equal(t, 1390, linkMRU, "the link ceiling on an ordinary 1500-octet path")
	assert.Equal(t, 1384, linkMRU-MLPPPOverhead, "what the bundle may advertise")
}
