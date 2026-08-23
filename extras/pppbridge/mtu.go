package pppbridge

import (
	"net"
)

// PPP over Hysteria2 MTU overhead breakdown:
//
// The max inner IP packet (PPP MTU) is constrained by the smallest bottleneck
// in the encapsulation chain. For datagram mode, the QUIC datagram must fit in
// a single QUIC packet whose size is limited by both the WAN path MTU and
// quic-go's internal MaxPacketBufferSize (1452, hardcoded for IPv6 worst case).
// PMTUD binary search adds further tolerance loss (up to maxMTUDiff+1 = 21 bytes).
//
// === Datagram mode (dataStreams == 0): ===
//
//   QUIC packet (UDP payload, after PMTUD):
//    |- quic-go's per-packet reserve: 37 B  (see quicDatagramReserve)
//    |- PPP header (FF 03 + proto):    4 B
//    '- Inner IP packet:              <-- this is the PPP MTU
//
//   Framing overhead: 41 B = reserve(37) + PPP(4)
//
//   The reserve is quic-go's own figure and not the wire header, which is only
//   28 B (QUIC(9) + AEAD(16) + DATAGRAM(3)). What refuses an oversize datagram
//   is quic-go's estimate, so the estimate is what has to be budgeted for; see
//   quicDatagramReserve.
//
// === Multi-stream mode (dataStreams > 0): ===
//
//   QUIC packet (UDP payload, after PMTUD):
//    |- QUIC short header:           9 B
//    |- QUIC AEAD tag:              16 B
//    |- QUIC STREAM frame header:    9 B
//    |- Length prefix:                2 B
//    |- PPP header (FF 03 + proto):  4 B
//    '- Inner IP packet:            <-- this is the PPP MTU
//
//   Framing overhead: 40 B = QUIC(9) + AEAD(16) + STREAM(9) + LenPfx(2) + PPP(4)

const (
	// quic-go caps PMTUD at this value (1500 - 40 IPv6 - 8 UDP), even for IPv4.
	quicMaxPacketBufferSize = 1452
	// PMTUD binary search stops when max-min <= maxMTUDiff (20). Worst-case
	// convergence leaves the discovered size up to maxMTUDiff+1 below the true max.
	pmtudSafetyMargin = 21

	// 1 (type byte) + CID(4) + PN. The packet number field is 1-4 octets and
	// quic-go picks the width at send time, so assuming the narrowest is not
	// safe: measured against real quic-go at the MaxPacketBufferSize ceiling,
	// a 7-octet estimate leaves the computed MTU one byte too large and every
	// full-size frame is refused. Budget for the widest packet number instead.
	// See TestMTUSimulationAgainstRealQUIC, which asserts non-negative headroom.
	quicShortHeader       = 9  // 1 (type byte) + CID(4) + PN(4, worst case)
	quicAEADTag           = 16 // Poly1305
	datagramFrameOverhead = 3  // type(1) + length varint(2)

	// What quic-go reserves per packet before it will accept a datagram, and
	// therefore what a datagram-mode frame has to be budgeted against.
	//
	// It refuses anything above estimateMaxPayloadSize(CurrentSize), which is
	// CurrentSize - 1 - 20 - 16: a type byte, the *maximum* connection ID length
	// rather than the one in use, and the AEAD tag. That is deliberately
	// conservative on quic-go's part and it is not negotiable from here -- the
	// datagram is refused against this number whatever the real header costs.
	//
	// Budgeting the real header instead is what this used to do, and it left the
	// computed MTU nine octets above what the transport would take: 28 modelled
	// against 37 enforced. Loss-free that still converged with a single byte of
	// slack, so it passed every test and every ordinary path; one lost probe near
	// the top of the ladder erased it, and every full-size packet was then
	// dropped by the relay with the path perfectly healthy.
	//
	// The three constants above stay because the multi-stream branch is a real
	// framing calculation -- a stream frame that spans packets is merely
	// inefficient, never refused -- and because the difference between the two
	// numbers is the point being recorded here.
	quicDatagramReserve = 37
	streamFrameOverhead = 9 // type(1) + stream ID(~4) + offset(~2) + length(~2)
	lengthPrefix        = 2
	// PPPHeaderLen is what a PPP frame costs on top of the packet inside it:
	// address, control, and a two-octet protocol field. It is the exact
	// difference between an MTU and the frame that carries it, which is why the
	// transport ceiling is quoted as MTU + this and not as the MTU.
	PPPHeaderLen = 4 // FF 03 + protocol(2)

	// MLPPPOverhead is what one multilink header costs, and therefore how far the
	// bundle MTU sits below what a single link can carry. The links negotiate the
	// ceiling; the bundle is this much less, because a packet sent as a single
	// fragment -- which is what happens whenever the bundle is down to one live
	// link -- still has to fit inside it.
	//
	// Six, not four. The kernel picks between them at ppp_generic.c:1953,
	//
	//	hdrlen = (ppp->flags & SC_MP_XSHORTSEQ)? MPHDRLEN_SSN: MPHDRLEN;
	//
	// where MPHDRLEN is 6 (00 3D plus a 4-octet long-sequence header) and
	// MPHDRLEN_SSN is 4. SC_MP_XSHORTSEQ comes from the tssn argument of
	// cfg_bundle(), which multilink.c passes as ho->neg_ssnhf -- short sequence
	// numbers on transmit only if we ACKed the peer's request for them.
	//
	// pppd 2.5.2 can never ACK it. lcp.c:1784 rejects the option unless
	// ao->neg_ssnhf is set, and nothing sets it: lcp_init() BZEROs
	// lcp_allowoptions[0] and assigns eleven fields by hand, none of them this
	// one, and the "mpshortseq" option cannot reach it either -- o_bool writes
	// its addr2 only under OPT_A2COPY/A2CLR/A2CLRB/A2OR (options.c:843) and
	// mpshortseq carries none of them. It sets lcp_wantoptions instead, which is
	// the receive direction. So the option asks the peer to send short sequence
	// numbers and says nothing about what we send.
	//
	// Transmit is therefore always long-sequence, and the cost is always 6. At 4
	// the bundle MTU is two octets too large, which is invisible while two or more
	// links are up -- each fragment is about len/nfree -- and drops every
	// full-size packet the moment one link is left. It reads as "the redundancy
	// does not work", which is the opposite of what a bundle is for.
	MLPPPOverhead = 6

	udpHeader      = 8
	ipv4Header     = 20
	ipv6Header     = 40
	salamanderCost = 8
	minPPPMTU      = 576
	maxPPPMTU      = 1500
)

// CalculatePPPMTU computes the largest inner packet ONE LINK can carry, given
// the WAN interface MTU, whether the outer connection uses IPv6, whether
// Salamander obfuscation is on, and the dataStreams count (0 = datagram mode,
// >0 = multi-stream mode).
//
// The calculation accounts for quic-go's MaxPacketBufferSize cap and PMTUD
// binary search convergence tolerance.
//
// This is the link ceiling and not the bundle MTU. Multilink is not a parameter
// here on purpose: it used to be, and callers passed false and then subtracted
// MLPPPOverhead themselves, so the same octets were accounted for in two places
// and only one of them was ever used. Subtracting at the call site is the one
// that survived, because it is where the difference between "what a link
// carries" and "what the bundle advertises" is visible.
func CalculatePPPMTU(wanMTU int, outerIsIPv6, salamander bool, dataStreams int) int {
	outerIP := ipv4Header
	if outerIsIPv6 {
		outerIP = ipv6Header
	}

	maxQUICPacket := wanMTU - outerIP - udpHeader
	if salamander {
		maxQUICPacket -= salamanderCost
	}
	if maxQUICPacket > quicMaxPacketBufferSize {
		maxQUICPacket = quicMaxPacketBufferSize
	}
	maxQUICPacket -= pmtudSafetyMargin

	var framingOverhead int
	if dataStreams > 0 {
		framingOverhead = quicShortHeader + quicAEADTag + streamFrameOverhead + lengthPrefix + PPPHeaderLen
	} else {
		framingOverhead = quicDatagramReserve + PPPHeaderLen
	}
	mtu := maxQUICPacket - framingOverhead
	if mtu < minPPPMTU {
		mtu = minPPPMTU
	}
	// Unreachable while quic-go caps a packet at 1452: the largest this can
	// compute is 1452 - 21 - 41 = 1390. It stays because that cap is quic-go's
	// choice, not ours, and a fork or a future release that raised it would
	// otherwise hand pppd an MTU above what PPP allows.
	if mtu > maxPPPMTU {
		mtu = maxPPPMTU
	}
	return mtu
}

// ClampPPPMTU bounds an MTU to the range PPP allows.
//
// For the figures that do not come from CalculatePPPMTU -- one negotiated with
// the far end, one an operator typed -- because those carry no bound of their
// own and pppd accepts an unusable one without complaint.
func ClampPPPMTU(mtu int) int {
	if mtu > maxPPPMTU {
		return maxPPPMTU
	}
	if mtu < minPPPMTU {
		return minPPPMTU
	}
	return mtu
}

// MTUParams configures auto PPP MTU calculation.
type MTUParams struct {
	RemoteAddr  net.Addr
	Salamander  bool
	DataStreams int
}

// AutoPPPMTU calculates a PPP MTU for a path that has not been measured.
//
// This is the value used before Path MTU discovery has anything to say, and the
// only one available where it never will -- quic-go sets the DF bit on Linux,
// Windows and macOS alone, so on any other platform pmtud.DisablePathMTUDiscovery
// forces discovery off and probes would be fragmented rather than refused. Every
// caller prefers a measured figure and reaches this only when there is none.
//
// The link is assumed to be a 1500-octet Ethernet path. Assuming rather than
// asking the interface is deliberate: the local NIC's MTU describes the first
// hop and nothing beyond it, so a smaller number there is not evidence about the
// path and a larger one is not permission. Where the real path is narrower the
// answer is discovery, which measures it end to end, or PATH_NARROWED, which
// rebuilds the link when it turns out to have been too big.
func AutoPPPMTU(p MTUParams) int {
	const assumedWANMTU = 1500
	isIPv6 := false

	if udpAddr, ok := p.RemoteAddr.(*net.UDPAddr); ok && udpAddr != nil {
		isIPv6 = udpAddr.IP.To4() == nil
	} else if p.RemoteAddr == nil {
		// Unknown remote: assume worst case
		isIPv6 = true
		p.Salamander = true
	}

	return CalculatePPPMTU(assumedWANMTU, isIPv6, p.Salamander, p.DataStreams)
}
