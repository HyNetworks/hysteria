package pppbridge

import "sync/atomic"

// Counters accumulate the PPP traffic one link has carried.
//
// This exists because a member of a Multilink PPP bundle is the one thing on the
// router whose traffic nothing else can measure. The kernel keeps byte counters
// on the bundle unit and none at all on a channel -- there is no netdev, no
// /sys entry and no ioctl -- and pppd never even computes per-link figures for a
// member, because it returns early from start_networks() once the join succeeds.
// So the only place a member's share of the bundle is visible is here, in the
// process that carries it, which is one process per link by construction.
//
// The numbers are PPP frames with HDLC already stripped, which is neither what
// the subscriber sent nor what the WAN carried. They run above user payload by
// the PPP header and the per-fragment Multilink header, and by every LCP echo --
// members echo every five seconds, so an idle link in a bundle still counts. And
// they run below the wire by HDLC framing, the QUIC header and AEAD tag, UDP/IP,
// obfuscation padding, and every retransmission. The figure to compare them
// against is each other, not the bundle device's rx_bytes.
type Counters struct {
	RxBytes  atomic.Uint64
	RxFrames atomic.Uint64
	TxBytes  atomic.Uint64
	TxFrames atomic.Uint64
}

// Snapshot is a reading of all four counters, taken for publication.
type Snapshot struct {
	RxBytes  uint64
	RxFrames uint64
	TxBytes  uint64
	TxFrames uint64
}

// Read takes a snapshot.
//
// Deliberately not atomic across the four loads: a sampler running once a second
// against counters moving at line rate would have to stop the relay to get a
// consistent tuple, and the cost of that is real while the benefit is not. The
// four values can disagree by at most one frame, which is invisible in a figure
// rendered as megabytes.
func (c *Counters) Read() Snapshot {
	if c == nil {
		return Snapshot{}
	}
	return Snapshot{
		RxBytes:  c.RxBytes.Load(),
		RxFrames: c.RxFrames.Load(),
		TxBytes:  c.TxBytes.Load(),
		TxFrames: c.TxFrames.Load(),
	}
}

// addRx records a frame that arrived from the transport and was handed to the
// endpoint.
func (c *Counters) addRx(n int) {
	c.RxBytes.Add(uint64(n))
	c.RxFrames.Add(1)
}

// addTx records a frame that came from the endpoint and was accepted by the
// transport.
func (c *Counters) addTx(n int) {
	c.TxBytes.Add(uint64(n))
	c.TxFrames.Add(1)
}
