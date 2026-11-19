package frag

import (
	"github.com/apernet/hysteria/core/v2/internal/protocol"
)

func FragUDPMessage(m *protocol.UDPMessage, maxSize int) []protocol.UDPMessage {
	if m.Size() <= maxSize {
		return []protocol.UDPMessage{*m}
	}
	fullPayload := m.Data
	maxPayloadSize := maxSize - m.HeaderSize()
	if maxPayloadSize <= 0 {
		return nil
	}
	// UDPMessage.FragCount is a uint8 on the wire, so a message cannot be
	// split into more than 255 fragments. Compute the count with an int first
	// to avoid uint8 overflow producing a short (or empty) slice.
	fragCount := (len(fullPayload) + maxPayloadSize - 1) / maxPayloadSize // round up
	if fragCount > 255 {
		return nil
	}
	off := 0
	fragID := uint8(0)
	frags := make([]protocol.UDPMessage, fragCount)
	for off < len(fullPayload) {
		payloadSize := len(fullPayload) - off
		if payloadSize > maxPayloadSize {
			payloadSize = maxPayloadSize
		}
		frag := *m
		frag.FragID = fragID
		frag.FragCount = uint8(fragCount)
		frag.Data = fullPayload[off : off+payloadSize]
		frags[fragID] = frag
		off += payloadSize
		fragID++
	}
	return frags
}

// Defragger handles the defragmentation of UDP messages.
// The current implementation can only handle one packet ID at a time.
// If another packet arrives before a packet has received all fragments
// in their entirety, any previous state is discarded.
type Defragger struct {
	pktID uint16
	frags []*protocol.UDPMessage
	count uint8
	size  int // data size
}

func (d *Defragger) Feed(m *protocol.UDPMessage) *protocol.UDPMessage {
	if m.FragCount <= 1 {
		return m
	}
	if m.FragID >= m.FragCount {
		// wtf is this?
		return nil
	}
	if m.PacketID != d.pktID || m.FragCount != uint8(len(d.frags)) {
		// new message, clear previous state
		d.pktID = m.PacketID
		d.frags = make([]*protocol.UDPMessage, m.FragCount)
		d.frags[m.FragID] = m
		d.count = 1
		d.size = len(m.Data)
	} else if d.frags[m.FragID] == nil {
		d.frags[m.FragID] = m
		d.count++
		d.size += len(m.Data)
		if int(d.count) == len(d.frags) {
			// all fragments received, assemble
			data := make([]byte, d.size)
			off := 0
			for _, frag := range d.frags {
				off += copy(data[off:], frag.Data)
			}
			m.Data = data
			m.FragID = 0
			m.FragCount = 1
			return m
		}
	}
	return nil
}
