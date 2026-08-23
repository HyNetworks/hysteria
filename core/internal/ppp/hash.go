package ppp

import (
	"encoding/binary"
	"hash/fnv"
	"net"
)

// flowHash parses a raw PPP frame to extract the inner IP 5-tuple,
// hashes it with FNV-1a, and returns an index in [0, n).
// For non-IP protocols, it hashes the PPP protocol field.
func flowHash(frame []byte, n int, debugLog DebugLogFunc) int {
	if n <= 1 {
		return 0
	}

	off := 0
	if len(frame) < 1 {
		return 0
	}
	// Skip address/control field (FF 03) if present
	if len(frame) >= 2 && frame[0] == 0xFF && frame[1] == 0x03 {
		off = 2
	}
	if off >= len(frame) {
		return 0
	}

	// Read protocol field: PFC means 1 byte when low bit is set
	var proto uint16
	if frame[off]&0x01 == 1 {
		proto = uint16(frame[off])
		off++
	} else {
		if off+2 > len(frame) {
			return 0
		}
		proto = binary.BigEndian.Uint16(frame[off : off+2])
		off += 2
	}

	payload := frame[off:]
	h := fnv.New32a()

	var srcIP, dstIP net.IP
	var ipProto uint8
	var srcPort, dstPort uint16
	var isIP bool

	switch proto {
	case 0x0021: // IPv4
		if len(payload) < 20 {
			break
		}
		isIP = true
		ipProto = payload[9]
		srcIP = net.IP(payload[12:16])
		dstIP = net.IP(payload[16:20])
		ihl := int(payload[0]&0x0F) * 4
		if ihl >= 20 && len(payload) >= ihl+4 {
			if ipProto == 6 || ipProto == 17 { // TCP or UDP
				srcPort = binary.BigEndian.Uint16(payload[ihl : ihl+2])
				dstPort = binary.BigEndian.Uint16(payload[ihl+2 : ihl+4])
			}
		}
	case 0x0057: // IPv6
		if len(payload) < 40 {
			break
		}
		isIP = true
		ipProto = payload[6]
		srcIP = net.IP(payload[8:24])
		dstIP = net.IP(payload[24:40])
		if len(payload) >= 44 {
			if ipProto == 6 || ipProto == 17 { // TCP or UDP
				srcPort = binary.BigEndian.Uint16(payload[40:42])
				dstPort = binary.BigEndian.Uint16(payload[42:44])
			}
		}
	}

	if isIP {
		_, _ = h.Write(srcIP)
		_, _ = h.Write(dstIP)
		_ = binary.Write(h, binary.BigEndian, ipProto)
		_ = binary.Write(h, binary.BigEndian, srcPort)
		_ = binary.Write(h, binary.BigEndian, dstPort)
	} else {
		// Protocol only, deliberately not the payload: every frame of a given
		// non-IP protocol has to land on the same stream.
		//
		// The non-IP protocols here are the PPP control protocols and, when MLPPP
		// is negotiated, multilink (0x003D). Both are ordered sequences -- an LCP
		// exchange is a conversation, and MP carries its own sequence space that
		// the peer reassembles in order. Mixing the payload into the key would
		// scatter either of them across independent reliable streams, which can
		// reorder them relative to each other.
		//
		// The cost is that once MLPPP is negotiated every frame is 0x003D, so
		// dataStreams > 0 collapses to a single stream. That is the correct
		// outcome rather than a regression: striping an MP sequence is not safe.
		_ = binary.Write(h, binary.BigEndian, proto)
	}

	hashVal := h.Sum32()
	idx := int(hashVal) % n
	// Only reachable where int is 32 bits, which makes the conversion above
	// signed: a negative index would be an out-of-range write into m.writeMu.
	if idx < 0 {
		idx += n
	}

	if debugLog != nil {
		if isIP {
			debugLog(
				"PPP flow hash",
				"pppProto", proto,
				"srcIP", srcIP,
				"dstIP", dstIP,
				"ipProto", ipProto,
				"srcPort", srcPort,
				"dstPort", dstPort,
				"hash", hashVal,
				"streamIdx", idx,
			)
		} else {
			debugLog(
				"PPP flow hash (non-IP)",
				"pppProto", proto,
				"hash", hashVal,
				"streamIdx", idx,
			)
		}
	}

	return idx
}
