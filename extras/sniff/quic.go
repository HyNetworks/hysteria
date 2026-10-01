package sniff

import (
	"bytes"
	"cmp"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"slices"

	"golang.org/x/crypto/cryptobyte"

	"github.com/apernet/quic-go/quicvarint"
)

// quicVersions are the QUIC versions whose Initial packets we can decrypt (RFC 9001, RFC 9369).
var quicVersions = map[uint32]struct {
	salt        []byte
	initialType uint8
	labelPrefix string
}{
	0x00000001: {
		salt:        []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a},
		initialType: 0b00,
		labelPrefix: "quic ",
	},
	0x6b3343cf: {
		salt:        []byte{0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9},
		initialType: 0b01,
		labelPrefix: "quicv2 ",
	},
}

// quicCrypto collects the CRYPTO frames in the client Initial packets of a QUIC connection.
// Clients like Chrome split the ClientHello across packets, and shuffle its fragments.
type quicCrypto struct {
	dcid   []byte
	frames []quicCryptoFrame
}

type quicCryptoFrame struct {
	offset uint64
	data   []byte
}

// feed collects the CRYPTO frames of the Initial packets coalesced in a datagram,
// and reports whether it had any.
func (c *quicCrypto) feed(b []byte) bool {
	found := false
	for len(b) > 0 {
		s := cryptobyte.String(b)
		var first uint8
		var version uint32
		var dcid, scid, token cryptobyte.String
		var length uint64
		if !s.ReadUint8(&first) || first&0x80 == 0 || // Long header
			!s.ReadUint32(&version) ||
			!s.ReadUint8LengthPrefixed(&dcid) ||
			!s.ReadUint8LengthPrefixed(&scid) {
			break
		}
		v, ok := quicVersions[version]
		if !ok {
			break
		}
		initial := (first>>4)&0b11 == v.initialType
		if initial && !readVarintPrefixed(&s, &token) {
			break
		}
		if !readVarint(&s, &length) || uint64(len(s)) < length {
			break
		}
		pnOffset := len(b) - len(s)
		packet := b[:pnOffset+int(length)]
		b = b[len(packet):]
		if !initial || c.dcid != nil && !bytes.Equal(dcid, c.dcid) {
			continue
		}
		payload := decryptInitial(packet, pnOffset, dcid, v.salt, v.labelPrefix)
		if payload == nil {
			continue
		}
		c.dcid = dcid
		c.frames = appendCryptoFrames(c.frames, payload)
		found = true
	}
	return found
}

// stream returns the contiguous start of the CRYPTO stream.
func (c *quicCrypto) stream() []byte {
	slices.SortFunc(c.frames, func(a, b quicCryptoFrame) int { return cmp.Compare(a.offset, b.offset) })
	var stream []byte
	for _, f := range c.frames {
		n := uint64(len(stream))
		if f.offset > n {
			break
		}
		if f.offset+uint64(len(f.data)) > n {
			stream = append(stream, f.data[n-f.offset:]...)
		}
	}
	return stream
}

// decryptInitial removes the protection of a client Initial packet (RFC 9001, Section 5),
// and returns its payload, or nil if it can't.
func decryptInitial(packet []byte, pnOffset int, dcid, salt []byte, labelPrefix string) []byte {
	if len(packet) < pnOffset+4+16 {
		return nil
	}
	secret, _ := hkdf.Extract(sha256.New, dcid, salt)
	secret = hkdfExpandLabel(secret, "client in", sha256.Size)

	// Header protection
	hp, _ := aes.NewCipher(hkdfExpandLabel(secret, labelPrefix+"hp", 16))
	mask := make([]byte, 16)
	hp.Encrypt(mask, packet[pnOffset+4:pnOffset+4+16])
	header := slices.Clone(packet[:pnOffset+4])
	header[0] ^= mask[0] & 0x0f
	pnLen := int(header[0]&0x03) + 1
	header = header[:pnOffset+pnLen]
	var pn uint64
	for i := range pnLen {
		header[pnOffset+i] ^= mask[1+i]
		pn = pn<<8 | uint64(header[pnOffset+i])
	}

	// Packet protection. The packet number is the truncated one, as nothing has been
	// received on the connection that could make it larger.
	block, _ := aes.NewCipher(hkdfExpandLabel(secret, labelPrefix+"key", 16))
	aead, _ := cipher.NewGCM(block)
	nonce := hkdfExpandLabel(secret, labelPrefix+"iv", aead.NonceSize())
	binary.BigEndian.PutUint64(nonce[4:], binary.BigEndian.Uint64(nonce[4:])^pn)
	payload, err := aead.Open(nil, nonce, packet[pnOffset+pnLen:], header)
	if err != nil {
		return nil
	}
	return payload
}

// appendCryptoFrames appends the CRYPTO frames in a decrypted Initial packet payload.
// It stops at the first frame that isn't PADDING, PING or CRYPTO, as a client doesn't
// send any other before it hears from the server.
func appendCryptoFrames(frames []quicCryptoFrame, payload []byte) []quicCryptoFrame {
	s := cryptobyte.String(payload)
	for !s.Empty() {
		var typ, offset uint64
		var data cryptobyte.String
		if !readVarint(&s, &typ) {
			break
		}
		switch typ {
		case 0x00, 0x01: // PADDING, PING
		case 0x06: // CRYPTO
			if !readVarint(&s, &offset) || !readVarintPrefixed(&s, &data) {
				return frames
			}
			frames = append(frames, quicCryptoFrame{offset, data})
		default:
			return frames
		}
	}
	return frames
}

func readVarint(s *cryptobyte.String, v *uint64) bool {
	n, l, err := quicvarint.Parse(*s)
	if err != nil {
		return false
	}
	*v = n
	return s.Skip(l)
}

func readVarintPrefixed(s, out *cryptobyte.String) bool {
	var n uint64
	if !readVarint(s, &n) || uint64(len(*s)) < n {
		return false
	}
	return s.ReadBytes((*[]byte)(out), int(n))
}

// hkdfExpandLabel implements HKDF-Expand-Label from RFC 8446, Section 7.1, with an empty context.
func hkdfExpandLabel(secret []byte, label string, length int) []byte {
	info := []byte{byte(length >> 8), byte(length), byte(len("tls13 ") + len(label))}
	info = append(info, "tls13 "...)
	info = append(info, label...)
	info = append(info, 0)
	out, _ := hkdf.Expand(sha256.New, secret, string(info), length)
	return out
}
