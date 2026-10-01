package sniff

import (
	"io"

	"golang.org/x/crypto/cryptobyte"
)

// readClientHello reads TLS records from r until it has a ClientHello, which can be
// fragmented across records, and returns its body.
func readClientHello(r io.Reader) []byte {
	var stream []byte
	header := make([]byte, 5)
	for {
		if _, err := io.ReadFull(r, header); err != nil || header[0] != 0x16 || header[1] != 0x03 {
			return nil
		}
		fragment := make([]byte, int(header[3])<<8|int(header[4]))
		if _, err := io.ReadFull(r, fragment); err != nil {
			return nil
		}
		stream = append(stream, fragment...)
		if hello, more := clientHello(stream); !more {
			return hello
		}
	}
}

// clientHello returns the body of the ClientHello message at the start of a TLS handshake stream.
// more reports that the stream is too short to tell.
func clientHello(stream []byte) (hello []byte, more bool) {
	if len(stream) < 4 {
		return nil, true
	}
	if stream[0] != 1 { // client_hello
		return nil, false
	}
	n := int(stream[1])<<16 | int(stream[2])<<8 | int(stream[3])
	if len(stream) < 4+n {
		return nil, true
	}
	return stream[4 : 4+n], false
}

// serverName returns the host_name in the server_name extension of a ClientHello body.
func serverName(hello []byte) string {
	s := cryptobyte.String(hello)
	var skipped, exts cryptobyte.String
	if !s.Skip(2+32) || // legacy_version, random
		!s.ReadUint8LengthPrefixed(&skipped) || // legacy_session_id
		!s.ReadUint16LengthPrefixed(&skipped) || // cipher_suites
		!s.ReadUint8LengthPrefixed(&skipped) || // legacy_compression_methods
		!s.ReadUint16LengthPrefixed(&exts) {
		return ""
	}
	for !exts.Empty() {
		var typ uint16
		var ext, names cryptobyte.String
		if !exts.ReadUint16(&typ) || !exts.ReadUint16LengthPrefixed(&ext) {
			return ""
		}
		if typ != 0 { // server_name
			continue
		}
		if !ext.ReadUint16LengthPrefixed(&names) {
			return ""
		}
		for !names.Empty() {
			var nameType uint8
			var name cryptobyte.String
			if !names.ReadUint8(&nameType) || !names.ReadUint16LengthPrefixed(&name) {
				return ""
			}
			if nameType == 0 { // host_name
				return string(name)
			}
		}
		return ""
	}
	return ""
}
