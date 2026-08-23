package pppbridge

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHDLCEncodeBasic(t *testing.T) {
	// LCP Configure-Request with address+control: FF 03 C0 21 01 01 00 04
	pppFrame := []byte{0xFF, 0x03, 0xC0, 0x21, 0x01, 0x01, 0x00, 0x04}
	encoded := EncodeHDLC(pppFrame)

	assert.Equal(t, byte(0x7E), encoded[0], "must start with flag")
	assert.Equal(t, byte(0x7E), encoded[len(encoded)-1], "must end with flag")
	// After opening flag: 0xFF (not escaped, > 0x1F), then 0x03 (escaped, < 0x20)
	assert.Equal(t, byte(0xFF), encoded[1], "address byte")
	assert.Equal(t, byte(0x7D), encoded[2], "escape for control")
	assert.Equal(t, byte(0x23), encoded[3], "0x03 ^ 0x20")
	assert.Equal(t, byte(0xC0), encoded[4], "first protocol byte")
}

func TestHDLCDecodeBasic(t *testing.T) {
	pppFrame := []byte{0xFF, 0x03, 0xC0, 0x21, 0x01, 0x01, 0x00, 0x04}
	encoded := EncodeHDLC(pppFrame)
	decoded, err := DecodeHDLC(encoded)
	require.NoError(t, err)
	assert.Equal(t, pppFrame, decoded)
}

func TestHDLCRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"single byte", []byte{0x42}},
		{"100 bytes", make([]byte, 100)},
		{"1400 bytes", make([]byte, 1400)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for i := range tt.data {
				tt.data[i] = byte(i % 256)
			}
			encoded := EncodeHDLC(tt.data)
			decoded, err := DecodeHDLC(encoded)
			require.NoError(t, err)
			assert.Equal(t, tt.data, decoded)
		})
	}
}

func TestHDLCByteStuffing(t *testing.T) {
	pppFrame := []byte{0xFF, 0x03, 0x7E, 0x7D, 0x01, 0x02, 0x03}
	encoded := EncodeHDLC(pppFrame)

	decoded, err := DecodeHDLC(encoded)
	require.NoError(t, err)
	assert.Equal(t, pppFrame, decoded)

	// Encoded should be longer than raw due to escaping:
	// Flag(1) + escaped content (0x03,0x7E,0x7D,0x01,0x02,0x03 all need escaping) + FCS(2-4) + flag(1)
	assert.Greater(t, len(encoded), len(pppFrame)+4)
}

func TestHDLCDecodeMultipleFrames(t *testing.T) {
	frame1 := []byte{0xFF, 0x03, 0xC0, 0x21, 0x01, 0x01, 0x00, 0x04}
	frame2 := []byte{0xFF, 0x03, 0x80, 0x21, 0x01, 0x02, 0x00, 0x06}

	enc1 := EncodeHDLC(frame1)
	enc2 := EncodeHDLC(frame2)

	// Concatenate: the closing flag of frame1 serves as opening flag of frame2
	combined := make([]byte, 0, len(enc1)+len(enc2)-1)
	combined = append(combined, enc1...)
	combined = append(combined, enc2[1:]...) // skip opening flag of frame2

	frames, err := DecodeHDLCStream(combined)
	require.NoError(t, err)
	require.Len(t, frames, 2)
	assert.Equal(t, frame1, frames[0])
	assert.Equal(t, frame2, frames[1])
}

func TestHDLCDecodeMalformed(t *testing.T) {
	t.Run("bad FCS", func(t *testing.T) {
		pppFrame := []byte{0xFF, 0x03, 0xC0, 0x21, 0x01, 0x01, 0x00, 0x04}
		encoded := EncodeHDLC(pppFrame)
		// Corrupt the FCS (second to last byte before closing flag)
		encoded[len(encoded)-2] ^= 0xFF
		_, err := DecodeHDLC(encoded)
		assert.Error(t, err)
	})

	t.Run("no closing flag", func(t *testing.T) {
		data := []byte{0x7E, 0xFF, 0x03, 0x00, 0x21}
		_, err := DecodeHDLC(data)
		assert.Error(t, err)
	})

	t.Run("empty frame", func(t *testing.T) {
		data := []byte{0x7E, 0x7E}
		_, err := DecodeHDLC(data)
		assert.Error(t, err)
	})
}
