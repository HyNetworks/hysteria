package pppbridge

import (
	"io"
	"math/rand"

	"github.com/apernet/quic-go/quicvarint"
)

const (
	pppRespPaddingMin = 128
	pppRespPaddingMax = 1024
	paddingChars      = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)

func randomPadding(min, max int) string {
	n := min + rand.Intn(max-min)
	bs := make([]byte, n)
	for i := range bs {
		bs[i] = paddingChars[rand.Intn(len(paddingChars))]
	}
	return string(bs)
}

// writePPPResponse writes a PPP response with dataStreams field.
func writePPPResponse(w io.Writer, ok bool, msg string, dataStreams, mtu int) error {
	padding := randomPadding(pppRespPaddingMin, pppRespPaddingMax)
	var buf []byte
	if ok {
		buf = append(buf, 0)
	} else {
		buf = append(buf, 1)
	}
	buf = quicvarint.Append(buf, uint64(len(msg)))
	buf = append(buf, msg...)
	buf = quicvarint.Append(buf, uint64(dataStreams))
	buf = quicvarint.Append(buf, uint64(mtu))
	buf = quicvarint.Append(buf, uint64(len(padding)))
	buf = append(buf, padding...)
	_, err := w.Write(buf)
	return err
}
