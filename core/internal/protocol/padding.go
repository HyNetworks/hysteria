package protocol

import (
	"math/rand"
)

const (
	paddingChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)

// padding specifies a half-open range [Min, Max).
type padding struct {
	Min int
	Max int
}

func (p padding) String() string {
	n := p.Min
	if p.Max > p.Min {
		n += rand.Intn(p.Max - p.Min)
	}
	bs := make([]byte, n)
	for i := range bs {
		bs[i] = paddingChars[rand.Intn(len(paddingChars))]
	}
	return string(bs)
}

var (
	authRequestPadding  = padding{Min: 1024}
	authResponsePadding = padding{Min: 1024}
	tcpRequestPadding   = padding{Min: 1200}
	tcpResponsePadding  = padding{Min: 1200}
)