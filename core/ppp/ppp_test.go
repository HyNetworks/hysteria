package ppp

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

// The two decisions this package makes for everyone else.
//
// EffectiveMTU sizes every PPP link, and IsFrameTooLarge decides whether a
// refused frame is a dropped packet or a dead session. Both are three lines
// long, and both are wrong in a way nothing else would catch: an MTU one octet
// too large means every full-size packet is refused for the life of the session,
// and a misclassified refusal means the link flaps instead of degrading.

const PPPHeaderLen = 4 // FF 03 + protocol(2)

// The link can only be as wide as the narrower of the two transports, because a
// frame has to cross both.
func TestEffectiveMTUTakesTheNarrowerSide(t *testing.T) {
	tests := []struct {
		name           string
		client, server int
		want           int
	}{
		{"the client is narrower", 1300, 1452, 1296},
		{"the server is narrower", 1452, 1300, 1296},
		{"they agree", 1404, 1404, 1400},
		{"only the client reported one", 1404, 0, 1400},
		{"only the server reported one", 0, 1404, 1400},
		{"neither reported one", 0, 0, 0},
		{"the budget is all header", 4, 1404, 0},
		{"the budget is less than the header", 3, 1404, 0},
		{"one octet of payload", 5, 1404, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := SessionParams{ClientMaxFrame: tt.client, ServerMaxFrame: tt.server}
			assert.Equal(t, tt.want, p.EffectiveMTU(PPPHeaderLen))
		})
	}
}

// A transport that reports nothing must not drag the answer to zero when the
// other side did report something: "unknown" is not "narrow".
func TestEffectiveMTUIgnoresASideThatReportsNothing(t *testing.T) {
	both := SessionParams{ClientMaxFrame: 1404, ServerMaxFrame: 1404}.EffectiveMTU(PPPHeaderLen)
	clientOnly := SessionParams{ClientMaxFrame: 1404}.EffectiveMTU(PPPHeaderLen)
	assert.Equal(t, both, clientOnly)
}

func TestFrameTooLargeError(t *testing.T) {
	e := &FrameTooLargeError{FrameSize: 1500, MaxSize: 1400}
	assert.Equal(t, "ppp: frame of 1500 bytes exceeds the transport limit of 1400", e.Error())

	// Any two of them match, whatever the sizes: callers ask "was this a size
	// refusal", never "was it this exact size refusal".
	assert.True(t, errors.Is(e, &FrameTooLargeError{}))
	assert.False(t, errors.Is(e, errors.New("something else")))
}

// The classification has to survive being wrapped, because it travels up through
// the relay inside whatever context the caller added.
func TestIsFrameTooLarge(t *testing.T) {
	assert.False(t, IsFrameTooLarge(nil))
	assert.False(t, IsFrameTooLarge(errors.New("transport gone")))
	assert.True(t, IsFrameTooLarge(&FrameTooLargeError{FrameSize: 9, MaxSize: 8}))
	assert.True(t, IsFrameTooLarge(
		fmt.Errorf("sending: %w", &FrameTooLargeError{FrameSize: 9, MaxSize: 8}),
	))
}
