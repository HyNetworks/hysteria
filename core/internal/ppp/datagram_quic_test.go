package ppp

import (
	"testing"
	"time"

	corePPP "github.com/apernet/hysteria/core/v2/ppp"
	"github.com/apernet/quic-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// DatagramIO against a real QUIC connection.
//
// Datagram mode is the default: it gives PPP the unreliable link it was designed
// for, and every frame a subscriber sends goes through SendData. The two things
// that cannot be checked against a fake are the ones that matter most here --
// that quic-go's DatagramTooLargeError becomes a FrameTooLargeError (a dropped
// packet, not a dead session), and that MaxFrameSize reports what quic-go
// currently believes the path carries, which is what sizes the PPP MTU.

func datagramPair(t *testing.T) *quicPair {
	t.Helper()
	return newQUICPair(t, &quic.Config{EnableDatagrams: true})
}

func TestDatagramIOCarriesAFrameEndToEnd(t *testing.T) {
	p := datagramPair(t)

	recvCh := make(chan []byte, 4)
	go func() {
		for {
			msg, err := p.server.ReceiveDatagram(t.Context())
			if err != nil {
				close(recvCh)
				return
			}
			recvCh <- msg
		}
	}()

	client := NewDatagramIO(p.client, nil)
	t.Cleanup(func() { _ = client.Close() })

	want := []byte{0xFF, 0x03, 0xC0, 0x21, 0x01, 0x00}
	require.NoError(t, client.SendData(want))

	select {
	case got := <-recvCh:
		assert.Equal(t, want, got, "a PPP frame crosses the datagram transport unaltered")
	case <-time.After(10 * time.Second):
		t.Fatal("the datagram never arrived")
	}
}

// A frame that does not fit is a packet to drop, not a session to end. The relay
// depends on telling the two apart: treating the first full-size download as a
// dead link would make the session flap instead of degrade.
func TestDatagramIOReportsAnOversizeFrameAsDroppable(t *testing.T) {
	p := datagramPair(t)
	io := NewDatagramIO(p.client, nil)
	t.Cleanup(func() { _ = io.Close() })

	err := io.SendData(make([]byte, 4096))
	require.Error(t, err)
	require.True(t, corePPP.IsFrameTooLarge(err),
		"quic-go's size refusal must become a FrameTooLargeError, or the relay ends the session")

	var tooLarge *corePPP.FrameTooLargeError
	require.ErrorAs(t, err, &tooLarge)
	assert.Equal(t, 4096, tooLarge.FrameSize)
	assert.Greater(t, tooLarge.MaxSize, 0, "the error has to say what would have fitted")
	assert.Less(t, tooLarge.MaxSize, 4096)
}

// MaxFrameSize is what the MTU calculation and the black-hole probe both size
// themselves against, so it has to report quic-go's live figure rather than a
// constant -- and asking must not queue anything.
func TestDatagramIOMaxFrameSizeReportsTheLiveCeiling(t *testing.T) {
	p := datagramPair(t)
	io := NewDatagramIO(p.client, nil)
	t.Cleanup(func() { _ = io.Close() })

	sizer, ok := io.(corePPP.MaxFrameSizer)
	require.True(t, ok, "the datagram transport must be able to report its ceiling")

	max := sizer.MaxFrameSize()
	require.Greater(t, max, 0)
	assert.LessOrEqual(t, max, 1452, "quic-go caps a packet at MaxPacketBufferSize")

	// The figure is usable: a frame of exactly that size goes, one octet more
	// does not.
	assert.NoError(t, io.SendData(make([]byte, max)))
	assert.True(t, corePPP.IsFrameTooLarge(io.SendData(make([]byte, max+1))),
		"the reported ceiling must be the real one, not an estimate")
}

// A peer that did not negotiate datagram support gives no ceiling at all. Zero
// means "unknown", and the MTU calculation falls back to its own estimate rather
// than sizing the link against nothing.
func TestDatagramIOMaxFrameSizeIsZeroWithoutDatagramSupport(t *testing.T) {
	p := newQUICPair(t, nil) // datagrams off
	io := NewDatagramIO(p.client, nil)
	t.Cleanup(func() { _ = io.Close() })

	assert.Zero(t, io.(corePPP.MaxFrameSizer).MaxFrameSize())
}

// A connection that has gone away is a dead transport, not a frame to drop. The
// send side does not necessarily notice -- quic-go accepts a datagram into a
// connection that is already closing -- so the verdict comes from the receive
// side, which is where the relay reads it.
func TestDatagramIOReportsADeadConnectionOnTheReceiveSide(t *testing.T) {
	p := datagramPair(t)
	recvCh := make(chan []byte)
	io := NewDatagramIO(p.client, recvCh)
	t.Cleanup(func() { _ = io.Close() })

	// Closing the channel is what the connection's dispatcher does when the
	// connection ends.
	close(recvCh)

	_, err := io.ReceiveData()
	require.Error(t, err)
	assert.False(t, corePPP.IsFrameTooLarge(err),
		"a dead connection must not be mistaken for a frame that was merely too big")
}
