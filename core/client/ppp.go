package client

import (
	"time"

	coreErrs "github.com/apernet/hysteria/core/v2/errors"
	internalppp "github.com/apernet/hysteria/core/v2/internal/ppp"
	"github.com/apernet/hysteria/core/v2/internal/protocol"
	"github.com/apernet/hysteria/core/v2/internal/utils"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/quicvarint"
)

// PPP opens a PPP session. maxFrameSize is the largest frame this client will
// accept; pass 0 to have it measured.
//
// Passing it is what nospawn mode does, and it has to: there the control is
// inverted -- pppd is the parent and this process is its pty child, so pppd's
// MRU was fixed by its own configuration before this code ran and nothing
// measured here could change it. Measuring anyway would spend up to five seconds
// per dial arriving at a number with nowhere to go, and under a multilink bundle
// that cost is paid once per link on every rebuild.
//
// The passed figure is also the better one to give the server. It is what pppd
// is actually using, where a measurement is an inference about the path.
func (c *clientImpl) PPP(dataStreams, maxFrameSize int) (*PPPConn, error) {
	stream, err := c.openStream()
	if err != nil {
		return nil, wrapIfConnectionClosed(err)
	}
	// Measure what this client's transport can carry before asking for a session,
	// so the server can size the PPP link to the smaller of the two directions.
	// In multi-stream mode a reliable stream imposes no per-frame limit beyond
	// the 16-bit length prefix.
	//
	// The settle and timeout figures are floors: Path MTU discovery is paced in
	// round trips, so the callee widens both from the connection's own RTT rather
	// than reporting whatever rung it had reached when a constant ran out.
	switch {
	case maxFrameSize > 0:
	case dataStreams == 0:
		maxFrameSize = internalppp.StableDatagramBudget(c.conn, 300*time.Millisecond, 5*time.Second)
	default:
		maxFrameSize = protocol.MaxPPPFrameSize
	}
	if err := protocol.WritePPPRequest(stream, dataStreams, maxFrameSize); err != nil {
		_ = stream.Close()
		return nil, wrapIfConnectionClosed(err)
	}
	ok, msg, serverDS, negotiatedMTU, err := protocol.ReadPPPResponse(stream)
	if err != nil {
		_ = stream.Close()
		return nil, wrapIfConnectionClosed(err)
	}
	if !ok {
		_ = stream.Close()
		return nil, coreErrs.DialError{Message: msg}
	}

	if serverDS > 0 {
		// Multi-stream mode: open N data streams
		rawStreams := make([]*quic.Stream, 0, serverDS)
		for i := 0; i < serverDS; i++ {
			ds, err := c.conn.OpenStream()
			if err != nil {
				for _, s := range rawStreams {
					_ = s.Close()
				}
				_ = stream.Close()
				return nil, wrapIfConnectionClosed(err)
			}
			hdr := quicvarint.Append(nil, protocol.FrameTypePPPData)
			hdr = quicvarint.Append(hdr, uint64(i))
			if _, err := ds.Write(hdr); err != nil {
				_ = ds.Close()
				for _, s := range rawStreams {
					_ = s.Close()
				}
				_ = stream.Close()
				return nil, wrapIfConnectionClosed(err)
			}
			rawStreams = append(rawStreams, ds)
		}

		dataIO := internalppp.NewMultiStreamIO(rawStreams, nil)
		return &PPPConn{
			ControlStream: &utils.QStream{Stream: stream.Stream},
			Data:          dataIO,
			MTU:           negotiatedMTU,
			closeFn: func() error {
				_ = dataIO.Close()
				return stream.Close()
			},
		}, nil
	}

	// Datagram mode
	if c.dispatcher == nil {
		_ = stream.Close()
		return nil, coreErrs.DialError{Message: "PPP datagram mode requires PPPMode in client config"}
	}

	c.dispatcher.pppCh = make(chan []byte, 256)
	c.dispatcher.pppActive.Store(true)
	dataIO := internalppp.NewDatagramIO(c.conn, c.dispatcher.pppCh)

	return &PPPConn{
		ControlStream: &utils.QStream{Stream: stream.Stream},
		Data:          dataIO,
		MTU:           negotiatedMTU,
		closeFn: func() error {
			c.dispatcher.pppActive.Store(false)
			_ = dataIO.Close()
			return stream.Close()
		},
	}, nil
}
