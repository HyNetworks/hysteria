package integration_tests

import (
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/apernet/hysteria/core/v2/client"
	coreErrs "github.com/apernet/hysteria/core/v2/errors"
	"github.com/apernet/hysteria/core/v2/internal/integration_tests/mocks"
	"github.com/apernet/hysteria/core/v2/internal/protocol"
	"github.com/apernet/hysteria/core/v2/ppp"
	"github.com/apernet/hysteria/core/v2/server"
)

// echoPPPHandler implements server.PPPRequestHandler.
// It writes a PPP response, activates data transport via createDataIO,
// then echoes control stream bytes back and echoes data frames back via PPPDataIO.
type echoPPPHandler struct{}

func (h *echoPPPHandler) HandlePPP(control io.ReadWriteCloser, params ppp.SessionParams, createDataIO func() (ppp.PPPDataIO, error), addr net.Addr, id string) {
	defer control.Close()

	_ = protocol.WritePPPResponse(control, true, "OK", params.DataStreams, 0)

	dataIO, err := createDataIO()
	if err != nil {
		return
	}
	defer dataIO.Close()

	// Echo control stream in one goroutine
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = io.Copy(control, control)
	}()

	// Echo data frames
	for {
		frame, err := dataIO.ReceiveData()
		if err != nil {
			break
		}
		if err := dataIO.SendData(frame); err != nil {
			break
		}
	}

	<-done
}

// TestClientServerPPPDatagram tests PPP with datagram mode (dataStreams=0).
func TestClientServerPPPDatagram(t *testing.T) {
	udpConn, udpAddr, err := serverConn()
	if !assert.NoError(t, err) {
		return
	}
	auth := mocks.NewMockAuthenticator(t)
	auth.EXPECT().Authenticate(mock.Anything, mock.Anything, mock.Anything).Return(true, "nobody")
	s, err := server.NewServer(&server.Config{
		TLSConfig:         serverTLSConfig(),
		Conn:              udpConn,
		Authenticator:     auth,
		PPPRequestHandler: &echoPPPHandler{},
	})
	if !assert.NoError(t, err) {
		return
	}
	defer s.Close()
	go s.Serve()

	c, _, err := client.NewClient(&client.Config{
		ServerAddr: udpAddr,
		TLSConfig:  client.TLSConfig{InsecureSkipVerify: true},
		PPPMode:    true,
	})
	if !assert.NoError(t, err) {
		return
	}
	defer c.Close()

	// Open PPP connection in datagram mode
	pppConn, err := c.PPP(0, 0)
	if !assert.NoError(t, err) {
		return
	}
	defer pppConn.Close()

	// Test control stream echo
	sData := []byte("control hello")
	_, err = pppConn.ControlStream.Write(sData)
	assert.NoError(t, err)
	rData := make([]byte, len(sData))
	_, err = io.ReadFull(pppConn.ControlStream, rData)
	assert.NoError(t, err)
	assert.Equal(t, sData, rData)

	// Test data frame echo (via datagrams)
	// Small delay to allow datagram path to set up
	time.Sleep(100 * time.Millisecond)
	dataFrame := []byte{0xFF, 0x03, 0x00, 0x21, 0x45, 0x00, 0x00, 0x14} // Fake IPv4 PPP frame
	err = pppConn.Data.SendData(dataFrame)
	assert.NoError(t, err)
	received, err := pppConn.Data.ReceiveData()
	assert.NoError(t, err)
	assert.Equal(t, dataFrame, received)
}

// TestClientServerPPPMultiStream tests PPP with multi-stream mode (dataStreams=2).
func TestClientServerPPPMultiStream(t *testing.T) {
	udpConn, udpAddr, err := serverConn()
	if !assert.NoError(t, err) {
		return
	}
	auth := mocks.NewMockAuthenticator(t)
	auth.EXPECT().Authenticate(mock.Anything, mock.Anything, mock.Anything).Return(true, "nobody")
	s, err := server.NewServer(&server.Config{
		TLSConfig:         serverTLSConfig(),
		Conn:              udpConn,
		Authenticator:     auth,
		PPPRequestHandler: &echoPPPHandler{},
	})
	if !assert.NoError(t, err) {
		return
	}
	defer s.Close()
	go s.Serve()

	c, _, err := client.NewClient(&client.Config{
		ServerAddr: udpAddr,
		TLSConfig:  client.TLSConfig{InsecureSkipVerify: true},
	})
	if !assert.NoError(t, err) {
		return
	}
	defer c.Close()

	// Open PPP connection in multi-stream mode (2 data streams)
	pppConn, err := c.PPP(2, 0)
	if !assert.NoError(t, err) {
		return
	}
	defer pppConn.Close()

	// Test control stream echo
	sData := []byte("multistream control")
	_, err = pppConn.ControlStream.Write(sData)
	assert.NoError(t, err)
	rData := make([]byte, len(sData))
	_, err = io.ReadFull(pppConn.ControlStream, rData)
	assert.NoError(t, err)
	assert.Equal(t, sData, rData)

	// Test data frame echo (via multi-stream)
	dataFrame := []byte{0xFF, 0x03, 0x00, 0x21, 0x45, 0x00, 0x00, 0x14}
	err = pppConn.Data.SendData(dataFrame)
	assert.NoError(t, err)
	received, err := pppConn.Data.ReceiveData()
	assert.NoError(t, err)
	assert.Equal(t, dataFrame, received)
}

// drainPPPHandler implements server.PPPRequestHandler.
// It accepts the PPP session, activates data transport, then blocks until the
// control stream is closed. This lets the test cleanly close and reopen sessions.
type drainPPPHandler struct{}

func (h *drainPPPHandler) HandlePPP(control io.ReadWriteCloser, params ppp.SessionParams, createDataIO func() (ppp.PPPDataIO, error), addr net.Addr, id string) {
	defer control.Close()

	_ = protocol.WritePPPResponse(control, true, "OK", params.DataStreams, 0)

	dataIO, err := createDataIO()
	if err != nil {
		return
	}
	defer dataIO.Close()

	buf := make([]byte, 4096)
	for {
		if _, err := control.Read(buf); err != nil {
			return
		}
	}
}

// TestClientServerPPPReconnectDatagram verifies that a second PPP session
// (datagram mode) can start on the same QUIC connection after the first ends.
func TestClientServerPPPReconnectDatagram(t *testing.T) {
	udpConn, udpAddr, err := serverConn()
	if !assert.NoError(t, err) {
		return
	}
	auth := mocks.NewMockAuthenticator(t)
	auth.EXPECT().Authenticate(mock.Anything, mock.Anything, mock.Anything).Return(true, "nobody")
	s, err := server.NewServer(&server.Config{
		TLSConfig:         serverTLSConfig(),
		Conn:              udpConn,
		Authenticator:     auth,
		PPPRequestHandler: &drainPPPHandler{},
	})
	if !assert.NoError(t, err) {
		return
	}
	defer s.Close()
	go s.Serve()

	c, _, err := client.NewClient(&client.Config{
		ServerAddr: udpAddr,
		TLSConfig:  client.TLSConfig{InsecureSkipVerify: true},
		PPPMode:    true,
	})
	if !assert.NoError(t, err) {
		return
	}
	defer c.Close()

	for i := 0; i < 3; i++ {
		pppConn, err := c.PPP(0, 0)
		if !assert.NoError(t, err, "PPP open attempt %d", i) {
			return
		}
		pppConn.Close()
		time.Sleep(200 * time.Millisecond)
	}
}

// TestClientServerPPPReconnectMultiStream verifies that a second PPP session
// (multi-stream mode) can start on the same QUIC connection after the first ends.
func TestClientServerPPPReconnectMultiStream(t *testing.T) {
	udpConn, udpAddr, err := serverConn()
	if !assert.NoError(t, err) {
		return
	}
	auth := mocks.NewMockAuthenticator(t)
	auth.EXPECT().Authenticate(mock.Anything, mock.Anything, mock.Anything).Return(true, "nobody")
	s, err := server.NewServer(&server.Config{
		TLSConfig:         serverTLSConfig(),
		Conn:              udpConn,
		Authenticator:     auth,
		PPPRequestHandler: &drainPPPHandler{},
	})
	if !assert.NoError(t, err) {
		return
	}
	defer s.Close()
	go s.Serve()

	c, _, err := client.NewClient(&client.Config{
		ServerAddr: udpAddr,
		TLSConfig:  client.TLSConfig{InsecureSkipVerify: true},
	})
	if !assert.NoError(t, err) {
		return
	}
	defer c.Close()

	for i := 0; i < 3; i++ {
		pppConn, err := c.PPP(2, 0)
		if !assert.NoError(t, err, "PPP open attempt %d", i) {
			return
		}
		pppConn.Close()
		time.Sleep(200 * time.Millisecond)
	}
}

// TestClientServerPPPDisabled tests PPP when PPPRequestHandler is nil.
func TestClientServerPPPDisabled(t *testing.T) {
	udpConn, udpAddr, err := serverConn()
	if !assert.NoError(t, err) {
		return
	}
	auth := mocks.NewMockAuthenticator(t)
	auth.EXPECT().Authenticate(mock.Anything, mock.Anything, mock.Anything).Return(true, "nobody")
	s, err := server.NewServer(&server.Config{
		TLSConfig:     serverTLSConfig(),
		Conn:          udpConn,
		Authenticator: auth,
	})
	assert.NoError(t, err)
	defer s.Close()
	go s.Serve()

	c, _, err := client.NewClient(&client.Config{
		ServerAddr: udpAddr,
		TLSConfig:  client.TLSConfig{InsecureSkipVerify: true},
		PPPMode:    true,
	})
	if !assert.NoError(t, err) {
		return
	}
	defer c.Close()

	type pppResult struct {
		conn *client.PPPConn
		err  error
	}
	// Both modes must be refused, and refused the same way: the server has no
	// handler at all, so the mode requested is irrelevant. Running two in a row
	// on the same client also shows the refusal leaves the QUIC connection
	// usable -- the second request gets an answer rather than a dead connection.
	for _, dataStreams := range []int{0, 2} {
		t.Run(fmt.Sprintf("dataStreams=%d", dataStreams), func(t *testing.T) {
			resCh := make(chan pppResult, 1)
			go func() {
				conn, err := c.PPP(dataStreams, 0)
				resCh <- pppResult{conn, err}
			}()

			var res pppResult
			select {
			case res = <-resCh:
			case <-time.After(10 * time.Second):
				t.Fatal("PPP() against a server with no PPPRequestHandler never returned")
			}
			if res.conn != nil {
				res.conn.Close()
			}

			require.Error(t, res.err, "a server with no PPPRequestHandler must refuse the session")
			assert.Nil(t, res.conn, "a refused session must not hand back a usable PPPConn")

			// The refusal is the server's own message on the control stream, not
			// a transport failure -- that is what tells the client PPP is simply
			// switched off rather than broken.
			var dialErr coreErrs.DialError
			require.ErrorAs(t, res.err, &dialErr, "got %T: %v", res.err, res.err)
			assert.Equal(t, "PPP not enabled on server", dialErr.Message)
		})
	}
}
