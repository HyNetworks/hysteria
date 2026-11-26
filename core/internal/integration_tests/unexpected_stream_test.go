package integration_tests

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/apernet/hysteria/core/v2/internal/integration_tests/mocks"
	"github.com/apernet/hysteria/core/v2/internal/protocol"
	"github.com/apernet/hysteria/core/v2/server"
)

// TestServerUnexpectedStreamAfterAuth checks that an authenticated client's stream
// that starts with neither HEADERS nor a TCP request only resets that stream.
// Before, HTTP/3 closed the whole connection with H3_FRAME_UNEXPECTED.
func TestServerUnexpectedStreamAfterAuth(t *testing.T) {
	udpConn, udpAddr, err := serverConn()
	assert.NoError(t, err)
	auth := mocks.NewMockAuthenticator(t)
	auth.EXPECT().Authenticate(mock.Anything, mock.Anything, mock.Anything).Return(true, "nobody")
	s, err := server.NewServer(&server.Config{
		TLSConfig:     serverTLSConfig(),
		Conn:          udpConn,
		Outbound:      mocks.NewMockOutbound(t),
		Authenticator: auth,
	})
	assert.NoError(t, err)
	defer s.Close()
	go s.Serve()

	var conn *quic.Conn
	rt := &http3.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		Dial: func(ctx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			qc, err := quic.DialAddrEarly(ctx, udpAddr.String(), tlsCfg, cfg)
			conn = qc
			return qc, err
		},
	}
	defer rt.Close()
	req := &http.Request{
		Method: http.MethodPost,
		URL:    &url.URL{Scheme: "https", Host: protocol.URLHost, Path: protocol.URLPath},
		Header: make(http.Header),
	}
	protocol.AuthRequestToHeader(req.Header, protocol.AuthRequest{Auth: "x"})
	resp, err := rt.RoundTrip(req)
	assert.NoError(t, err)
	assert.Equal(t, protocol.StatusAuthOK, resp.StatusCode)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	str, err := conn.OpenStreamSync(ctx)
	assert.NoError(t, err)
	_, err = str.Write([]byte{0x00, 0x05, 'h', 'e', 'l', 'l', 'o'}) // HTTP/3 DATA frame
	assert.NoError(t, err)
	_ = str.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, err = str.Read(make([]byte, 1))
	var serr *quic.StreamError
	assert.ErrorAs(t, err, &serr)
	select {
	case <-conn.Context().Done():
		t.Fatalf("connection closed: %v", context.Cause(conn.Context()))
	case <-time.After(500 * time.Millisecond):
	}
}
