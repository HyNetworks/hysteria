package integration_tests

import (
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"

	"github.com/apernet/hysteria/core/v2/client"
	coreErrs "github.com/apernet/hysteria/core/v2/errors"
	"github.com/apernet/hysteria/core/v2/internal/integration_tests/mocks"
	"github.com/apernet/hysteria/core/v2/server"
)

func TestRejectedAuthReleasesResponse(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	udpConn, udpAddr, err := serverConn()
	require.NoError(t, err)
	defer udpConn.Close()
	auth := mocks.NewMockAuthenticator(t)
	auth.EXPECT().Authenticate(mock.Anything, "rejected", uint64(0)).Return(false, "").Times(10)
	s, err := server.NewServer(&server.Config{
		Conn:          udpConn,
		TLSConfig:     serverTLSConfig(),
		Authenticator: auth,
	})
	require.NoError(t, err)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = s.Serve()
	}()
	defer func() {
		_ = s.Close()
		<-done
	}()
	for i := 0; i < 10; i++ {
		c, info, err := client.NewClient(&client.Config{
			ServerAddr: udpAddr,
			Auth:       "rejected",
			TLSConfig:  client.TLSConfig{InsecureSkipVerify: true},
		})
		if c != nil {
			_ = c.Close()
		}
		var authErr coreErrs.AuthError
		require.ErrorAs(t, err, &authErr)
		require.Nil(t, c)
		require.Nil(t, info)
	}
}
