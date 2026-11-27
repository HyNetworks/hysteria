package auth

import (
	"crypto/subtle"
	"net"

	"github.com/apernet/hysteria/core/v2/server"
)

var _ server.Authenticator = &PasswordAuthenticator{}

// PasswordAuthenticator is a simple authenticator that checks the password against a single string.
type PasswordAuthenticator struct {
	Password string
}

func (a *PasswordAuthenticator) Authenticate(addr net.Addr, auth string, tx uint64) (ok bool, id string) {
	if subtle.ConstantTimeCompare([]byte(a.Password), []byte(auth)) == 1 {
		return true, "user"
	}
	return false, ""
}
