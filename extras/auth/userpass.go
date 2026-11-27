package auth

import (
	"crypto/subtle"
	"net"
	"strings"

	"github.com/apernet/hysteria/core/v2/server"
)

const (
	userPassSeparator = ":"
)

var _ server.Authenticator = &UserPassAuthenticator{}

// UserPassAuthenticator checks the provided auth string against a map of username/password pairs.
// The format of the auth string must be "username:password".
type UserPassAuthenticator struct {
	users map[string]string
}

func NewUserPassAuthenticator(users map[string]string) *UserPassAuthenticator {
	// Usernames are case-insensitive, as they are already lowercased by viper.
	// Lowercase it again on our own to make it explicit.
	lcUsers := make(map[string]string, len(users))
	for user, pass := range users {
		lcUsers[strings.ToLower(user)] = pass
	}
	return &UserPassAuthenticator{users: lcUsers}
}

func (a *UserPassAuthenticator) Authenticate(addr net.Addr, auth string, tx uint64) (ok bool, id string) {
	u, p, ok := splitUserPass(auth)
	if !ok {
		return false, ""
	}
	rp, found := a.users[u]
	passOK := subtle.ConstantTimeCompare([]byte(rp), []byte(p)) == 1
	if !found || !passOK {
		return false, ""
	}
	return true, u
}

func splitUserPass(auth string) (user, pass string, ok bool) {
	rs := strings.SplitN(auth, userPassSeparator, 2)
	if len(rs) != 2 {
		return "", "", false
	}
	// Usernames are case-insensitive
	return strings.ToLower(rs[0]), rs[1], true
}
