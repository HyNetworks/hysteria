package auth

import (
	"context"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/apernet/hysteria/core/v2/server"
)

const commandAuthTimeout = 10 * time.Second

var _ server.Authenticator = &CommandAuthenticator{}

type CommandAuthenticator struct {
	Cmd string
}

func (a *CommandAuthenticator) Authenticate(addr net.Addr, auth string, tx uint64) (ok bool, id string) {
	ctx, cancel := context.WithTimeout(context.Background(), commandAuthTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, a.Cmd, addr.String(), auth, strconv.Itoa(int(tx)))
	out, err := cmd.Output()
	if err != nil {
		// This includes failing to execute the command,
		// or the command exiting with a non-zero exit code.
		return false, ""
	} else {
		return true, strings.TrimSpace(string(out))
	}
}
