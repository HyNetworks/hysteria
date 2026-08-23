//go:build !windows

package pppbridge

import (
	"io"
	"os/exec"
	"syscall"

	"github.com/creack/pty"
)

const bridgeIOMode = "pty"

func (b *Bridge) startProcess(cmd *exec.Cmd) (childReader io.Reader, childWriter io.WriteCloser, cleanup func(), err error) {
	// pppd needs a tty, not a pipe: it puts the line into raw mode itself and
	// refuses to run on anything it cannot ioctl. Open failing means the host is
	// out of pseudo-terminals, which no test can arrange without breaking the
	// machine it runs on.
	ptmx, tty, err := pty.Open()
	if err != nil {
		return nil, nil, nil, err
	}
	cmd.Stdin = tty
	cmd.Stdout = tty
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true}
	if err := cmd.Start(); err != nil {
		tty.Close()
		ptmx.Close()
		return nil, nil, nil, err
	}
	tty.Close()
	return ptmx, ptmx, func() { ptmx.Close() }, nil
}
