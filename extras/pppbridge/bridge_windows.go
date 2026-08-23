//go:build windows

package pppbridge

import (
	"io"
	"os/exec"
)

const bridgeIOMode = "pipe"

func (b *Bridge) startProcess(cmd *exec.Cmd) (childReader io.Reader, childWriter io.WriteCloser, cleanup func(), err error) {
	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		return nil, nil, nil, err
	}
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, nil, nil, err
	}
	return stdoutPipe, stdinPipe, func() { stdinPipe.Close() }, nil
}
