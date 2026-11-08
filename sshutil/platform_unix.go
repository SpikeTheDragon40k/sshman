//go:build unix

package sshutil

import (
	"net"
	"os"
	"syscall"
)

var forwardedSignals = []os.Signal{os.Interrupt, syscall.SIGTERM, syscall.SIGHUP}

// listenAgent listens on a unix socket inside the 0700 session directory.
func listenAgent(path string) (net.Listener, error) {
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = l.Close()
		return nil, err
	}
	return l, nil
}
