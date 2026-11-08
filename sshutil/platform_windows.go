//go:build windows

package sshutil

import (
	"errors"
	"net"
	"os"
)

var forwardedSignals = []os.Signal{os.Interrupt}

// ErrAgentUnsupported is returned on Windows, where Win32-OpenSSH expects the
// agent on a named pipe. See docs/remediation/DECISIONS.md (D-10).
var ErrAgentUnsupported = errors.New("connect with a vault key is not supported on Windows yet (Win32-OpenSSH needs a named-pipe agent); see docs/remediation/STATUS.md Q-13")

func listenAgent(string) (net.Listener, error) { return nil, ErrAgentUnsupported }
