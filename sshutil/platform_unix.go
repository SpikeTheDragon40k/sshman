//go:build unix

package sshutil

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"syscall"
)

var forwardedSignals = []os.Signal{os.Interrupt, syscall.SIGTERM, syscall.SIGHUP}

// safePathRe matches paths that ssh_config will not reinterpret: no '%'
// tokens, '~', '${VAR}' expansion or whitespace.
var safePathRe = regexp.MustCompile(`^[A-Za-z0-9/._-]+$`)

// maxSocketPath stays below the smallest sun_path limit (104 on macOS).
const maxSocketPath = 100

func sessionTempDir() (string, error) {
	base := os.TempDir()
	// Leave room for "/sshman-XXXXXXXXXX/agent.sock".
	if !safePathRe.MatchString(base) || len(base)+30 > maxSocketPath {
		base = "/tmp"
	}
	dir, err := os.MkdirTemp(base, "sshman-")
	if err != nil {
		return "", fmt.Errorf("failed to create session directory: %w", err)
	}
	if !safePathRe.MatchString(dir) {
		_ = os.RemoveAll(dir)
		return "", fmt.Errorf("temporary directory %q contains characters ssh would reinterpret; set TMPDIR to a simple path", dir)
	}
	return dir, nil
}

// pathOption returns p as an ssh_config option value.
func pathOption(p string) (string, error) {
	if !safePathRe.MatchString(p) {
		return "", fmt.Errorf("path %q contains characters ssh would reinterpret", p)
	}
	return p, nil
}

// listenAgent listens on a unix socket inside the 0700 session directory.
func listenAgent(dir string) (net.Listener, string, error) {
	path := filepath.Join(dir, "agent.sock")
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, "", err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = l.Close()
		return nil, "", err
	}
	return l, path, nil
}
