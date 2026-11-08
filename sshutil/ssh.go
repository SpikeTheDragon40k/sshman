// Package sshutil validates entries and key material and runs OpenSSH with a
// short-lived, read-only, in-process agent that holds exactly one vault key.
package sshutil

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"sync"

	"github.com/sshman-org/sshman/model"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// Options controls how ssh is run.
type Options struct {
	// RemoteCommand is run instead of an interactive shell when non-empty.
	RemoteCommand []string
	// AcceptNewHostKey adds unknown host keys to known_hosts without asking
	// (StrictHostKeyChecking=accept-new). Changed keys are still refused.
	// Off by default so the user's own policy applies (S-05).
	AcceptNewHostKey bool
	// SSHPath overrides the ssh executable (tests). Default: "ssh" from PATH.
	SSHPath string
	// testArgs are prepended to the ssh arguments (tests only, e.g. -F).
	testArgs []string
	Stdin    io.Reader
	Stdout   io.Writer
	Stderr   io.Writer
}

func (o *Options) sshPath() string {
	if o.SSHPath != "" {
		return o.SSHPath
	}
	return "ssh"
}

func (o *Options) streams() (io.Reader, io.Writer, io.Writer) {
	in, out, errw := o.Stdin, o.Stdout, o.Stderr
	if in == nil {
		in = os.Stdin
	}
	if out == nil {
		out = os.Stdout
	}
	if errw == nil {
		errw = os.Stderr
	}
	return in, out, errw
}

// connectArgs builds the ssh argument list for authenticating with the
// session agent (Q-02, S-01, S-05, S-06).
//
//   - IdentityAgent points at the session socket explicitly, so a user's
//     IdentityAgent setting cannot redirect authentication, and
//     SSH_AUTH_SOCK is left untouched for any ProxyJump/ProxyCommand child.
//   - IdentityFile names the public key and IdentitiesOnly=yes makes ssh
//     offer only that key, signing through the agent.
//   - ForwardAgent=no: the vault key is never forwarded to the remote host,
//     whatever ~/.ssh/config says.
//   - StrictHostKeyChecking is not overridden unless explicitly requested.
//   - "--" ends option parsing before the destination.
func connectArgs(e *model.Entry, sock, pubFile string, opts *Options) []string {
	args := []string{
		"-o", "IdentityAgent=" + sock,
		"-o", "IdentityFile=" + pubFile,
		"-o", "IdentitiesOnly=yes",
		"-o", "ForwardAgent=no",
		"-o", "AddKeysToAgent=no",
		"-o", "PasswordAuthentication=no",
	}
	if opts.AcceptNewHostKey {
		args = append(args, "-o", "StrictHostKeyChecking=accept-new")
	}
	// Port 22 and 0 are left to ssh_config, as before, so Host aliases keep
	// their configured Port.
	if e.Port > 0 && e.Port != 22 {
		args = append(args, "-p", strconv.Itoa(e.Port))
	}
	args = append(args, "--", e.Addr())
	return append(args, opts.RemoteCommand...)
}

// session is a temporary directory holding the public key file, plus the
// agent server (a unix socket in that directory, or a named pipe on
// Windows). sock and pubFile are the values passed to ssh_config options.
type session struct {
	dir      string
	sock     string
	pubFile  string
	listener net.Listener
	wg       sync.WaitGroup
}

// startSession loads key into a read-only agent served on a private socket.
func startSession(e *model.Entry) (*session, error) {
	rawKey, signer, err := ParseStoredKey(e.Key)
	if err != nil {
		return nil, fmt.Errorf("entry %q: %w", e.Name, err)
	}
	ag, err := newReadOnlyAgent(rawKey, "sshman:"+e.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to load key into agent: %w", err)
	}
	dir, err := sessionTempDir()
	if err != nil {
		return nil, err
	}
	s := &session{dir: dir}
	pubPath := filepath.Join(dir, "id.pub")
	// Only the public key is written to disk; the private key never is.
	if err := os.WriteFile(pubPath, ssh.MarshalAuthorizedKey(signer.PublicKey()), 0o600); err != nil {
		s.close()
		return nil, err
	}
	if s.pubFile, err = pathOption(pubPath); err != nil {
		s.close()
		return nil, err
	}
	l, sock, err := listenAgent(dir)
	if err != nil {
		s.close()
		return nil, err
	}
	s.listener, s.sock = l, sock
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				defer conn.Close()
				_ = agent.ServeAgent(ag, conn)
			}()
		}
	}()
	return s, nil
}

func (s *session) close() {
	if s.listener != nil {
		_ = s.listener.Close()
	}
	_ = os.RemoveAll(s.dir)
}

// Connect opens an ssh session to the entry using its vault key.
func Connect(e *model.Entry, opts Options) error {
	if err := ValidateEntry(e); err != nil {
		return err
	}
	if e.Key == "" {
		return fmt.Errorf("entry %q has no private key", e.Name)
	}
	s, err := startSession(e)
	if err != nil {
		return err
	}
	defer s.close()
	return runSSH(opts.sshPath(), append(slices.Clone(opts.testArgs), connectArgs(e, s.sock, s.pubFile, &opts)...), &opts)
}

// runSSH runs ssh in the foreground. SIGINT is left to ssh (it shares the
// terminal's process group); SIGTERM and SIGHUP are forwarded so that the
// deferred cleanup of the session directory still runs.
func runSSH(path string, args []string, opts *Options) error {
	in, out, errw := opts.streams()
	cmd := exec.Command(path, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = in, out, errw
	sigc := make(chan os.Signal, 4)
	signal.Notify(sigc, forwardedSignals...)
	defer signal.Stop(sigc)
	if err := cmd.Start(); err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return fmt.Errorf("OpenSSH client %q not found in PATH", path)
		}
		return err
	}
	done := make(chan struct{})
	go func() {
		for {
			select {
			case sig := <-sigc:
				if sig != os.Interrupt {
					_ = cmd.Process.Signal(sig)
				}
			case <-done:
				return
			}
		}
	}()
	err := cmd.Wait()
	close(done)
	return err
}

// ExitCode returns the exit status of a failed ssh run, or -1.
func ExitCode(err error) int {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return -1
}
