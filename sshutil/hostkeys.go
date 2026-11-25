package sshutil

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/sshman-org/sshman/model"
	"golang.org/x/crypto/ssh"
)

// ValidateHostKeys checks that every pinned line is exactly one known_hosts
// entry.
func ValidateHostKeys(lines []string) error {
	for _, l := range lines {
		if strings.ContainsAny(l, "\r\n") {
			return errors.New("pinned host key must be a single line")
		}
		_, _, _, _, rest, err := ssh.ParseKnownHosts([]byte(l))
		if err != nil {
			return fmt.Errorf("invalid pinned host key: %w", err)
		}
		if len(bytes.TrimSpace(rest)) != 0 {
			return errors.New("invalid pinned host key: trailing data")
		}
	}
	return nil
}

// HostKeyFingerprints returns "<type> <SHA256 fingerprint>" for each pinned
// line, skipping lines that do not parse.
func HostKeyFingerprints(lines []string) []string {
	var out []string
	for _, l := range lines {
		if _, _, pub, _, _, err := ssh.ParseKnownHosts([]byte(l)); err == nil {
			out = append(out, pub.Type()+" "+ssh.FingerprintSHA256(pub))
		}
	}
	return out
}

// knownHostsArgs makes file the only known_hosts ssh reads or writes, so
// neither ~/.ssh/known_hosts nor the system file can vouch for the host.
func knownHostsArgs(file string) []string {
	return []string{
		"-o", "UserKnownHostsFile=" + file,
		"-o", "GlobalKnownHostsFile=" + file,
		"-o", "UpdateHostKeys=no",
	}
}

// sshArgs prepends the test arguments and, if e has pinned host keys, the
// options that make them the only trusted keys. ssh keeps the first value of
// an option, so StrictHostKeyChecking=yes here wins over a later
// accept-new. The returned cleanup removes the temporary pin file.
func sshArgs(e *model.Entry, opts *Options, rest []string) ([]string, func(), error) {
	args := slices.Clone(opts.testArgs)
	if len(e.HostKeys) == 0 {
		return append(args, rest...), func() {}, nil
	}
	if err := ValidateHostKeys(e.HostKeys); err != nil {
		return nil, nil, fmt.Errorf("entry %q: %w", e.Name, err)
	}
	dir, err := sessionTempDir()
	if err != nil {
		return nil, nil, err
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	file := filepath.Join(dir, "known_hosts")
	if err := os.WriteFile(file, []byte(strings.Join(e.HostKeys, "\n")+"\n"), 0o600); err != nil {
		cleanup()
		return nil, nil, err
	}
	opt, err := pathOption(file)
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	args = append(args, knownHostsArgs(opt)...)
	args = append(args, "-o", "StrictHostKeyChecking=yes")
	return append(args, rest...), cleanup, nil
}

// PinHostKey logs in with e's vault key using an empty, private known_hosts
// file, so ssh shows the host key fingerprint for the user to confirm (or
// accepts it with opts.AcceptNewHostKey), and returns the lines ssh recorded.
// Existing pins are ignored: this is how a pin is set or replaced.
func PinHostKey(e *model.Entry, opts Options) ([]string, error) {
	if err := ValidateEntry(e); err != nil {
		return nil, err
	}
	if e.Key == "" {
		return nil, fmt.Errorf("entry %q has no private key to log in with", e.Name)
	}
	s, err := startSession(e)
	if err != nil {
		return nil, err
	}
	defer s.close()
	file := filepath.Join(s.dir, "known_hosts")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		return nil, err
	}
	opt, err := pathOption(file)
	if err != nil {
		return nil, err
	}
	opts.RemoteCommand = []string{"true"}
	args := append(slices.Clone(opts.testArgs), knownHostsArgs(opt)...)
	args = append(args, connectArgs(e, s.sock, s.pubFile, &opts)...)
	if err := runSSH(opts.sshPath(), args, &opts); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	var lines []string
	for _, l := range strings.Split(string(data), "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
			lines = append(lines, l)
		}
	}
	if len(lines) == 0 {
		return nil, errors.New("ssh recorded no host key; check that your ssh config does not disable host key checking for this host")
	}
	if err := ValidateHostKeys(lines); err != nil {
		return nil, err
	}
	return lines, nil
}
