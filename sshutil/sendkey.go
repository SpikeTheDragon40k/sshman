package sshutil

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/sshman-org/sshman/model"
)

// installKeyScript returns a POSIX sh script that appends keyLine to
// ~/.ssh/authorized_keys unless that key is already present (S-13). It runs
// under "sh -c" so the remote login shell (bash, zsh, fish, csh, ...) only has
// to pass one single-quoted word through. keyLine comes from
// CanonicalAuthorizedKey and contains only [A-Za-z0-9+/=@._:, -], so it can be
// placed inside double quotes without escaping.
func installKeyScript(keyLine string) string {
	typeAndBlob := strings.Join(strings.Fields(keyLine)[:2], " ")
	return `umask 077; mkdir -p "$HOME/.ssh" || exit 1; f="$HOME/.ssh/authorized_keys"; touch "$f" || exit 1; ` +
		`if grep -qF "` + typeAndBlob + `" "$f"; then echo "sshman: key already present in $f" >&2; ` +
		`else if [ -s "$f" ] && [ -n "$(tail -c 1 "$f")" ]; then echo >> "$f"; fi; ` +
		`echo "` + keyLine + `" >> "$f" || exit 1; echo "sshman: key added to $f" >&2; fi; ` +
		`chmod 700 "$HOME/.ssh" && chmod 600 "$f"`
}

func remoteInstallCommand(keyLine string) string {
	return "sh -c '" + installKeyScript(keyLine) + "'"
}

// sendKeyArgs authenticates with the user's normal ssh setup, including
// password or keyboard-interactive prompts typed into ssh itself, so a
// password-only server can be bootstrapped (Q-04). Forwarding is disabled.
func sendKeyArgs(e *model.Entry, keyLine string, opts *Options) []string {
	args := []string{
		"-o", "ForwardAgent=no",
		"-o", "ForwardX11=no",
		"-o", "ClearAllForwardings=yes",
		"-o", "PermitLocalCommand=no",
		"-T",
	}
	if opts.AcceptNewHostKey {
		args = append(args, "-o", "StrictHostKeyChecking=accept-new")
	}
	if e.Port > 0 && e.Port != 22 {
		args = append(args, "-p", strconv.Itoa(e.Port))
	}
	return append(args, "--", e.Addr(), remoteInstallCommand(keyLine))
}

// sendKeyViaArgs authenticates with another vault entry's key through the
// session agent, e.g. to install a rotated key using the old one.
func sendKeyViaArgs(e *model.Entry, keyLine, sock, pubFile string, opts *Options) []string {
	args := []string{
		"-o", "IdentityAgent=" + sock,
		"-o", "IdentityFile=" + pubFile,
		"-o", "IdentitiesOnly=yes",
		"-o", "ForwardAgent=no",
		"-o", "AddKeysToAgent=no",
		"-o", "ForwardX11=no",
		"-o", "ClearAllForwardings=yes",
		"-o", "PermitLocalCommand=no",
		"-T",
	}
	if opts.AcceptNewHostKey {
		args = append(args, "-o", "StrictHostKeyChecking=accept-new")
	}
	if e.Port > 0 && e.Port != 22 {
		args = append(args, "-p", strconv.Itoa(e.Port))
	}
	return append(args, "--", e.Addr(), remoteInstallCommand(keyLine))
}

// SendPublicKey installs the entry's public key in the remote
// authorized_keys. If via is non-nil, its vault key is used to log in;
// otherwise ssh uses the user's own configuration and may prompt for a
// password.
func SendPublicKey(e *model.Entry, via *model.Entry, opts Options) error {
	if err := ValidateEntry(e); err != nil {
		return err
	}
	keyLine, err := EntryPublicKey(e.Key, e.PubKey)
	if err != nil {
		return fmt.Errorf("entry %q: %w", e.Name, err)
	}
	keyLine, _, err = CanonicalAuthorizedKey(keyLine)
	if err != nil {
		return err
	}
	if via == nil {
		return runSSH(opts.sshPath(), append(slices.Clone(opts.testArgs), sendKeyArgs(e, keyLine, &opts)...), &opts)
	}
	if via.Key == "" {
		return fmt.Errorf("entry %q has no private key to log in with", via.Name)
	}
	s, err := startSession(via)
	if err != nil {
		return err
	}
	defer s.close()
	return runSSH(opts.sshPath(), append(slices.Clone(opts.testArgs), sendKeyViaArgs(e, keyLine, s.sock, s.pubFile, &opts)...), &opts)
}
