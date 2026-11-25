package sshutil

import (
	"errors"
	"fmt"
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
	key := typeAndBlob(keyLine)
	return `umask 077; mkdir -p "$HOME/.ssh" || exit 1; f="$HOME/.ssh/authorized_keys"; touch "$f" || exit 1; ` +
		`if grep -qF "` + key + `" "$f"; then echo "sshman: key already present in $f" >&2; ` +
		`else if [ -s "$f" ] && [ -n "$(tail -c 1 "$f")" ]; then echo >> "$f"; fi; ` +
		`echo "` + keyLine + `" >> "$f" || exit 1; echo "sshman: key added to $f" >&2; fi; ` +
		`chmod 700 "$HOME/.ssh" && chmod 600 "$f"`
}

func remoteInstallCommand(keyLine string) string {
	return "sh -c '" + installKeyScript(keyLine) + "'"
}

// typeAndBlob returns "<type> <base64>" of a canonical key line: the part
// that identifies the key, whatever its comment or options.
func typeAndBlob(keyLine string) string {
	return strings.Join(strings.Fields(keyLine)[:2], " ")
}

// removeKeyScript returns a POSIX sh script that deletes every
// authorized_keys line carrying oldLine's key. It refuses to touch the file
// unless keepLine's key is in it, so a rotation can never lock the user out.
// Both lines come from CanonicalAuthorizedKey (see installKeyScript).
// shortcut: mv replaces a symlinked authorized_keys with a regular file;
// resolve the link first if users report such setups.
func removeKeyScript(oldLine, keepLine string) string {
	oldKey, keepKey := typeAndBlob(oldLine), typeAndBlob(keepLine)
	return `f="$HOME/.ssh/authorized_keys"; ` +
		`grep -qF "` + keepKey + `" "$f" || { echo "sshman: new key not found in $f; old key kept" >&2; exit 1; }; ` +
		`if ! grep -qF "` + oldKey + `" "$f"; then echo "sshman: old key not present in $f" >&2; exit 0; fi; ` +
		`umask 077; t="$f.sshman.$$"; ` +
		`if grep -vF "` + oldKey + `" "$f" > "$t" && chmod 600 "$t" && mv -f "$t" "$f"; then echo "sshman: old key removed from $f" >&2; ` +
		`else rm -f "$t"; exit 1; fi`
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
func sendKeyViaArgs(e *model.Entry, remoteCmd, sock, pubFile string, opts *Options) []string {
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
	return append(args, "--", e.Addr(), remoteCmd)
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
		args, done, err := sshArgs(e, &opts, sendKeyArgs(e, keyLine, &opts))
		if err != nil {
			return err
		}
		defer done()
		return runSSH(opts.sshPath(), args, &opts)
	}
	if via.Key == "" {
		return fmt.Errorf("entry %q has no private key to log in with", via.Name)
	}
	s, err := startSession(via)
	if err != nil {
		return err
	}
	defer s.close()
	args, done, err := sshArgs(e, &opts, sendKeyViaArgs(e, remoteInstallCommand(keyLine), s.sock, s.pubFile, &opts))
	if err != nil {
		return err
	}
	defer done()
	return runSSH(opts.sshPath(), args, &opts)
}

// RemovePublicKey logs in with e's own vault key and removes oldLine's key
// from the remote authorized_keys. The login itself proves e's key works; the
// script also checks that e's key is listed before removing anything.
func RemovePublicKey(e *model.Entry, oldLine string, opts Options) error {
	if err := ValidateEntry(e); err != nil {
		return err
	}
	keep, err := EntryPublicKey(e.Key, e.PubKey)
	if err != nil {
		return fmt.Errorf("entry %q: %w", e.Name, err)
	}
	old, _, err := CanonicalAuthorizedKey(oldLine)
	if err != nil {
		return err
	}
	if typeAndBlob(old) == typeAndBlob(keep) {
		return errors.New("refusing to remove the key used to log in")
	}
	s, err := startSession(e)
	if err != nil {
		return err
	}
	defer s.close()
	cmd := "sh -c '" + removeKeyScript(old, keep) + "'"
	args, done, err := sshArgs(e, &opts, sendKeyViaArgs(e, cmd, s.sock, s.pubFile, &opts))
	if err != nil {
		return err
	}
	defer done()
	return runSSH(opts.sshPath(), args, &opts)
}
