package app

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/sshman-org/sshman/vault"
)

// Doctor checks the vault location, file safety, format and the OpenSSH
// client without asking for the password. It returns an error if a problem
// needs attention.
func (a *App) Doctor() error {
	problems := 0
	ok := func(f string, args ...any) { fmt.Fprintf(a.Stdout, "  ok    "+f+"\n", args...) }
	warn := func(f string, args ...any) { fmt.Fprintf(a.Stdout, "  WARN  "+f+"\n", args...) }
	bad := func(f string, args ...any) { problems++; fmt.Fprintf(a.Stdout, "  FAIL  "+f+"\n", args...) }

	fmt.Fprintf(a.Stdout, "Vault: %s\n", a.VaultPath)
	info, size, err := vault.Inspect(a.VaultPath)
	switch {
	case errors.Is(err, vault.ErrNotFound):
		bad("vault does not exist (create it with 'sshman init')")
	case err != nil:
		bad("%v", err)
	default:
		ok("file is private, owned by you and not a symlink (%d bytes)", size)
		p := info.Params
		if info.Outdated() {
			warn("format v%d, Argon2id t=%d m=%dMiB p=%d; run 'sshman passwd' to re-encrypt with current parameters", info.Version, p.Time, p.MemoryKiB/1024, p.Threads)
		} else {
			ok("format v%d, Argon2id t=%d m=%dMiB p=%d", info.Version, p.Time, p.MemoryKiB/1024, p.Threads)
		}
	}
	if _, _, err := vault.Inspect(vault.BackupPath(a.VaultPath)); err == nil {
		ok("backup present: %s", vault.BackupPath(a.VaultPath))
	} else if !errors.Is(err, vault.ErrNotFound) {
		warn("backup %s: %v", vault.BackupPath(a.VaultPath), err)
	} else {
		warn("no backup yet (one is kept automatically after the first change)")
	}

	fmt.Fprintln(a.Stdout, "OpenSSH client:")
	sshPath := a.SSH.SSHPath
	if sshPath == "" {
		sshPath = "ssh"
	}
	if p, err := exec.LookPath(sshPath); err != nil {
		bad("ssh not found in PATH (needed for connect and sendkey)")
	} else {
		out, _ := exec.Command(p, "-V").CombinedOutput()
		ok("%s (%s)", p, strings.TrimSpace(string(out)))
	}
	if runtime.GOOS == "windows" {
		warn("connect with vault keys is not supported on Windows yet (sendkey and vault management are)")
	}
	if os.Getenv("SSH_AUTH_SOCK") != "" {
		ok("your own ssh-agent is untouched; sshman uses a private per-session agent")
	}
	if problems > 0 {
		return fmt.Errorf("%d problem(s) found", problems)
	}
	return nil
}
