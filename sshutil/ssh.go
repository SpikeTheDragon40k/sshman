package sshutil

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/SpikeTheDragon40k/sshman/model"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

var validHostRe = regexp.MustCompile(`^[a-zA-Z0-9._:%\[\]-]+$`)
var validUserRe = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)

func ValidateEntry(e *model.Entry) error {
	if e.Name == "" {
		return fmt.Errorf("name is required")
	}
	if e.User == "" {
		return fmt.Errorf("user is required")
	}
	if e.Host == "" {
		return fmt.Errorf("host is required")
	}
	if !validUserRe.MatchString(e.User) {
		return fmt.Errorf("invalid user %q: must match %s", e.User, validUserRe.String())
	}
	if !validHostRe.MatchString(e.Host) {
		return fmt.Errorf("invalid host %q: must match %s", e.Host, validHostRe.String())
	}
	if e.Port < 0 || e.Port > 65535 {
		return fmt.Errorf("invalid port %d: must be 0-65535", e.Port)
	}
	return nil
}

func sshHardeningArgs() []string {
	return []string{
		"-o", "StrictHostKeyChecking=accept-new",
		"-o", "PasswordAuthentication=no",
		"-o", "IdentitiesOnly=yes",
	}
}

func Connect(entry *model.Entry) error {
	if entry.Key == "" {
		return fmt.Errorf("no private key in entry %q", entry.Name)
	}

	tmpDir, err := os.MkdirTemp("", "sshman-*")
	if err != nil {
		return fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	sockPath := filepath.Join(tmpDir, "agent.sock")
	ag := agent.NewKeyring()

	rawKey, err := ssh.ParseRawPrivateKey([]byte(entry.Key))
	if err != nil {
		return fmt.Errorf("failed to parse private key: %w", err)
	}

	if err := ag.Add(agent.AddedKey{PrivateKey: rawKey}); err != nil {
		return fmt.Errorf("failed to add key to agent: %w", err)
	}

	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		return fmt.Errorf("failed to listen on agent socket: %w", err)
	}
	defer listener.Close()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go agent.ServeAgent(ag, conn)
		}
	}()

	args := append(sshHardeningArgs())
	if entry.Port > 0 && entry.Port != 22 {
		args = append(args, "-p", fmt.Sprintf("%d", entry.Port))
	}
	args = append(args, entry.Addr())

	cmd := exec.Command("ssh", args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(), "SSH_AUTH_SOCK="+sockPath)

	return cmd.Run()
}

func SendPublicKey(entry *model.Entry) error {
	if entry.PubKey == "" {
		return fmt.Errorf("no public key in entry %q", entry.Name)
	}

	if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(entry.PubKey)); err != nil {
		return fmt.Errorf("invalid public key: %w", err)
	}

	remote := entry.Addr()
	quotedKey := fmt.Sprintf("'%s'", strings.ReplaceAll(strings.TrimSpace(entry.PubKey), "'", "'\"'\"'"))
	cmdStr := fmt.Sprintf(
		"mkdir -p ~/.ssh && chmod 700 ~/.ssh && echo %s >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys",
		quotedKey,
	)

	args := append(sshHardeningArgs(), remote, cmdStr)
	sshCmd := exec.Command("ssh", args...)
	sshCmd.Stdout = os.Stdout
	sshCmd.Stderr = os.Stderr
	sshCmd.Stdin = os.Stdin
	sshCmd.Env = append(os.Environ())
	fmt.Printf("Sending public key to %s...\n", remote)
	return sshCmd.Run()
}
