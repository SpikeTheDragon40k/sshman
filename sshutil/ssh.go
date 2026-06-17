package sshutil

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/SpikeTheDragon40k/sshman/model"
)

func WriteTempKey(keyPEM string) (string, error) {
	tmpFile, err := os.CreateTemp("", "sshkey-*")
	if err != nil {
		return "", err
	}
	if _, err := tmpFile.Write([]byte(keyPEM)); err != nil {
		tmpFile.Close()
		os.Remove(tmpFile.Name())
		return "", err
	}
	if err := tmpFile.Close(); err != nil {
		os.Remove(tmpFile.Name())
		return "", err
	}
	return tmpFile.Name(), nil
}

func Connect(entry *model.Entry) error {
	if entry.Key == "" {
		return fmt.Errorf("no private key in entry %q", entry.Name)
	}
	tmpPath, err := WriteTempKey(entry.Key)
	if err != nil {
		return fmt.Errorf("failed to write temp key: %w", err)
	}
	defer os.Remove(tmpPath)

	args := []string{"-i", tmpPath}
	if entry.Port > 0 && entry.Port != 22 {
		args = append(args, "-p", fmt.Sprintf("%d", entry.Port))
	}
	args = append(args, entry.Addr())

	cmd := exec.Command("ssh", args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	fmt.Printf("Connecting to %s...\n", entry.Addr())
	return cmd.Run()
}

func BuildSSHCommand(entry *model.Entry) (string, string, error) {
	if entry.Key == "" {
		return "", "", fmt.Errorf("no private key in entry %q", entry.Name)
	}
	tmpPath, err := WriteTempKey(entry.Key)
	if err != nil {
		return "", "", fmt.Errorf("failed to write temp key: %w", err)
	}
	cmd := fmt.Sprintf("ssh %s -i %s", entry.AddrPort(), tmpPath)
	return cmd, tmpPath, nil
}

func SendPublicKey(entry *model.Entry) error {
	if entry.PubKey == "" {
		return fmt.Errorf("no public key in entry %q", entry.Name)
	}
	remote := entry.Addr()
	pubKeyEscaped := strings.ReplaceAll(strings.TrimSpace(entry.PubKey), "'", "'\"'\"'")
	cmdStr := fmt.Sprintf(
		"mkdir -p ~/.ssh && chmod 700 ~/.ssh && echo '%s' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys",
		pubKeyEscaped,
	)
	sshCmd := exec.Command("ssh", remote, cmdStr)
	sshCmd.Stdout = os.Stdout
	sshCmd.Stderr = os.Stderr
	sshCmd.Stdin = os.Stdin
	fmt.Printf("Sending public key to %s...\n", remote)
	return sshCmd.Run()
}
