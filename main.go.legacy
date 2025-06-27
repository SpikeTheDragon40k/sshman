package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/atotto/clipboard"
	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/argon2"
	"golang.org/x/term"
)

type Entry struct {
	Name string `json:"name"`
	User string `json:"user"`
	Host string `json:"host"`
	Key  string `json:"key"`
}

const vaultFile = "vault.vssh"

func deriveKey(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
}

func encryptVault(entries []Entry, password string) ([]byte, error) {
	plaintext, err := json.Marshal(entries)
	if err != nil {
		return nil, err
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	key := deriveKey(password, salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	return append(append(salt, nonce...), ciphertext...), nil
}

func decryptVault(data []byte, password string) ([]Entry, error) {
	if len(data) < 28 {
		return nil, errors.New("invalid vault file format")
	}
	salt := data[:16]
	nonce := data[16:28]
	ciphertext := data[28:]
	key := deriveKey(password, salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.New("incorrect password or corrupted vault")
	}
	var entries []Entry
	err = json.Unmarshal(plaintext, &entries)
	return entries, err
}

func loadVault(password string) ([]Entry, error) {
	data, err := os.ReadFile(vaultFile)
	if err != nil {
		return nil, err
	}
	return decryptVault(data, password)
}

func saveVault(entries []Entry, password string) error {
	data, err := encryptVault(entries, password)
	if err != nil {
		return err
	}
	return os.WriteFile(vaultFile, data, 0600)
}

func readPassword(prompt string) (string, error) {
	fmt.Print(prompt)
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		return "", err
	}
	return string(bytes.TrimSpace(bytePassword)), nil
}

func main() {
	app := &cli.App{
		Name:  "sshman",
		Usage: "Manage SSH keys securely",
		Commands: []*cli.Command{
			{
				Name:  "init",
				Usage: "Initialize vault (create empty vault file)",
				Action: func(c *cli.Context) error {
					if _, err := os.Stat(vaultFile); err == nil {
						return fmt.Errorf("vault already exists at %s", vaultFile)
					}
					password, err := readPassword("Set vault password: ")
					if err != nil {
						return err
					}
					return saveVault([]Entry{}, password)
				},
			},
			{
				Name:  "add",
				Usage: "Add new SSH entry",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "name", Required: true},
					&cli.StringFlag{Name: "user", Required: true},
					&cli.StringFlag{Name: "host", Required: true},
					&cli.StringFlag{Name: "key", Required: true},
				},
				Action: func(c *cli.Context) error {
					password, err := readPassword("Vault password: ")
					if err != nil {
						return err
					}
					entries, err := loadVault(password)
					if err != nil {
						return fmt.Errorf("failed to load vault: %w", err)
					}

					entry := Entry{
						Name: c.String("name"),
						User: c.String("user"),
						Host: c.String("host"),
						Key:  c.String("key"),
					}
					entries = append(entries, entry)

					if err := saveVault(entries, password); err != nil {
						return fmt.Errorf("failed to save vault: %w", err)
					}
					fmt.Println("Entry added successfully.")
					return nil
				},
			},
			{
				Name:  "list",
				Usage: "List all entries",
				Action: func(c *cli.Context) error {
					password, err := readPassword("Vault password: ")
					if err != nil {
						return err
					}
					entries, err := loadVault(password)
					if err != nil {
						return err
					}
					for _, e := range entries {
						fmt.Printf("%s: %s@%s\n", e.Name, e.User, e.Host)
					}
					return nil
				},
			},
			{
				Name:  "copy",
				Usage: "Copy SSH command to clipboard",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "name", Required: true},
				},
				Action: func(c *cli.Context) error {
					password, err := readPassword("Vault password: ")
					if err != nil {
						return err
					}
					entries, err := loadVault(password)
					if err != nil {
						return err
					}
					name := c.String("name")
					for _, e := range entries {
						if e.Name == name {
							cmd := fmt.Sprintf("ssh %s@%s -i %s", e.User, e.Host, e.Key)
							if err := clipboard.WriteAll(cmd); err != nil {
								return err
							}
							fmt.Println("Copied to clipboard:", cmd)
							return nil
						}
					}
					return errors.New("entry not found")
				},
			},
			{
				Name:  "delete",
				Usage: "Delete entry by name",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "name", Required: true},
				},
				Action: func(c *cli.Context) error {
					password, err := readPassword("Vault password: ")
					if err != nil {
						return err
					}
					entries, err := loadVault(password)
					if err != nil {
						return err
					}
					name := c.String("name")
					newEntries := []Entry{}
					found := false
					for _, e := range entries {
						if e.Name == name {
							found = true
							continue
						}
						newEntries = append(newEntries, e)
					}
					if !found {
						return errors.New("entry not found")
					}
					if err := saveVault(newEntries, password); err != nil {
						return err
					}
					fmt.Println("Entry deleted.")
					return nil
				},
			},
			{
				Name:  "update",
				Usage: "Update entry",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "name", Required: true},
					&cli.StringFlag{Name: "user"},
					&cli.StringFlag{Name: "host"},
					&cli.StringFlag{Name: "key"},
				},
				Action: func(c *cli.Context) error {
					password, err := readPassword("Vault password: ")
					if err != nil {
						return err
					}
					entries, err := loadVault(password)
					if err != nil {
						return err
					}
					name := c.String("name")
					updated := false
					for i := range entries {
						if entries[i].Name == name {
							if c.IsSet("user") {
								entries[i].User = c.String("user")
							}
							if c.IsSet("host") {
								entries[i].Host = c.String("host")
							}
							if c.IsSet("key") {
								entries[i].Key = c.String("key")
							}
							updated = true
							break
						}
					}
					if !updated {
						return errors.New("entry not found")
					}
					if err := saveVault(entries, password); err != nil {
						return err
					}
					fmt.Println("Entry updated.")
					return nil
				},
			},
			{
				Name:  "search",
				Usage: "Search entries by keyword",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "query", Required: true},
				},
				Action: func(c *cli.Context) error {
					password, err := readPassword("Vault password: ")
					if err != nil {
						return err
					}
					entries, err := loadVault(password)
					if err != nil {
						return err
					}
					query := c.String("query")
					found := false
					for _, e := range entries {
						if strings.Contains(e.Name, query) || strings.Contains(e.User, query) || strings.Contains(e.Host, query) {
							fmt.Printf("%s: %s@%s\n", e.Name, e.User, e.Host)
							found = true
						}
					}
					if !found {
						fmt.Println("No matching entries found.")
					}
					return nil
				},
			},
			{
				Name:  "genkey",
				Usage: "Generate SSH key pair files",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "name", Required: true},
					&cli.StringFlag{Name: "bits", Value: "2048"},
				},
				Action: func(c *cli.Context) error {
					name := c.String("name")
					bits := c.Int("bits")
					if bits != 2048 && bits != 4096 {
						return errors.New("only 2048 or 4096 bits allowed")
					}
					keyPath := name + ".key"
					pubKeyPath := name + ".key.pub"

					// Use ssh-keygen to generate key (system must have ssh-keygen)
					cmd := exec.Command("ssh-keygen", "-t", "rsa", "-b", fmt.Sprintf("%d", bits), "-f", keyPath, "-N", "")
					cmd.Stderr = os.Stderr
					cmd.Stdout = os.Stdout
					if err := cmd.Run(); err != nil {
						return fmt.Errorf("ssh-keygen failed: %w", err)
					}
					fmt.Printf("Key pair generated:\nPrivate: %s\nPublic: %s\n", keyPath, pubKeyPath)
					return nil
				},
			},
			{
				Name:  "connect",
				Usage: "Connect to SSH host from vault",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "name", Required: true},
				},
				Action: func(c *cli.Context) error {
					password, err := readPassword("Vault password: ")
					if err != nil {
						return err
					}
					entries, err := loadVault(password)
					if err != nil {
						return err
					}
					name := c.String("name")
					for _, e := range entries {
						if e.Name == name {
							args := []string{}
							if e.Key != "" {
								args = append(args, "-i", e.Key)
							}
							args = append(args, fmt.Sprintf("%s@%s", e.User, e.Host))
							cmd := exec.Command("ssh", args...)
							cmd.Stdin = os.Stdin
							cmd.Stdout = os.Stdout
							cmd.Stderr = os.Stderr
							fmt.Printf("Connecting to %s@%s...\n", e.User, e.Host)
							return cmd.Run()
						}
					}
					return errors.New("entry not found")
				},
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}
