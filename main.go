package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/atotto/clipboard"
	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/argon2"
)

type Entry struct {
	Name string `json:"name"`
	User string `json:"user"`
	Host string `json:"host"`
	Key  string `json:"key"`
}

const vaultFile = "vault.enc"

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
		return nil, errors.New("invalid vault")
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
		return nil, err
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

func getVaultPassword() (string, error) {
	if pw := os.Getenv("VAULT_PASSWORD"); pw != "" {
		return pw, nil
	}
	fmt.Print("Vault password: ")
	var password string
	fmt.Scanln(&password)
	return password, nil
}

func main() {
	app := &cli.App{
		Name:  "sshman",
		Usage: "Manage SSH keys securely",
		Commands: []*cli.Command{
			{
				Name:  "init",
				Usage: "Initialize vault",
				Action: func(c *cli.Context) error {
					if _, err := os.Stat(vaultFile); err == nil {
						return fmt.Errorf("vault already exists")
					}
					password, err := getVaultPassword()
					if err != nil {
						return err
					}
					return saveVault([]Entry{}, password)
				},
			},
			{
				Name:  "add",
				Usage: "Add new entry",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "name"},
					&cli.StringFlag{Name: "user"},
					&cli.StringFlag{Name: "host"},
					&cli.StringFlag{Name: "key"},
				},
				Action: func(c *cli.Context) error {
					password, err := getVaultPassword()
					if err != nil {
						return err
					}
					entries, err := loadVault(password)
					if err != nil {
						return err
					}
					entry := Entry{
						Name: c.String("name"),
						User: c.String("user"),
						Host: c.String("host"),
						Key:  c.String("key"),
					}
					entries = append(entries, entry)
					return saveVault(entries, password)
				},
			},
			{
				Name:  "connect",
				Usage: "Connect to host securely using stored key",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "name"},
				},
				Action: func(c *cli.Context) error {
					password, err := getVaultPassword()
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
							tmpFile, err := os.CreateTemp("", "sshkey_*.key")
							if err != nil {
								return err
							}
							defer os.Remove(tmpFile.Name())
							if _, err := tmpFile.Write([]byte(e.Key)); err != nil {
								return err
							}
							tmpFile.Close()
							cmd := exec.Command("ssh", "-i", tmpFile.Name(), fmt.Sprintf("%s@%s", e.User, e.Host))
							cmd.Stdin = os.Stdin
							cmd.Stdout = os.Stdout
							cmd.Stderr = os.Stderr
							return cmd.Run()
						}
					}
					return errors.New("entry not found")
				},
			},
		},
	}
	app.Run(os.Args)
}
