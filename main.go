package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/cipher"
	"crypto/aes"	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
	"syscall"


	"github.com/atotto/clipboard"
	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

type Entry struct {
	Name   string `json:"name"`
	User   string `json:"user"`
	Host   string `json:"host"`
	Key    string `json:"key"`             // private key PEM content
	PubKey string `json:"pubkey,omitempty"` // public key authorized_keys format
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

func generateRSAKeyPair(bits int) (privateKeyPEM string, publicKeyAuthorized string, err error) {
	privKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return "", "", err
	}
	privDER := x509.MarshalPKCS1PrivateKey(privKey)
	privBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privDER,
	}
	privPEMBytes := pem.EncodeToMemory(privBlock)
	if privPEMBytes == nil {
		return "", "", errors.New("failed to encode private key")
	}
	privPEM := string(privPEMBytes)

	pub, err := ssh.NewPublicKey(&privKey.PublicKey)
	if err != nil {
		return "", "", err
	}
	pubAuthorized := string(ssh.MarshalAuthorizedKey(pub))

	return privPEM, pubAuthorized, nil
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
				Usage: "Add new SSH entry with existing private key PEM content",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "name", Required: true},
					&cli.StringFlag{Name: "user", Required: true},
					&cli.StringFlag{Name: "host", Required: true},
					&cli.StringFlag{Name: "key", Required: true}, // private key PEM content (as string)
					&cli.StringFlag{Name: "pubkey"},              // optional public key (authorized_keys)
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
						Name:   c.String("name"),
						User:   c.String("user"),
						Host:   c.String("host"),
						Key:    c.String("key"),
						PubKey: c.String("pubkey"),
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
							// Create temp file for private key since ssh requires a file
							tmpFile, err := ioutil.TempFile("", "sshkey-*")
							if err != nil {
								return err
							}
							defer os.Remove(tmpFile.Name())

							if _, err := tmpFile.Write([]byte(e.Key)); err != nil {
								tmpFile.Close()
								return err
							}
							tmpFile.Close()

							cmd := fmt.Sprintf("ssh %s@%s -i %s", e.User, e.Host, tmpFile.Name())
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
					 &cli.StringFlag{Name: "pubkey"},
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
					var found bool
					for i := range entries {
						if entries[i].Name == name {
							found = true
							if c.String("user") != "" {
								entries[i].User = c.String("user")
							}
							if c.String("host") != "" {
								entries[i].Host = c.String("host")
							}
							if c.String("key") != "" {
								entries[i].Key = c.String("key")
							}
							if c.String("pubkey") != "" {
								entries[i].PubKey = c.String("pubkey")
							}
							break
						}
					}
					if !found {
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
				Name:  "connect",
				Usage: "Connect to host using stored private key",
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
					var e *Entry
					for i := range entries {
						if entries[i].Name == name {
							e = &entries[i]
							break
						}
					}
					if e == nil {
						return errors.New("entry not found")
					}
					if e.Key == "" {
						return errors.New("no private key in entry")
					}

					// Create temporary file for private key
					tmpFile, err := ioutil.TempFile("", "sshkey-*")
					if err != nil {
						return err
					}
					defer os.Remove(tmpFile.Name())

					if _, err := tmpFile.Write([]byte(e.Key)); err != nil {
						tmpFile.Close()
						return err
					}
					tmpFile.Close()

					args := []string{"-i", tmpFile.Name(), fmt.Sprintf("%s@%s", e.User, e.Host)}
					cmd := exec.Command("ssh", args...)
					cmd.Stdin = os.Stdin
					cmd.Stdout = os.Stdout
					cmd.Stderr = os.Stderr
					fmt.Printf("Connecting to %s@%s...\n", e.User, e.Host)
					return cmd.Run()
				},
			},
			{
				Name:  "genkey",
				Usage: "Generate new SSH key pair and store in vault",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "name", Required: true},
					&cli.StringFlag{Name: "user", Required: true},
					&cli.StringFlag{Name: "host", Required: true},
					&cli.IntFlag{Name: "bits", Value: 2048},
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

					bits := c.Int("bits")
					privKeyPEM, pubKeyAuthorized, err := generateRSAKeyPair(bits)
					if err != nil {
						return err
					}

					entry := Entry{
						Name:   c.String("name"),
						User:   c.String("user"),
						Host:   c.String("host"),
						Key:    privKeyPEM,
						PubKey: pubKeyAuthorized,
					}
					entries = append(entries, entry)

					if err := saveVault(entries, password); err != nil {
						return err
					}
					fmt.Println("Key pair generated and saved in vault.")
					return nil
				},
			},
			{
				Name:  "sendkey",
				Usage: "Send public key to remote server's authorized_keys",
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
					var entry *Entry
					for i := range entries {
						if entries[i].Name == name {
							entry = &entries[i]
							break
						}
					}
					if entry == nil {
						return errors.New("entry not found")
					}
					if entry.PubKey == "" {
						return errors.New("no public key found in vault entry")
					}

					// Prepare the ssh command to add public key to remote authorized_keys
					remote := fmt.Sprintf("%s@%s", entry.User, entry.Host)
					pubKeyEscaped := strings.ReplaceAll(strings.TrimSpace(entry.PubKey), "'", "'\"'\"'")
					cmdStr := fmt.Sprintf("mkdir -p ~/.ssh && chmod 700 ~/.ssh && echo '%s' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys", pubKeyEscaped)

					sshCmd := exec.Command("ssh", remote, cmdStr)
					sshCmd.Stdout = os.Stdout
					sshCmd.Stderr = os.Stderr
					sshCmd.Stdin = os.Stdin

					fmt.Printf("Sending public key to %s...\n", remote)
					return sshCmd.Run()
				},
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		fmt.Println("Error:", err)
	}
}
