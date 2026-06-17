package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"syscall"

	"github.com/SpikeTheDragon40k/sshman/keygen"
	"github.com/SpikeTheDragon40k/sshman/model"
	"github.com/SpikeTheDragon40k/sshman/sshutil"
	"github.com/SpikeTheDragon40k/sshman/vault"
	"github.com/atotto/clipboard"
	"github.com/urfave/cli/v2"
	"golang.org/x/term"
)

const DefaultVaultFile = "vault.vssh"

func readPassword(prompt string) (string, error) {
	fmt.Print(prompt)
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		return "", err
	}
	return string(bytes.TrimSpace(bytePassword)), nil
}

func printBanner() {
	fmt.Print(`
  ______    ______   __    __  __       __   ______   __    __
 /      \  /      \ /  |  /  |/  \     /  | /      \ /  \  /  |
/$$$$$$  |/$$$$$$  |$$ |  $$ |$$  \   /$$ |/$$$$$$  |$$  \ $$ |
$$ \__$$/ $$ \__$$/ $$ |__$$ |$$$  \ /$$$ |$$ |__$$ |$$$  \$$ |
$$      \ $$      \ $$    $$ |$$$$  /$$$$ |$$    $$ |$$$$  $$ |
 $$$$$$  | $$$$$$  |$$$$$$$$ |$$ $$ $$/$$ |$$$$$$$$ |$$ $$ $$ |
/  \__$$ |/  \__$$ |$$ |  $$ |$$ |$$$/ $$ |$$ |  $$ |$$ |$$$$ |
$$    $$/ $$    $$/ $$ |  $$ |$$ | $/  $$ |$$ |  $$ |$$ | $$$ |
 $$$$$$/   $$$$$$/  $$/   $$/ $$/      $$/ $$/   $$/ $$/   $$/
                                                               
 Secure SSH Key Manager
`)
}

func resolveKeyInput(value string) (string, error) {
	if value == "" {
		return "", nil
	}
	if info, err := os.Stat(value); err == nil && !info.IsDir() {
		data, err := os.ReadFile(value)
		if err != nil {
			return "", fmt.Errorf("failed to read key file %q: %w", value, err)
		}
		return string(data), nil
	}
	return value, nil
}

func Commands() []*cli.Command {
	return []*cli.Command{
		initCmd(),
		addCmd(),
		listCmd(),
		searchCmd(),
		copyCmd(),
		deleteCmd(),
		updateCmd(),
		connectCmd(),
		genkeyCmd(),
		sendkeyCmd(),
	}
}

func initCmd() *cli.Command {
	return &cli.Command{
		Name:  "init",
		Usage: "Initialize vault (create empty vault file)",
		Action: func(c *cli.Context) error {
			printBanner()
			vf := c.String("vault")
			if vf == "" {
				vf = DefaultVaultFile
			}
			if _, err := os.Stat(vf); err == nil {
				return fmt.Errorf("vault already exists at %s", vf)
			}
			password, err := readPassword("Set vault password: ")
			if err != nil {
				return err
			}
			return vault.Save(vf, password, []model.Entry{})
		},
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "vault", Usage: "path to vault file"},
		},
	}
}

func addCmd() *cli.Command {
	return &cli.Command{
		Name:  "add",
		Usage: "Add new SSH entry",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "name", Required: true},
			&cli.StringFlag{Name: "user", Required: true},
			&cli.StringFlag{Name: "host", Required: true},
			&cli.IntFlag{Name: "port", Value: 22},
			&cli.StringFlag{Name: "key", Required: true},
			&cli.StringFlag{Name: "pubkey"},
			&cli.StringFlag{Name: "vault"},
		},
		Action: func(c *cli.Context) error {
			vf := c.String("vault")
			if vf == "" {
				vf = DefaultVaultFile
			}
			password, err := readPassword("Vault password: ")
			if err != nil {
				return err
			}
			entries, err := vault.Load(vf, password)
			if err != nil {
				return fmt.Errorf("failed to load vault: %w", err)
			}
			keyContent, err := resolveKeyInput(c.String("key"))
			if err != nil {
				return err
			}
			entry := model.Entry{
				Name:   c.String("name"),
				User:   c.String("user"),
				Host:   c.String("host"),
				Port:   c.Int("port"),
				Key:    keyContent,
				PubKey: c.String("pubkey"),
			}
			entries = append(entries, entry)
			if err := vault.Save(vf, password, entries); err != nil {
				return fmt.Errorf("failed to save vault: %w", err)
			}
			fmt.Println("Entry added successfully.")
			return nil
		},
	}
}

func listCmd() *cli.Command {
	return &cli.Command{
		Name:  "list",
		Usage: "List all entries",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "vault"},
		},
		Action: func(c *cli.Context) error {
			vf := c.String("vault")
			if vf == "" {
				vf = DefaultVaultFile
			}
			password, err := readPassword("Vault password: ")
			if err != nil {
				return err
			}
			printBanner()
			entries, err := vault.Load(vf, password)
			if err != nil {
				return err
			}
			if len(entries) == 0 {
				fmt.Println("No entries in vault.")
				return nil
			}
			for _, e := range entries {
				port := ""
				if e.Port > 0 && e.Port != 22 {
					port = fmt.Sprintf(":%d", e.Port)
				}
				fmt.Printf("  %s: %s@%s%s\n", e.Name, e.User, e.Host, port)
			}
			return nil
		},
	}
}

func searchCmd() *cli.Command {
	return &cli.Command{
		Name:  "search",
		Usage: "Search entries by keyword",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "query", Aliases: []string{"q"}, Required: true},
			&cli.StringFlag{Name: "vault"},
		},
		Action: func(c *cli.Context) error {
			vf := c.String("vault")
			if vf == "" {
				vf = DefaultVaultFile
			}
			password, err := readPassword("Vault password: ")
			if err != nil {
				return err
			}
			entries, err := vault.Load(vf, password)
			if err != nil {
				return err
			}
			results := model.Search(entries, c.String("query"))
			if len(results) == 0 {
				fmt.Println("No matching entries found.")
				return nil
			}
			for _, e := range results {
				port := ""
				if e.Port > 0 && e.Port != 22 {
					port = fmt.Sprintf(":%d", e.Port)
				}
				fmt.Printf("  %s: %s@%s%s\n", e.Name, e.User, e.Host, port)
			}
			return nil
		},
	}
}

func copyCmd() *cli.Command {
	return &cli.Command{
		Name:  "copy",
		Usage: "Copy SSH command to clipboard",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "name", Required: true},
			&cli.StringFlag{Name: "vault"},
		},
		Action: func(c *cli.Context) error {
			vf := c.String("vault")
			if vf == "" {
				vf = DefaultVaultFile
			}
			password, err := readPassword("Vault password: ")
			if err != nil {
				return err
			}
			entries, err := vault.Load(vf, password)
			if err != nil {
				return err
			}
			entry := model.FindByName(entries, c.String("name"))
			if entry == nil {
				return errors.New("entry not found")
			}
			cmdStr := fmt.Sprintf("ssh %s", entry.AddrPort())
			if err := clipboard.WriteAll(cmdStr); err != nil {
				return fmt.Errorf("clipboard write failed: %w", err)
			}
			fmt.Println("Copied to clipboard:", cmdStr)
			return nil
		},
	}
}

func deleteCmd() *cli.Command {
	return &cli.Command{
		Name:  "delete",
		Usage: "Delete entry by name",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "name", Required: true},
			&cli.StringFlag{Name: "vault"},
		},
		Action: func(c *cli.Context) error {
			vf := c.String("vault")
			if vf == "" {
				vf = DefaultVaultFile
			}
			password, err := readPassword("Vault password: ")
			if err != nil {
				return err
			}
			entries, err := vault.Load(vf, password)
			if err != nil {
				return err
			}
			newEntries, found := model.DeleteByName(entries, c.String("name"))
			if !found {
				return errors.New("entry not found")
			}
			if err := vault.Save(vf, password, newEntries); err != nil {
				return err
			}
			fmt.Println("Entry deleted.")
			return nil
		},
	}
}

func updateCmd() *cli.Command {
	return &cli.Command{
		Name:  "update",
		Usage: "Update entry",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "name", Required: true},
			&cli.StringFlag{Name: "user"},
			&cli.StringFlag{Name: "host"},
			&cli.IntFlag{Name: "port"},
			&cli.StringFlag{Name: "key"},
			&cli.StringFlag{Name: "pubkey"},
			&cli.StringFlag{Name: "vault"},
		},
		Action: func(c *cli.Context) error {
			vf := c.String("vault")
			if vf == "" {
				vf = DefaultVaultFile
			}
			password, err := readPassword("Vault password: ")
			if err != nil {
				return err
			}
			entries, err := vault.Load(vf, password)
			if err != nil {
				return err
			}
			entry := model.FindByName(entries, c.String("name"))
			if entry == nil {
				return errors.New("entry not found")
			}
			if c.IsSet("user") {
				entry.User = c.String("user")
			}
			if c.IsSet("host") {
				entry.Host = c.String("host")
			}
			if c.IsSet("port") {
				entry.Port = c.Int("port")
			}
			if c.IsSet("key") {
				keyContent, err := resolveKeyInput(c.String("key"))
				if err != nil {
					return err
				}
				entry.Key = keyContent
			}
			if c.IsSet("pubkey") {
				entry.PubKey = c.String("pubkey")
			}
			if err := vault.Save(vf, password, entries); err != nil {
				return err
			}
			fmt.Println("Entry updated.")
			return nil
		},
	}
}

func connectCmd() *cli.Command {
	return &cli.Command{
		Name:  "connect",
		Usage: "Connect to host using stored private key",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "name", Required: true},
			&cli.StringFlag{Name: "vault"},
		},
		Action: func(c *cli.Context) error {
			vf := c.String("vault")
			if vf == "" {
				vf = DefaultVaultFile
			}
			password, err := readPassword("Vault password: ")
			if err != nil {
				return err
			}
			entries, err := vault.Load(vf, password)
			if err != nil {
				return err
			}
			entry := model.FindByName(entries, c.String("name"))
			if entry == nil {
				return errors.New("entry not found")
			}
			return sshutil.Connect(entry)
		},
	}
}

func genkeyCmd() *cli.Command {
	return &cli.Command{
		Name:  "genkey",
		Usage: "Generate new RSA SSH key pair and store in vault",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "name", Required: true},
			&cli.StringFlag{Name: "user", Required: true},
			&cli.StringFlag{Name: "host", Required: true},
			&cli.IntFlag{Name: "port", Value: 22},
			&cli.IntFlag{Name: "bits", Value: 2048},
			&cli.StringFlag{Name: "vault"},
		},
		Action: func(c *cli.Context) error {
			vf := c.String("vault")
			if vf == "" {
				vf = DefaultVaultFile
			}
			password, err := readPassword("Vault password: ")
			if err != nil {
				return err
			}
			entries, err := vault.Load(vf, password)
			if err != nil {
				return fmt.Errorf("failed to load vault: %w", err)
			}
			kp, err := keygen.GenerateRSA(c.Int("bits"))
			if err != nil {
				return err
			}
			entry := model.Entry{
				Name:   c.String("name"),
				User:   c.String("user"),
				Host:   c.String("host"),
				Port:   c.Int("port"),
				Key:    kp.PrivatePEM,
				PubKey: kp.PublicKey,
			}
			entries = append(entries, entry)
			if err := vault.Save(vf, password, entries); err != nil {
				return fmt.Errorf("failed to save vault: %w", err)
			}
			fmt.Println("Key pair generated and saved in vault.")
			return nil
		},
	}
}

func sendkeyCmd() *cli.Command {
	return &cli.Command{
		Name:  "sendkey",
		Usage: "Send public key to remote server's authorized_keys",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "name", Required: true},
			&cli.StringFlag{Name: "vault"},
		},
		Action: func(c *cli.Context) error {
			vf := c.String("vault")
			if vf == "" {
				vf = DefaultVaultFile
			}
			password, err := readPassword("Vault password: ")
			if err != nil {
				return err
			}
			entries, err := vault.Load(vf, password)
			if err != nil {
				return err
			}
			entry := model.FindByName(entries, c.String("name"))
			if entry == nil {
				return errors.New("entry not found")
			}
			return sshutil.SendPublicKey(entry)
		},
	}
}
