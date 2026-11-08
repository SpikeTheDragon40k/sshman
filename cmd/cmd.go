// Package cmd maps the command-line interface onto package app.
package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/atotto/clipboard"
	"github.com/sshman-org/sshman/app"
	"github.com/sshman-org/sshman/keygen"
	"github.com/sshman-org/sshman/sshutil"
	"github.com/urfave/cli/v2"
)

// Env is the process environment injected into commands (tests replace it).
type Env struct {
	Stdin     io.Reader
	Stdout    io.Writer
	Stderr    io.Writer
	Prompt    app.Prompter
	Getenv    func(string) string
	Configure func(*app.App) // optional hook for tests
}

// DefaultEnv uses the real terminal and process streams.
func DefaultEnv() *Env {
	return &Env{Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr, Prompt: app.TTYPrompter{}, Getenv: os.Getenv}
}

const banner = `
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
`

func vaultFlag() cli.Flag {
	return &cli.StringFlag{Name: "vault", Usage: "path to the vault file (default: $SSHMAN_VAULT or <config dir>/sshman/vault.vssh)"}
}

// NewApp builds the CLI application.
func NewApp(env *Env, version string) *cli.App {
	return &cli.App{
		Name:                 "sshman",
		Usage:                "manage SSH keys and connections in an encrypted vault",
		Version:              version,
		EnableBashCompletion: true,
		Reader:               env.Stdin,
		Writer:               env.Stdout,
		ErrWriter:            env.Stderr,
		Flags:                []cli.Flag{vaultFlag()},
		Commands:             Commands(env),
		ExitErrHandler:       func(*cli.Context, error) {}, // main reports errors
		CommandNotFound: func(c *cli.Context, name string) {
			fmt.Fprintf(env.Stderr, "sshman: unknown command %q; run 'sshman help'\n", name)
		},
	}
}

// newApp builds an app.App for a command invocation, resolving the vault
// path from the command flag, the global flag or $SSHMAN_VAULT.
func newApp(c *cli.Context, env *Env) (*app.App, error) {
	flag := c.String("vault")
	if flag == "" {
		for _, p := range c.Lineage() {
			if p.IsSet("vault") {
				flag = p.String("vault")
				break
			}
		}
	}
	path, err := app.ResolveVaultPath(flag, env.Getenv, env.Stderr)
	if err != nil {
		return nil, err
	}
	a := &app.App{
		Stdin: env.Stdin, Stdout: env.Stdout, Stderr: env.Stderr,
		Prompt: env.Prompt, VaultPath: path,
		Clipboard: clipboard.WriteAll,
	}
	if env.Configure != nil {
		env.Configure(a)
	}
	return a, nil
}

func action(env *Env, fn func(c *cli.Context, a *app.App) error) cli.ActionFunc {
	return func(c *cli.Context) error {
		a, err := newApp(c, env)
		if err != nil {
			return err
		}
		return fn(c, a)
	}
}

func entryFlags(withPortDefault bool) []cli.Flag {
	port := &cli.IntFlag{Name: "port", Usage: "SSH port"}
	if withPortDefault {
		port.Value = 22
	}
	return []cli.Flag{
		&cli.StringFlag{Name: "name", Usage: "unique entry name", Required: true},
		&cli.StringFlag{Name: "user", Usage: "remote user name", Required: withPortDefault},
		&cli.StringFlag{Name: "host", Usage: "host name or IP address", Required: withPortDefault},
		port,
		&cli.StringSliceFlag{Name: "tag", Usage: "tag (repeatable or comma-separated)"},
		&cli.StringFlag{Name: "notes", Usage: "free-text notes (stored encrypted; do not put secrets here)"},
		&cli.BoolFlag{Name: "favorite", Usage: "mark as favorite"},
		vaultFlag(),
	}
}

func entryInput(c *cli.Context) app.EntryInput {
	return app.EntryInput{
		Name: c.String("name"), User: c.String("user"), Host: c.String("host"), Port: c.Int("port"),
		Tags: c.StringSlice("tag"), Notes: c.String("notes"), Favorite: c.Bool("favorite"),
	}
}

func nameFlag() cli.Flag {
	return &cli.StringFlag{Name: "name", Aliases: []string{"n"}, Usage: "entry name", Required: true}
}

// Commands returns the subcommands.
func Commands(env *Env) []*cli.Command {
	return []*cli.Command{
		{
			Name:  "init",
			Usage: "create a new, empty vault",
			Flags: []cli.Flag{vaultFlag()},
			Action: action(env, func(c *cli.Context, a *app.App) error {
				fmt.Fprint(env.Stderr, banner)
				return a.Init()
			}),
		},
		{
			Name:      "add",
			Usage:     "add an entry with an existing private key",
			UsageText: "sshman add --name NAME --user USER --host HOST [--port N] --key FILE|- [--pubkey LINE]",
			Flags: append(entryFlags(true),
				&cli.StringFlag{Name: "key", Usage: "private key file, or - to read it from stdin (raw key text is not accepted)", Required: true},
				&cli.StringFlag{Name: "pubkey", Usage: "public key line to verify against the private key (optional; derived if omitted)"},
			),
			Action: action(env, func(c *cli.Context, a *app.App) error {
				return a.Add(entryInput(c), c.String("key"), c.String("pubkey"))
			}),
		},
		{
			Name:  "genkey",
			Usage: "generate a key pair and store it in a new entry (prints the public key)",
			Flags: append(entryFlags(true),
				&cli.StringFlag{Name: "type", Value: "ed25519", Usage: "key type: ed25519 (recommended) or rsa"},
				&cli.IntFlag{Name: "bits", Value: keygen.DefaultRSABits, Usage: "RSA key size: 3072 or 4096"},
			),
			Action: action(env, func(c *cli.Context, a *app.App) error {
				return a.GenKey(entryInput(c), c.String("type"), c.Int("bits"))
			}),
		},
		{
			Name:  "list",
			Usage: "list entries",
			Flags: []cli.Flag{
				&cli.StringFlag{Name: "tag", Usage: "only entries with this tag"},
				&cli.BoolFlag{Name: "favorites", Usage: "only favorites"},
				&cli.BoolFlag{Name: "json", Usage: "machine-readable JSON output"},
				vaultFlag(),
			},
			Action: action(env, func(c *cli.Context, a *app.App) error {
				return a.List(app.ListInput{Tag: c.String("tag"), Favorites: c.Bool("favorites"), JSON: c.Bool("json")})
			}),
		},
		{
			Name:  "search",
			Usage: "search entries by name, user, host or tag",
			Flags: []cli.Flag{
				&cli.StringFlag{Name: "query", Aliases: []string{"q"}, Required: true},
				&cli.StringFlag{Name: "tag", Usage: "only entries with this tag"},
				&cli.BoolFlag{Name: "json", Usage: "machine-readable JSON output"},
				vaultFlag(),
			},
			Action: action(env, func(c *cli.Context, a *app.App) error {
				return a.List(app.ListInput{Query: c.String("query"), Tag: c.String("tag"), JSON: c.Bool("json")})
			}),
		},
		{
			Name:  "show",
			Usage: "show an entry's details and public key (never the private key)",
			Flags: []cli.Flag{nameFlag(), &cli.BoolFlag{Name: "json", Usage: "JSON output"}, vaultFlag()},
			Action: action(env, func(c *cli.Context, a *app.App) error {
				return a.Show(c.String("name"), c.Bool("json"))
			}),
		},
		{
			Name:  "pubkey",
			Usage: "print an entry's public key in authorized_keys format",
			Flags: []cli.Flag{nameFlag(), vaultFlag()},
			Action: action(env, func(c *cli.Context, a *app.App) error {
				return a.PubKey(c.String("name"))
			}),
		},
		{
			Name:  "copy",
			Usage: "copy the ssh command for an entry to the clipboard",
			Flags: []cli.Flag{nameFlag(), vaultFlag()},
			Action: action(env, func(c *cli.Context, a *app.App) error {
				return a.Copy(c.String("name"))
			}),
		},
		{
			Name:  "update",
			Usage: "change fields of an entry",
			Flags: []cli.Flag{
				nameFlag(),
				&cli.StringFlag{Name: "user"},
				&cli.StringFlag{Name: "host"},
				&cli.IntFlag{Name: "port"},
				&cli.StringFlag{Name: "key", Usage: "replace the private key: file path or - for stdin"},
				&cli.StringFlag{Name: "pubkey", Usage: "public key line (must match the private key)"},
				&cli.StringSliceFlag{Name: "tag", Usage: "replace tags (repeatable or comma-separated; empty string clears)"},
				&cli.StringFlag{Name: "notes"},
				&cli.BoolFlag{Name: "favorite", Usage: "set or clear (--favorite=false) the favorite mark"},
				vaultFlag(),
			},
			Action: action(env, func(c *cli.Context, a *app.App) error {
				var in app.UpdateInput
				str := func(n string) *string {
					if !c.IsSet(n) {
						return nil
					}
					v := c.String(n)
					return &v
				}
				in.User, in.Host, in.Notes, in.KeySrc, in.PubKey = str("user"), str("host"), str("notes"), str("key"), str("pubkey")
				if c.IsSet("port") {
					v := c.Int("port")
					in.Port = &v
				}
				if c.IsSet("tag") {
					v := c.StringSlice("tag")
					in.Tags = &v
				}
				if c.IsSet("favorite") {
					v := c.Bool("favorite")
					in.Favorite = &v
				}
				return a.Update(c.String("name"), in)
			}),
		},
		{
			Name:  "rename",
			Usage: "rename an entry",
			Flags: []cli.Flag{nameFlag(), &cli.StringFlag{Name: "to", Usage: "new name", Required: true}, vaultFlag()},
			Action: action(env, func(c *cli.Context, a *app.App) error {
				return a.Rename(c.String("name"), c.String("to"))
			}),
		},
		{
			Name:  "delete",
			Usage: "delete an entry",
			Flags: []cli.Flag{nameFlag(), &cli.BoolFlag{Name: "yes", Aliases: []string{"y"}, Usage: "do not ask for confirmation"}, vaultFlag()},
			Action: action(env, func(c *cli.Context, a *app.App) error {
				return a.Delete(c.String("name"), c.Bool("yes"))
			}),
		},
		{
			Name:      "connect",
			Usage:     "open an SSH session using the entry's vault key",
			UsageText: "sshman connect --name NAME [--accept-new-host-key] [-- REMOTE COMMAND...]",
			Flags: []cli.Flag{
				nameFlag(),
				&cli.BoolFlag{Name: "accept-new-host-key", Usage: "trust and record an unknown host key without asking (changed keys are still refused)"},
				vaultFlag(),
			},
			Action: action(env, func(c *cli.Context, a *app.App) error {
				return a.Connect(c.String("name"), c.Bool("accept-new-host-key"), c.Args().Slice())
			}),
		},
		{
			Name:  "sendkey",
			Usage: "install an entry's public key in the remote authorized_keys",
			Description: "Logs in with your normal ssh setup (ssh may ask for the account password),\n" +
				"or with another entry's vault key via --via. The key is added only if not already present.",
			Flags: []cli.Flag{
				nameFlag(),
				&cli.StringFlag{Name: "via", Usage: "log in with this entry's vault key (e.g. the key being rotated out)"},
				&cli.BoolFlag{Name: "accept-new-host-key", Usage: "trust and record an unknown host key without asking"},
				vaultFlag(),
			},
			Action: action(env, func(c *cli.Context, a *app.App) error {
				return a.SendKey(c.String("name"), c.String("via"), c.Bool("accept-new-host-key"))
			}),
		},
		{
			Name:  "passwd",
			Usage: "change the vault password (re-encrypts with current parameters)",
			Flags: []cli.Flag{vaultFlag()},
			Action: action(env, func(c *cli.Context, a *app.App) error {
				return a.Passwd()
			}),
		},
		{
			Name:  "restore",
			Usage: "replace a damaged vault with its automatic backup",
			Flags: []cli.Flag{&cli.BoolFlag{Name: "yes", Aliases: []string{"y"}, Usage: "do not ask for confirmation"}, vaultFlag()},
			Action: action(env, func(c *cli.Context, a *app.App) error {
				return a.Restore(c.Bool("yes"))
			}),
		},
	}
}

// Run executes the CLI and returns the process exit code. Errors go to
// stderr; stdout carries only command output.
func Run(env *Env, args []string, version string) int {
	err := NewApp(env, version).Run(args)
	switch {
	case err == nil:
		return app.ExitOK
	case errors.Is(err, app.ErrAborted):
		fmt.Fprintln(env.Stderr, "Aborted.")
		return app.ExitError
	case sshutil.ExitCode(err) >= 0:
		// ssh already reported the failure on stderr; pass its status on.
		return sshutil.ExitCode(err)
	}
	fmt.Fprintln(env.Stderr, "Error:", err)
	return app.ExitCode(err)
}
