// Package app implements sshman's commands independently of the CLI
// framework, with injectable I/O and prompts so that every workflow can be
// tested without a terminal.
package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/sshman-org/sshman/keygen"
	"github.com/sshman-org/sshman/model"
	"github.com/sshman-org/sshman/sshutil"
	"github.com/sshman-org/sshman/vault"
)

// Exit codes. ssh's own exit status is passed through for connect.
const (
	ExitOK       = 0
	ExitError    = 1
	ExitUsage    = 2
	ExitAuth     = 3
	ExitNotFound = 4
	ExitUnsafe   = 5
	ExitConflict = 6
)

var (
	ErrEntryNotFound = errors.New("entry not found")
	ErrEntryExists   = errors.New("an entry with this name already exists")
	ErrAborted       = errors.New("aborted")
)

// UsageError marks invalid input.
type UsageError struct{ Err error }

func (e *UsageError) Error() string { return e.Err.Error() }
func (e *UsageError) Unwrap() error { return e.Err }

func usage(err error) error {
	if err == nil {
		return nil
	}
	return &UsageError{err}
}

// ExitCode maps an error to the process exit status.
func ExitCode(err error) int {
	if err == nil {
		return ExitOK
	}
	if c := sshutil.ExitCode(err); c >= 0 {
		return c
	}
	var ue *UsageError
	switch {
	case errors.As(err, &ue):
		return ExitUsage
	case errors.Is(err, vault.ErrAuth):
		return ExitAuth
	case errors.Is(err, vault.ErrNotFound), errors.Is(err, ErrEntryNotFound):
		return ExitNotFound
	case errors.Is(err, vault.ErrUnsafe):
		return ExitUnsafe
	case errors.Is(err, vault.ErrExists), errors.Is(err, ErrEntryExists):
		return ExitConflict
	}
	return ExitError
}

// App holds the injected environment of one command invocation.
type App struct {
	Stdin     io.Reader
	Stdout    io.Writer
	Stderr    io.Writer
	Prompt    Prompter
	VaultPath string
	// SSH is the base configuration passed to sshutil (tests set SSHPath).
	SSH       sshutil.Options
	Clipboard func(string) error
	Now       func() time.Time
}

func (a *App) now() time.Time {
	if a.Now != nil {
		return a.Now().UTC()
	}
	return time.Now().UTC().Truncate(time.Second)
}

func (a *App) notef(format string, args ...any) {
	fmt.Fprintf(a.Stderr, format+"\n", args...)
}

// EnvVault names the environment variable that selects the vault path. It
// holds a path, never a secret.
const EnvVault = "SSHMAN_VAULT"

// LegacyVaultFile is the CWD-relative default used before v2.
const LegacyVaultFile = "vault.vssh"

// DefaultVaultPath is <user config dir>/sshman/vault.vssh, e.g.
// ~/.config/sshman/vault.vssh on Linux (S-10).
func DefaultVaultPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine the user configuration directory (%v); pass --vault", err)
	}
	return filepath.Join(dir, "sshman", "vault.vssh"), nil
}

// ResolveVaultPath picks the vault: --vault, then $SSHMAN_VAULT, then the
// per-user default. For compatibility, a ./vault.vssh from an older version
// is still used (with a warning) when no default vault exists yet.
func ResolveVaultPath(flag string, getenv func(string) string, stderr io.Writer) (string, error) {
	if flag != "" {
		return flag, nil
	}
	if env := getenv(EnvVault); env != "" {
		return env, nil
	}
	def, err := DefaultVaultPath()
	if err != nil {
		return "", err
	}
	if _, err := os.Lstat(def); err == nil {
		return def, nil
	}
	if fi, err := os.Lstat(LegacyVaultFile); err == nil && fi.Mode().IsRegular() {
		abs, _ := filepath.Abs(LegacyVaultFile)
		fmt.Fprintf(stderr, "warning: using %s from the current directory (pre-v2 default).\n"+
			"         Move it to %s or pass --vault to silence this warning.\n", abs, def)
		return abs, nil
	}
	return def, nil
}

// legacyTrimmed returns the whitespace-trimmed form of pw if it differs.
// Versions before v2 trimmed the password before use, so a vault created
// with surrounding spaces only opens with the trimmed form.
func legacyTrimmed(pw []byte) []byte {
	t := []byte(strings.TrimSpace(string(pw)))
	if len(t) == len(pw) || len(t) == 0 {
		return nil
	}
	return t
}

func (a *App) password(prompt string) ([]byte, error) {
	pw, err := a.Prompt.Password(prompt)
	if err != nil {
		return nil, err
	}
	return pw, nil
}

func (a *App) warnWeak(pw []byte) {
	if utf8.RuneCount(pw) < MinPasswordLen {
		a.notef("warning: your vault password is shorter than %d characters; change it with 'sshman passwd'", MinPasswordLen)
	}
}

// read decrypts the vault for a read-only command.
func (a *App) read() ([]model.Entry, error) {
	pw, err := a.password("Vault password: ")
	if err != nil {
		return nil, err
	}
	defer zero(pw)
	entries, info, err := vault.LoadInfo(a.VaultPath, pw)
	if errors.Is(err, vault.ErrAuth) {
		if alt := legacyTrimmed(pw); alt != nil {
			defer zero(alt)
			entries, info, err = vault.LoadInfo(a.VaultPath, alt)
		}
	}
	if err != nil {
		return nil, a.explainLoad(err)
	}
	a.warnWeak(pw)
	if info.Outdated() {
		a.notef("note: this vault uses format v%d; it is upgraded automatically on the next change", info.Version)
	}
	return entries, nil
}

// update runs a locked read-modify-write transaction.
func (a *App) update(fn func([]model.Entry) ([]model.Entry, error)) error {
	pw, err := a.password("Vault password: ")
	if err != nil {
		return err
	}
	defer zero(pw)
	err = vault.Update(a.VaultPath, pw, fn)
	if errors.Is(err, vault.ErrAuth) {
		if alt := legacyTrimmed(pw); alt != nil {
			defer zero(alt)
			err = vault.Update(a.VaultPath, alt, fn)
		}
	}
	if err != nil {
		return a.explainLoad(err)
	}
	a.warnWeak(pw)
	return nil
}

func (a *App) explainLoad(err error) error {
	switch {
	case errors.Is(err, vault.ErrNotFound):
		return fmt.Errorf("%w (create one with 'sshman init', or pass --vault)", err)
	case errors.Is(err, vault.ErrAuth), errors.Is(err, vault.ErrFormat):
		if _, serr := os.Stat(vault.BackupPath(a.VaultPath)); serr == nil {
			return fmt.Errorf("%w; if the vault is damaged, 'sshman restore' can recover the previous version from %s", err, vault.BackupPath(a.VaultPath))
		}
	}
	return err
}

func (a *App) newPassword() ([]byte, error) {
	pw, err := a.password("New vault password: ")
	if err != nil {
		return nil, err
	}
	if err := CheckPasswordPolicy(pw); err != nil {
		zero(pw)
		return nil, usage(err)
	}
	confirm, err := a.password("Confirm vault password: ")
	if err != nil {
		zero(pw)
		return nil, err
	}
	defer zero(confirm)
	if string(pw) != string(confirm) {
		zero(pw)
		return nil, usage(errors.New("passwords do not match"))
	}
	return pw, nil
}

// Init creates a new empty vault.
func (a *App) Init() error {
	if _, err := os.Lstat(a.VaultPath); err == nil {
		return fmt.Errorf("%w at %s", vault.ErrExists, a.VaultPath)
	}
	dir := filepath.Dir(a.VaultPath)
	if _, err := os.Stat(dir); errors.Is(err, fs.ErrNotExist) {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	pw, err := a.newPassword()
	if err != nil {
		return err
	}
	defer zero(pw)
	if err := vault.Create(a.VaultPath, pw); err != nil {
		return err
	}
	a.notef("Vault created at %s", a.VaultPath)
	return nil
}

// Passwd re-encrypts the vault under a new password with the current
// recommended KDF parameters.
func (a *App) Passwd() error {
	cur, err := a.password("Current vault password: ")
	if err != nil {
		return err
	}
	defer zero(cur)
	if _, err := vault.Load(a.VaultPath, cur); errors.Is(err, vault.ErrAuth) {
		if alt := legacyTrimmed(cur); alt != nil {
			if _, err2 := vault.Load(a.VaultPath, alt); err2 == nil {
				zero(cur)
				cur = alt
			} else {
				zero(alt)
				return a.explainLoad(err)
			}
		} else {
			return a.explainLoad(err)
		}
	} else if err != nil {
		return a.explainLoad(err)
	}
	pw, err := a.newPassword()
	if err != nil {
		return err
	}
	defer zero(pw)
	if err := vault.ChangePassword(a.VaultPath, cur, pw, vault.DefaultParams); err != nil {
		return a.explainLoad(err)
	}
	a.notef("Vault password changed; the vault was re-encrypted with current parameters.")
	return nil
}

// Restore recovers the vault from its backup.
func (a *App) Restore(yes bool) error {
	bak := vault.BackupPath(a.VaultPath)
	if _, err := os.Stat(bak); err != nil {
		return fmt.Errorf("no backup at %s: %w", bak, vault.ErrNotFound)
	}
	if !yes {
		ok, err := a.Prompt.Confirm(fmt.Sprintf("Replace %s with its backup %s?", a.VaultPath, bak))
		if err != nil {
			return err
		}
		if !ok {
			return ErrAborted
		}
	}
	pw, err := a.password("Vault password (for the backup): ")
	if err != nil {
		return err
	}
	defer zero(pw)
	n, err := vault.Restore(a.VaultPath, pw)
	if err != nil {
		return err
	}
	a.notef("Restored %d entries from %s (the replaced file was kept as %s.corrupt)", n, bak, a.VaultPath)
	return nil
}

// readKeySource reads private key input from a file path or "-" (stdin).
// Raw key text on the command line is not accepted (S-02).
func (a *App) readKeySource(src string) (*sshutil.KeyMaterial, error) {
	if strings.Contains(src, "PRIVATE KEY") || strings.Contains(src, "\n") {
		return nil, usage(errors.New("raw key material on the command line is not accepted (it leaks through ps and shell history); pass a file path, or '-' to read the key from stdin"))
	}
	var data []byte
	var err error
	if src == "-" {
		data, err = io.ReadAll(io.LimitReader(a.Stdin, sshutil.MaxKeyFileSize+1))
		if err != nil {
			return nil, err
		}
	} else {
		fi, serr := os.Stat(src)
		if serr != nil {
			return nil, usage(fmt.Errorf("key file %q: %w", src, serr))
		}
		if !fi.Mode().IsRegular() {
			return nil, usage(fmt.Errorf("key file %q is not a regular file", src))
		}
		f, oerr := os.Open(src)
		if oerr != nil {
			return nil, oerr
		}
		data, err = io.ReadAll(io.LimitReader(f, sshutil.MaxKeyFileSize+1))
		f.Close()
		if err != nil {
			return nil, err
		}
	}
	defer zero(data)
	km, err := sshutil.ParsePrivateKey(data, func() ([]byte, error) {
		return a.password("Passphrase for the private key: ")
	})
	if err != nil {
		return nil, usage(err)
	}
	if km.Decrypted {
		a.notef("The key was decrypted and is now protected by the vault password.")
	}
	if src != "-" {
		a.notef("Tip: once you have checked the entry works, you can delete %s; the key is stored in the vault.", src)
	}
	return km, nil
}

// EntryInput holds the fields of add and genkey.
type EntryInput struct {
	Name, User, Host string
	Port             int
	Tags             []string
	Notes            string
	Favorite         bool
}

func (in *EntryInput) entry() model.Entry {
	return model.Entry{Name: in.Name, User: in.User, Host: in.Host, Port: in.Port, Tags: normalizeTags(in.Tags), Notes: in.Notes, Favorite: in.Favorite}
}

func normalizeTags(tags []string) []string {
	var out []string
	for _, t := range tags {
		for _, p := range strings.Split(t, ",") {
			p = strings.TrimSpace(p)
			if p != "" && !slices.ContainsFunc(out, func(o string) bool { return strings.EqualFold(o, p) }) {
				out = append(out, p)
			}
		}
	}
	return out
}

func validateTags(tags []string) error {
	for _, t := range tags {
		if err := sshutil.ValidateName(t); err != nil {
			return fmt.Errorf("invalid tag %q: %v", t, err)
		}
	}
	return nil
}

func insertUnique(entries []model.Entry, e model.Entry) ([]model.Entry, error) {
	if model.FindByName(entries, e.Name) != nil {
		return nil, fmt.Errorf("%w: %q (use 'sshman update' or choose another name)", ErrEntryExists, e.Name)
	}
	return append(entries, e), nil
}

// Add stores a new entry with an imported private key.
func (a *App) Add(in EntryInput, keySrc, pubKey string) error {
	e := in.entry()
	if err := sshutil.ValidateEntry(&e); err != nil {
		return usage(err)
	}
	if err := validateTags(e.Tags); err != nil {
		return usage(err)
	}
	km, err := a.readKeySource(keySrc)
	if err != nil {
		return err
	}
	if err := sshutil.MatchPublicKey(pubKey, km); err != nil {
		return usage(err)
	}
	now := a.now()
	e.Key, e.PubKey = km.PrivatePEM, km.AuthorizedKey
	e.CreatedAt, e.UpdatedAt, e.KeyCreatedAt = now, now, now
	if err := a.update(func(entries []model.Entry) ([]model.Entry, error) { return insertUnique(entries, e) }); err != nil {
		return err
	}
	a.notef("Entry %q added (%s %s).", e.Name, km.Type, km.Fingerprint)
	return nil
}

// GenKey generates a key pair and stores it in a new entry. The public key
// is printed to stdout.
func (a *App) GenKey(in EntryInput, keyType string, bits int) error {
	e := in.entry()
	if err := sshutil.ValidateEntry(&e); err != nil {
		return usage(err)
	}
	if err := validateTags(e.Tags); err != nil {
		return usage(err)
	}
	var gen func() (*keygen.KeyPair, error)
	switch keyType {
	case "ed25519", "":
		gen = func() (*keygen.KeyPair, error) { return keygen.GenerateEd25519("sshman:" + e.Name) }
	case "rsa":
		if bits == 0 {
			bits = keygen.DefaultRSABits
		}
		if !slices.Contains(keygen.AllowedRSABits, bits) {
			return usage(fmt.Errorf("unsupported RSA key size %d: use 3072 or 4096", bits))
		}
		gen = func() (*keygen.KeyPair, error) { return keygen.GenerateRSA(bits, "sshman:"+e.Name) }
	default:
		return usage(fmt.Errorf("unsupported key type %q: use ed25519 (recommended) or rsa", keyType))
	}
	var kp *keygen.KeyPair
	err := a.update(func(entries []model.Entry) ([]model.Entry, error) {
		if model.FindByName(entries, e.Name) != nil {
			return nil, fmt.Errorf("%w: %q", ErrEntryExists, e.Name)
		}
		var err error
		if kp, err = gen(); err != nil {
			return nil, err
		}
		now := a.now()
		e.Key, e.PubKey = kp.PrivatePEM, strings.TrimSpace(kp.PublicKey)
		e.CreatedAt, e.UpdatedAt, e.KeyCreatedAt = now, now, now
		return insertUnique(entries, e)
	})
	if err != nil {
		return err
	}
	a.notef("Key pair generated for %q (%s). Install it with: sshman sendkey --name %s", e.Name, kp.Fingerprint, e.Name)
	fmt.Fprint(a.Stdout, kp.PublicKey)
	return nil
}

// UpdateInput holds optional changes; nil means unchanged.
type UpdateInput struct {
	User, Host, Notes *string
	Port              *int
	KeySrc, PubKey    *string
	Tags              *[]string
	Favorite          *bool
}

// Update changes fields of an existing entry.
func (a *App) Update(name string, in UpdateInput) error {
	var km *sshutil.KeyMaterial
	if in.KeySrc != nil {
		var err error
		if km, err = a.readKeySource(*in.KeySrc); err != nil {
			return err
		}
	}
	var tags []string
	if in.Tags != nil {
		tags = normalizeTags(*in.Tags)
		if err := validateTags(tags); err != nil {
			return usage(err)
		}
	}
	err := a.update(func(entries []model.Entry) ([]model.Entry, error) {
		e := model.FindByName(entries, name)
		if e == nil {
			return nil, fmt.Errorf("%w: %q", ErrEntryNotFound, name)
		}
		if in.User != nil {
			e.User = *in.User
		}
		if in.Host != nil {
			e.Host = *in.Host
		}
		if in.Port != nil {
			e.Port = *in.Port
		}
		if in.Notes != nil {
			e.Notes = *in.Notes
		}
		if in.Favorite != nil {
			e.Favorite = *in.Favorite
		}
		if in.Tags != nil {
			e.Tags = tags
		}
		if km != nil {
			e.Key, e.PubKey, e.KeyCreatedAt = km.PrivatePEM, km.AuthorizedKey, a.now()
		}
		if in.PubKey != nil {
			if km == nil && e.Key != "" {
				if _, err := sshutil.EntryPublicKey(e.Key, *in.PubKey); err != nil {
					return nil, usage(err)
				}
			} else if km != nil {
				if err := sshutil.MatchPublicKey(*in.PubKey, km); err != nil {
					return nil, usage(err)
				}
			}
			if strings.TrimSpace(*in.PubKey) != "" {
				canon, _, err := sshutil.CanonicalAuthorizedKey(*in.PubKey)
				if err != nil {
					return nil, usage(err)
				}
				e.PubKey = canon
			}
		}
		if err := sshutil.ValidateEntry(e); err != nil {
			return nil, usage(err)
		}
		e.UpdatedAt = a.now()
		return entries, nil
	})
	if err != nil {
		return err
	}
	a.notef("Entry %q updated.", name)
	return nil
}

// Rename changes an entry's name.
func (a *App) Rename(oldName, newName string) error {
	if err := sshutil.ValidateName(newName); err != nil {
		return usage(err)
	}
	err := a.update(func(entries []model.Entry) ([]model.Entry, error) {
		e := model.FindByName(entries, oldName)
		if e == nil {
			return nil, fmt.Errorf("%w: %q", ErrEntryNotFound, oldName)
		}
		if oldName != newName && model.FindByName(entries, newName) != nil {
			return nil, fmt.Errorf("%w: %q", ErrEntryExists, newName)
		}
		e.Name, e.UpdatedAt = newName, a.now()
		return entries, nil
	})
	if err != nil {
		return err
	}
	a.notef("Entry %q renamed to %q.", oldName, newName)
	return nil
}

// Delete removes one entry, asking for confirmation unless yes is set.
func (a *App) Delete(name string, yes bool) error {
	if !yes {
		ok, err := a.Prompt.Confirm(fmt.Sprintf("Delete entry %q and its private key from the vault?", name))
		if err != nil {
			return err
		}
		if !ok {
			return ErrAborted
		}
	}
	remaining := 0
	err := a.update(func(entries []model.Entry) ([]model.Entry, error) {
		out, found := model.DeleteByName(entries, name)
		if !found {
			return nil, fmt.Errorf("%w: %q", ErrEntryNotFound, name)
		}
		remaining = model.CountByName(out, name)
		return out, nil
	})
	if err != nil {
		return err
	}
	a.notef("Entry %q deleted.", name)
	if remaining > 0 {
		a.notef("warning: %d more entr(ies) named %q remain (created by an older version); rename them with 'sshman rename'", remaining, name)
	}
	return nil
}

// EntryView is the public, secret-free representation of an entry used for
// display and JSON output. It never contains private key material.
type EntryView struct {
	Name          string     `json:"name"`
	User          string     `json:"user"`
	Host          string     `json:"host"`
	Port          int        `json:"port,omitempty"`
	Tags          []string   `json:"tags,omitempty"`
	Favorite      bool       `json:"favorite,omitempty"`
	Notes         string     `json:"notes,omitempty"`
	KeyType       string     `json:"key_type,omitempty"`
	Fingerprint   string     `json:"fingerprint,omitempty"`
	PublicKey     string     `json:"public_key,omitempty"`
	HasPrivateKey bool       `json:"has_private_key"`
	KeyError      string     `json:"key_error,omitempty"`
	CreatedAt     *time.Time `json:"created_at,omitempty"`
	UpdatedAt     *time.Time `json:"updated_at,omitempty"`
	KeyCreatedAt  *time.Time `json:"key_created_at,omitempty"`
}

func timePtr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

// View builds the secret-free view of e.
func View(e *model.Entry) EntryView {
	v := EntryView{
		Name: e.Name, User: e.User, Host: e.Host, Port: e.Port,
		Tags: e.Tags, Favorite: e.Favorite, Notes: e.Notes,
		HasPrivateKey: e.Key != "",
		CreatedAt:     timePtr(e.CreatedAt), UpdatedAt: timePtr(e.UpdatedAt), KeyCreatedAt: timePtr(e.KeyCreatedAt),
	}
	if line, err := sshutil.EntryPublicKey(e.Key, e.PubKey); err == nil {
		if canon, pub, err := sshutil.CanonicalAuthorizedKey(line); err == nil {
			v.PublicKey, v.KeyType = canon, pub.Type()
			v.Fingerprint = sshutil.Fingerprint(pub)
		}
	} else if e.Key != "" || e.PubKey != "" {
		v.KeyError = err.Error()
	}
	return v
}

// ListInput filters list/search output.
type ListInput struct {
	Query     string
	Tag       string
	Favorites bool
	JSON      bool
	// KeyOlderThan keeps entries whose key is older than this many days
	// (or has no recorded creation date), for rotation reviews.
	KeyOlderThan int
}

// List prints entries, optionally filtered. Only data goes to stdout.
func (a *App) List(in ListInput) error {
	entries, err := a.read()
	if err != nil {
		return err
	}
	var out []EntryView
	for i := range entries {
		e := &entries[i]
		if in.Query != "" && !e.Matches(in.Query) {
			continue
		}
		if in.Tag != "" && !e.HasTag(in.Tag) {
			continue
		}
		if in.Favorites && !e.Favorite {
			continue
		}
		if in.KeyOlderThan > 0 && !e.KeyCreatedAt.IsZero() && a.now().Sub(e.KeyCreatedAt) < time.Duration(in.KeyOlderThan)*24*time.Hour {
			continue
		}
		out = append(out, View(e))
	}
	slices.SortStableFunc(out, func(x, y EntryView) int {
		if x.Favorite != y.Favorite {
			if x.Favorite {
				return -1
			}
			return 1
		}
		return strings.Compare(strings.ToLower(x.Name), strings.ToLower(y.Name))
	})
	if in.JSON {
		if out == nil {
			out = []EntryView{}
		}
		enc := json.NewEncoder(a.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(out)
	}
	if len(out) == 0 {
		if in.Query != "" || in.Tag != "" || in.Favorites || in.KeyOlderThan > 0 {
			a.notef("No matching entries found.")
		} else {
			a.notef("No entries in vault.")
		}
		return nil
	}
	for _, v := range out {
		port := ""
		if v.Port > 0 && v.Port != 22 {
			port = fmt.Sprintf(":%d", v.Port)
		}
		star := " "
		if v.Favorite {
			star = "*"
		}
		tags := ""
		if len(v.Tags) > 0 {
			tags = "  [" + strings.Join(v.Tags, ", ") + "]"
		}
		fmt.Fprintf(a.Stdout, "%s %s: %s@%s%s%s\n", star, v.Name, v.User, v.Host, port, tags)
	}
	return nil
}

func (a *App) find(name string) (*model.Entry, []model.Entry, error) {
	entries, err := a.read()
	if err != nil {
		return nil, nil, err
	}
	e := model.FindByName(entries, name)
	if e == nil {
		return nil, nil, fmt.Errorf("%w: %q", ErrEntryNotFound, name)
	}
	return e, entries, nil
}

// Show prints an entry's details (never the private key).
func (a *App) Show(name string, asJSON bool) error {
	e, _, err := a.find(name)
	if err != nil {
		return err
	}
	v := View(e)
	if asJSON {
		enc := json.NewEncoder(a.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(v)
	}
	w := a.Stdout
	fmt.Fprintf(w, "Name:         %s\n", v.Name)
	fmt.Fprintf(w, "Destination:  %s\n", e.AddrPort())
	if len(v.Tags) > 0 {
		fmt.Fprintf(w, "Tags:         %s\n", strings.Join(v.Tags, ", "))
	}
	if v.Favorite {
		fmt.Fprintf(w, "Favorite:     yes\n")
	}
	if v.Notes != "" {
		fmt.Fprintf(w, "Notes:        %s\n", v.Notes)
	}
	if v.KeyError != "" {
		fmt.Fprintf(w, "Key:          ERROR: %s\n", v.KeyError)
	} else if v.KeyType != "" {
		fmt.Fprintf(w, "Key type:     %s\n", v.KeyType)
		fmt.Fprintf(w, "Fingerprint:  %s\n", v.Fingerprint)
		fmt.Fprintf(w, "Private key:  %s\n", map[bool]string{true: "stored in vault", false: "none (public key only)"}[v.HasPrivateKey])
	}
	if v.KeyCreatedAt != nil {
		age := a.now().Sub(*v.KeyCreatedAt)
		fmt.Fprintf(w, "Key created:  %s (%d days ago)\n", v.KeyCreatedAt.Format(time.DateOnly), int(age.Hours()/24))
	}
	if v.PublicKey != "" {
		fmt.Fprintf(w, "Public key:   %s\n", v.PublicKey)
	}
	return nil
}

// PubKey prints the entry's public key in authorized_keys format.
func (a *App) PubKey(name string) error {
	e, _, err := a.find(name)
	if err != nil {
		return err
	}
	line, err := sshutil.EntryPublicKey(e.Key, e.PubKey)
	if err != nil {
		return err
	}
	fmt.Fprintln(a.Stdout, line)
	return nil
}

// Copy puts "ssh user@host [-p port]" on the clipboard. No secrets.
func (a *App) Copy(name string) error {
	e, _, err := a.find(name)
	if err != nil {
		return err
	}
	cmd := "ssh " + e.AddrPort()
	if a.Clipboard == nil {
		return errors.New("clipboard not available")
	}
	if err := a.Clipboard(cmd); err != nil {
		return fmt.Errorf("clipboard write failed: %w", err)
	}
	a.notef("Copied to clipboard: %s", cmd)
	return nil
}

func (a *App) sshOptions(acceptNew bool, remote []string) sshutil.Options {
	o := a.SSH
	o.AcceptNewHostKey = acceptNew
	o.RemoteCommand = remote
	if o.Stdin == nil {
		o.Stdin = a.Stdin
	}
	if o.Stdout == nil {
		o.Stdout = a.Stdout
	}
	if o.Stderr == nil {
		o.Stderr = a.Stderr
	}
	return o
}

// Connect opens an SSH session with the entry's vault key. The vault is
// unlocked (and its lock released) before ssh starts.
func (a *App) Connect(name string, acceptNew bool, remote []string) error {
	e, _, err := a.find(name)
	if err != nil {
		return err
	}
	return sshutil.Connect(e, a.sshOptions(acceptNew, remote))
}

// SendKey installs the entry's public key on its host. With via, the vault
// key of another entry is used to log in; otherwise ssh may ask for the
// account password.
func (a *App) SendKey(name, via string, acceptNew bool) error {
	e, entries, err := a.find(name)
	if err != nil {
		return err
	}
	var viaEntry *model.Entry
	if via != "" {
		if viaEntry = model.FindByName(entries, via); viaEntry == nil {
			return fmt.Errorf("%w: %q", ErrEntryNotFound, via)
		}
	}
	a.notef("Installing the public key of %q on %s ...", e.Name, e.AddrPort())
	return sshutil.SendPublicKey(e, viaEntry, a.sshOptions(acceptNew, nil))
}
