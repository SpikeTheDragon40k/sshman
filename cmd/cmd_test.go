package cmd

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/sshman-org/sshman/app"
	"github.com/sshman-org/sshman/vault"
	"golang.org/x/crypto/ssh"
)

func init() {
	vault.DefaultParams = vault.Params{Time: 1, MemoryKiB: 8 * 1024, Threads: 1}
}

// fakePrompt returns queued answers; it fails the test if it runs dry.
type fakePrompt struct {
	t         *testing.T
	passwords []string
	confirms  []bool
	asked     []string
}

func (f *fakePrompt) Password(p string) ([]byte, error) {
	f.asked = append(f.asked, p)
	if len(f.passwords) == 0 {
		return nil, errors.New("unexpected password prompt: " + p)
	}
	pw := f.passwords[0]
	f.passwords = f.passwords[1:]
	return []byte(pw), nil
}

func (f *fakePrompt) Confirm(p string) (bool, error) {
	f.asked = append(f.asked, p)
	if len(f.confirms) == 0 {
		return false, errors.New("unexpected confirm: " + p)
	}
	c := f.confirms[0]
	f.confirms = f.confirms[1:]
	return c, nil
}

type harness struct {
	t      *testing.T
	dir    string
	vault  string
	prompt *fakePrompt
	stdin  string
	out    bytes.Buffer
	errb   bytes.Buffer
}

func newHarness(t *testing.T) *harness {
	dir := t.TempDir()
	_ = os.Chmod(dir, 0o700)
	return &harness{t: t, dir: dir, vault: filepath.Join(dir, "v.vssh"), prompt: &fakePrompt{t: t}}
}

func (h *harness) run(args ...string) int {
	h.out.Reset()
	h.errb.Reset()
	env := &Env{
		Stdin: strings.NewReader(h.stdin), Stdout: &h.out, Stderr: &h.errb,
		Prompt: h.prompt,
		Getenv: func(k string) string {
			if k == app.EnvVault {
				return h.vault
			}
			return ""
		},
		Configure: func(a *app.App) { a.Clipboard = func(string) error { return nil } },
	}
	return Run(env, append([]string{"sshman"}, args...), "test")
}

func (h *harness) pw(p ...string) { h.prompt.passwords = append(h.prompt.passwords, p...) }

const goodPW = "correct horse battery"

func (h *harness) init() {
	h.t.Helper()
	h.pw(goodPW, goodPW)
	if code := h.run("init"); code != 0 {
		h.t.Fatalf("init: %d %s", code, h.errb.String())
	}
}

func writeKey(t *testing.T, dir, name, passphrase string) (string, ssh.PublicKey) {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	var blk *pem.Block
	var err error
	if passphrase == "" {
		blk, err = ssh.MarshalPrivateKey(priv, name)
	} else {
		blk, err = ssh.MarshalPrivateKeyWithPassphrase(priv, name, []byte(passphrase))
	}
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, pem.EncodeToMemory(blk), 0o600); err != nil {
		t.Fatal(err)
	}
	s, _ := ssh.NewSignerFromKey(priv)
	return p, s.PublicKey()
}

// S-04: empty, whitespace-only and short passwords are rejected; nothing is
// written.
func TestInitPasswordPolicy(t *testing.T) {
	for _, bad := range []string{"", "   ", "\t\t", "short-pw"} {
		h := newHarness(t)
		h.pw(bad, bad)
		if code := h.run("init"); code != app.ExitUsage {
			t.Errorf("password %q: exit %d, stderr=%s", bad, code, h.errb.String())
		}
		if _, err := os.Stat(h.vault); err == nil {
			t.Errorf("vault written for password %q", bad)
		}
	}
	h := newHarness(t)
	h.pw(goodPW, goodPW+"x")
	if code := h.run("init"); code == 0 || !strings.Contains(h.errb.String(), "do not match") {
		t.Fatalf("mismatch accepted: %s", h.errb.String())
	}
}

// S-04: whitespace is preserved exactly.
func TestPasswordWhitespacePreserved(t *testing.T) {
	h := newHarness(t)
	spaced := "  spaced password  "
	h.pw(spaced, spaced)
	if code := h.run("init"); code != 0 {
		t.Fatal(h.errb.String())
	}
	if _, err := vault.Load(h.vault, []byte(spaced)); err != nil {
		t.Fatalf("exact password does not open the vault: %v", err)
	}
	if _, err := vault.Load(h.vault, []byte(strings.TrimSpace(spaced))); err == nil {
		t.Fatal("trimmed password opens a new vault; whitespace was not preserved")
	}
}

func TestInitRefusesExisting(t *testing.T) {
	h := newHarness(t)
	h.init()
	before, _ := os.ReadFile(h.vault)
	if code := h.run("init"); code != app.ExitConflict {
		t.Fatalf("exit %d", code)
	}
	after, _ := os.ReadFile(h.vault)
	if !bytes.Equal(before, after) {
		t.Fatal("init overwrote the vault")
	}
}

// S-02 / Q-06: raw key text is refused without echoing it, missing files are
// errors, '-' reads stdin, and the public key is derived.
func TestAddKeyInput(t *testing.T) {
	h := newHarness(t)
	h.init()
	keyPath, pub := writeKey(t, h.dir, "id_test", "")
	raw, _ := os.ReadFile(keyPath)

	if code := h.run("add", "--name", "a", "--user", "u", "--host", "h.example", "--key", string(raw)); code != app.ExitUsage {
		t.Fatalf("raw key accepted: %d", code)
	}
	if strings.Contains(h.errb.String(), "OPENSSH PRIVATE KEY") || strings.Contains(h.errb.String(), string(raw[40:80])) {
		t.Fatal("error message echoed key material")
	}
	if code := h.run("add", "--name", "a", "--user", "u", "--host", "h.example", "--key", filepath.Join(h.dir, "typo")); code != app.ExitUsage {
		t.Fatalf("missing key file accepted: %d", code)
	}

	h.pw(goodPW)
	if code := h.run("add", "--name", "a", "--user", "u", "--host", "h.example", "--key", keyPath, "--tag", "prod,web"); code != 0 {
		t.Fatalf("add from file: %s", h.errb.String())
	}
	h.stdin = string(raw)
	h.pw(goodPW)
	if code := h.run("add", "--name", "b", "--user", "u", "--host", "h2.example", "--key", "-"); code != 0 {
		t.Fatalf("add from stdin: %s", h.errb.String())
	}
	h.stdin = ""

	entries, err := vault.Load(h.vault, []byte(goodPW))
	if err != nil || len(entries) != 2 {
		t.Fatalf("%v %d", err, len(entries))
	}
	want := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
	if entries[0].PubKey != want || entries[0].KeyCreatedAt.IsZero() || len(entries[0].Tags) != 2 {
		t.Fatalf("entry = %+v", entries[0])
	}

	// Mismatched --pubkey is rejected.
	_, otherPub := writeKey(t, h.dir, "other", "")
	h.pw(goodPW)
	if code := h.run("add", "--name", "c", "--user", "u", "--host", "h", "--key", keyPath, "--pubkey", string(ssh.MarshalAuthorizedKey(otherPub))); code != app.ExitUsage {
		t.Fatalf("mismatched pubkey accepted: %d %s", code, h.errb.String())
	}
}

// S-14: a passphrase-protected key is decrypted on import.
func TestAddPassphraseProtectedKey(t *testing.T) {
	h := newHarness(t)
	h.init()
	keyPath, _ := writeKey(t, h.dir, "id_prot", "key passphrase")
	h.stdin = ""
	h.pw("key passphrase", goodPW)
	if code := h.run("add", "--name", "p", "--user", "u", "--host", "h", "--key", keyPath); code != 0 {
		t.Fatalf("%d %s", code, h.errb.String())
	}
	entries, _ := vault.Load(h.vault, []byte(goodPW))
	if _, err := ssh.ParseRawPrivateKey([]byte(entries[0].Key)); err != nil {
		t.Fatalf("stored key not usable without passphrase: %v", err)
	}
}

// Q-05: duplicate names are rejected; delete removes exactly one.
func TestDuplicatesAndDelete(t *testing.T) {
	h := newHarness(t)
	h.init()
	keyPath, _ := writeKey(t, h.dir, "k", "")
	h.pw(goodPW)
	h.run("add", "--name", "a", "--user", "u", "--host", "h", "--key", keyPath)
	h.pw(goodPW)
	if code := h.run("add", "--name", "a", "--user", "u", "--host", "h", "--key", keyPath); code != app.ExitConflict {
		t.Fatalf("duplicate accepted: %d", code)
	}
	h.prompt.confirms = []bool{false}
	if code := h.run("delete", "--name", "a"); code == 0 {
		t.Fatal("declined delete succeeded")
	}
	h.pw(goodPW)
	if code := h.run("delete", "--name", "a", "--yes"); code != 0 {
		t.Fatal(h.errb.String())
	}
	h.pw(goodPW)
	if code := h.run("delete", "--name", "a", "--yes"); code != app.ExitNotFound {
		t.Fatalf("exit %d", code)
	}
}

// JSON output is machine readable and never contains private keys.
func TestListJSONHasNoSecrets(t *testing.T) {
	h := newHarness(t)
	h.init()
	keyPath, _ := writeKey(t, h.dir, "k", "")
	h.pw(goodPW)
	h.run("add", "--name", "web", "--user", "u", "--host", "h", "--port", "2222", "--key", keyPath, "--tag", "prod", "--favorite")
	h.pw(goodPW)
	if code := h.run("list", "--json"); code != 0 {
		t.Fatal(h.errb.String())
	}
	if strings.Contains(h.out.String(), "PRIVATE KEY") {
		t.Fatal("private key in JSON output")
	}
	var views []app.EntryView
	if err := json.Unmarshal(h.out.Bytes(), &views); err != nil {
		t.Fatalf("stdout is not clean JSON: %v\n%s", err, h.out.String())
	}
	if len(views) != 1 || views[0].Port != 2222 || !views[0].Favorite || views[0].Fingerprint == "" {
		t.Fatalf("%+v", views)
	}
	// Plain list: data only on stdout; the prompt is not mixed in.
	h.pw(goodPW)
	h.run("list")
	if got := h.out.String(); !strings.Contains(got, "web: u@h:2222") || strings.Contains(got, "password") {
		t.Fatalf("list stdout = %q", got)
	}
	h.pw(goodPW)
	h.run("show", "--name", "web")
	if strings.Contains(h.out.String(), "PRIVATE KEY") || !strings.Contains(h.out.String(), "SHA256:") {
		t.Fatalf("show = %s", h.out.String())
	}
	h.pw(goodPW)
	h.run("pubkey", "--name", "web")
	if !strings.HasPrefix(h.out.String(), "ssh-ed25519 ") {
		t.Fatalf("pubkey = %q", h.out.String())
	}
}

func TestWrongPasswordExitCode(t *testing.T) {
	h := newHarness(t)
	h.init()
	h.pw("wrong password here")
	if code := h.run("list"); code != app.ExitAuth {
		t.Fatalf("exit %d", code)
	}
	if !strings.HasPrefix(h.errb.String(), "Error:") {
		t.Fatalf("error not on stderr: %q", h.errb.String())
	}
	if h.out.Len() != 0 {
		t.Fatalf("stdout polluted: %q", h.out.String())
	}
}

func TestGenKeyAndRename(t *testing.T) {
	h := newHarness(t)
	h.init()
	h.pw(goodPW)
	if code := h.run("genkey", "--name", "g", "--user", "u", "--host", "h"); code != 0 {
		t.Fatal(h.errb.String())
	}
	if !strings.HasPrefix(h.out.String(), "ssh-ed25519 ") {
		t.Fatalf("public key not printed: %q", h.out.String())
	}
	h.pw(goodPW)
	if code := h.run("genkey", "--name", "r", "--user", "u", "--host", "h", "--type", "rsa", "--bits", "2048"); code != app.ExitUsage {
		t.Fatalf("2048-bit generation allowed: %d", code)
	}
	h.pw(goodPW)
	if code := h.run("rename", "--name", "g", "--to", "g2"); code != 0 {
		t.Fatal(h.errb.String())
	}
	entries, _ := vault.Load(h.vault, []byte(goodPW))
	if len(entries) != 1 || entries[0].Name != "g2" {
		t.Fatalf("%+v", entries)
	}
}

func TestPasswd(t *testing.T) {
	h := newHarness(t)
	h.init()
	h.pw(goodPW, "short")
	if code := h.run("passwd"); code != app.ExitUsage {
		t.Fatalf("weak new password accepted: %d", code)
	}
	newPW := "a brand new passphrase"
	h.pw(goodPW, newPW, newPW)
	if code := h.run("passwd"); code != 0 {
		t.Fatal(h.errb.String())
	}
	if _, err := vault.Load(h.vault, []byte(newPW)); err != nil {
		t.Fatal(err)
	}
}

// Compatibility: a vault created by the original sshman with a password that
// had surrounding spaces (stored trimmed) still opens when the user types it
// the same way, and keeps working after an update.
func TestLegacyTrimmedPasswordVault(t *testing.T) {
	h := newHarness(t)
	data, err := os.ReadFile("testdata/legacy-trimmed.vssh")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(h.vault, data, 0o600); err != nil {
		t.Fatal(err)
	}
	typed := "  spaced legacy pass  "
	h.pw(typed)
	if code := h.run("list"); code != 0 {
		t.Fatalf("legacy vault: %s", h.errb.String())
	}
	if !strings.Contains(h.errb.String(), "format v1") {
		t.Fatalf("no upgrade note: %s", h.errb.String())
	}
	// The legacy vault has duplicate names: delete removes only one.
	h.pw(typed)
	if code := h.run("delete", "--name", "dup", "--yes"); code != 0 {
		t.Fatal(h.errb.String())
	}
	if !strings.Contains(h.errb.String(), "1 more entr") {
		t.Fatalf("no duplicate warning: %s", h.errb.String())
	}
	entries, info, err := vault.LoadInfo(h.vault, []byte("spaced legacy pass"))
	if err != nil || len(entries) != 1 || info.Version != 2 {
		t.Fatalf("after update: %v %d %+v", err, len(entries), info)
	}
}

// S-10: the CWD vault of older versions is still found, with a warning; a
// new default lives in the user config directory.
func TestVaultPathResolution(t *testing.T) {
	cfg := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", cfg)
	t.Setenv("HOME", cfg)
	t.Setenv("AppData", cfg)
	cwd := t.TempDir()
	t.Chdir(cwd)
	var errb bytes.Buffer
	get := func(string) string { return "" }
	p, err := app.ResolveVaultPath("", get, &errb)
	if err != nil || !strings.HasPrefix(p, cfg) || errb.Len() != 0 {
		t.Fatalf("default = %q %v %q", p, err, errb.String())
	}
	if err := os.WriteFile(filepath.Join(cwd, "vault.vssh"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	p, _ = app.ResolveVaultPath("", get, &errb)
	if filepath.Base(p) != "vault.vssh" || !strings.HasPrefix(p, cwd) && !strings.Contains(p, filepath.Base(cwd)) || !strings.Contains(errb.String(), "warning") {
		t.Fatalf("legacy = %q %q", p, errb.String())
	}
	p, _ = app.ResolveVaultPath("/explicit", func(string) string { return "/env" }, &errb)
	if p != "/explicit" {
		t.Fatal("flag precedence")
	}
	p, _ = app.ResolveVaultPath("", func(string) string { return "/env" }, &errb)
	if p != "/env" {
		t.Fatal("env precedence")
	}
}

func TestRestoreCommand(t *testing.T) {
	h := newHarness(t)
	h.init()
	keyPath, _ := writeKey(t, h.dir, "k", "")
	h.pw(goodPW)
	h.run("add", "--name", "a", "--user", "u", "--host", "h", "--key", keyPath)
	if err := os.WriteFile(h.vault, []byte("corrupted-corrupted-corrupted-corrupted-corrupted"), 0o600); err != nil {
		t.Fatal(err)
	}
	h.pw(goodPW)
	if code := h.run("list"); code == 0 || !strings.Contains(h.errb.String(), "sshman restore") {
		t.Fatalf("no restore hint: %s", h.errb.String())
	}
	h.pw(goodPW)
	if code := h.run("restore", "--yes"); code != 0 {
		t.Fatal(h.errb.String())
	}
	h.pw(goodPW)
	if code := h.run("list"); code != 0 {
		t.Fatal(h.errb.String())
	}
}

func TestDoctor(t *testing.T) {
	h := newHarness(t)
	if code := h.run("doctor"); code == 0 || !strings.Contains(h.out.String(), "does not exist") {
		t.Fatalf("missing vault: %d %s", code, h.out.String())
	}
	h.init()
	if code := h.run("doctor"); !strings.Contains(h.out.String(), "format v2") {
		t.Fatalf("doctor: %d %s %s", code, h.out.String(), h.errb.String())
	}
	if len(h.prompt.asked) != 2 {
		t.Fatalf("doctor must not prompt for the password: %v", h.prompt.asked)
	}
	if runtime.GOOS == "windows" {
		// POSIX modes are not checked on Windows (DECISIONS D-09); doctor
		// must not claim the file is private.
		if strings.Contains(h.out.String(), "private") || !strings.Contains(h.out.String(), "ACLs are not checked") {
			t.Fatalf("doctor overstates Windows checks: %s", h.out.String())
		}
		return
	}
	_ = os.Chmod(h.vault, 0o644)
	if code := h.run("doctor"); code == 0 || !strings.Contains(h.out.String(), "FAIL") {
		t.Fatalf("insecure perms not reported: %s", h.out.String())
	}
}

func TestListKeyOlderThanAndCompletion(t *testing.T) {
	h := newHarness(t)
	h.init()
	h.pw(goodPW)
	h.run("genkey", "--name", "fresh", "--user", "u", "--host", "h")
	h.pw(goodPW)
	h.run("list", "--key-older-than", "30")
	if strings.Contains(h.out.String(), "fresh") {
		t.Fatalf("fresh key listed as old: %s", h.out.String())
	}
	if code := h.run("completion", "bash"); code != 0 || !strings.Contains(h.out.String(), "complete -o default") {
		t.Fatal("completion")
	}
}
