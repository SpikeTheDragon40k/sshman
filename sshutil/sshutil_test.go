package sshutil

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/sshman-org/sshman/model"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func genEd25519(t *testing.T, passphrase string) (pemData []byte, pub ssh.PublicKey) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var blk *pem.Block
	if passphrase == "" {
		blk, err = ssh.MarshalPrivateKey(priv, "test")
	} else {
		blk, err = ssh.MarshalPrivateKeyWithPassphrase(priv, "test", []byte(passphrase))
	}
	if err != nil {
		t.Fatal(err)
	}
	signer, _ := ssh.NewSignerFromKey(priv)
	return pem.EncodeToMemory(blk), signer.PublicKey()
}

func TestValidateUserAndHostRejectOptionInjection(t *testing.T) {
	for _, u := range []string{"-Fevil", "-Jattacker", "-v", "-oProxyCommand=x", ".hidden", "a b", "a@b", ""} {
		if ValidateUser(u) == nil {
			t.Errorf("user %q accepted", u)
		}
	}
	for _, u := range []string{"root", "ubuntu", "deploy-bot", "svc_1", "a.b"} {
		if err := ValidateUser(u); err != nil {
			t.Errorf("user %q rejected: %v", u, err)
		}
	}
	for _, h := range []string{"-oProxyCommand=x", "-Fevil", "host name", "a..b", "-host", "ex ample.com", "bad/host", "[1.2.3.4]", "[::1", "fe80::1%bad zone", strings.Repeat("a", 64) + ".com", ""} {
		if ValidateHost(h) == nil {
			t.Errorf("host %q accepted", h)
		}
	}
	for _, h := range []string{"example.com", "example.com.", "10.0.0.1", "::1", "[::1]", "fe80::1%eth0", "[2001:db8::1]", "my_alias", "db-01.internal"} {
		if err := ValidateHost(h); err != nil {
			t.Errorf("host %q rejected: %v", h, err)
		}
	}
	for _, p := range []int{-1, 65536, 1 << 20} {
		if ValidatePort(p) == nil {
			t.Errorf("port %d accepted", p)
		}
	}
	for _, n := range []string{"", "-x", " lead", "trail ", "a\x00b", "a\nb", strings.Repeat("n", 129)} {
		if ValidateName(n) == nil {
			t.Errorf("name %q accepted", n)
		}
	}
}

func TestConnectArgs(t *testing.T) {
	e := &model.Entry{Name: "n", User: "alice", Host: "example.com", Port: 2222}
	args := connectArgs(e, "/tmp/s/agent.sock", "/tmp/s/id.pub", &Options{RemoteCommand: []string{"uptime"}})
	joined := strings.Join(args, " ")
	for _, want := range []string{
		"IdentityAgent=/tmp/s/agent.sock",
		"IdentityFile=/tmp/s/id.pub",
		"IdentitiesOnly=yes",
		"ForwardAgent=no",
		"-p 2222",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("args missing %q: %v", want, args)
		}
	}
	if strings.Contains(joined, "StrictHostKeyChecking") {
		t.Error("StrictHostKeyChecking must not be overridden by default (S-05)")
	}
	i := slices.Index(args, "--")
	if i < 0 || args[i+1] != "alice@example.com" || args[i+2] != "uptime" {
		t.Fatalf("'--' must directly precede the destination: %v", args)
	}
	args = connectArgs(e, "/s", "/p", &Options{AcceptNewHostKey: true})
	if !slices.Contains(args, "StrictHostKeyChecking=accept-new") {
		t.Error("AcceptNewHostKey not honoured")
	}
	e.Port = 22
	if slices.Contains(connectArgs(e, "/s", "/p", &Options{}), "-p") {
		t.Error("port 22 should be left to ssh_config")
	}
}

func TestParsePrivateKey(t *testing.T) {
	plain, pub := genEd25519(t, "")
	km, err := ParsePrivateKey(plain, nil)
	if err != nil {
		t.Fatal(err)
	}
	if km.Fingerprint != ssh.FingerprintSHA256(pub) || km.Decrypted {
		t.Fatalf("unexpected key material %+v", km)
	}

	// S-14: passphrase-protected keys are decrypted and stored decrypted.
	prot, ppub := genEd25519(t, "correct horse")
	if _, err := ParsePrivateKey(prot, nil); !errors.Is(err, ErrPassphraseRequired) {
		t.Fatalf("want ErrPassphraseRequired, got %v", err)
	}
	if _, err := ParsePrivateKey(prot, func() ([]byte, error) { return []byte("wrong"), nil }); err == nil || !strings.Contains(err.Error(), "incorrect passphrase") {
		t.Fatalf("wrong passphrase: %v", err)
	}
	km, err = ParsePrivateKey(prot, func() ([]byte, error) { return []byte("correct horse"), nil })
	if err != nil {
		t.Fatal(err)
	}
	if !km.Decrypted || km.Fingerprint != ssh.FingerprintSHA256(ppub) {
		t.Fatalf("decrypt: %+v", km)
	}
	if _, _, err := ParseStoredKey(km.PrivatePEM); err != nil {
		t.Fatalf("stored decrypted key not usable: %v", err)
	}

	// Q-06 / P7: paths, garbage and trailing data are rejected.
	for _, bad := range [][]byte{
		[]byte("~/.ssh/id_ed25519_typo"),
		[]byte("-----BEGIN NOTHING-----\nAAAA\n-----END NOTHING-----\n"),
		append(append([]byte{}, plain...), []byte("extra trailing data")...),
		append(append([]byte{}, plain...), plain...),
		make([]byte, MaxKeyFileSize+1),
	} {
		if _, err := ParsePrivateKey(bad, nil); err == nil {
			t.Errorf("accepted bad key input %.40q", bad)
		}
	}
}

func TestParsePrivateKeyRejectsWeakRSA(t *testing.T) {
	if testing.Short() {
		t.Skip("RSA generation")
	}
	k, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := ssh.MarshalPrivateKey(k, "")
	if _, err := ParsePrivateKey(pem.EncodeToMemory(blk), nil); err == nil || !strings.Contains(err.Error(), "too weak") {
		t.Fatalf("1024-bit RSA: %v", err)
	}
}

func TestCanonicalAuthorizedKey(t *testing.T) {
	_, pub := genEd25519(t, "")
	base := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
	got, _, err := CanonicalAuthorizedKey(base + " user@host")
	if err != nil || got != base+" user@host" {
		t.Fatalf("got %q %v", got, err)
	}
	got, _, _ = CanonicalAuthorizedKey(base + " evil\"$(rm -rf ~)`x`'")
	if strings.ContainsAny(got, "\"$`'()") {
		t.Fatalf("comment not sanitised: %q", got)
	}
	for _, bad := range []string{
		base + "\n" + base,                 // second line (S-13)
		base + " c\nssh-ed25519 AAAA evil", // trailing line
		`command="/bin/sh" ` + base,        // options
		`from="10.0.0.0/8",no-pty ` + base, // options
		"not a key",
		"",
	} {
		if _, _, err := CanonicalAuthorizedKey(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestEntryPublicKeyMismatch(t *testing.T) {
	privA, _ := genEd25519(t, "")
	_, pubB := genEd25519(t, "")
	lineB := string(ssh.MarshalAuthorizedKey(pubB))
	if _, err := EntryPublicKey(string(privA), lineB); err == nil {
		t.Fatal("mismatched stored public key accepted")
	}
	if got, err := EntryPublicKey(string(privA), ""); err != nil || !strings.HasPrefix(got, "ssh-ed25519 ") {
		t.Fatalf("derive: %q %v", got, err)
	}
	if got, err := EntryPublicKey("", lineB); err != nil || !strings.HasPrefix(got, "ssh-ed25519 ") {
		t.Fatalf("pub only: %q %v", got, err)
	}
}

// S-07: a client of the session socket can list and sign with the one key,
// and nothing else.
func TestReadOnlyAgent(t *testing.T) {
	plain, pub := genEd25519(t, "")
	raw, _, err := ParseStoredKey(string(plain))
	if err != nil {
		t.Fatal(err)
	}
	ag, err := newReadOnlyAgent(raw, "c")
	if err != nil {
		t.Fatal(err)
	}
	c1, c2 := net.Pipe()
	go func() { _ = agent.ServeAgent(ag, c2) }()
	defer c1.Close()
	client := agent.NewClient(c1)

	keys, err := client.List()
	if err != nil || len(keys) != 1 || string(keys[0].Marshal()) != string(pub.Marshal()) {
		t.Fatalf("List: %v %v", keys, err)
	}
	sig, err := client.Sign(pub, []byte("data"))
	if err != nil {
		t.Fatal(err)
	}
	if err := pub.Verify([]byte("data"), sig); err != nil {
		t.Fatal(err)
	}
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	if err := client.Add(agent.AddedKey{PrivateKey: other}); err == nil {
		t.Error("Add succeeded")
	}
	if err := client.Remove(pub); err == nil {
		t.Error("Remove succeeded")
	}
	if err := client.RemoveAll(); err == nil {
		t.Error("RemoveAll succeeded")
	}
	if err := client.Lock([]byte("x")); err == nil {
		t.Error("Lock succeeded")
	}
	if _, err := client.Extension("session-bind@openssh.com", nil); err == nil {
		t.Error("Extension succeeded")
	}
	if keys, _ := client.List(); len(keys) != 1 {
		t.Fatal("key set changed")
	}
}

// S-13: run the remote install script with a local POSIX sh against a fake
// HOME. It must append exactly one line, be idempotent, and repair a missing
// trailing newline.
func TestInstallKeyScriptLocally(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs POSIX sh")
	}
	shPath, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	_, pub := genEd25519(t, "")
	line, _, err := CanonicalAuthorizedKey(strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))) + " sshman-test")
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	ak := filepath.Join(home, ".ssh", "authorized_keys")
	run := func() {
		// Execute exactly what the remote login shell would: `sh -c '<script>'`.
		cmd := exec.Command(shPath, "-c", remoteInstallCommand(line))
		cmd.Env = []string{"HOME=" + home, "PATH=" + os.Getenv("PATH")}
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("script failed: %v\n%s", err, out)
		}
	}
	run()
	run()
	b, _ := os.ReadFile(ak)
	if strings.Count(string(b), "ssh-ed25519 ") != 1 {
		t.Fatalf("expected one key line, got:\n%s", b)
	}
	// Existing file without trailing newline must not be corrupted.
	if err := os.WriteFile(ak, []byte("ssh-rsa AAAAexisting other"), 0o600); err != nil {
		t.Fatal(err)
	}
	run()
	b, _ = os.ReadFile(ak)
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(lines) != 2 || lines[0] != "ssh-rsa AAAAexisting other" || lines[1] != line {
		t.Fatalf("authorized_keys corrupted:\n%q", b)
	}
	fi, _ := os.Stat(ak)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode().Perm())
	}
}

func TestSendKeyArgs(t *testing.T) {
	e := &model.Entry{Name: "n", User: "bob", Host: "h.example", Port: 2200}
	args := sendKeyArgs(e, "ssh-ed25519 AAAA c", &Options{})
	if slices.Contains(args, "PasswordAuthentication=no") {
		t.Error("sendkey must allow password bootstrap (Q-04)")
	}
	if !slices.Contains(args, "ForwardAgent=no") {
		t.Error("ForwardAgent=no missing")
	}
	i := slices.Index(args, "--")
	if i < 0 || args[i+1] != "bob@h.example" || len(args) != i+3 {
		t.Fatalf("bad arg layout: %v", args)
	}
}

func TestValidateMalformedHostsAndUsers(t *testing.T) {
	for _, h := range []string{
		"exаmple.com",            // Cyrillic 'а' homoglyph
		"еxample.com",            // Cyrillic 'е'
		"example.com​",           // zero-width space
		strings.Repeat("a", 300), // over length
		strings.Repeat("a.", 128) + "com",
		"host\x00evil",
		"host\nProxyCommand=x",
		"[fe80::1%eth0;rm]",
		"%eth0",
		"..",
		".",
	} {
		if ValidateHost(h) == nil {
			t.Errorf("host %q accepted", h)
		}
	}
	for _, u := range []string{"rооt" /* Cyrillic o */, "user\x00", strings.Repeat("u", 65), "u\tv"} {
		if ValidateUser(u) == nil {
			t.Errorf("user %q accepted", u)
		}
	}
	for _, p := range []int{-1, 65536, -65535} {
		if ValidatePort(p) == nil {
			t.Errorf("port %d accepted", p)
		}
	}
	if ValidatePort(0) != nil || ValidatePort(65535) != nil {
		t.Error("boundary ports rejected")
	}
}
