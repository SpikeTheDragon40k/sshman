//go:build unix

package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeSSH "logs in" only when the key named by IdentityFile (or, without
// one, any key: password login) is listed in $HOME/.ssh/authorized_keys,
// then runs the remote command locally with sh, as a real server would.
// Given an empty UserKnownHostsFile, it records $FAKE_HOSTKEY there, as ssh
// does when the user accepts a new host key.
const fakeSSH = `#!/bin/sh
id=""
kh=""
while [ $# -gt 0 ]; do
  case "$1" in
    -o) case "$2" in IdentityFile=*) id="${2#IdentityFile=}";; UserKnownHostsFile=*) kh="${2#UserKnownHostsFile=}";; esac; shift 2;;
    -p) shift 2;;
    --) shift; break;;
    *) shift;;
  esac
done
shift
if [ -n "$id" ]; then
  key=$(cut -d' ' -f1,2 "$id")
  grep -qF "$key" "$HOME/.ssh/authorized_keys" 2>/dev/null || { echo "Permission denied (publickey)" >&2; exit 255; }
fi
if [ -n "$kh" ] && [ ! -s "$kh" ]; then echo "$FAKE_HOSTKEY" >> "$kh"; fi
exec sh -c "$*"
`

func setupRotate(t *testing.T) (*harness, string) {
	t.Helper()
	h := newHarness(t)
	h.ssh = filepath.Join(h.dir, "fake-ssh")
	if err := os.WriteFile(h.ssh, []byte(fakeSSH), 0o700); err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(h.dir, "home")
	t.Setenv("HOME", home)
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	h.init()
	h.pw(goodPW)
	if code := h.run("genkey", "--name", "web", "--user", "deploy", "--host", "web.example"); code != 0 {
		t.Fatal(h.errb.String())
	}
	return h, filepath.Join(home, ".ssh", "authorized_keys")
}

func (h *harness) pubkey(name string) string {
	h.t.Helper()
	h.pw(goodPW)
	if code := h.run("pubkey", "--name", name); code != 0 {
		h.t.Fatal(h.errb.String())
	}
	return strings.Join(strings.Fields(h.out.String())[:2], " ")
}

func TestRotate(t *testing.T) {
	h, ak := setupRotate(t)
	oldKey := h.pubkey("web")
	other := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOtherKeyOtherKeyOtherKeyOtherKeyOtherKe other"
	if err := os.WriteFile(ak, []byte(other+"\n"+oldKey+" sshman:web\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	h.pw(goodPW) // one prompt for the whole rotation
	if code := h.run("rotate", "--name", "web"); code != 0 {
		t.Fatalf("rotate: %d %s", code, h.errb.String())
	}
	newKey := h.pubkey("web")
	if newKey == oldKey {
		t.Fatal("vault key not replaced")
	}
	b, _ := os.ReadFile(ak)
	got := string(b)
	if strings.Contains(got, oldKey) || !strings.Contains(got, newKey) || !strings.HasPrefix(got, other+"\n") {
		t.Fatalf("authorized_keys after rotate:\n%s", got)
	}
}

// If the current key cannot log in, nothing changes anywhere.
func TestRotateFailsSafely(t *testing.T) {
	h, ak := setupRotate(t)
	oldKey := h.pubkey("web")
	if err := os.WriteFile(ak, []byte("ssh-ed25519 AAAAunrelated x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	h.pw(goodPW)
	if code := h.run("rotate", "--name", "web"); code == 0 || !strings.Contains(h.errb.String(), "nothing was changed") {
		t.Fatalf("rotate without access: %d %s", code, h.errb.String())
	}
	if h.pubkey("web") != oldKey {
		t.Fatal("vault changed although the new key was never installed")
	}
	if b, _ := os.ReadFile(ak); string(b) != "ssh-ed25519 AAAAunrelated x\n" {
		t.Fatalf("authorized_keys changed:\n%s", b)
	}
}

// F-09 through the CLI: pin, show, the pin is dropped when the host changes,
// and --clear removes it. F: the entry name works as an argument.
func TestPinAndPositionalName(t *testing.T) {
	h, ak := setupRotate(t)
	if err := os.WriteFile(ak, []byte(h.pubkey("web")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	hostKey := "web.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGGh3LCAgsg8tKu9nQ8zwHdsGDXUwq0O2x6Pi3P1vGgZ"
	t.Setenv("FAKE_HOSTKEY", hostKey)

	h.pw(goodPW)
	if code := h.run("pin", "web"); code != 0 {
		t.Fatalf("pin: %s", h.errb.String())
	}
	if !strings.Contains(h.errb.String(), "Pinned ssh-ed25519 SHA256:") {
		t.Fatalf("no fingerprint printed: %s", h.errb.String())
	}
	h.pw(goodPW)
	if code := h.run("show", "web"); code != 0 || !strings.Contains(h.out.String(), "Host key:     pinned ssh-ed25519 SHA256:") {
		t.Fatalf("show: %s %s", h.out.String(), h.errb.String())
	}
	h.pw(goodPW)
	if code := h.run("connect", "web", "--", "echo", "CONNECTED"); code != 0 || !strings.Contains(h.out.String(), "CONNECTED") {
		t.Fatalf("connect web -- cmd: %s %s", h.out.String(), h.errb.String())
	}

	h.pw(goodPW)
	if code := h.run("update", "--host", "web2.example", "web"); code != 0 || !strings.Contains(h.errb.String(), "pinned host key was removed") {
		t.Fatalf("update: %s", h.errb.String())
	}
	h.pw(goodPW)
	h.run("show", "--json", "web")
	if strings.Contains(h.out.String(), "host_keys") {
		t.Fatalf("pin kept after host change: %s", h.out.String())
	}

	h.pw(goodPW)
	h.run("pin", "web")
	h.pw(goodPW)
	if code := h.run("pin", "--clear", "web"); code != 0 {
		t.Fatal(h.errb.String())
	}
	h.pw(goodPW)
	h.run("show", "--json", "web")
	if strings.Contains(h.out.String(), "host_keys") {
		t.Fatalf("pin not cleared: %s", h.out.String())
	}

	// Positional-name errors need no password.
	for _, args := range [][]string{{"show"}, {"show", "web", "--json"}, {"show", "web", "extra"}, {"connect", "web", "-v"}} {
		if code := h.run(args...); code != 2 {
			t.Fatalf("%v: exit %d, want 2 (usage): %s", args, code, h.errb.String())
		}
	}
}
