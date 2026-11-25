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
const fakeSSH = `#!/bin/sh
id=""
while [ $# -gt 0 ]; do
  case "$1" in
    -o) case "$2" in IdentityFile=*) id="${2#IdentityFile=}";; esac; shift 2;;
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
exec sh -c "$1"
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
