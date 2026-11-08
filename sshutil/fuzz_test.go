package sshutil

import (
	"slices"
	"strings"
	"testing"

	"github.com/sshman-org/sshman/model"
)

// FuzzValidateAndArgs: any entry that validates produces an argument list
// in which the destination follows "--" and cannot be read as an option.
func FuzzValidateAndArgs(f *testing.F) {
	f.Add("n", "root", "example.com", 22)
	f.Add("n", "-Fevil", "host", 22)
	f.Add("n", "u", "-oProxyCommand=x", 1)
	f.Add("n", "u", "[::1]", 65535)
	f.Fuzz(func(t *testing.T, name, user, host string, port int) {
		e := &model.Entry{Name: name, User: user, Host: host, Port: port}
		if ValidateEntry(e) != nil {
			return
		}
		if strings.HasPrefix(user, "-") || strings.HasPrefix(host, "-") {
			t.Fatalf("option-like value accepted: %q %q", user, host)
		}
		if strings.ContainsAny(user+host, " \t\r\n'\"`$;|&<>") {
			t.Fatalf("shell/space characters accepted: %q %q", user, host)
		}
		args := connectArgs(e, "/s", "/p", &Options{})
		i := slices.Index(args, "--")
		if i < 0 || i+1 >= len(args) || args[i+1] != e.Addr() {
			t.Fatalf("bad args %v", args)
		}
	})
}

// FuzzCanonicalAuthorizedKey: any accepted public key yields one line made
// only of characters that are safe inside the remote double-quoted script.
func FuzzCanonicalAuthorizedKey(f *testing.F) {
	f.Add("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGuVay7s2q5KM8Mt7oDghmsdlf+/rlGKvYzYuc5ctBAj c")
	f.Add("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGuVay7s2q5KM8Mt7oDghmsdlf+/rlGKvYzYuc5ctBAj \"$(x)\n")
	f.Add(`command="x" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGuVay7s2q5KM8Mt7oDghmsdlf+/rlGKvYzYuc5ctBAj`)
	f.Fuzz(func(t *testing.T, in string) {
		line, _, err := CanonicalAuthorizedKey(in)
		if err != nil {
			return
		}
		for _, r := range line {
			ok := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("+/=@._:- ", r)
			if !ok {
				t.Fatalf("unsafe character %q in %q", r, line)
			}
		}
		if !strings.Contains(remoteInstallCommand(line), line) {
			t.Fatal("line not embedded verbatim")
		}
	})
}

// FuzzParsePrivateKey: arbitrary input never panics.
func FuzzParsePrivateKey(f *testing.F) {
	f.Add([]byte("-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n"))
	f.Add([]byte("garbage"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParsePrivateKey(data, func() ([]byte, error) { return []byte("x"), nil })
	})
}
