package sshutil

// Portable end-to-end tests: the real OpenSSH client (ssh, or ssh.exe on
// Windows) authenticates against an in-process x/crypto/ssh server on
// 127.0.0.1, using the vault key through sshman's session agent (unix
// socket or named pipe). No sshd is needed, so this runs on every OS in CI.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sshman-org/sshman/model"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type inprocServer struct {
	addr          *net.TCPAddr
	hostKey       ssh.PublicKey
	agentRequests atomic.Int32 // auth-agent-req@openssh.com received
	logins        atomic.Int32
}

func startInprocServer(t *testing.T, authorized ssh.PublicKey) *inprocServer {
	t.Helper()
	_, hk, _ := ed25519.GenerateKey(rand.Reader)
	hs, _ := ssh.NewSignerFromKey(hk)
	srv := &inprocServer{hostKey: hs.PublicKey()}
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
			if bytes.Equal(k.Marshal(), authorized.Marshal()) {
				return nil, nil
			}
			return nil, errors.New("unauthorized key")
		},
	}
	cfg.AddHostKey(hs)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	srv.addr = l.Addr().(*net.TCPAddr)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go srv.handle(c, cfg)
		}
	}()
	return srv
}

func (s *inprocServer) handle(c net.Conn, cfg *ssh.ServerConfig) {
	defer c.Close()
	sc, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		return
	}
	defer sc.Close()
	s.logins.Add(1)
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != "session" {
			_ = nc.Reject(ssh.UnknownChannelType, "only sessions")
			continue
		}
		ch, creqs, err := nc.Accept()
		if err != nil {
			return
		}
		go func() {
			defer ch.Close()
			for r := range creqs {
				switch r.Type {
				case "auth-agent-req@openssh.com":
					s.agentRequests.Add(1)
					_ = r.Reply(false, nil)
				case "exec", "shell":
					_ = r.Reply(true, nil)
					fmt.Fprintf(ch, "AUTH_OK\n")
					_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
					return
				default:
					_ = r.Reply(r.WantReply, nil)
				}
			}
		}()
	}
}

// sshClientConfig writes an isolated, deliberately hostile client config
// (ForwardAgent yes, a bogus IdentityAgent) and returns -F arguments.
func sshClientConfig(t *testing.T, srv *inprocServer) []string {
	t.Helper()
	dir := t.TempDir()
	kh := filepath.Join(dir, "known_hosts")
	line := fmt.Sprintf("[127.0.0.1]:%d %s", srv.addr.Port, ssh.MarshalAuthorizedKey(srv.hostKey))
	if err := os.WriteFile(kh, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	empty := filepath.Join(dir, "empty")
	_ = os.WriteFile(empty, nil, 0o600)
	q := func(p string) string { return `"` + strings.ReplaceAll(p, `\`, "/") + `"` }
	cfg := filepath.Join(dir, "config")
	content := "Host *\n" +
		"  UserKnownHostsFile " + q(kh) + "\n" +
		"  GlobalKnownHostsFile " + q(empty) + "\n" +
		"  StrictHostKeyChecking yes\n" +
		"  BatchMode yes\n" +
		"  ForwardAgent yes\n" +
		"  IdentityAgent " + q(filepath.Join(dir, "no-such-agent")) + "\n" +
		"  LogLevel ERROR\n"
	if err := os.WriteFile(cfg, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return []string{"-F", strings.ReplaceAll(cfg, `\`, "/")}
}

func requireSSH(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skip("OpenSSH client not installed")
	}
}

func TestConnectInprocServer(t *testing.T) {
	defer watchdog(t, 60*time.Second)()
	requireSSH(t)
	t.Setenv("SSH_AUTH_SOCK", "")
	priv, pub := genEd25519(t, "")
	srv := startInprocServer(t, pub)
	e := &model.Entry{Name: "inproc", User: "tester", Host: "127.0.0.1", Port: srv.addr.Port, Key: string(priv)}
	var out, errb bytes.Buffer
	opts := Options{Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errb, RemoteCommand: []string{"true"}, testArgs: sshClientConfig(t, srv)}
	if err := Connect(e, opts); err != nil {
		t.Fatalf("connect: %v\nstdout=%s\nstderr=%s", err, out.String(), errb.String())
	}
	if !strings.Contains(out.String(), "AUTH_OK") {
		t.Fatalf("no output: %q %q", out.String(), errb.String())
	}
	if n := srv.agentRequests.Load(); n != 0 {
		t.Fatalf("client requested agent forwarding %d time(s) despite ForwardAgent=no", n)
	}

	// A different vault key is refused: only the entry's key is offered.
	other, _ := genEd25519(t, "")
	e2 := *e
	e2.Key = string(other)
	out.Reset()
	errb.Reset()
	if err := Connect(&e2, opts); err == nil {
		t.Fatalf("unauthorized vault key logged in: %s", out.String())
	}
}

// The session's agent endpoint (unix socket or named pipe) serves exactly
// one key read-only, and disappears when the session closes.
func TestSessionAgentEndpoint(t *testing.T) {
	defer watchdog(t, 30*time.Second)()
	priv, pub := genEd25519(t, "")
	s, err := startSession(&model.Entry{Name: "ep", Key: string(priv)})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := dialAgent(s.sock)
	if err != nil {
		s.close()
		t.Fatalf("dial %s: %v", s.sock, err)
	}
	c := agent.NewClient(conn)
	keys, err := c.List()
	if err != nil || len(keys) != 1 || !bytes.Equal(keys[0].Marshal(), pub.Marshal()) {
		t.Fatalf("List: %v %v", keys, err)
	}
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	if err := c.Add(agent.AddedKey{PrivateKey: other}); err == nil {
		t.Error("Add succeeded")
	}
	conn.Close()
	s.close()
	if c2, err := dialAgent(s.sock); err == nil {
		c2.Close()
		t.Fatal("agent endpoint still reachable after close")
	}
}
