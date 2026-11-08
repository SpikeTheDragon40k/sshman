//go:build windows

package sshutil

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var forwardedSignals = []os.Signal{os.Interrupt}

func sessionTempDir() (string, error) {
	dir, err := os.MkdirTemp("", "sshman-")
	if err != nil {
		return "", fmt.Errorf("failed to create session directory: %w", err)
	}
	return dir, nil
}

// pathOption returns a Windows path as an ssh_config option value. Win32
// OpenSSH accepts forward slashes, which avoids backslash escaping in the
// config tokenizer; the value is quoted so user names with spaces work.
// Characters ssh would expand ('%' tokens, '${}', a leading '~') or that
// would break the quoting are refused.
func pathOption(p string) (string, error) {
	q := strings.ReplaceAll(p, `\`, "/")
	if strings.ContainsAny(q, "%$\"\r\n\t") || strings.HasPrefix(q, "~") {
		return "", fmt.Errorf("path %q contains characters ssh would reinterpret; set TEMP to a simple path", p)
	}
	return `"` + q + `"`, nil
}

// listenAgent serves the agent on a new, randomly named pipe that only the
// current user (and SYSTEM) can open. Win32-OpenSSH reads agents from named
// pipes. The first instance is created with FILE_FLAG_FIRST_PIPE_INSTANCE so
// that another process cannot squat the name, and remote clients are
// rejected.
func listenAgent(string) (net.Listener, string, error) {
	var rnd [16]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return nil, "", err
	}
	name := `\\.\pipe\sshman-agent-` + hex.EncodeToString(rnd[:])
	sa, err := currentUserOnlySA()
	if err != nil {
		return nil, "", err
	}
	l := &pipeListener{name: name, sa: sa}
	h, err := l.newInstance(true)
	if err != nil {
		return nil, "", fmt.Errorf("create agent pipe: %w", err)
	}
	l.pending = h
	// ssh_config value: forward slashes, quoted (see pathOption).
	opt := `"` + strings.ReplaceAll(name, `\`, "/") + `"`
	return l, opt, nil
}

// currentUserOnlySA returns security attributes with a protected DACL that
// grants full access to the current user and SYSTEM only.
func currentUserOnlySA() (*windows.SecurityAttributes, error) {
	sid, err := currentUserSID()
	if err != nil {
		return nil, err
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;GA;;;" + sid.String() + ")(A;;GA;;;SY)")
	if err != nil {
		return nil, err
	}
	return &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
		InheritHandle:      0,
	}, nil
}

func currentUserSID() (*windows.SID, error) {
	tu, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	return tu.User.Sid.Copy()
}

type pipeListener struct {
	name    string
	sa      *windows.SecurityAttributes
	mu      sync.Mutex
	pending windows.Handle
	closed  bool
}

func (l *pipeListener) newInstance(first bool) (windows.Handle, error) {
	name, err := windows.UTF16PtrFromString(l.name)
	if err != nil {
		return windows.InvalidHandle, err
	}
	flags := uint32(windows.PIPE_ACCESS_DUPLEX)
	if first {
		flags |= windows.FILE_FLAG_FIRST_PIPE_INSTANCE
	}
	mode := uint32(windows.PIPE_TYPE_BYTE | windows.PIPE_READMODE_BYTE | windows.PIPE_WAIT | windows.PIPE_REJECT_REMOTE_CLIENTS)
	return windows.CreateNamedPipe(name, flags, mode, windows.PIPE_UNLIMITED_INSTANCES, 64<<10, 64<<10, 0, l.sa)
}

// Accept waits for a client on the pending instance and creates the next
// instance before returning, so there is always one waiting.
func (l *pipeListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil, net.ErrClosed
	}
	h := l.pending
	l.pending = windows.InvalidHandle
	l.mu.Unlock()
	if h == windows.InvalidHandle {
		var err error
		if h, err = l.newInstance(false); err != nil {
			return nil, err
		}
	}
	err := windows.ConnectNamedPipe(h, nil)
	if err != nil && !errors.Is(err, windows.ERROR_PIPE_CONNECTED) {
		_ = windows.CloseHandle(h)
		return nil, err
	}
	l.mu.Lock()
	closed := l.closed
	l.mu.Unlock()
	if closed {
		_ = windows.CloseHandle(h)
		return nil, net.ErrClosed
	}
	return &pipeConn{f: os.NewFile(uintptr(h), l.name), h: h}, nil
}

// Close stops accepting. A blocked ConnectNamedPipe is released by
// connecting to the pipe once ourselves.
func (l *pipeListener) Close() error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	l.closed = true
	pending := l.pending
	l.pending = windows.InvalidHandle
	l.mu.Unlock()
	if pending != windows.InvalidHandle {
		// Never handed to Accept.
		_ = windows.CloseHandle(pending)
		return nil
	}
	// An Accept may be blocked in ConnectNamedPipe; connect once to wake it.
	if name, err := windows.UTF16PtrFromString(l.name); err == nil {
		if h, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, 0, 0); err == nil {
			_ = windows.CloseHandle(h)
		}
	}
	return nil
}

func (l *pipeListener) Addr() net.Addr { return pipeAddr(l.name) }

type pipeAddr string

func (a pipeAddr) Network() string { return "pipe" }
func (a pipeAddr) String() string  { return string(a) }

type pipeConn struct {
	f *os.File
	h windows.Handle
}

func (c *pipeConn) Read(b []byte) (int, error)  { return c.f.Read(b) }
func (c *pipeConn) Write(b []byte) (int, error) { return c.f.Write(b) }
func (c *pipeConn) Close() error {
	_ = windows.FlushFileBuffers(c.h)
	_ = windows.DisconnectNamedPipe(c.h)
	return c.f.Close()
}
func (c *pipeConn) LocalAddr() net.Addr                { return pipeAddr("") }
func (c *pipeConn) RemoteAddr() net.Addr               { return pipeAddr("") }
func (c *pipeConn) SetDeadline(t time.Time) error      { return nil }
func (c *pipeConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *pipeConn) SetWriteDeadline(t time.Time) error { return nil }
