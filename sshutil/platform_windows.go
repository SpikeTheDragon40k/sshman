//go:build windows

package sshutil

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
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
	closeEv, err := windows.CreateEvent(nil, 1, 0, nil) // manual reset: stays signalled
	if err != nil {
		return nil, "", err
	}
	l := &pipeListener{name: name, sa: sa, closeEv: closeEv, pending: windows.InvalidHandle}
	h, err := l.newInstance(true)
	if err != nil {
		_ = windows.CloseHandle(closeEv)
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
	closeEv windows.Handle // signalled by Close; never reset
	mu      sync.Mutex
	pending windows.Handle // first instance, not yet handed to Accept
	closed  bool
}

func (l *pipeListener) newInstance(first bool) (windows.Handle, error) {
	name, err := windows.UTF16PtrFromString(l.name)
	if err != nil {
		return windows.InvalidHandle, err
	}
	flags := uint32(windows.PIPE_ACCESS_DUPLEX | windows.FILE_FLAG_OVERLAPPED)
	if first {
		flags |= windows.FILE_FLAG_FIRST_PIPE_INSTANCE
	}
	mode := uint32(windows.PIPE_TYPE_BYTE | windows.PIPE_READMODE_BYTE | windows.PIPE_WAIT | windows.PIPE_REJECT_REMOTE_CLIENTS)
	return windows.CreateNamedPipe(name, flags, mode, windows.PIPE_UNLIMITED_INSTANCES, 64<<10, 64<<10, 0, l.sa)
}

// Accept waits, with overlapped I/O, for a client on a pipe instance or for
// Close. Waiting on the close event as well means Close can never miss a
// blocked Accept.
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
	ev, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		_ = windows.CloseHandle(h)
		return nil, err
	}
	defer windows.CloseHandle(ev)
	ov := windows.Overlapped{HEvent: ev}
	err = windows.ConnectNamedPipe(h, &ov)
	switch {
	case err == nil, errors.Is(err, windows.ERROR_PIPE_CONNECTED):
	case errors.Is(err, windows.ERROR_IO_PENDING):
		which, werr := windows.WaitForMultipleObjects([]windows.Handle{ev, l.closeEv}, false, windows.INFINITE)
		if werr != nil || which != windows.WAIT_OBJECT_0 {
			_ = windows.CancelIoEx(h, &ov)
			var n uint32
			_ = windows.GetOverlappedResult(h, &ov, &n, true)
			_ = windows.CloseHandle(h)
			if werr != nil {
				return nil, werr
			}
			return nil, net.ErrClosed
		}
		var n uint32
		if err := windows.GetOverlappedResult(h, &ov, &n, false); err != nil {
			_ = windows.CloseHandle(h)
			return nil, err
		}
	default:
		_ = windows.CloseHandle(h)
		return nil, err
	}
	return newPipeConn(h)
}

// Close stops accepting and releases any blocked Accept.
func (l *pipeListener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	if l.pending != windows.InvalidHandle {
		_ = windows.CloseHandle(l.pending)
		l.pending = windows.InvalidHandle
	}
	return windows.SetEvent(l.closeEv)
}

func (l *pipeListener) Addr() net.Addr { return pipeAddr(l.name) }

type pipeAddr string

func (a pipeAddr) Network() string { return "pipe" }
func (a pipeAddr) String() string  { return string(a) }

// pipeConn does overlapped reads and writes on an overlapped pipe handle
// (os.NewFile would treat it as blocking). One read and one write may be in
// progress at a time, which is how the agent protocol uses it.
type pipeConn struct {
	h         windows.Handle
	rev, wev  windows.Handle
	closeOnce sync.Once
}

func newPipeConn(h windows.Handle) (*pipeConn, error) {
	rev, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		_ = windows.CloseHandle(h)
		return nil, err
	}
	wev, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		_ = windows.CloseHandle(rev)
		_ = windows.CloseHandle(h)
		return nil, err
	}
	return &pipeConn{h: h, rev: rev, wev: wev}, nil
}

func pipeErr(err error) error {
	if errors.Is(err, windows.ERROR_BROKEN_PIPE) || errors.Is(err, windows.ERROR_PIPE_NOT_CONNECTED) ||
		errors.Is(err, windows.ERROR_NO_DATA) || errors.Is(err, windows.ERROR_OPERATION_ABORTED) {
		return io.EOF
	}
	return err
}

func (c *pipeConn) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	var n uint32
	ov := windows.Overlapped{HEvent: c.rev}
	err := windows.ReadFile(c.h, b, &n, &ov)
	if errors.Is(err, windows.ERROR_IO_PENDING) {
		err = windows.GetOverlappedResult(c.h, &ov, &n, true)
	}
	if err != nil {
		return int(n), pipeErr(err)
	}
	if n == 0 {
		return 0, io.EOF
	}
	return int(n), nil
}

func (c *pipeConn) Write(b []byte) (int, error) {
	written := 0
	for written < len(b) {
		var n uint32
		ov := windows.Overlapped{HEvent: c.wev}
		err := windows.WriteFile(c.h, b[written:], &n, &ov)
		if errors.Is(err, windows.ERROR_IO_PENDING) {
			err = windows.GetOverlappedResult(c.h, &ov, &n, true)
		}
		written += int(n)
		if err != nil {
			return written, pipeErr(err)
		}
	}
	return written, nil
}

func (c *pipeConn) Close() error {
	c.closeOnce.Do(func() {
		_ = windows.CancelIoEx(c.h, nil)
		_ = windows.DisconnectNamedPipe(c.h)
		_ = windows.CloseHandle(c.h)
		_ = windows.CloseHandle(c.rev)
		_ = windows.CloseHandle(c.wev)
	})
	return nil
}

func (c *pipeConn) LocalAddr() net.Addr                { return pipeAddr("") }
func (c *pipeConn) RemoteAddr() net.Addr               { return pipeAddr("") }
func (c *pipeConn) SetDeadline(t time.Time) error      { return nil }
func (c *pipeConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *pipeConn) SetWriteDeadline(t time.Time) error { return nil }
