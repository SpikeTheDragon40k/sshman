//go:build unix

package vault

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// lockTimeout bounds how long a command waits for another sshman process.
var lockTimeout = 30 * time.Second

type fileLock struct{ f *os.File }

func acquire(path string, exclusive bool) (*fileLock, error) {
	dir := filepath.Dir(path)
	if err := checkDir(dir); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("%w at %s", ErrNotFound, path)
		}
		return nil, err
	}
	f, err := os.OpenFile(lockPath(path), os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		// A reader on a read-only location can proceed without a lock:
		// writers replace the vault by rename, so a reader always sees a
		// complete file.
		if !exclusive && (errors.Is(err, syscall.EROFS) || errors.Is(err, syscall.EACCES)) {
			return &fileLock{}, nil
		}
		if errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf("%w: lock file %s is a symlink", ErrUnsafe, lockPath(path))
		}
		return nil, err
	}
	if err := checkOwner(f, lockPath(path)); err != nil {
		_ = f.Close()
		return nil, err
	}
	how := unix.LOCK_SH
	if exclusive {
		how = unix.LOCK_EX
	}
	deadline := time.Now().Add(lockTimeout)
	for {
		err := unix.Flock(int(f.Fd()), how|unix.LOCK_NB)
		if err == nil {
			return &fileLock{f: f}, nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EINTR) {
			_ = f.Close()
			return nil, fmt.Errorf("lock %s: %w", lockPath(path), err)
		}
		if time.Now().After(deadline) {
			_ = f.Close()
			return nil, fmt.Errorf("timed out waiting for another sshman process to release %s", lockPath(path))
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (l *fileLock) release() {
	if l == nil || l.f == nil {
		return
	}
	_ = unix.Flock(int(l.f.Fd()), unix.LOCK_UN)
	_ = l.f.Close()
}

func openNoFollow(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if errors.Is(err, syscall.ELOOP) {
		return nil, fmt.Errorf("%w: %s is a symlink", ErrUnsafe, path)
	}
	return f, err
}

// checkFile rejects a vault path that is a symlink or not a regular file.
// A missing file is not an error here; the subsequent open reports it.
func checkFile(path string) error {
	fi, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if fi.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("%w: %s is a symlink; point --vault at the real file", ErrUnsafe, path)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%w: %s is not a regular file", ErrUnsafe, path)
	}
	return checkDir(filepath.Dir(path))
}

func checkOwner(f *os.File, name string) error {
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%w: %s is not a regular file", ErrUnsafe, name)
	}
	if int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("%w: %s is owned by uid %d, not the current user (uid %d)", ErrUnsafe, name, st.Uid, os.Geteuid())
	}
	return nil
}

// checkOpenFile verifies ownership and that no other user can read or write
// the vault (the same rule OpenSSH applies to private key files).
func checkOpenFile(f *os.File, name string) error {
	if err := checkOwner(f, name); err != nil {
		return err
	}
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("%w: %s has permissions %04o; it must be accessible only by you (run: chmod 600 %q)", ErrUnsafe, name, perm, name)
	}
	return nil
}

// checkDir rejects a directory that another user could use to replace or
// remove the vault: it must be owned by the current user or root, and must
// not be group- or world-writable unless the sticky bit is set.
func checkDir(dir string) error {
	fi, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	if int(st.Uid) != os.Geteuid() && st.Uid != 0 {
		return fmt.Errorf("%w: directory %s is owned by uid %d", ErrUnsafe, dir, st.Uid)
	}
	if fi.Mode()&fs.ModeSticky == 0 {
		perm := fi.Mode().Perm()
		if perm&0o002 != 0 {
			return fmt.Errorf("%w: directory %s is writable by all users (mode %04o); keep the vault in a private directory", ErrUnsafe, dir, perm)
		}
		if perm&0o020 != 0 {
			// Common with umask 002 and per-user groups. Members of the
			// group could delete or replace the vault (denial of service);
			// they cannot read it or make sshman follow a link.
			Warnf("warning: directory %s is group-writable (mode %04o); consider: chmod g-w %q", dir, perm, dir)
		}
	}
	return nil
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	if err := d.Sync(); err != nil && !errors.Is(err, syscall.EINVAL) && !errors.Is(err, syscall.ENOTSUP) {
		return err
	}
	return nil
}
