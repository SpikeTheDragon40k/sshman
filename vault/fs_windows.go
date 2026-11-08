//go:build windows

package vault

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows"
)

var lockTimeout = 30 * time.Second

type fileLock struct{ f *os.File }

func acquire(path string, exclusive bool) (*fileLock, error) {
	dir := filepath.Dir(path)
	if _, err := os.Stat(dir); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("%w at %s", ErrNotFound, path)
		}
		return nil, err
	}
	if err := checkFile(lockPath(path)); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(lockPath(path), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		if !exclusive && errors.Is(err, fs.ErrPermission) {
			return &fileLock{}, nil
		}
		return nil, err
	}
	var flags uint32 = windows.LOCKFILE_FAIL_IMMEDIATELY
	if exclusive {
		flags |= windows.LOCKFILE_EXCLUSIVE_LOCK
	}
	deadline := time.Now().Add(lockTimeout)
	for {
		ol := new(windows.Overlapped)
		err := windows.LockFileEx(windows.Handle(f.Fd()), flags, 0, 1, 0, ol)
		if err == nil {
			return &fileLock{f: f}, nil
		}
		if !errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
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
	ol := new(windows.Overlapped)
	_ = windows.UnlockFileEx(windows.Handle(l.f.Fd()), 0, 1, 0, ol)
	_ = l.f.Close()
}

func openNoFollow(path string) (*os.File, error) {
	if err := checkFile(path); err != nil {
		return nil, err
	}
	return os.Open(path)
}

func checkFile(path string) error {
	fi, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if fi.Mode()&fs.ModeSymlink != 0 || fi.Mode()&fs.ModeIrregular != 0 {
		return fmt.Errorf("%w: %s is a symlink or reparse point", ErrUnsafe, path)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%w: %s is not a regular file", ErrUnsafe, path)
	}
	return nil
}

// On Windows, POSIX permission bits are not meaningful and ACLs are not yet
// inspected; see docs/remediation/DECISIONS.md (D-09).
func checkOpenFile(*os.File, string) error { return nil }

func checkDir(dir string) error {
	fi, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	return nil
}

func syncDir(string) error { return nil }
