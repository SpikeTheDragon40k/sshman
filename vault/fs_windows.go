//go:build windows

package vault

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
	"unsafe"

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
	_, statErr := os.Lstat(lockPath(path))
	f, err := os.OpenFile(lockPath(path), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		if !exclusive && errors.Is(err, fs.ErrPermission) {
			return &fileLock{}, nil
		}
		return nil, err
	}
	if errors.Is(statErr, fs.ErrNotExist) {
		if err := restrictFile(f); err != nil {
			_ = f.Close()
			return nil, err
		}
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

// checkOpenFile is the Windows counterpart of the Unix mode check (S-10):
// the file must be owned by the current user (or SYSTEM/Administrators), and
// its DACL must not grant read, write or permission changes to any other
// account. Deny entries and inherit-only entries are ignored.
func checkOpenFile(f *os.File, name string) error {
	sd, err := windows.GetSecurityInfo(windows.Handle(f.Fd()), windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("read security descriptor of %s: %w", name, err)
	}
	user, err := currentUserSID()
	if err != nil {
		return err
	}
	trusted := trustedSIDs(user)
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	if owner == nil || !sidIn(owner, trusted) {
		return fmt.Errorf("%w: %s is owned by %s, not by you", ErrUnsafe, name, sidName(owner))
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	hint := fmt.Sprintf("(run: icacls \"%s\" /inheritance:r /grant:r \"%%USERNAME%%:F\")", name)
	if dacl == nil {
		return fmt.Errorf("%w: %s has no access control list, so everyone can access it %s", ErrUnsafe, name, hint)
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return err
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		if ace.Mask&dangerousAccess == 0 {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sidIn(sid, trusted) {
			return fmt.Errorf("%w: %s grants access to %s %s", ErrUnsafe, name, sidName(sid), hint)
		}
	}
	return nil
}

// Rights that would let another account read the vault, change it, or
// change who may access it.
const dangerousAccess = windows.FILE_READ_DATA | windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA |
	windows.GENERIC_READ | windows.GENERIC_WRITE | windows.GENERIC_ALL |
	windows.WRITE_DAC | windows.WRITE_OWNER | windows.DELETE

func trustedSIDs(user *windows.SID) []*windows.SID {
	out := []*windows.SID{user}
	for _, t := range []windows.WELL_KNOWN_SID_TYPE{windows.WinLocalSystemSid, windows.WinBuiltinAdministratorsSid} {
		if s, err := windows.CreateWellKnownSid(t); err == nil {
			out = append(out, s)
		}
	}
	return out
}

func sidIn(s *windows.SID, set []*windows.SID) bool {
	for _, t := range set {
		if s.Equals(t) {
			return true
		}
	}
	return false
}

func sidName(s *windows.SID) string {
	if s == nil {
		return "nobody"
	}
	if acct, dom, _, err := s.LookupAccount(""); err == nil {
		if dom != "" {
			return dom + `\` + acct
		}
		return acct
	}
	return s.String()
}

func currentUserSID() (*windows.SID, error) {
	tu, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	return tu.User.Sid.Copy()
}

// restrictFile replaces the inherited ACL of a newly created vault, backup or
// lock file with a protected DACL granting full control to the current user
// and SYSTEM only.
func restrictFile(f *os.File) error {
	user, err := currentUserSID()
	if err != nil {
		return err
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;" + user.String() + ")(A;;FA;;;SY)")
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	// By path: handles from os.OpenFile lack WRITE_DAC.
	if err := windows.SetNamedSecurityInfo(f.Name(), windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		return fmt.Errorf("restrict access to %s: %w", f.Name(), err)
	}
	return nil
}

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
