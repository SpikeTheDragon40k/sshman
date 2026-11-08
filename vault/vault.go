// Package vault stores sshman entries in a password-encrypted file.
//
// All exported functions that touch the file system take an advisory lock on
// "<vault>.lock" so that concurrent sshman processes cannot corrupt the vault
// or lose each other's updates. Writes go to a fresh, randomly named temporary
// file in the same directory, which is synced and atomically renamed over the
// vault; the previous version is kept as "<vault>.bak".
package vault

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/sshman-org/sshman/model"
)

var (
	// ErrExists is returned by Create when a vault already exists.
	ErrExists = errors.New("vault already exists")
	// ErrNotFound is returned when the vault file does not exist.
	ErrNotFound = errors.New("vault not found")
	// ErrUnsafe is returned when the vault file or its directory could be
	// read or replaced by another user, or the path is a symlink.
	ErrUnsafe = errors.New("unsafe vault location")
)

// BackupPath returns the path of the backup kept next to the vault.
func BackupPath(path string) string { return path + ".bak" }

func lockPath(path string) string { return path + ".lock" }

// Warnf reports non-fatal safety findings. The CLI sets it to print to
// stderr; it is silent by default.
var Warnf = func(format string, args ...any) {}

// faultHook lets tests simulate a crash or I/O failure at a given point of
// the write path. It is a no-op in production.
var faultHook = func(string) error { return nil }

// Load decrypts the vault at path.
func Load(path string, password []byte) ([]model.Entry, error) {
	entries, _, err := LoadInfo(path, password)
	return entries, err
}

// LoadInfo decrypts the vault at path and reports its format.
func LoadInfo(path string, password []byte) ([]model.Entry, Info, error) {
	l, err := acquire(path, false)
	if err != nil {
		return nil, Info{}, err
	}
	defer l.release()
	return load(path, password)
}

// Save encrypts entries with the default parameters and atomically replaces
// the vault at path, creating it if needed.
func Save(path string, password []byte, entries []model.Entry) error {
	l, err := acquire(path, true)
	if err != nil {
		return err
	}
	defer l.release()
	return save(path, password, entries, DefaultParams)
}

// Create writes a new, empty vault. It fails with ErrExists if a file (or
// symlink) is already present at path, without modifying it.
func Create(path string, password []byte) error {
	l, err := acquire(path, true)
	if err != nil {
		return err
	}
	defer l.release()
	if _, err := os.Lstat(path); err == nil {
		return fmt.Errorf("%w at %s", ErrExists, path)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return save(path, password, []model.Entry{}, DefaultParams)
}

// Update runs a locked read-modify-write transaction: the vault is decrypted,
// fn is called with its entries, and the returned entries are saved. If fn
// returns an error nothing is written. Vaults in an older format or with
// outdated KDF parameters are upgraded transparently on write.
func Update(path string, password []byte, fn func([]model.Entry) ([]model.Entry, error)) error {
	l, err := acquire(path, true)
	if err != nil {
		return err
	}
	defer l.release()
	entries, _, err := load(path, password)
	if err != nil {
		return err
	}
	updated, err := fn(entries)
	if err != nil {
		return err
	}
	return save(path, password, updated, DefaultParams)
}

// ChangePassword re-encrypts the vault under newPassword with params. The
// backup is replaced by the new vault so that no copy encrypted under the old
// password is left behind by sshman.
func ChangePassword(path string, oldPassword, newPassword []byte, params Params) error {
	if err := params.Validate(); err != nil {
		return err
	}
	l, err := acquire(path, true)
	if err != nil {
		return err
	}
	defer l.release()
	entries, _, err := load(path, oldPassword)
	if err != nil {
		return err
	}
	if err := save(path, newPassword, entries, params); err != nil {
		return err
	}
	// Verify before discarding the old-password backup.
	if _, _, err := load(path, newPassword); err != nil {
		return fmt.Errorf("verification after password change failed (backup kept at %s): %w", BackupPath(path), err)
	}
	return replaceBackup(path)
}

// Restore replaces the vault with its backup after checking that the backup
// decrypts with password. The current vault (even if unreadable) is kept as
// "<vault>.corrupt".
func Restore(path string, password []byte) (int, error) {
	l, err := acquire(path, true)
	if err != nil {
		return 0, err
	}
	defer l.release()
	bak := BackupPath(path)
	entries, _, err := load(bak, password)
	if err != nil {
		return 0, fmt.Errorf("backup %s: %w", bak, err)
	}
	if _, err := os.Lstat(path); err == nil {
		if err := os.Rename(path, path+".corrupt"); err != nil {
			return 0, err
		}
	}
	if err := save(path, password, entries, DefaultParams); err != nil {
		return 0, err
	}
	return len(entries), nil
}

func readVaultFile(path string) ([]byte, error) {
	if err := checkFile(path); err != nil {
		return nil, err
	}
	f, err := openNoFollow(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("%w at %s", ErrNotFound, path)
		}
		return nil, err
	}
	defer f.Close()
	// Re-check the opened file, not the path, to close the Lstat/open race.
	if err := checkOpenFile(f, path); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(f, maxVaultSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxVaultSize {
		return nil, fmt.Errorf("%w: file larger than %d bytes", ErrFormat, maxVaultSize)
	}
	return data, nil
}

func load(path string, password []byte) ([]model.Entry, Info, error) {
	data, err := readVaultFile(path)
	if err != nil {
		return nil, Info{}, err
	}
	return decryptVault(data, password)
}

// save must be called with the exclusive lock held.
func save(path string, password []byte, entries []model.Entry, params Params) (err error) {
	dir := filepath.Dir(path)
	if err := checkDir(dir); err != nil {
		return err
	}
	exists := false
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&fs.ModeSymlink != 0 || !fi.Mode().IsRegular() {
			return fmt.Errorf("%w: %s is not a regular file", ErrUnsafe, path)
		}
		exists = true
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}

	data, err := encryptVault(entries, password, params)
	if err != nil {
		return err
	}

	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		if err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmpName)
		}
	}()
	if err = tmp.Chmod(0o600); err != nil {
		return err
	}
	if _, err = tmp.Write(data); err != nil {
		return err
	}
	if err = tmp.Sync(); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if err = faultHook("before-rename"); err != nil {
		return err
	}
	if exists {
		if err = keepBackup(path); err != nil {
			return fmt.Errorf("failed to keep backup of previous vault: %w", err)
		}
	}
	if err = os.Rename(tmpName, path); err != nil {
		return err
	}
	return syncDir(dir)
}

// keepBackup points "<vault>.bak" at the current vault contents. It uses a
// hard link where possible (atomic, no extra copy) and falls back to copying.
func keepBackup(path string) error {
	dir := filepath.Dir(path)
	bak := BackupPath(path)
	tmpName, err := reserveTempName(dir, "."+filepath.Base(bak)+".*.tmp")
	if err != nil {
		return err
	}
	if err := os.Link(path, tmpName); err != nil {
		if err := copyFile(path, tmpName); err != nil {
			_ = os.Remove(tmpName)
			return err
		}
	}
	if err := os.Rename(tmpName, bak); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return nil
}

// replaceBackup makes the backup a copy of the current vault.
func replaceBackup(path string) error {
	if err := keepBackup(path); err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
}

// reserveTempName returns an unused, unpredictable path in dir. The name is
// created exclusively and then removed so that os.Link can claim it; dir has
// already been checked to be writable only by the current user.
func reserveTempName(dir, pattern string) (string, error) {
	f, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return "", err
	}
	name := f.Name()
	_ = f.Close()
	if err := os.Remove(name); err != nil {
		return "", err
	}
	return name, nil
}

func copyFile(src, dst string) error {
	in, err := openNoFollow(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Sync(); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}
