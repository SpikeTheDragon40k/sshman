//go:build unix

package vault

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// S-03 / P1: a symlink planted at any predictable sibling path must never be
// followed. The old code wrote through "<vault>.tmp".
func TestSymlinkAtLegacyTmpPathNotFollowed(t *testing.T) {
	path := newVaultPath(t)
	victim := filepath.Join(t.TempDir(), "victim.txt")
	if err := os.WriteFile(victim, []byte("precious"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, path+".tmp"); err != nil {
		t.Fatal(err)
	}
	if err := Save(path, pw("pw-symlink"), sampleEntries()); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(victim); !bytes.Equal(b, []byte("precious")) {
		t.Fatal("symlink target was overwritten")
	}
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		t.Fatal("vault became a symlink")
	}
}

// S-03 / P2: a pre-existing permissive temp file must not loosen the mode.
func TestPreexistingPermissiveTmpIgnored(t *testing.T) {
	path := newVaultPath(t)
	if err := os.WriteFile(path+".tmp", nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Save(path, pw("pw-mode"), sampleEntries()); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(path)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("vault mode %v", fi.Mode().Perm())
	}
}

func TestVaultSymlinkRefused(t *testing.T) {
	path := newVaultPath(t)
	real := filepath.Join(filepath.Dir(path), "real.vssh")
	if err := Save(real, pw("pw-link"), sampleEntries()); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, path); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path, pw("pw-link")); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("Load via symlink: want ErrUnsafe, got %v", err)
	}
	if err := Save(path, pw("pw-link"), nil); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("Save via symlink: want ErrUnsafe, got %v", err)
	}
	if err := Create(path, pw("pw-link")); !errors.Is(err, ErrExists) {
		t.Fatalf("Create over symlink: want ErrExists, got %v", err)
	}
}

func TestLockSymlinkRefused(t *testing.T) {
	path := newVaultPath(t)
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.Symlink(victim, lockPath(path)); err != nil {
		t.Fatal(err)
	}
	if err := Create(path, pw("pw-lock")); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("want ErrUnsafe, got %v", err)
	}
	if _, err := os.Lstat(victim); err == nil {
		t.Fatal("lock symlink target was created")
	}
}

// S-10 / P3: a vault readable or writable by others is refused.
func TestInsecurePermissionsRefused(t *testing.T) {
	path := newVaultPath(t)
	if err := Save(path, pw("pw-perm"), sampleEntries()); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []os.FileMode{0o644, 0o640, 0o666, 0o604} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path, pw("pw-perm")); !errors.Is(err, ErrUnsafe) {
			t.Fatalf("mode %04o: want ErrUnsafe, got %v", mode, err)
		}
	}
	_ = os.Chmod(path, 0o600)
	if _, err := Load(path, pw("pw-perm")); err != nil {
		t.Fatal(err)
	}
}

func TestWritableDirectoryRefused(t *testing.T) {
	path := newVaultPath(t)
	if err := Save(path, pw("pw-dir"), sampleEntries()); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(path)
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	if _, err := Load(path, pw("pw-dir")); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("world-writable dir: want ErrUnsafe, got %v", err)
	}
	// Group-writable: allowed with a warning (umask 002 setups).
	if err := os.Chmod(dir, 0o770); err != nil {
		t.Fatal(err)
	}
	var warned string
	Warnf = func(f string, a ...any) { warned = fmt.Sprintf(f, a...) }
	t.Cleanup(func() { Warnf = func(string, ...any) {} })
	if _, err := Load(path, pw("pw-dir")); err != nil {
		t.Fatalf("group-writable dir refused: %v", err)
	}
	if !strings.Contains(warned, "group-writable") {
		t.Fatalf("no warning: %q", warned)
	}
	// Sticky world-writable directories (like /tmp) are accepted.
	if err := os.Chmod(dir, 0o777|os.ModeSticky); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path, pw("pw-dir")); err != nil {
		t.Fatalf("sticky dir: %v", err)
	}
}

func TestBackupIsSeparateInode(t *testing.T) {
	path := newVaultPath(t)
	if err := Save(path, pw("pw-bak"), sampleEntries()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(BackupPath(path)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("first save must not create a backup")
	}
	if err := Save(path, pw("pw-bak"), sampleEntries()[:1]); err != nil {
		t.Fatal(err)
	}
	bak, err := Load(BackupPath(path), pw("pw-bak"))
	if err != nil || len(bak) != 2 {
		t.Fatalf("backup should hold previous version: %v %d", err, len(bak))
	}
	cur, _ := Load(path, pw("pw-bak"))
	if len(cur) != 1 {
		t.Fatal("current vault wrong")
	}
	fi, _ := os.Stat(BackupPath(path))
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("backup mode %v", fi.Mode().Perm())
	}
}
