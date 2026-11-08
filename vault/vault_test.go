package vault

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"github.com/sshman-org/sshman/model"
)

// testParams keeps unit tests fast. Production code always uses DefaultParams
// or parameters read from the authenticated header.
var testParams = Params{Time: 1, MemoryKiB: minMemoryKiB, Threads: 1}

func init() {
	// Make Save/Update/Create cheap in tests without touching the exported
	// default used by production code paths outside this package.
	DefaultParams = testParams
}

func pw(s string) []byte { return []byte(s) }

func newVaultPath(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dir, "vault.vssh")
}

func sampleEntries() []model.Entry {
	return []model.Entry{
		{Name: "server1", User: "root", Host: "10.0.0.1", Port: 22, Key: "fake-key-data"},
		{Name: "server2", User: "admin", Host: "10.0.0.2", Port: 2222, Key: "another-key"},
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	enc, err := encryptVault(sampleEntries(), pw("test-password-123"), testParams)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(enc, []byte(magic)) {
		t.Fatal("v2 vault must start with magic")
	}
	got, info, err := decryptVault(enc, pw("test-password-123"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Version != formatV2 || info.Params != testParams {
		t.Fatalf("info = %+v", info)
	}
	if len(got) != 2 || got[0].Name != "server1" || got[1].Port != 2222 {
		t.Fatalf("round trip mismatch: %+v", got)
	}
}

func TestDecryptWrongPassword(t *testing.T) {
	enc, err := encryptVault(sampleEntries(), pw("correct-password"), testParams)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := decryptVault(enc, pw("wrong-password")); !errors.Is(err, ErrAuth) {
		t.Fatalf("want ErrAuth, got %v", err)
	}
}

// S-12: every header byte is authenticated. Flipping any single byte of the
// file must fail with a generic error and never panic.
func TestTamperEveryByte(t *testing.T) {
	enc, err := encryptVault(sampleEntries()[:1], pw("pw-for-tamper-test"), testParams)
	if err != nil {
		t.Fatal(err)
	}
	for i := range enc {
		mod := bytes.Clone(enc)
		mod[i] ^= 0x01
		if _, _, err := decryptVault(mod, pw("pw-for-tamper-test")); err == nil {
			t.Fatalf("byte %d flipped but decryption succeeded", i)
		} else if !errors.Is(err, ErrAuth) && !errors.Is(err, ErrFormat) {
			t.Fatalf("byte %d: unexpected error type %v", i, err)
		}
	}
}

func TestTruncationNeverPanics(t *testing.T) {
	enc, err := encryptVault(sampleEntries()[:1], pw("pw-for-trunc-test"), testParams)
	if err != nil {
		t.Fatal(err)
	}
	for n := 0; n < len(enc); n++ {
		if _, _, err := decryptVault(enc[:n], pw("pw-for-trunc-test")); err == nil {
			t.Fatalf("truncated to %d bytes but decryption succeeded", n)
		}
	}
}

// A crafted header must not be able to request huge KDF costs.
func TestHeaderParamBounds(t *testing.T) {
	enc, err := encryptVault(nil, pw("pw-bounds-test"), testParams)
	if err != nil {
		t.Fatal(err)
	}
	mod := bytes.Clone(enc)
	// memory field: offset magic(6)+ver(1)+kdf(1)+time(4)
	off := len(magic) + 2 + 4
	mod[off], mod[off+1], mod[off+2], mod[off+3] = 0xff, 0xff, 0xff, 0xff
	if _, _, err := decryptVault(mod, pw("pw-bounds-test")); !errors.Is(err, ErrFormat) {
		t.Fatalf("want ErrFormat for oversized memory, got %v", err)
	}
	mod = bytes.Clone(enc)
	mod[len(magic)] = 9 // unknown version
	if _, _, err := decryptVault(mod, pw("pw-bounds-test")); !errors.Is(err, ErrFormat) {
		t.Fatalf("want ErrFormat for unknown version, got %v", err)
	}
}

func TestOversizedFileRejected(t *testing.T) {
	if _, _, err := decryptVault(make([]byte, maxVaultSize+1), pw("x")); !errors.Is(err, ErrFormat) {
		t.Fatalf("want ErrFormat, got %v", err)
	}
}

// Compatibility: a vault written by the original (pre-remediation) code must
// still open, and is upgraded to v2 on the next write.
func TestLegacyFixtureMigration(t *testing.T) {
	path := newVaultPath(t)
	data, err := os.ReadFile("testdata/legacy-v1.vssh")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	entries, info, err := LoadInfo(path, pw("legacy-fixture-password"))
	if err != nil {
		t.Fatalf("legacy load: %v", err)
	}
	if info.Version != legacyVersion || info.Params != legacyParams || !info.Outdated() {
		t.Fatalf("legacy info = %+v", info)
	}
	if len(entries) != 2 || entries[1].Name != "legacy-two" || entries[1].Port != 2200 || entries[1].Key != "SYNTHETIC-NOT-A-REAL-KEY-2" {
		t.Fatalf("legacy entries = %+v", entries)
	}
	if _, _, err := LoadInfo(path, pw("wrong")); !errors.Is(err, ErrAuth) {
		t.Fatalf("legacy wrong password: %v", err)
	}
	// Any write upgrades the format.
	if err := Update(path, pw("legacy-fixture-password"), func(e []model.Entry) ([]model.Entry, error) { return e, nil }); err != nil {
		t.Fatal(err)
	}
	entries2, info2, err := LoadInfo(path, pw("legacy-fixture-password"))
	if err != nil {
		t.Fatal(err)
	}
	if info2.Version != formatV2 || len(entries2) != 2 {
		t.Fatalf("after upgrade: info=%+v n=%d", info2, len(entries2))
	}
	// The backup still holds the original legacy bytes for rollback.
	bak, err := os.ReadFile(BackupPath(path))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bak, data) {
		t.Fatal("backup should be the pre-upgrade legacy vault")
	}
}

func TestSaveLoadAndPermissions(t *testing.T) {
	path := newVaultPath(t)
	if err := Save(path, pw("pw-save-load"), sampleEntries()); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path, pw("pw-save-load"))
	if err != nil || len(got) != 2 {
		t.Fatalf("load: %v %v", got, err)
	}
	if runtime.GOOS != "windows" {
		fi, _ := os.Stat(path)
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("vault mode %v, want 0600", fi.Mode().Perm())
		}
	}
	// No temp files left behind.
	matches, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".*.tmp"))
	if len(matches) != 0 {
		t.Fatalf("leftover temp files: %v", matches)
	}
}

func TestLoadMissing(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nope.vssh"), pw("x")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	if _, err := Load(filepath.Join(t.TempDir(), "nodir", "v.vssh"), pw("x")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing dir: want ErrNotFound, got %v", err)
	}
}

func TestCreateRefusesExisting(t *testing.T) {
	path := newVaultPath(t)
	if err := Create(path, pw("pw-create-1")); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	if err := Create(path, pw("pw-create-2")); !errors.Is(err, ErrExists) {
		t.Fatalf("want ErrExists, got %v", err)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("Create modified an existing vault")
	}
	if _, err := Load(path, pw("pw-create-1")); err != nil {
		t.Fatal(err)
	}
}

func TestUpdateErrorWritesNothing(t *testing.T) {
	path := newVaultPath(t)
	if err := Save(path, pw("pw-update"), sampleEntries()); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	boom := errors.New("boom")
	err := Update(path, pw("pw-update"), func(e []model.Entry) ([]model.Entry, error) { return nil, boom })
	if !errors.Is(err, boom) {
		t.Fatalf("got %v", err)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("vault changed although fn failed")
	}
	if err := Update(path, pw("wrong"), func(e []model.Entry) ([]model.Entry, error) { return nil, nil }); !errors.Is(err, ErrAuth) {
		t.Fatalf("wrong password Update: %v", err)
	}
}

// Q-03: concurrent read-modify-write transactions must neither corrupt the
// vault nor lose updates.
func TestConcurrentUpdatesNoLostWrites(t *testing.T) {
	path := newVaultPath(t)
	if err := Create(path, pw("pw-concurrent")); err != nil {
		t.Fatal(err)
	}
	const workers, perWorker = 4, 10
	var wg sync.WaitGroup
	errs := make(chan error, workers*perWorker)
	for w := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range perWorker {
				name := fmt.Sprintf("w%d-%d", w, i)
				errs <- Update(path, pw("pw-concurrent"), func(e []model.Entry) ([]model.Entry, error) {
					return append(e, model.Entry{Name: name, User: "u", Host: "h", Key: "k"}), nil
				})
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("update failed: %v", err)
		}
	}
	got, err := Load(path, pw("pw-concurrent"))
	if err != nil {
		t.Fatalf("vault unreadable after concurrent updates: %v", err)
	}
	if len(got) != workers*perWorker {
		t.Fatalf("lost updates: have %d entries, want %d", len(got), workers*perWorker)
	}
}

func TestChangePassword(t *testing.T) {
	path := newVaultPath(t)
	if err := Save(path, pw("old-password-1"), sampleEntries()); err != nil {
		t.Fatal(err)
	}
	if err := Save(path, pw("old-password-1"), sampleEntries()); err != nil { // creates .bak under old pw
		t.Fatal(err)
	}
	if err := ChangePassword(path, pw("old-password-1"), pw("new-password-2"), testParams); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path, pw("old-password-1")); !errors.Is(err, ErrAuth) {
		t.Fatalf("old password still works: %v", err)
	}
	if got, err := Load(path, pw("new-password-2")); err != nil || len(got) != 2 {
		t.Fatalf("new password: %v", err)
	}
	// The backup must not remain decryptable with the old password.
	if _, err := Load(BackupPath(path), pw("old-password-1")); err == nil {
		t.Fatal("backup still encrypted under the old password")
	}
	if _, err := Load(BackupPath(path), pw("new-password-2")); err != nil {
		t.Fatalf("backup under new password: %v", err)
	}
	if err := ChangePassword(path, pw("wrong"), pw("x-new-password"), testParams); !errors.Is(err, ErrAuth) {
		t.Fatalf("ChangePassword with wrong old password: %v", err)
	}
}

func TestRestoreFromBackup(t *testing.T) {
	path := newVaultPath(t)
	if err := Save(path, pw("pw-restore"), sampleEntries()); err != nil {
		t.Fatal(err)
	}
	if err := Save(path, pw("pw-restore"), sampleEntries()[:1]); err != nil {
		t.Fatal(err)
	}
	// Corrupt the live vault.
	if err := os.WriteFile(path, []byte("garbage-garbage-garbage-garbage-garbage-garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path, pw("pw-restore")); err == nil {
		t.Fatal("corrupted vault loaded")
	}
	n, err := Restore(path, pw("pw-restore"))
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("restored %d entries, want 2 (previous version)", n)
	}
	if _, err := os.Stat(path + ".corrupt"); err != nil {
		t.Fatalf("corrupt copy not kept: %v", err)
	}
	if _, err := Restore(path, pw("wrong")); !errors.Is(err, ErrAuth) {
		t.Fatalf("restore with wrong password: %v", err)
	}
}

func TestEmptyVault(t *testing.T) {
	path := newVaultPath(t)
	if err := Create(path, pw("pw-empty")); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path, pw("pw-empty"))
	if err != nil || got == nil || len(got) != 0 {
		t.Fatalf("got %v %v", got, err)
	}
}

// Q-15 fault injection: a failure after the new data is written but before
// the rename must leave the previous vault intact and no temp file behind.
func TestInterruptedWriteKeepsOldVault(t *testing.T) {
	path := newVaultPath(t)
	if err := Save(path, pw("pw-fault"), sampleEntries()); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	injected := errors.New("injected crash")
	faultHook = func(point string) error {
		if point == "before-rename" {
			return injected
		}
		return nil
	}
	t.Cleanup(func() { faultHook = func(string) error { return nil } })
	err := Update(path, pw("pw-fault"), func(e []model.Entry) ([]model.Entry, error) { return e[:1], nil })
	if !errors.Is(err, injected) {
		t.Fatalf("got %v", err)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("vault modified by failed write")
	}
	if got, err := Load(path, pw("pw-fault")); err != nil || len(got) != 2 {
		t.Fatalf("old vault not readable: %v", err)
	}
	matches, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".*.tmp"))
	if len(matches) != 0 {
		t.Fatalf("temp file left behind: %v", matches)
	}
}

func TestRecommendedParams(t *testing.T) {
	want := Params{Time: 3, MemoryKiB: 64 * 1024, Threads: 4}
	if RecommendedParams != want {
		t.Fatalf("RecommendedParams = %+v, want RFC 9106 profile %+v", RecommendedParams, want)
	}
	if err := RecommendedParams.Validate(); err != nil {
		t.Fatal(err)
	}
	if !(Info{Version: formatV2, Params: legacyParams}).Outdated() {
		t.Fatal("legacy params should be outdated")
	}
}
