package vault

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/SpikeTheDragon40k/sshman/model"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	password := "test-password-123"
	entries := []model.Entry{
		{Name: "server1", User: "root", Host: "10.0.0.1", Port: 22, Key: "fake-key-data"},
		{Name: "server2", User: "admin", Host: "10.0.0.2", Port: 2222, Key: "another-key"},
	}
	encrypted, err := encryptVault(entries, password)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}
	if len(encrypted) < 28 {
		t.Fatal("encrypted data too short")
	}
	decrypted, err := decryptVault(encrypted, password)
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}
	if len(decrypted) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(decrypted))
	}
	if decrypted[0].Name != "server1" || decrypted[0].Host != "10.0.0.1" {
		t.Fatal("round-trip data mismatch for entry 0")
	}
	if decrypted[1].Port != 2222 {
		t.Fatal("round-trip port mismatch for entry 1")
	}
}

func TestDecryptWrongPassword(t *testing.T) {
	password := "correct-password"
	entries := []model.Entry{{Name: "test", User: "u", Host: "h"}}
	encrypted, err := encryptVault(entries, password)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}
	_, err = decryptVault(encrypted, "wrong-password")
	if err == nil {
		t.Fatal("expected error for wrong password")
	}
}

func TestDecryptCorruptData(t *testing.T) {
	_, err := decryptVault([]byte("too short"), "password")
	if err == nil {
		t.Fatal("expected error for too-short data")
	}
	_, err = decryptVault(make([]byte, 28), "password")
	if err == nil {
		t.Fatal("expected error for corrupt data")
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	vaultPath := filepath.Join(dir, "test.vssh")
	password := "vault-password"
	entries := []model.Entry{
		{Name: "alpha", User: "u1", Host: "h1"},
		{Name: "beta", User: "u2", Host: "h2"},
	}
	if err := Save(vaultPath, password, entries); err != nil {
		t.Fatalf("save failed: %v", err)
	}
	if _, err := os.Stat(vaultPath); os.IsNotExist(err) {
		t.Fatal("vault file was not created")
	}
	loaded, err := Load(vaultPath, password)
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}
	if len(loaded) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(loaded))
	}
}

func TestLoadNonexistentFile(t *testing.T) {
	_, err := Load("/nonexistent/path.vssh", "password")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestEmptyVault(t *testing.T) {
	password := "empty-test"
	encrypted, err := encryptVault([]model.Entry{}, password)
	if err != nil {
		t.Fatalf("encrypt empty failed: %v", err)
	}
	decrypted, err := decryptVault(encrypted, password)
	if err != nil {
		t.Fatalf("decrypt empty failed: %v", err)
	}
	if len(decrypted) != 0 {
		t.Fatal("expected empty result")
	}
}
