//go:build unix

package cmd

import (
	"os"
	"testing"
)

// makeInsecure makes the vault readable by other users.
func makeInsecure(t *testing.T, path string) {
	t.Helper()
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
}
