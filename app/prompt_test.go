package app

import (
	"bytes"
	"strings"
	"testing"
)

func TestCheckPasswordPolicyMalformed(t *testing.T) {
	bad := map[string][]byte{
		"empty":              nil,
		"whitespace only":    []byte(" \t\n\r  \t\t  \n "),
		"short":              []byte("elevenchars"),
		"short multibyte":    []byte("ñññññññññññ"), // 11 runes, 22 bytes
		"non-utf8":           {0xff, 0xfe, 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k'},
		"1 MiB":              bytes.Repeat([]byte("a"), 1<<20),
		"just over 1024":     bytes.Repeat([]byte("a"), maxSecretLen+1),
		"unicode whitespace": []byte(strings.Repeat(" ", 12)), // NBSP is whitespace for TrimSpace
	}
	for name, pw := range bad {
		if err := CheckPasswordPolicy(pw); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	good := map[string][]byte{
		"twelve ascii":     []byte("twelve-chars"),
		"twelve multibyte": []byte("ññññññññññññ"),
		"with nul":         []byte("abc\x00defghijkl"),
		"surrounding ws":   []byte("  spaced password  "),
		"exactly 1024":     bytes.Repeat([]byte("a"), maxSecretLen),
	}
	for name, pw := range good {
		if err := CheckPasswordPolicy(pw); err != nil {
			t.Errorf("%s rejected: %v", name, err)
		}
	}
}

func TestLegacyTrimmed(t *testing.T) {
	if legacyTrimmed([]byte("nospace-password")) != nil {
		t.Fatal("no trimming needed")
	}
	if got := legacyTrimmed([]byte("  x y  ")); string(got) != "x y" {
		t.Fatalf("got %q", got)
	}
	if legacyTrimmed([]byte("    ")) != nil {
		t.Fatal("all-space password must not become empty")
	}
}
