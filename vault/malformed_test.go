package vault

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/sshman-org/sshman/model"
)

// sealPayload encrypts arbitrary plaintext as a valid v2 vault, so tests can
// check how hostile *decrypted* content is handled.
func sealPayload(t *testing.T, plaintext []byte, password []byte) []byte {
	t.Helper()
	enc, err := encryptVault(nil, password, testParams)
	if err != nil {
		t.Fatal(err)
	}
	h, err := parseV2(enc)
	if err != nil {
		t.Fatal(err)
	}
	key := deriveKey(password, h.salt, testParams)
	gcm, err := newGCM(key)
	if err != nil {
		t.Fatal(err)
	}
	return gcm.Seal(bytes.Clone(h.aad), h.nonce, plaintext, h.aad)
}

// A sparse 1 GiB file must be refused from its size, without reading it.
func TestHugeVaultFileRefusedWithoutReading(t *testing.T) {
	path := newVaultPath(t)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(1 << 30); err != nil {
		f.Close()
		t.Skipf("sparse files unsupported: %v", err)
	}
	f.Close()
	start := time.Now()
	_, err = Load(path, pw("pw"))
	if !errors.Is(err, ErrFormat) || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("want size error, got %v", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("size check took %v; file was probably read", d)
	}
	if _, _, err := Inspect(path); !errors.Is(err, ErrFormat) {
		t.Fatalf("Inspect: %v", err)
	}
}

func TestHostileDecryptedPayloads(t *testing.T) {
	password := pw("pw-hostile-payload")
	deep := strings.Repeat("[", 100000) + strings.Repeat("]", 100000)
	cases := map[string]string{
		"deeply nested":        `{"entries":` + deep + `}`,
		"wrong type port":      `{"entries":[{"name":"a","port":"twenty-two"}]}`,
		"wrong type entries":   `{"entries":"nope"}`,
		"entries is object":    `{"entries":{"name":"a"}}`,
		"truncated json":       `{"entries":[{"name":"a"`,
		"not json":             "\x00\x01\x02",
		"array instead (v2)":   `[{"name":"a"}]`,
		"huge number":          `{"entries":[{"port":1e400}]}`,
		"invalid utf8 in name": "{\"entries\":[{\"name\":\"\xff\xfe\"}]}",
	}
	for name, pl := range cases {
		t.Run(name, func(t *testing.T) {
			data := sealPayload(t, []byte(pl), password)
			entries, _, err := decryptVault(data, password)
			if name == "invalid utf8 in name" {
				// encoding/json replaces invalid UTF-8; the name is then
				// rejected by validation on any edit. It must not panic.
				if err != nil {
					t.Fatalf("unexpected error %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("accepted hostile payload: %+v", entries)
			}
			if !errors.Is(err, ErrFormat) {
				t.Fatalf("want ErrFormat, got %v", err)
			}
		})
	}
}

// A vault with very many entries still round-trips (no artificial limit
// below the 64 MiB file cap).
func TestManyEntries(t *testing.T) {
	if testing.Short() {
		t.Skip("large")
	}
	es := make([]model.Entry, 100000)
	for i := range es {
		es[i] = model.Entry{Name: fmt.Sprintf("h%d", i), User: "u", Host: "h", Key: "k"}
	}
	enc, err := encryptVault(es, pw("pw-many"), testParams)
	if err != nil {
		t.Fatal(err)
	}
	got, _, err := decryptVault(enc, pw("pw-many"))
	if err != nil || len(got) != len(es) {
		t.Fatalf("%v %d", err, len(got))
	}
}

// Passwords are opaque bytes to the vault: NUL bytes, non-UTF-8 and long
// passwords round-trip exactly and are not truncated at the NUL.
func TestUnusualPasswordBytes(t *testing.T) {
	for name, p := range map[string][]byte{
		"nul inside":  []byte("abc\x00def-long-enough"),
		"non-utf8":    {0xff, 0xfe, 0xfd, 'x', 'y', 'z', 0x80, 0x81, 0x82, 0x83, 0x84, 0x85},
		"1 KiB":       bytes.Repeat([]byte("p"), 1024),
		"unicode":     []byte("pässwörd-🔑-long"),
		"only spaces": []byte("            "),
	} {
		t.Run(name, func(t *testing.T) {
			enc, err := encryptVault(sampleEntries(), p, testParams)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := decryptVault(enc, p); err != nil {
				t.Fatalf("round trip: %v", err)
			}
			if i := bytes.IndexByte(p, 0); i >= 0 {
				if _, _, err := decryptVault(enc, p[:i]); err == nil {
					t.Fatal("password truncated at NUL")
				}
			}
		})
	}
}
