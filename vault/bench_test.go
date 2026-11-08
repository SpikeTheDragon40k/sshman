package vault

import (
	"fmt"
	"testing"

	"github.com/sshman-org/sshman/model"
)

func benchEntries(n int) []model.Entry {
	es := make([]model.Entry, n)
	for i := range es {
		es[i] = model.Entry{Name: fmt.Sprintf("host-%d", i), User: "deploy", Host: fmt.Sprintf("10.0.%d.%d", i/256, i%256), Port: 22,
			Key: "-----BEGIN OPENSSH PRIVATE KEY-----\n" + string(make([]byte, 400)) + "\n-----END OPENSSH PRIVATE KEY-----\n"}
	}
	return es
}

// Benchmarks use the production parameters: unlock cost is dominated by
// Argon2id by design and must not be "optimised" by weakening the KDF.
func BenchmarkUnlockRecommended(b *testing.B) {
	enc, err := encryptVault(benchEntries(10), []byte("bench-password"), RecommendedParams)
	if err != nil {
		b.Fatal(err)
	}
	for b.Loop() {
		if _, _, err := decryptVault(enc, []byte("bench-password")); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSaveRecommended(b *testing.B) {
	path := b.TempDir() + "/v.vssh"
	es := benchEntries(10)
	old := DefaultParams
	DefaultParams = RecommendedParams
	b.Cleanup(func() { DefaultParams = old })
	for b.Loop() {
		if err := Save(path, []byte("bench-password"), es); err != nil {
			b.Fatal(err)
		}
	}
}

// Large vault: cost beyond the KDF (JSON + AES-GCM) for 5000 entries.
func BenchmarkLargeVaultFastKDF(b *testing.B) {
	enc, err := encryptVault(benchEntries(5000), []byte("bench-password"), testParams)
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(enc)))
	for b.Loop() {
		if _, _, err := decryptVault(enc, []byte("bench-password")); err != nil {
			b.Fatal(err)
		}
	}
}
