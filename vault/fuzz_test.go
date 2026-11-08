package vault

import (
	"testing"
)

// FuzzDecryptVault: arbitrary bytes and passwords never panic, and an error
// always means no entries were returned.
func FuzzDecryptVault(f *testing.F) {
	enc, _ := encryptVault(sampleEntries(), []byte("fuzz-password"), testParams)
	f.Add(enc, []byte("fuzz-password"))
	f.Add([]byte(magic+"\x02\x01"), []byte("x"))
	f.Add(make([]byte, 64), []byte(""))
	f.Fuzz(func(t *testing.T, data, password []byte) {
		if len(password) > 64 {
			password = password[:64]
		}
		entries, _, err := decryptVault(data, password)
		if err != nil && entries != nil {
			t.Fatal("entries returned with an error")
		}
	})
}
