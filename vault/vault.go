package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"

	"github.com/SpikeTheDragon40k/sshman/model"
	"golang.org/x/crypto/argon2"
)

const (
	saltLen  = 16
	nonceLen = 12
	minLen   = saltLen + nonceLen
)

func deriveKey(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, 2, 64*1024, 4, 32)
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func encryptVault(entries []model.Entry, password string) ([]byte, error) {
	plaintext, err := json.Marshal(entries)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(plaintext)

	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	key := deriveKey(password, salt)
	defer zeroBytes(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	out := make([]byte, 0, saltLen+nonceLen+len(ciphertext))
	out = append(out, salt...)
	out = append(out, nonce...)
	out = append(out, ciphertext...)
	return out, nil
}

func decryptVault(data []byte, password string) ([]model.Entry, error) {
	if len(data) < minLen {
		return nil, errors.New("invalid vault file: too short")
	}
	salt := data[:saltLen]
	nonce := data[saltLen : saltLen+nonceLen]
	ciphertext := data[saltLen+nonceLen:]
	key := deriveKey(password, salt)
	defer zeroBytes(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.New("incorrect password or corrupted vault")
	}
	defer zeroBytes(plaintext)

	var entries []model.Entry
	if err := json.Unmarshal(plaintext, &entries); err != nil {
		return nil, err
	}
	return entries, nil
}

func Load(path, password string) ([]model.Entry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return decryptVault(data, password)
}

func Save(path, password string, entries []model.Entry) error {
	data, err := encryptVault(entries, password)
	if err != nil {
		return err
	}
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return err
	}
	f, err := os.OpenFile(tmpPath, os.O_RDONLY, 0600)
	if err != nil {
		os.Remove(tmpPath)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return err
	}
	f.Close()
	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return err
	}
	return nil
}
