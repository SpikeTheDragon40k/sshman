package vault

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/sshman-org/sshman/model"
	"golang.org/x/crypto/argon2"
)

// Vault file formats.
//
// Legacy (v1, written by sshman <= 0.x):
//
//	salt(16) || nonce(12) || AES-256-GCM(JSON array of entries)
//
// Argon2id parameters were fixed at t=2, m=64 MiB, p=4 and nothing in the
// file was authenticated except the ciphertext.
//
// Current (v2):
//
//	magic "SSHMAN" (6) || version (1) = 2 || kdf (1) = 1 (argon2id)
//	|| time (4, BE) || memory KiB (4, BE) || threads (1) || saltLen (1)
//	|| salt || nonce (12) || AES-256-GCM(JSON object, AAD = all preceding bytes)
//
// Every header byte is passed to GCM as additional data, so changing the
// version, KDF parameters, salt or nonce makes decryption fail.

const (
	magic          = "SSHMAN"
	formatV2       = 2
	kdfArgon2id    = 1
	nonceLen       = 12
	saltLen        = 16
	keyLen         = 32
	legacySaltLen  = 16
	legacyMinLen   = legacySaltLen + nonceLen
	v2FixedHdrLen  = len(magic) + 1 + 1 + 4 + 4 + 1 + 1
	gcmTagLen      = 16
	maxVaultSize   = 64 << 20 // refuse to read anything larger
	minSaltLen     = 16
	maxSaltLen     = 64
	minTime        = 1
	maxTime        = 16
	minMemoryKiB   = 8 * 1024
	maxMemoryKiB   = 1024 * 1024 // 1 GiB
	minThreads     = 1
	maxThreads     = 64
	legacyVersion  = 1
	currentVersion = formatV2
)

// Params are the Argon2id cost parameters used to derive the vault key.
type Params struct {
	Time      uint32 // iterations
	MemoryKiB uint32 // memory in KiB
	Threads   uint8  // parallelism
}

// RecommendedParams follows RFC 9106 §4, second recommended option
// (t=3, m=64 MiB), with p=4.
var RecommendedParams = Params{Time: 3, MemoryKiB: 64 * 1024, Threads: 4}

// DefaultParams are used for every new write. Only tests change it.
var DefaultParams = RecommendedParams

// legacyParams are the parameters hard-coded in the v1 format.
var legacyParams = Params{Time: 2, MemoryKiB: 64 * 1024, Threads: 4}

// Validate reports whether p is within the accepted bounds. The bounds stop a
// crafted header from forcing an enormous allocation or run time.
func (p Params) Validate() error {
	if p.Time < minTime || p.Time > maxTime {
		return fmt.Errorf("argon2id time %d out of range [%d,%d]", p.Time, minTime, maxTime)
	}
	if p.MemoryKiB < minMemoryKiB || p.MemoryKiB > maxMemoryKiB {
		return fmt.Errorf("argon2id memory %d KiB out of range [%d,%d]", p.MemoryKiB, minMemoryKiB, maxMemoryKiB)
	}
	if p.Threads < minThreads || p.Threads > maxThreads {
		return fmt.Errorf("argon2id threads %d out of range [%d,%d]", p.Threads, minThreads, maxThreads)
	}
	return nil
}

// Info describes a decrypted vault's on-disk format.
type Info struct {
	Version int
	Params  Params
}

// Outdated reports whether the vault should be re-encrypted with the current
// format and default parameters.
func (i Info) Outdated() bool {
	return i.Version != currentVersion || i.Params != DefaultParams
}

var (
	// ErrAuth is returned when the password is wrong or the ciphertext or
	// authenticated header was modified. The two cases are deliberately
	// indistinguishable.
	ErrAuth = errors.New("incorrect password or corrupted vault")
	// ErrFormat is returned when the file is not a vault sshman can read.
	ErrFormat = errors.New("not a valid sshman vault")
)

// payload is the plaintext JSON document of a v2 vault.
type payload struct {
	Entries []model.Entry `json:"entries"`
}

func deriveKey(password, salt []byte, p Params) []byte {
	return argon2.IDKey(password, salt, p.Time, p.MemoryKiB, p.Threads, keyLen)
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// encryptVault serialises entries into the current (v2) format.
func encryptVault(entries []model.Entry, password []byte, p Params) ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if entries == nil {
		entries = []model.Entry{}
	}
	plaintext, err := json.Marshal(payload{Entries: entries})
	if err != nil {
		return nil, err
	}
	defer zeroBytes(plaintext)

	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	hdr := make([]byte, 0, v2FixedHdrLen+saltLen+nonceLen)
	hdr = append(hdr, magic...)
	hdr = append(hdr, formatV2, kdfArgon2id)
	hdr = binary.BigEndian.AppendUint32(hdr, p.Time)
	hdr = binary.BigEndian.AppendUint32(hdr, p.MemoryKiB)
	hdr = append(hdr, p.Threads, byte(len(salt)))
	hdr = append(hdr, salt...)
	hdr = append(hdr, nonce...)

	key := deriveKey(password, salt, p)
	defer zeroBytes(key)
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(hdr), len(hdr)+len(plaintext)+gcm.Overhead())
	copy(out, hdr)
	return gcm.Seal(out, nonce, plaintext, hdr), nil
}

type parsedHeader struct {
	info       Info
	salt       []byte
	nonce      []byte
	aad        []byte
	ciphertext []byte
}

func parseV2(data []byte) (*parsedHeader, error) {
	if len(data) < v2FixedHdrLen {
		return nil, fmt.Errorf("%w: truncated header", ErrFormat)
	}
	off := len(magic)
	version := data[off]
	kdf := data[off+1]
	off += 2
	if version != formatV2 {
		return nil, fmt.Errorf("%w: unsupported vault version %d (this sshman reads up to %d)", ErrFormat, version, currentVersion)
	}
	if kdf != kdfArgon2id {
		return nil, fmt.Errorf("%w: unsupported key derivation function %d", ErrFormat, kdf)
	}
	p := Params{
		Time:      binary.BigEndian.Uint32(data[off:]),
		MemoryKiB: binary.BigEndian.Uint32(data[off+4:]),
		Threads:   data[off+8],
	}
	sl := int(data[off+9])
	off += 10
	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFormat, err)
	}
	if sl < minSaltLen || sl > maxSaltLen {
		return nil, fmt.Errorf("%w: salt length %d out of range", ErrFormat, sl)
	}
	if len(data) < off+sl+nonceLen+gcmTagLen {
		return nil, fmt.Errorf("%w: truncated", ErrFormat)
	}
	salt := data[off : off+sl]
	nonce := data[off+sl : off+sl+nonceLen]
	hdrEnd := off + sl + nonceLen
	return &parsedHeader{
		info:       Info{Version: formatV2, Params: p},
		salt:       salt,
		nonce:      nonce,
		aad:        data[:hdrEnd],
		ciphertext: data[hdrEnd:],
	}, nil
}

// decryptVault decrypts either format. It never returns partially decoded
// entries: any error means nothing was recovered.
func decryptVault(data []byte, password []byte) ([]model.Entry, Info, error) {
	if len(data) > maxVaultSize {
		return nil, Info{}, fmt.Errorf("%w: file larger than %d bytes", ErrFormat, maxVaultSize)
	}
	if bytes.HasPrefix(data, []byte(magic)) {
		h, err := parseV2(data)
		if err != nil {
			return nil, Info{}, err
		}
		plaintext, err := open(password, h.salt, h.nonce, h.ciphertext, h.aad, h.info.Params)
		if err != nil {
			return nil, Info{}, err
		}
		defer zeroBytes(plaintext)
		var pl payload
		if err := json.Unmarshal(plaintext, &pl); err != nil {
			return nil, Info{}, fmt.Errorf("%w: decrypted payload is not valid JSON", ErrFormat)
		}
		if pl.Entries == nil {
			pl.Entries = []model.Entry{}
		}
		return pl.Entries, h.info, nil
	}

	// Legacy v1. A random legacy salt starts with "SSHMAN" with probability
	// 2^-48, which is negligible.
	if len(data) < legacyMinLen+gcmTagLen {
		return nil, Info{}, fmt.Errorf("%w: too short", ErrFormat)
	}
	salt := data[:legacySaltLen]
	nonce := data[legacySaltLen:legacyMinLen]
	plaintext, err := open(password, salt, nonce, data[legacyMinLen:], nil, legacyParams)
	if err != nil {
		return nil, Info{}, err
	}
	defer zeroBytes(plaintext)
	var entries []model.Entry
	if err := json.Unmarshal(plaintext, &entries); err != nil {
		return nil, Info{}, fmt.Errorf("%w: decrypted payload is not valid JSON", ErrFormat)
	}
	if entries == nil {
		entries = []model.Entry{}
	}
	return entries, Info{Version: legacyVersion, Params: legacyParams}, nil
}

func open(password, salt, nonce, ciphertext, aad []byte, p Params) ([]byte, error) {
	key := deriveKey(password, salt, p)
	defer zeroBytes(key)
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, ErrAuth
	}
	return plaintext, nil
}
