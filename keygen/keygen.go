// Package keygen generates SSH key pairs in memory.
package keygen

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// AllowedRSABits are the RSA sizes genkey will create (Q-10). 2048-bit keys
// can still be imported, but new keys use at least 3072 bits (NIST SP 800-57
// guidance beyond 2030).
var AllowedRSABits = []int{3072, 4096}

// DefaultRSABits is used when no size is given.
const DefaultRSABits = 3072

// KeyPair holds a generated key. PrivatePEM is in OpenSSH format, so it can
// be used directly by ssh-keygen and OpenSSH as well as by sshman.
type KeyPair struct {
	PrivatePEM  string
	PublicKey   string // authorized_keys line including the comment, with trailing newline
	Fingerprint string
}

func finish(priv any, comment string) (*KeyPair, error) {
	blk, err := ssh.MarshalPrivateKey(priv, comment)
	if err != nil {
		return nil, fmt.Errorf("failed to encode private key: %w", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, fmt.Errorf("failed to create public key: %w", err)
	}
	pub := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	if comment != "" {
		pub += " " + comment
	}
	return &KeyPair{
		PrivatePEM:  string(pem.EncodeToMemory(blk)),
		PublicKey:   pub + "\n",
		Fingerprint: ssh.FingerprintSHA256(signer.PublicKey()),
	}, nil
}

// GenerateRSA creates an RSA key of one of the AllowedRSABits sizes.
func GenerateRSA(bits int, comment string) (*KeyPair, error) {
	ok := false
	for _, b := range AllowedRSABits {
		ok = ok || b == bits
	}
	if !ok {
		return nil, fmt.Errorf("unsupported RSA key size %d: use 3072 or 4096 (or prefer ed25519)", bits)
	}
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, fmt.Errorf("rsa generation failed: %w", err)
	}
	return finish(priv, comment)
}

// GenerateEd25519 creates an Ed25519 key (the recommended default).
func GenerateEd25519(comment string) (*KeyPair, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ed25519 generation failed: %w", err)
	}
	return finish(priv, comment)
}
