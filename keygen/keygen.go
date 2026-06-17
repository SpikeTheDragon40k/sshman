package keygen

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"golang.org/x/crypto/ssh"
)

type KeyPair struct {
	PrivatePEM string
	PublicKey  string // authorized_keys format
}

func GenerateRSA(bits int) (*KeyPair, error) {
	if bits < 2048 {
		return nil, errors.New("rsa key size must be at least 2048 bits")
	}
	privKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, fmt.Errorf("rsa generation failed: %w", err)
	}
	privDER := x509.MarshalPKCS1PrivateKey(privKey)
	privBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privDER,
	}
	privPEMBytes := pem.EncodeToMemory(privBlock)
	if privPEMBytes == nil {
		return nil, errors.New("failed to encode private key to PEM")
	}
	pub, err := ssh.NewPublicKey(&privKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create public key: %w", err)
	}
	pubAuthorized := string(ssh.MarshalAuthorizedKey(pub))
	return &KeyPair{
		PrivatePEM: string(privPEMBytes),
		PublicKey:  pubAuthorized,
	}, nil
}
