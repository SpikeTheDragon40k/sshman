package keygen

import (
	"strings"
	"testing"
)

func TestGenerateRSA(t *testing.T) {
	kp, err := GenerateRSA(2048)
	if err != nil {
		t.Fatalf("GenerateRSA failed: %v", err)
	}
	if kp.PrivatePEM == "" {
		t.Fatal("expected non-empty private key PEM")
	}
	if kp.PublicKey == "" {
		t.Fatal("expected non-empty public key")
	}
	if !strings.HasPrefix(kp.PrivatePEM, "-----BEGIN RSA PRIVATE KEY-----") {
		t.Fatal("private key PEM has wrong header")
	}
	if !strings.HasPrefix(kp.PublicKey, "ssh-rsa ") {
		t.Fatal("public key should start with ssh-rsa")
	}
}

func TestGenerateRSARejectsSmallBits(t *testing.T) {
	_, err := GenerateRSA(1024)
	if err == nil {
		t.Fatal("expected error for 1024-bit key")
	}
}

func TestGenerateRSA4096(t *testing.T) {
	kp, err := GenerateRSA(4096)
	if err != nil {
		t.Fatalf("GenerateRSA 4096 failed: %v", err)
	}
	if kp.PrivatePEM == "" {
		t.Fatal("expected non-empty private key PEM")
	}
}

func TestGenerateEd25519(t *testing.T) {
	kp, err := GenerateEd25519()
	if err != nil {
		t.Fatalf("GenerateEd25519 failed: %v", err)
	}
	if kp.PrivatePEM == "" {
		t.Fatal("expected non-empty private key PEM")
	}
	if kp.PublicKey == "" {
		t.Fatal("expected non-empty public key")
	}
	if !strings.HasPrefix(kp.PrivatePEM, "-----BEGIN PRIVATE KEY-----") {
		t.Fatal("private key PEM has wrong header")
	}
	if !strings.HasPrefix(kp.PublicKey, "ssh-ed25519 ") {
		t.Fatal("public key should start with ssh-ed25519")
	}
}
