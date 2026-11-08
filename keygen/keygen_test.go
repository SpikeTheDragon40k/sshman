package keygen

import (
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func checkPair(t *testing.T, kp *KeyPair, typ string) {
	t.Helper()
	if !strings.HasPrefix(kp.PrivatePEM, "-----BEGIN OPENSSH PRIVATE KEY-----") {
		t.Fatalf("private key should be OpenSSH PEM: %.40q", kp.PrivatePEM)
	}
	if !strings.HasPrefix(kp.PublicKey, typ+" ") || !strings.HasSuffix(kp.PublicKey, " c1\n") {
		t.Fatalf("public key %q", kp.PublicKey)
	}
	signer, err := ssh.ParsePrivateKey([]byte(kp.PrivatePEM))
	if err != nil {
		t.Fatal(err)
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(kp.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	if string(pub.Marshal()) != string(signer.PublicKey().Marshal()) {
		t.Fatal("public key does not match private key")
	}
	if kp.Fingerprint != ssh.FingerprintSHA256(pub) {
		t.Fatal("fingerprint mismatch")
	}
}

func TestGenerateEd25519(t *testing.T) {
	kp, err := GenerateEd25519("c1")
	if err != nil {
		t.Fatal(err)
	}
	checkPair(t, kp, "ssh-ed25519")
}

func TestGenerateRSA(t *testing.T) {
	if testing.Short() {
		t.Skip("slow")
	}
	kp, err := GenerateRSA(DefaultRSABits, "c1")
	if err != nil {
		t.Fatal(err)
	}
	checkPair(t, kp, "ssh-rsa")
}

// Q-10: only 3072 and 4096 are generated; huge sizes are refused up front.
func TestGenerateRSARejectsOtherSizes(t *testing.T) {
	for _, bits := range []int{0, 1024, 2048, 3000, 8192, 65536} {
		if _, err := GenerateRSA(bits, ""); err == nil {
			t.Errorf("%d bits accepted", bits)
		}
	}
}
