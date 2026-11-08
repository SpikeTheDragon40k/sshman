package sshutil

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"golang.org/x/crypto/ssh"
)

// MaxKeyFileSize bounds key input read from files or stdin.
const MaxKeyFileSize = 64 << 10

// MinRSABits is the smallest RSA modulus accepted on import.
const MinRSABits = 2048

// KeyMaterial is a validated private key ready to be stored.
type KeyMaterial struct {
	// PrivatePEM is the canonical PEM encoding stored in the vault. Keys
	// that were passphrase-protected on input are stored decrypted (the
	// vault is the protection layer) in OpenSSH format.
	PrivatePEM string
	// AuthorizedKey is the public key in authorized_keys format, without a
	// trailing newline and without a comment.
	AuthorizedKey string
	Fingerprint   string
	Type          string
	// Decrypted reports whether a passphrase was needed.
	Decrypted bool
}

// ErrPassphraseRequired is returned when a protected key is supplied and no
// passphrase callback is available.
var ErrPassphraseRequired = errors.New("private key is passphrase protected")

// PassphraseFunc returns the passphrase for a protected key.
type PassphraseFunc func() ([]byte, error)

// ParsePrivateKey validates private key input (Q-06, S-14). It rejects
// non-key data, trailing data, DSA keys and RSA keys under 2048 bits. If the
// key is passphrase protected, passphrase is called to decrypt it.
func ParsePrivateKey(data []byte, passphrase PassphraseFunc) (*KeyMaterial, error) {
	if len(data) > MaxKeyFileSize {
		return nil, fmt.Errorf("key input larger than %d bytes", MaxKeyFileSize)
	}
	trimmed := bytes.TrimSpace(data)
	if !bytes.HasPrefix(trimmed, []byte("-----BEGIN ")) {
		return nil, errors.New("input is not a PEM-encoded private key (expected a file starting with -----BEGIN ...)")
	}
	block, rest := pem.Decode(trimmed)
	if block == nil {
		return nil, errors.New("could not decode PEM private key")
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("unexpected data after the private key; supply exactly one key")
	}
	canonical := pem.EncodeToMemory(block)

	raw, err := ssh.ParseRawPrivateKey(canonical)
	decrypted := false
	var missing *ssh.PassphraseMissingError
	if errors.As(err, &missing) {
		if passphrase == nil {
			return nil, ErrPassphraseRequired
		}
		pass, perr := passphrase()
		if perr != nil {
			return nil, perr
		}
		raw, err = ssh.ParseRawPrivateKeyWithPassphrase(canonical, pass)
		zero(pass)
		if errors.Is(err, x509.IncorrectPasswordError) {
			return nil, errors.New("incorrect passphrase for private key")
		}
		decrypted = true
	}
	if err != nil {
		return nil, fmt.Errorf("invalid private key: %w", err)
	}
	if err := checkKeyStrength(raw); err != nil {
		return nil, err
	}
	signer, err := ssh.NewSignerFromKey(raw)
	if err != nil {
		return nil, fmt.Errorf("unsupported private key: %w", err)
	}
	if decrypted {
		blk, err := ssh.MarshalPrivateKey(raw, "")
		if err != nil {
			return nil, fmt.Errorf("re-encoding decrypted key: %w", err)
		}
		canonical = pem.EncodeToMemory(blk)
	}
	pub := signer.PublicKey()
	return &KeyMaterial{
		PrivatePEM:    string(canonical),
		AuthorizedKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))),
		Fingerprint:   ssh.FingerprintSHA256(pub),
		Type:          pub.Type(),
		Decrypted:     decrypted,
	}, nil
}

func checkKeyStrength(raw any) error {
	switch k := raw.(type) {
	case *rsa.PrivateKey:
		if bits := k.N.BitLen(); bits < MinRSABits {
			return fmt.Errorf("RSA key of %d bits is too weak; at least %d bits are required", bits, MinRSABits)
		}
	case *ecdsa.PrivateKey, ed25519.PrivateKey, *ed25519.PrivateKey:
	default:
		// Includes DSA, which is insecure and removed from OpenSSH.
		return fmt.Errorf("unsupported private key type %T: use ed25519 (recommended), ecdsa or rsa", raw)
	}
	return nil
}

// ParseStoredKey parses a private key already stored in the vault.
func ParseStoredKey(pemData string) (any, ssh.Signer, error) {
	raw, err := ssh.ParseRawPrivateKey([]byte(pemData))
	if err != nil {
		var missing *ssh.PassphraseMissingError
		if errors.As(err, &missing) {
			return nil, nil, errors.New("stored private key is passphrase protected; re-import it with 'sshman update --name NAME --key FILE' to store it decrypted in the vault")
		}
		return nil, nil, fmt.Errorf("stored private key is invalid: %w", err)
	}
	signer, err := ssh.NewSignerFromKey(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("stored private key is unsupported: %w", err)
	}
	return raw, signer, nil
}

var commentSafeRe = regexp.MustCompile(`[^A-Za-z0-9@._+:= -]`)

// CanonicalAuthorizedKey parses one public key in authorized_keys format and
// returns "<type> <base64>[ <comment>]". Options (e.g. command="..."),
// additional keys and any trailing data are rejected (S-13). Unsafe comment
// characters are removed.
func CanonicalAuthorizedKey(line string) (string, ssh.PublicKey, error) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return "", nil, errors.New("public key is empty")
	}
	if strings.ContainsAny(trimmed, "\r\n") {
		return "", nil, errors.New("public key must be a single line")
	}
	pub, comment, options, rest, err := ssh.ParseAuthorizedKey([]byte(trimmed))
	if err != nil {
		return "", nil, fmt.Errorf("invalid public key: %w", err)
	}
	if len(options) != 0 {
		return "", nil, errors.New("public key must not carry authorized_keys options")
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return "", nil, errors.New("unexpected data after the public key")
	}
	out := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
	if c := strings.TrimSpace(commentSafeRe.ReplaceAllString(comment, "")); c != "" {
		out += " " + c
	}
	return out, pub, nil
}

// MatchPublicKey checks that an optional user-supplied public key belongs to
// the private key.
func MatchPublicKey(pubLine string, km *KeyMaterial) error {
	if strings.TrimSpace(pubLine) == "" {
		return nil
	}
	_, pub, err := CanonicalAuthorizedKey(pubLine)
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))) != km.AuthorizedKey {
		return errors.New("public key does not match the private key")
	}
	return nil
}

// EntryPublicKey returns the canonical public key line for an entry: the
// stored PubKey if it matches the private key, otherwise an error. If no
// PubKey is stored it is derived from the private key.
func EntryPublicKey(privPEM, pubLine string) (string, error) {
	var derived string
	if privPEM != "" {
		_, signer, err := ParseStoredKey(privPEM)
		if err != nil {
			return "", err
		}
		derived = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	}
	if strings.TrimSpace(pubLine) == "" {
		if derived == "" {
			return "", errors.New("entry has neither a public nor a private key")
		}
		return derived, nil
	}
	canon, pub, err := CanonicalAuthorizedKey(pubLine)
	if err != nil {
		return "", err
	}
	if derived != "" && strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))) != derived {
		return "", errors.New("stored public key does not match the stored private key")
	}
	return canon, nil
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// Fingerprint returns the OpenSSH SHA256 fingerprint of pub.
func Fingerprint(pub ssh.PublicKey) string { return ssh.FingerprintSHA256(pub) }
