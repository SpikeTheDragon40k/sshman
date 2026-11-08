package app

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf8"

	"golang.org/x/term"
)

// Prompter reads secrets and confirmations from the user.
type Prompter interface {
	// Password prompts without echo. The caller zeroes the result.
	Password(prompt string) ([]byte, error)
	// Confirm asks a yes/no question; the default is no.
	Confirm(prompt string) (bool, error)
}

// ErrNoTerminal is returned when a secret is needed but there is no
// terminal to read it from. sshman never reads passwords from flags or
// environment variables.
var ErrNoTerminal = errors.New("a terminal is required to enter the password (sshman does not read passwords from arguments, environment variables or pipes)")

// maxSecretLen bounds a typed password or passphrase.
const maxSecretLen = 1024

// TTYPrompter reads from the controlling terminal, not stdin, so that key
// material can be piped on stdin ("--key -") while the password is typed.
type TTYPrompter struct{}

func (TTYPrompter) Password(prompt string) ([]byte, error) {
	in, out, closeFn, err := openTTY()
	if err != nil {
		return nil, ErrNoTerminal
	}
	defer closeFn()
	fmt.Fprint(out, prompt)
	b, err := term.ReadPassword(int(in.Fd()))
	fmt.Fprintln(out)
	if err != nil {
		return nil, err
	}
	if len(b) > maxSecretLen {
		zero(b)
		return nil, fmt.Errorf("input longer than %d bytes", maxSecretLen)
	}
	return b, nil
}

func (TTYPrompter) Confirm(prompt string) (bool, error) {
	in, out, closeFn, err := openTTY()
	if err != nil {
		return false, errors.New("confirmation needs a terminal; pass --yes to skip it")
	}
	defer closeFn()
	fmt.Fprint(out, prompt+" [y/N] ")
	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return false, err
	}
	a := strings.ToLower(strings.TrimSpace(line))
	return a == "y" || a == "yes", nil
}

func openTTY() (in *os.File, out *os.File, closeFn func(), err error) {
	inName, outName := ttyNames()
	in, err = os.OpenFile(inName, os.O_RDWR, 0)
	if err != nil {
		return nil, nil, nil, err
	}
	if !term.IsTerminal(int(in.Fd())) {
		in.Close()
		return nil, nil, nil, ErrNoTerminal
	}
	if outName == inName {
		return in, in, func() { in.Close() }, nil
	}
	out, err = os.OpenFile(outName, os.O_RDWR, 0)
	if err != nil {
		in.Close()
		return nil, nil, nil, err
	}
	return in, out, func() { in.Close(); out.Close() }, nil
}

// MinPasswordLen is the minimum length, in characters, of a new vault
// password (S-04).
const MinPasswordLen = 12

// CheckPasswordPolicy validates a new or changed vault password. Whitespace
// is preserved exactly as typed; it counts towards the length but a password
// made only of whitespace is rejected.
func CheckPasswordPolicy(pw []byte) error {
	if len(strings.TrimSpace(string(pw))) == 0 {
		return errors.New("password must not be empty or whitespace only")
	}
	if !utf8.Valid(pw) {
		return errors.New("password is not valid UTF-8")
	}
	if n := utf8.RuneCount(pw); n < MinPasswordLen {
		return fmt.Errorf("password must be at least %d characters (got %d); a passphrase of several words is easiest to remember", MinPasswordLen, n)
	}
	if len(pw) > maxSecretLen {
		return fmt.Errorf("password longer than %d bytes", maxSecretLen)
	}
	return nil
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
