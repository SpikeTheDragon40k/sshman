package sshutil

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"unicode"

	"github.com/sshman-org/sshman/model"
)

const (
	maxNameLen = 128
	maxUserLen = 64
	maxHostLen = 255
)

// A user must not start with '-' (it would be parsed as an ssh option, S-06)
// or '.'.
var validUserRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]*$`)

var hostLabelRe = regexp.MustCompile(`^[A-Za-z0-9_]([A-Za-z0-9_-]*[A-Za-z0-9_])?$`)

var zoneRe = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

// ValidateName checks an entry name.
func ValidateName(name string) error {
	if name == "" {
		return errors.New("name is required")
	}
	if len(name) > maxNameLen {
		return fmt.Errorf("name is longer than %d bytes", maxNameLen)
	}
	if strings.TrimSpace(name) != name {
		return errors.New("name must not start or end with whitespace")
	}
	if strings.HasPrefix(name, "-") {
		return errors.New("name must not start with '-'")
	}
	for _, r := range name {
		if unicode.IsControl(r) || r == unicode.ReplacementChar {
			return errors.New("name must not contain control or invalid characters")
		}
	}
	return nil
}

// ValidateUser checks a remote login name.
func ValidateUser(user string) error {
	if user == "" {
		return errors.New("user is required")
	}
	if len(user) > maxUserLen {
		return fmt.Errorf("user is longer than %d characters", maxUserLen)
	}
	if !validUserRe.MatchString(user) {
		return fmt.Errorf("invalid user %q: use letters, digits, '.', '_' or '-', not starting with '-' or '.'", user)
	}
	return nil
}

// ValidateHost accepts a DNS name (or ssh_config alias of the same shape),
// an IPv4 address, or an IPv6 address optionally in brackets and with a
// zone. Anything starting with '-' is rejected (S-06).
func ValidateHost(host string) error {
	if host == "" {
		return errors.New("host is required")
	}
	if len(host) > maxHostLen {
		return fmt.Errorf("host is longer than %d characters", maxHostLen)
	}
	if strings.HasPrefix(host, "-") {
		return fmt.Errorf("invalid host %q: must not start with '-'", host)
	}
	h := host
	bracketed := strings.HasPrefix(h, "[") && strings.HasSuffix(h, "]")
	if bracketed {
		h = h[1 : len(h)-1]
	}
	if bracketed || strings.Contains(h, ":") {
		addr, zone, _ := strings.Cut(h, "%")
		ip := net.ParseIP(addr)
		if ip == nil || ip.To4() != nil && !strings.Contains(addr, ":") {
			return fmt.Errorf("invalid host %q: not an IPv6 address", host)
		}
		if strings.Contains(h, "%") && !zoneRe.MatchString(zone) {
			return fmt.Errorf("invalid host %q: bad IPv6 zone", host)
		}
		return nil
	}
	if net.ParseIP(h) != nil {
		return nil
	}
	name := strings.TrimSuffix(h, ".")
	if name == "" {
		return fmt.Errorf("invalid host %q", host)
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) > 63 || !hostLabelRe.MatchString(label) {
			return fmt.Errorf("invalid host %q: each dot-separated label must be 1-63 letters, digits, '-' or '_' and not start or end with '-'", host)
		}
	}
	return nil
}

// ValidatePort accepts 0 (meaning the ssh default) and 1-65535.
func ValidatePort(port int) error {
	if port < 0 || port > 65535 {
		return fmt.Errorf("invalid port %d: must be 1-65535 (or 0 for the default)", port)
	}
	return nil
}

// ValidateEntry checks the connection fields of an entry. Key material is
// validated separately when it is imported (see ParsePrivateKey).
func ValidateEntry(e *model.Entry) error {
	if err := ValidateName(e.Name); err != nil {
		return err
	}
	if err := ValidateUser(e.User); err != nil {
		return err
	}
	if err := ValidateHost(e.Host); err != nil {
		return err
	}
	return ValidatePort(e.Port)
}
