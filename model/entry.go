// Package model defines vault entries and pure helpers over them.
package model

import (
	"fmt"
	"slices"
	"strings"
	"time"
)

// Entry is one SSH connection profile. Key holds the private key PEM; it is
// only ever stored inside the encrypted vault.
type Entry struct {
	Name   string `json:"name"`
	User   string `json:"user"`
	Host   string `json:"host"`
	Port   int    `json:"port"`
	Key    string `json:"key"`
	PubKey string `json:"pubkey,omitempty"`

	// Fields added in vault format v2. Older vaults simply omit them.
	Tags      []string  `json:"tags,omitempty"`
	Favorite  bool      `json:"favorite,omitempty"`
	Notes     string    `json:"notes,omitempty"`
	CreatedAt time.Time `json:"created_at,omitzero"`
	UpdatedAt time.Time `json:"updated_at,omitzero"`
	// KeyCreatedAt records when the key material was generated or imported,
	// for rotation reminders.
	KeyCreatedAt time.Time `json:"key_created_at,omitzero"`
}

func (e *Entry) Addr() string {
	return fmt.Sprintf("%s@%s", e.User, e.Host)
}

func (e *Entry) AddrPort() string {
	if e.Port > 0 && e.Port != 22 {
		return fmt.Sprintf("%s@%s -p %d", e.User, e.Host, e.Port)
	}
	return e.Addr()
}

// HasTag reports whether the entry carries tag (case-insensitive).
func (e *Entry) HasTag(tag string) bool {
	return slices.ContainsFunc(e.Tags, func(t string) bool { return strings.EqualFold(t, tag) })
}

func (e *Entry) Matches(query string) bool {
	q := strings.ToLower(query)
	if strings.Contains(strings.ToLower(e.Name), q) ||
		strings.Contains(strings.ToLower(e.User), q) ||
		strings.Contains(strings.ToLower(e.Host), q) {
		return true
	}
	for _, t := range e.Tags {
		if strings.Contains(strings.ToLower(t), q) {
			return true
		}
	}
	return false
}

// IndexByName returns the index of the first entry named name, or -1.
func IndexByName(entries []Entry, name string) int {
	return slices.IndexFunc(entries, func(e Entry) bool { return e.Name == name })
}

// FindByName returns the first entry named name.
func FindByName(entries []Entry, name string) *Entry {
	if i := IndexByName(entries, name); i >= 0 {
		return &entries[i]
	}
	return nil
}

// CountByName returns how many entries are named name. Vaults written by
// older versions may contain duplicates.
func CountByName(entries []Entry, name string) int {
	n := 0
	for _, e := range entries {
		if e.Name == name {
			n++
		}
	}
	return n
}

// DeleteByName removes the first entry named name only (Q-05: never more
// than one entry per delete).
func DeleteByName(entries []Entry, name string) ([]Entry, bool) {
	i := IndexByName(entries, name)
	if i < 0 {
		return entries, false
	}
	return slices.Delete(slices.Clone(entries), i, i+1), true
}

func Search(entries []Entry, query string) []Entry {
	var result []Entry
	for _, e := range entries {
		if e.Matches(query) {
			result = append(result, e)
		}
	}
	return result
}
