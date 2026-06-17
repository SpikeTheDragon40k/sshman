package model

import (
	"fmt"
	"strings"
)

type Entry struct {
	Name   string `json:"name"`
	User   string `json:"user"`
	Host   string `json:"host"`
	Port   int    `json:"port"`
	Key    string `json:"key"`
	PubKey string `json:"pubkey,omitempty"`
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

func (e *Entry) Matches(query string) bool {
	q := strings.ToLower(query)
	return strings.Contains(strings.ToLower(e.Name), q) ||
		strings.Contains(strings.ToLower(e.User), q) ||
		strings.Contains(strings.ToLower(e.Host), q)
}

func FindByName(entries []Entry, name string) *Entry {
	for i := range entries {
		if entries[i].Name == name {
			return &entries[i]
		}
	}
	return nil
}

func DeleteByName(entries []Entry, name string) ([]Entry, bool) {
	found := false
	var result []Entry
	for _, e := range entries {
		if e.Name == name {
			found = true
			continue
		}
		result = append(result, e)
	}
	return result, found
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
