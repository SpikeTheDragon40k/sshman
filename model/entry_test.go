package model

import "testing"

func TestEntryAddr(t *testing.T) {
	e := Entry{User: "ubuntu", Host: "1.2.3.4"}
	if e.Addr() != "ubuntu@1.2.3.4" {
		t.Fatalf("expected ubuntu@1.2.3.4, got %s", e.Addr())
	}
}

func TestEntryAddrPort(t *testing.T) {
	t.Run("default port 22 omits flag", func(t *testing.T) {
		e := Entry{User: "ubuntu", Host: "1.2.3.4", Port: 22}
		if e.AddrPort() != "ubuntu@1.2.3.4" {
			t.Fatalf("expected ubuntu@1.2.3.4, got %s", e.AddrPort())
		}
	})
	t.Run("custom port includes -p", func(t *testing.T) {
		e := Entry{User: "ubuntu", Host: "1.2.3.4", Port: 2222}
		if e.AddrPort() != "ubuntu@1.2.3.4 -p 2222" {
			t.Fatalf("expected ubuntu@1.2.3.4 -p 2222, got %s", e.AddrPort())
		}
	})
	t.Run("port 0 treated as default", func(t *testing.T) {
		e := Entry{User: "ubuntu", Host: "1.2.3.4"}
		if e.AddrPort() != "ubuntu@1.2.3.4" {
			t.Fatalf("expected ubuntu@1.2.3.4, got %s", e.AddrPort())
		}
	})
}

func TestEntryMatches(t *testing.T) {
	e := Entry{Name: "myserver", User: "ubuntu", Host: "1.2.3.4"}
	if !e.Matches("myserver") {
		t.Fatal("expected match on name")
	}
	if !e.Matches("ubuntu") {
		t.Fatal("expected match on user")
	}
	if !e.Matches("1.2.3") {
		t.Fatal("expected partial match on host")
	}
	if e.Matches("nonexistent") {
		t.Fatal("expected no match")
	}
	if !e.Matches("MyServer") {
		t.Fatal("expected case-insensitive match")
	}
}

func TestFindByName(t *testing.T) {
	entries := []Entry{
		{Name: "alpha", User: "user1", Host: "10.0.0.1"},
		{Name: "beta", User: "user2", Host: "10.0.0.2"},
	}
	e := FindByName(entries, "beta")
	if e == nil {
		t.Fatal("expected to find beta")
	}
	if e.Host != "10.0.0.2" {
		t.Fatalf("expected 10.0.0.2, got %s", e.Host)
	}
	if FindByName(entries, "gamma") != nil {
		t.Fatal("expected nil for missing entry")
	}
}

func TestDeleteByName(t *testing.T) {
	entries := []Entry{
		{Name: "a"}, {Name: "b"}, {Name: "c"},
	}
	result, found := DeleteByName(entries, "b")
	if !found {
		t.Fatal("expected to find b")
	}
	if len(result) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(result))
	}
	if result[0].Name != "a" || result[1].Name != "c" {
		t.Fatal("unexpected entries after deletion")
	}
	_, found = DeleteByName(entries, "z")
	if found {
		t.Fatal("expected not found")
	}
}

func TestSearch(t *testing.T) {
	entries := []Entry{
		{Name: "web-prod", User: "deploy", Host: "10.0.0.1"},
		{Name: "db-prod", User: "admin", Host: "10.0.0.2"},
		{Name: "web-staging", User: "deploy", Host: "10.0.1.1"},
	}
	r := Search(entries, "prod")
	if len(r) != 2 {
		t.Fatalf("expected 2 prod results, got %d", len(r))
	}
	r = Search(entries, "deploy")
	if len(r) != 2 {
		t.Fatalf("expected 2 deploy results, got %d", len(r))
	}
	r = Search(entries, "10.0.0")
	if len(r) != 2 {
		t.Fatalf("expected 2 results for 10.0.0, got %d", len(r))
	}
	r = Search(entries, "nonexistent")
	if len(r) != 0 {
		t.Fatalf("expected 0 results, got %d", len(r))
	}
}
