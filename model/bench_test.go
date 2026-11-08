package model

import (
	"fmt"
	"testing"
)

func BenchmarkSearch5000(b *testing.B) {
	es := make([]Entry, 5000)
	for i := range es {
		es[i] = Entry{Name: fmt.Sprintf("web-%d", i), User: "deploy", Host: fmt.Sprintf("h%d.example.com", i), Tags: []string{"prod"}}
	}
	for b.Loop() {
		_ = Search(es, "h4999")
	}
}
