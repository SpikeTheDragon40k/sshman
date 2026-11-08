package sshutil

import (
	"fmt"
	"os"
	"runtime"
	"testing"
	"time"
)

// watchdog fails fast with every goroutine's stack if a test hangs, instead
// of waiting for the global test timeout (expensive on CI runners).
func watchdog(t *testing.T, d time.Duration) func() {
	t.Helper()
	done := make(chan struct{})
	go func() {
		select {
		case <-done:
		case <-time.After(d):
			buf := make([]byte, 1<<20)
			n := runtime.Stack(buf, true)
			fmt.Fprintf(os.Stderr, "WATCHDOG: %s hung for %v\n%s\n", t.Name(), d, buf[:n])
			os.Exit(2)
		}
	}()
	return func() { close(done) }
}
