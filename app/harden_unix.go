//go:build unix && !linux

package app

import "golang.org/x/sys/unix"

// HardenProcess disables core dumps (S-11). Best effort.
func HardenProcess() {
	_ = unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0})
}
