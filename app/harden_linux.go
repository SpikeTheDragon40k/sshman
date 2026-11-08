//go:build linux

package app

import "golang.org/x/sys/unix"

// HardenProcess disables core dumps and, on Linux, marks the process
// non-dumpable, which also stops other processes of the same user from
// attaching with ptrace or reading /proc/<pid>/mem (S-11). Best effort.
func HardenProcess() {
	_ = unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0})
	_ = unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)
}
