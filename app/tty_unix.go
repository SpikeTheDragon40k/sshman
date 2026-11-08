//go:build !windows

package app

func ttyNames() (in, out string) { return "/dev/tty", "/dev/tty" }
