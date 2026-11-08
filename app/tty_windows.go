//go:build windows

package app

func ttyNames() (in, out string) { return "CONIN$", "CONOUT$" }
