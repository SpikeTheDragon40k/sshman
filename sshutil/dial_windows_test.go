//go:build windows

package sshutil

import (
	"net"
	"os"
	"strings"

	"golang.org/x/sys/windows"
)

// dialAgent opens the named pipe from its ssh_config option value.
func dialAgent(opt string) (net.Conn, error) {
	name := strings.ReplaceAll(strings.Trim(opt, `"`), "/", `\`)
	p, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		return nil, err
	}
	return &pipeConn{f: os.NewFile(uintptr(h), name), h: h}, nil
}
