//go:build windows

package sshutil

import (
	"net"
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
	h, err := windows.CreateFile(p, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OVERLAPPED, 0)
	if err != nil {
		return nil, err
	}
	return newPipeConn(h)
}
