//go:build unix

package sshutil

import "net"

func dialAgent(sock string) (net.Conn, error) { return net.Dial("unix", sock) }
