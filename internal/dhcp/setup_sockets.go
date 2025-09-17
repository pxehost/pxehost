//go:build !windows

package dhcp

import (
	"net"
	"syscall"
)

func setBroadcastSocketOption(conn *net.UDPConn) {
	if rc, err := conn.SyscallConn(); err == nil {
		_ = rc.Control(func(fd uintptr) {
			_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1)
		})
	}
}
