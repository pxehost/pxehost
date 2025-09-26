//go:build windows

package dhcp

import (
	"net"

	"golang.org/x/sys/windows"
)

func setBroadcastSocketOption(conn *net.UDPConn) {
	if rc, err := conn.SyscallConn(); err == nil {
		_ = rc.Control(func(fd uintptr) {
			_ = windows.SetsockoptInt(
				windows.Handle(fd),
				windows.SOL_SOCKET,
				windows.SO_BROADCAST,
				1,
			)
		})
	}
}
