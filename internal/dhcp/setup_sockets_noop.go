//go:build windows

package dhcp

import "net"

func setBroadcastSocketOption(conn *net.UDPConn) {
	// noop
}
