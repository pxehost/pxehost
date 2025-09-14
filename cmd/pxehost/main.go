package main

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"syscall"

	"github.com/srcreigh/pxehost/internal/app"
	"github.com/srcreigh/pxehost/internal/logging"
	"github.com/srcreigh/pxehost/internal/tftp"
)

func main() {
	// Bind privileged ports and drop priviledges.
	dhcpConn, tftpConn, err := bindPriviledgedPorts()
	if err != nil {
		slog.Error("failed to bind privileged ports", "err", err)
		os.Exit(1)
	}
	fmt.Println("Bound ports 67 (DHCP) and 69 (TFTP) with root privileges")

	// Drop privileges after binding privileged ports.
	if err := dropPrivileges(); err != nil {
		_ = dhcpConn.Close()
		_ = tftpConn.Close()
		slog.Error("failed to drop privileges", "err", err)
		os.Exit(1)
	}

	slog.SetDefault(slog.New(logging.NewPrettyHandler(os.Stderr, &slog.HandlerOptions{AddSource: true})))
	slog.Info("Dropped root privileges", "uid", os.Getuid(), "euid", os.Geteuid(), "gid", os.Getgid(), "egid", os.Getegid())

	// Configure slog default with pretty colorized formatter and source trimming.
	slog.SetDefault(slog.New(logging.NewPrettyHandler(os.Stderr, &slog.HandlerOptions{AddSource: true})))

	// Discover LAN IP to advertise to PXE clients.
	ip, err := outboundIP()
	if err != nil {
		slog.Error("Error detecting outbound IP", "err", err)
		os.Exit(1)
	}
	lanIP := ip
	slog.Info("Detected outbound IP", "ip", lanIP.String())

	cfg := app.NewConfig(
		app.WithDHCPPort(67),
		app.WithDHCPBroadcastPort(68),
		app.WithPXEPort(4011),
		app.WithTFTPPort(69),
		app.WithBootfileProvider(tftp.NewHTTPProvider("https://boot.netboot.xyz/ipxe/")),
		app.WithAdvertisedIP(lanIP),
		app.WithGeteuid(os.Geteuid),
		app.WithLogger(slog.Default()),
		app.WithPreboundDHCPConn(dhcpConn),
		app.WithPreboundTFTPConn(tftpConn),
	)

	a := app.New(cfg)
	if err := a.Start(); err != nil {
		slog.Error("failed to start services", "err", err)
		os.Exit(1)
	}

	// Handle shutdown
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)
	<-sigc
	slog.Info("shutting down...")
	a.Stop()
}

func bindPriviledgedPorts() (dhcpConn, tftpConn *net.UDPConn, err error) {
	// Bind privileged UDP ports (67 DHCP, 69 TFTP) early while privileged.
	// Use IPv4-only sockets.
	addr67, err := net.ResolveUDPAddr("udp4", ":67")
	if err != nil {
		slog.Error("resolve UDP 67 failed", "err", err)
		os.Exit(1)
	}
	dhcpConn, err = net.ListenUDP("udp4", addr67)
	if err != nil {
		slog.Error("bind UDP 67 failed", "err", err)
		os.Exit(1)
	}
	addr69, err := net.ResolveUDPAddr("udp4", ":69")
	if err != nil {
		_ = dhcpConn.Close()
		slog.Error("resolve UDP 69 failed", "err", err)
		os.Exit(1)
	}
	tftpConn, err = net.ListenUDP("udp4", addr69)
	if err != nil {
		_ = dhcpConn.Close()
		slog.Error("bind UDP 69 failed", "err", err)
		os.Exit(1)
	}
	return
}

// outboundIP discovers the preferred outbound IPv4 address by opening
// a UDP "connection" to a public IP. No packets are sent; the kernel
// selects a route and binds a local address which we return.
func outboundIP() (net.IP, error) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return nil, fmt.Errorf("outboundIP dial: %w", err)
	}
	defer func() {
		_ = conn.Close()
	}()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP, nil
}

// --- privilege dropping helpers ---

func mustAtoi(s string) int {
	i, err := strconv.Atoi(s)
	if err != nil {
		panic(err)
	}
	return i
}

func lookupUIDGID() (uid, gid int, home string) {
	// Prefer sudo-provided identity
	if su := os.Getenv("SUDO_UID"); su != "" {
		uid = mustAtoi(su)
		gid = mustAtoi(os.Getenv("SUDO_GID"))
		if name := os.Getenv("SUDO_USER"); name != "" {
			if u, err := user.Lookup(name); err == nil {
				home = u.HomeDir
			}
		}
		return
	}

	panic("could not find target user to drop privileges to")
}

func dropPrivileges() error {
	uid, gid, home := lookupUIDGID()

	// Order matters: clear supplementary groups, set GID, then UID.
	if err := syscall.Setgroups([]int{}); err != nil {
		return fmt.Errorf("setgroups: %w", err)
	}
	if err := syscall.Setgid(gid); err != nil {
		return fmt.Errorf("setgid: %w", err)
	}
	if err := syscall.Setuid(uid); err != nil {
		return fmt.Errorf("setuid: %w", err)
	}

	// Optional: update environment to match the target user
	if home != "" {
		_ = os.Setenv("HOME", home)
		_ = os.Chdir(home)
	}
	_ = os.Setenv("USER", os.Getenv("SUDO_USER"))

	return nil
}
