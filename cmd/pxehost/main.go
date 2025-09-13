package main

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/srcreigh/pxehost/internal/app"
	"github.com/srcreigh/pxehost/internal/logging"
	"github.com/srcreigh/pxehost/internal/tftp"
)

func main() {
	// Configure slog default with pretty colorized formatter and source trimming.
	slog.SetDefault(slog.New(logging.NewPrettyHandler(os.Stderr, &slog.HandlerOptions{AddSource: true})))
	// Discover LAN IP to advertise to PXE clients.
	lanIP := ""
	if ip, err := outboundIP(); err == nil {
		lanIP = ip.String()
	} else {
		slog.Error("Error detecting outbound IP", "err", err)
		os.Exit(1)
	}
	slog.Info("Detected outbound IP", "ip", lanIP)

	// Default bootfile provider: HTTP upstream
	provider := tftp.NewHTTPProvider("https://boot.netboot.xyz/ipxe/")

	cfg := app.NewConfig(
		app.WithDHCPPort(67),
		app.WithPXEPort(4011),
		app.WithTFTPPort(69),
		app.WithBootfileProvider(provider),
		app.WithAdvertisedIP(lanIP),
		app.WithGeteuid(os.Geteuid),
		app.WithLogger(slog.Default()),
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
