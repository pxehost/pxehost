package main

import (
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/pxehost/pxehost/internal/app"
	"github.com/pxehost/pxehost/internal/dhcp"
	"github.com/pxehost/pxehost/internal/logging"
	"github.com/pxehost/pxehost/internal/tftp"
)

func main() {
	if os.Geteuid() == 0 {
		fmt.Println("Running as root is not supported, exiting.")
		os.Exit(1)
	}

	// Configure slog default with pretty colorized formatter and source trimming.
	slog.SetDefault(slog.New(logging.NewPrettyHandler(os.Stderr, &slog.HandlerOptions{AddSource: true})))

	// Log the user and effective UID we're running as.
	slog.Info("Running as non-root.", "user", os.Getenv("USER"), "euid", os.Geteuid())

	// Discover LAN IP to advertise to PXE clients.
	lanIP, err := dhcp.OutboundIP()
	if err != nil {
		slog.Error("Error detecting outbound IP", "err", err)
		os.Exit(1)
	}
	slog.Info("Detected outbound IP.", "ip", lanIP.String())

	cfg := app.NewConfig(
		app.WithDHCPPort(67),
		app.WithDHCPBroadcastPort(68),
		app.WithPXEPort(4011),
		app.WithTFTPPort(69),
		app.WithBootfileProvider(
			tftp.NewCachedBootfileProvider(
				tftp.NewHTTPProvider("https://boot.netboot.xyz/ipxe/"),
			),
		),
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
	fmt.Println()
	slog.Info("shutting down...")
	a.Stop()
}
