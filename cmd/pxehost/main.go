package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/srcreigh/pxehost/internal/app"
)

func main() {
	// Discover LAN IP to advertise to PXE clients.
	lanIP := ""
	if ip, err := outboundIP(); err == nil {
		lanIP = ip.String()
	} else {
		log.Printf("Error detecting outbound IP: %v", err)
		os.Exit(1)
	}
	log.Printf("Detected outbound IP: %s", lanIP)

	cfg := app.NewConfig(
		app.WithDHCPPort(67),
		app.WithPXEPort(4011),
		app.WithTFTPPort(69),
		app.WithTFTPUpstreamBase("https://boot.netboot.xyz/ipxe/"),
		app.WithAdvertisedIP(lanIP),
		app.WithGeteuid(os.Geteuid),
	)

	a := app.New(cfg)
	if err := a.Start(); err != nil {
		log.Printf("failed to start services: %v", err)
		os.Exit(1)
	}

	// Handle shutdown
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)
	<-sigc
	log.Printf("shutting down...")
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
