package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/shanebo/macos-pxe-boot/internal/config"
	"github.com/shanebo/macos-pxe-boot/internal/dhcp"
	"github.com/shanebo/macos-pxe-boot/internal/tftp"
)

func main() {
	log.SetFlags(0)

	cfg := config.New(
		config.WithDHCPPort(67),
		config.WithPXEPort(4011),
		config.WithTFTPPort(69),
	)

	// Require root to bind privileged UDP/67 and receive broadcast traffic
	if os.Geteuid() != 0 {
		fmt.Println("This program must be run as root to bind UDP/67 (DHCP).")
		fmt.Println("Re-run with: sudo ./macos-pxe-boot")
		os.Exit(1)
	}

	// Discover our outbound IPv4 (used to advertise TFTP server)
	var lanIP string
	if ip, err := outboundIP(); err == nil && ip != nil {
		lanIP = ip.String()
		log.Printf("Detected outbound IP: %s", lanIP)
	} else {
		log.Printf("No outbound IP detected")
		os.Exit(1)
	}

	// Start internal TFTP proxy server that fetches bootfiles from netboot.xyz
	var tftps *tftp.Server
	{
		tftps = &tftp.Server{UpstreamBase: "https://boot.netboot.xyz/ipxe/", Port: cfg.TFTPPort}
		if err := tftps.StartAsync(); err != nil {
			log.Printf("error: TFTP server not started: %v", err)
			os.Exit(1)
		}
	}

	// Start ProxyDHCP — listens for PXE clients and responds with TFTP server and bootfile
	var proxy *dhcp.ProxyDHCP
	{
		proxy = &dhcp.ProxyDHCP{TFTPServerIP: lanIP, DHCPPort: cfg.DHCPPort, PXEPort: cfg.ProxyDHCPPort}
		if err := proxy.StartAsync(); err != nil {
			log.Printf("error: ProxyDHCP not started: %v", err)
			os.Exit(1)
		} else {
			log.Printf("Waiting for PXE clients on :%d and :%d (tftp=%s)", cfg.DHCPPort, cfg.ProxyDHCPPort, lanIP)
		}
	}

	// Handle shutdown
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)
	<-sigc
	log.Printf("shutting down...")
	_ = proxy.Close()
	_ = tftps.Close()
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
