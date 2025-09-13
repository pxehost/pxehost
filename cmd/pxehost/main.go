package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/shanebo/macos-pxe-boot/internal/dhcp"
	"github.com/shanebo/macos-pxe-boot/internal/netutil"
	"github.com/shanebo/macos-pxe-boot/internal/tftp"
)

func main() {
	log.SetFlags(0)

	// Require root to bind privileged UDP/67 and receive broadcast traffic
	if os.Geteuid() != 0 {
		fmt.Println("This program must be run as root to bind UDP/67 (DHCP).")
		fmt.Println("Re-run with: sudo ./macos-pxe-boot")
		os.Exit(1)
	}

	// Detect LAN IP (used to advertise TFTP server); continue regardless
	lanIP, iface := netutil.DetectLANIPv4()
	if lanIP != "" {
		if iface != "" {
			log.Printf("Detected LAN IP: %s (iface=%s)", lanIP, iface)
		} else {
			log.Printf("Detected LAN IP: %s", lanIP)
		}
	} else {
		log.Printf("No LAN IP detected; will advertise 127.0.0.1 for TFTP")
	}

	// Start internal TFTP proxy server (UDP/69) that fetches from netboot.xyz
	var tftps *tftp.Server
	{
		tftps = &tftp.Server{UpstreamBase: "https://boot.netboot.xyz/ipxe/"}
		if err := tftps.StartAsync(); err != nil {
			log.Printf("error: TFTP server not started: %v", err)
			os.Exit(1)
		}
	}

	// Start ProxyDHCP on UDP/67 and :4011 — selects bootfile by arch
	var proxy *dhcp.ProxyDHCP
	{
		advIP := lanIP
		if advIP == "" {
			advIP = "127.0.0.1"
		}
		proxy = &dhcp.ProxyDHCP{TFTPServerIP: advIP}
		if err := proxy.StartAsync(); err != nil {
			log.Printf("error: ProxyDHCP not started: %v", err)
			os.Exit(1)
		} else {
			log.Printf("Waiting for PXE clients on :67 and :4011 (tftp=%s)", advIP)
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
