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

	// Detect LAN IP and interface
	lanIP, iface := netutil.DetectLANIPv4()

	// Checklist and gating before starting ProxyDHCP
	allOK := true
	printHeader("Startup Checklist")

	okLAN := lanIP != "" && iface != ""
	printCheck(okLAN, fmt.Sprintf("LAN address: %s (iface: %s)", emptyDash(lanIP), emptyDash(iface)))
	if !okLAN {
		allOK = false
	}

	fmt.Println()

	if !allOK {
		fmt.Println()
		fmt.Println("Remediation:")
		if !okLAN {
			fmt.Println()
			fmt.Println("Ensure your Mac is connected to a LAN with IPv4 and try again.")
		}
		os.Exit(1)
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
			log.Printf("All checks passed. Waiting for PXE clients on :67 and :4011 (tftp=%s)", advIP)
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

func printHeader(title string) {
	fmt.Println(title)
	fmt.Println("-----------------")
}

func printCheck(ok bool, line string) {
	if ok {
		fmt.Printf("%s %s\n", green("✓"), line)
	} else {
		fmt.Printf("%s %s\n", red("✗"), line)
	}
}

func green(s string) string { return "\x1b[32m" + s + "\x1b[0m" }
func red(s string) string   { return "\x1b[31m" + s + "\x1b[0m" }

func emptyDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
