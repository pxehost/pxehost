package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/shanebo/macos-pxe-boot/internal/assets"
	"github.com/shanebo/macos-pxe-boot/internal/dhcp"
	"github.com/shanebo/macos-pxe-boot/internal/netutil"
	"github.com/shanebo/macos-pxe-boot/internal/setup"
)

func main() {
	log.SetFlags(0)
	dataDir := "/private/tftpboot"

	// Require root to bind privileged UDP/67 and receive broadcast traffic
	if os.Geteuid() != 0 {
		fmt.Println("This program must be run as root to bind UDP/67 (DHCP).")
		fmt.Println("Re-run with: sudo ./macos-pxe-boot")
		os.Exit(1)
	}

	// Detect LAN and router IPs
	lanIP, iface := netutil.DetectLANIPv4()
	routerIP := netutil.DetectDefaultGateway()

	// Checklist and gating before starting ProxyDHCP
	allOK := true
	printHeader("Startup Checklist")

	okLAN := lanIP != "" && iface != ""
	printCheck(okLAN, fmt.Sprintf("LAN address: %s (iface: %s)", emptyDash(lanIP), emptyDash(iface)))
	if !okLAN {
		allOK = false
	}

	okRouter := routerIP != ""
	printCheck(okRouter, fmt.Sprintf("Router detected: %s", emptyDash(routerIP)))

	// tftpd readiness
	readiness := setup.CheckTFTPD(dataDir)
	okTFTPD := readiness.Ready
	printCheck(okTFTPD, "tftpd ready and /private/tftpboot usable")

	fmt.Println()
	if !okLAN || !okTFTPD {
		allOK = false
	}

	if !allOK {
		fmt.Println()
		fmt.Println("Remediation:")
		if !okLAN {
			fmt.Println()
			fmt.Println("Ensure your Mac is connected to a LAN with IPv4 and try again.")
		}
		if !okTFTPD {
			setup.PrintTFTPDRemediation(readiness)
		}
		os.Exit(1)
	}

	// Download assets into tftpd root when possible
	if readiness.DirExists && readiness.DirWritable {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		if err := assets.EnsureNetbootAssets(ctx, dataDir); err != nil {
			log.Printf("warning: failed to download netboot.xyz assets to %s: %v", dataDir, err)
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
