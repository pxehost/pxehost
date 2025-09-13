package app

import (
	"fmt"
	"log"
	"os"

	"github.com/srcreigh/pxehost/internal/dhcp"
	"github.com/srcreigh/pxehost/internal/tftp"
)

// App wires together the components to run the PXE host.
// It is designed to be testable by allowing key OS calls to be overridden.
type App struct {
	cfg *Config

	// Dependencies that can be overridden in tests.
	EUID func() int // defaults to os.Geteuid

	// Runtime state
	tftps *tftp.Server
	proxy *dhcp.ProxyDHCP
}

// New constructs an App with sensible defaults.
func New(cfg *Config) *App {
	a := &App{
		cfg:  cfg,
		EUID: os.Geteuid,
	}
	return a
}

// CheckPrivileges ensures the process has sufficient privileges to bind
// privileged ports like UDP/67 used by DHCP/ProxyDHCP.
func (a *App) CheckPrivileges() error {
	if a == nil || a.EUID == nil {
		return fmt.Errorf("nil app or EUID dependency")
	}
	if a.EUID() != 0 {
		return fmt.Errorf("must run as root to bind UDP/67 (DHCP)")
	}
	return nil
}

// Start initializes and starts the TFTP proxy and ProxyDHCP services.
func (a *App) Start() error {
	if a == nil || a.cfg == nil {
		return fmt.Errorf("nil app or config")
	}
	if err := a.CheckPrivileges(); err != nil {
		return err
	}
	if a.cfg.AdvertisedIP == "" {
		return fmt.Errorf("missing AdvertisedIP in config")
	}
	if a.cfg.TFTPUpstreamBase == "" {
		return fmt.Errorf("missing TFTPUpstreamBase in config")
	}

	// Start TFTP proxy
	a.tftps = &tftp.Server{UpstreamBase: a.cfg.TFTPUpstreamBase, Port: a.cfg.TFTPPort, PacketLog: a.cfg.PacketLog}
	if err := a.tftps.StartAsync(); err != nil {
		return fmt.Errorf("tftp server start: %w", err)
	}

	// Start ProxyDHCP
	a.proxy = &dhcp.ProxyDHCP{TFTPServerIP: a.cfg.AdvertisedIP, DHCPPort: a.cfg.DHCPPort, PXEPort: a.cfg.ProxyDHCPPort, PacketLog: a.cfg.PacketLog}
	if err := a.proxy.StartAsync(); err != nil {
		_ = a.tftps.Close()
		return fmt.Errorf("proxydhcp start: %w", err)
	}
	log.Printf("Waiting for PXE clients on :%d and :%d (tftp=%s)", a.cfg.DHCPPort, a.cfg.ProxyDHCPPort, a.cfg.AdvertisedIP)
	return nil
}

// Stop gracefully shuts down services.
func (a *App) Stop() {
	if a == nil {
		return
	}
	if a.proxy != nil {
		_ = a.proxy.Close()
	}
	if a.tftps != nil {
		_ = a.tftps.Close()
	}
}
