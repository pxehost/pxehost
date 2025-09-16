package app

import (
	"fmt"

	"github.com/srcreigh/pxehost/internal/dhcp"
	"github.com/srcreigh/pxehost/internal/tftp"
)

// App wires together the components to run the PXE host.
// It is designed to be testable by allowing key OS calls to be overridden.
type App struct {
	cfg *Config

	// Runtime state
	tftps *tftp.Server
	proxy *dhcp.ProxyDHCP
}

// New constructs an App with sensible defaults.
func New(cfg *Config) *App {
	a := &App{
		cfg: cfg,
	}
	return a
}

// Start initializes and starts the TFTP proxy and ProxyDHCP services.
func (a *App) Start() error {
	if a == nil || a.cfg == nil {
		return fmt.Errorf("nil app or config")
	}
	if a.cfg.AdvertisedIP == nil {
		return fmt.Errorf("missing AdvertisedIP in config")
	}
	if a.cfg.Logger == nil {
		return fmt.Errorf("missing Logger in config")
	}
	if a.cfg.BootfileProvider == nil {
		return fmt.Errorf("missing BootfileProvider in config")
	}
	// Start TFTP proxy
	a.tftps = &tftp.Server{Provider: a.cfg.BootfileProvider, Port: a.cfg.TFTPPort, PacketLog: a.cfg.PacketLog, Logger: a.cfg.Logger}
	if err := a.tftps.StartAsync(); err != nil {
		return fmt.Errorf("tftp server start: %w", err)
	}

	// Start ProxyDHCP
	a.proxy = &dhcp.ProxyDHCP{
		TFTPServerIP:      a.cfg.AdvertisedIP,
		DHCPPort:          a.cfg.DHCPPort,
		PXEPort:           a.cfg.ProxyDHCPPort,
		PacketLog:         a.cfg.PacketLog,
		DHCPBroadcastPort: a.cfg.DHCPBroadcastPort,
		Logger:            a.cfg.Logger,
	}
	if err := a.proxy.StartAsync(); err != nil {
		_ = a.tftps.Close()
		return fmt.Errorf("proxydhcp start: %w", err)
	}
	a.cfg.Logger.Info("Waiting for PXE clients", "dhcp_port", a.cfg.DHCPPort, "pxe_port", a.cfg.ProxyDHCPPort, "tftp", a.cfg.AdvertisedIP)
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
