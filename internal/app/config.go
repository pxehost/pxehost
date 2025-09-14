package app

import (
	"log/slog"
	"net"

	"github.com/srcreigh/pxehost/internal/capture"
	"github.com/srcreigh/pxehost/internal/tftp"
)

// Config holds runtime configuration for the PXE host and its dependencies.
// Construct via functional options for testability.
type Config struct {
	DHCPPort         int                   // DHCP/ProxyDHCP listen port (typically 67)
	ProxyDHCPPort    int                   // PXE service listen port (typically 4011)
	TFTPPort         int                   // TFTP listen port (typically 69)
	BootfileProvider tftp.BootfileProvider // supplies bootfiles for TFTP server
	AdvertisedIP     net.IP                // IPv4 advertised to clients (TFTP server IP)
	PacketLog        capture.PacketLogger  // optional: packet logger implementation
	Geteuid          func() int            // used for permission checks
	Logger           *slog.Logger          // required: application logger
	// DHCPBroadcastPort sets the UDP port used for DHCP broadcast replies.
	// Useful for tests where the client listens on a specific port.
	DHCPBroadcastPort int

	// Optional prebound sockets for privileged ports. When provided,
	// services will use these instead of binding themselves, allowing
	// the process to drop privileges after binding.
	PreboundDHCPConn *net.UDPConn // UDP/67
	PreboundTFTPConn *net.UDPConn // UDP/69
}

// Option mutates a Config value.
type Option func(*Config)

// NewConfig constructs a Config from the provided options.
func NewConfig(opts ...Option) *Config {
	c := &Config{}
	for _, opt := range opts {
		if opt != nil {
			opt(c)
		}
	}
	return c
}

// WithDHCPPort sets the DHCP listen port.
func WithDHCPPort(p int) Option { return func(c *Config) { c.DHCPPort = p } }

// WithPXEPort sets the PXE service (ProxyDHCP) listen port.
func WithPXEPort(p int) Option { return func(c *Config) { c.ProxyDHCPPort = p } }

// WithTFTPPort sets the TFTP listen port.
func WithTFTPPort(p int) Option { return func(c *Config) { c.TFTPPort = p } }

// WithBootfileProvider sets the provider used by the TFTP server to fetch files.
func WithBootfileProvider(p tftp.BootfileProvider) Option {
	return func(c *Config) { c.BootfileProvider = p }
}

// WithAdvertisedIP sets the IPv4 address advertised to clients (TFTP server IP).
func WithAdvertisedIP(ip net.IP) Option { return func(c *Config) { c.AdvertisedIP = ip } }

// WithGeteuid sets the function used to get the effective user ID.
func WithGeteuid(geteuid func() int) Option { return func(c *Config) { c.Geteuid = geteuid } }

// WithPacketLogger sets the UDP packet logger implementation (may be nil to disable).
func WithPacketLogger(l capture.PacketLogger) Option { return func(c *Config) { c.PacketLog = l } }

// WithLogger sets the application slog logger (must be non-nil).
func WithLogger(l *slog.Logger) Option { return func(c *Config) { c.Logger = l } }

// WithDHCPBroadcastPort sets the UDP port used for DHCP broadcast replies.
func WithDHCPBroadcastPort(p int) Option { return func(c *Config) { c.DHCPBroadcastPort = p } }

// WithPreboundDHCPConn injects a prebound UDP socket for DHCP (port 67).
func WithPreboundDHCPConn(conn *net.UDPConn) Option {
	return func(c *Config) { c.PreboundDHCPConn = conn }
}

// WithPreboundTFTPConn injects a prebound UDP socket for TFTP (port 69).
func WithPreboundTFTPConn(conn *net.UDPConn) Option {
	return func(c *Config) { c.PreboundTFTPConn = conn }
}
