package app

// Config holds runtime configuration for the PXE host and its dependencies.
// Construct via functional options for testability.
type Config struct {
	DHCPPort         int        // DHCP/ProxyDHCP listen port (typically 67)
	ProxyDHCPPort    int        // PXE service listen port (typically 4011)
	TFTPPort         int        // TFTP listen port (typically 69)
	TFTPUpstreamBase string     // e.g. https://boot.netboot.xyz/ipxe/
	AdvertisedIP     string     // IPv4 advertised to clients (TFTP server IP)
	Geteuid          func() int // used for permission checks
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

// WithTFTPUpstreamBase sets the upstream base URL used by the TFTP proxy server.
func WithTFTPUpstreamBase(s string) Option { return func(c *Config) { c.TFTPUpstreamBase = s } }

// WithAdvertisedIP sets the IPv4 address advertised to clients (TFTP server IP).
func WithAdvertisedIP(ip string) Option { return func(c *Config) { c.AdvertisedIP = ip } }

// WithGeteuid sets the function used to get the effective user ID.
func WithGeteuid(geteuid func() int) Option { return func(c *Config) { c.Geteuid = geteuid } }
