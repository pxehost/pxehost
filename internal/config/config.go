package config

// Config holds runtime configuration for the PXE host.
// It is constructed via functional options (WithX style).
type Config struct {
	DHCPPort      int // DHCP/ProxyDHCP listen port (typically 67)
	ProxyDHCPPort int // PXE service listen port (typically 4011)
	TFTPPort      int // TFTP listen port (typically 69)
}

// Option mutates a Config value.
type Option func(*Config)

// New constructs a Config from the provided options.
func New(opts ...Option) *Config {
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
