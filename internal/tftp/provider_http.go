package tftp

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"path"
	"strings"
	"time"
)

// HTTPProvider fetches bootfiles from an HTTP(S) base URL.
type HTTPProvider struct {
	Base string // e.g. https://boot.netboot.xyz/ipxe/
}

// NewHTTPProvider constructs an HTTPProvider with the given base URL.
func NewHTTPProvider(base string) *HTTPProvider {
	if base != "" && !strings.HasSuffix(base, "/") {
		base += "/"
	}
	return &HTTPProvider{Base: base}
}

// GetBootfile fetches the given filename via HTTP.
func (p *HTTPProvider) GetBootfile(filename string) (io.ReadCloser, int64, error) {
	if p == nil || p.Base == "" {
		return nil, 0, fmt.Errorf("http provider: missing base URL")
	}
	name := path.Base(strings.TrimLeft(filename, "/\\"))
	url := p.Base + name

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		cancel()
		return nil, 0, fmt.Errorf("new request: %w", err)
	}
	client := http.DefaultClient
	resp, err := client.Do(req)
	if err != nil {
		cancel()
		return nil, 0, fmt.Errorf("http do: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		cancel()
		_ = resp.Body.Close()
		return nil, 0, fmt.Errorf("fetch %s: unexpected status: %s", url, resp.Status)
	}
	// Return a ReadCloser that cancels the context when closed
	return &cancelOnClose{ReadCloser: resp.Body, cancel: cancel}, resp.ContentLength, nil
}

type cancelOnClose struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (c *cancelOnClose) Close() error {
	if c.cancel != nil {
		c.cancel()
	}
	if err := c.ReadCloser.Close(); err != nil {
		return fmt.Errorf("http body close: %w", err)
	}
	return nil
}
