package tftp

import (
	"bytes"
	"fmt"
	"io"
	"sync"
	"time"
)

type cachedBootfileProvider struct {
	inner BootfileProvider
	mu    sync.RWMutex
	cache map[string]*cacheEntry
}

type cacheEntry struct {
	data []byte
	size int64
}

// Caches the results of the wrapped BootfileProvider.
//
// A BIOS rom, during a single boot, will usually start multiple TFTP sessions
// to negotiate options. This cache is meant to avoid re-downloading the file in
// that situation.
//
// For simplicity, it is a non-goal to avoid concurrent requests if 2 different
// machines open TFTP sessions at the same time.
func NewCachedBootfileProvider(inner BootfileProvider) BootfileProvider {
	p := &cachedBootfileProvider{
		inner: inner,
		cache: make(map[string]*cacheEntry),
	}
	// Clear the cache every 30 mins so that long-lived processes don't miss
	// updates.
	go func() {
		for {
			time.Sleep(30 * time.Minute)
			p.mu.Lock()
			p.cache = make(map[string]*cacheEntry)
			p.mu.Unlock()
		}
	}()
	return p
}

func (c *cachedBootfileProvider) GetBootfile(filename string) (io.ReadCloser, int64, error) {
	c.mu.RLock()
	if entry, ok := c.cache[filename]; ok {
		c.mu.RUnlock()
		return io.NopCloser(bytes.NewReader(entry.data)), entry.size, nil
	}
	c.mu.RUnlock()

	rc, _, err := c.inner.GetBootfile(filename)
	if err != nil {
		return nil, -1, fmt.Errorf("provider get bootfile %q: %w", filename, err)
	}
	defer func() {
		if cerr := rc.Close(); cerr != nil {
			_ = cerr
		}
	}()

	data, err := io.ReadAll(rc)
	if err != nil {
		return nil, -1, fmt.Errorf("read bootfile %q: %w", filename, err)
	}

	entry := &cacheEntry{data: data, size: int64(len(data))}
	c.mu.Lock()
	c.cache[filename] = entry
	c.mu.Unlock()

	return io.NopCloser(bytes.NewReader(entry.data)), entry.size, nil
}
