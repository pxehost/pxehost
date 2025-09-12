package assets

import (
    "context"
    "crypto/sha256"
    "fmt"
    "io"
    "net/http"
    "os"
    "path/filepath"
    "time"
)

// Known netboot.xyz artifacts to fetch via HTTPS.
var defaultFiles = []string{
    "netboot.xyz.kpxe", // BIOS PXE chainloader (iPXE)
    "netboot.xyz.efi",  // UEFI iPXE binary
}

// baseURL hosts iPXE binaries.
const baseURL = "https://boot.netboot.xyz/ipxe/"

// EnsureNetbootAssets downloads the netboot.xyz iPXE binaries if missing or stale.
func EnsureNetbootAssets(ctx context.Context, dir string) error {
    client := &http.Client{Timeout: 30 * time.Second}
    for _, f := range defaultFiles {
        dst := filepath.Join(dir, f)
        // If file exists and is non-empty, skip.
        if fi, err := os.Stat(dst); err == nil && fi.Size() > 0 {
            continue
        }
        url := baseURL + f
        if err := download(ctx, client, url, dst); err != nil {
            return fmt.Errorf("download %s: %w", f, err)
        }
    }
    return nil
}

func download(ctx context.Context, client *http.Client, url, dst string) error {
    req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
    if err != nil {
        return err
    }
    resp, err := client.Do(req)
    if err != nil {
        return err
    }
    defer resp.Body.Close()
    if resp.StatusCode != http.StatusOK {
        return fmt.Errorf("unexpected status: %s", resp.Status)
    }
    // Stream to temp file then rename
    tmp := dst + ".tmp"
    f, err := os.Create(tmp)
    if err != nil {
        return err
    }
    h := sha256.New()
    if _, err := io.Copy(io.MultiWriter(f, h), resp.Body); err != nil {
        f.Close()
        os.Remove(tmp)
        return err
    }
    if err := f.Close(); err != nil {
        os.Remove(tmp)
        return err
    }
    if err := os.Chmod(tmp, 0o644); err != nil {
        os.Remove(tmp)
        return err
    }
    return os.Rename(tmp, dst)
}
