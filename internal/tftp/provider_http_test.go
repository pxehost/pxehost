package tftp

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHTTPProviderPreservesBootfileDirectory(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/x86_64-efi/ipxe-legacy.efi" {
			t.Errorf("request path = %q", r.URL.Path)
		}
		_, _ = w.Write([]byte("iPXE"))
	}))
	t.Cleanup(server.Close)

	body, size, err := NewHTTPProvider(server.URL).GetBootfile("x86_64-efi-ipxe-legacy.efi")
	if err != nil {
		t.Fatalf("GetBootfile() error = %v", err)
	}
	t.Cleanup(func() { _ = body.Close() })

	got, err := io.ReadAll(body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(got) != "iPXE" || size != int64(len(got)) {
		t.Errorf("GetBootfile() = %q, %d; want %q, %d", got, size, "iPXE", len(got))
	}
}
