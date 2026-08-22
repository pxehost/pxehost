package dhcp

import "testing"

// Cannot use a folder in the bootfile path, because for ex if we
// use x86_64-efi/efi-legacy.efi for the bootfile, then iPXE will
// try to load x86_64-efi/autoexec.ipxe next, instead of just
// autoexec.ipxe.
func TestBootfileForArchUsesFlatFilenames(t *testing.T) {
	for _, arch := range []uint16{0x0006, 0x0007, 0x0009, 0x000a, 0x000b, 0x0019, 0x001b, 0x0027} {
		if got := bootfileForArch(arch); got == "" || containsSlash(got) {
			t.Errorf("bootfileForArch(%#04x) = %q, want a flat filename", arch, got)
		}
	}
}

func containsSlash(name string) bool {
	for _, char := range name {
		if char == '/' || char == '\\' {
			return true
		}
	}
	return false
}
