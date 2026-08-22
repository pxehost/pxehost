package dhcp

func bootfileForArch(arch uint16) string {
	// arch is DHCP option 93

	// EFI images are intentionally using the legacy variant because
	// non-legacy breaks USB keyboards.
	switch arch {
	case 0x0006:
		return "i386-efi-ipxe-legacy.efi"
	case 0x0007, 0x0009:
		return "x86_64-efi-ipxe-legacy.efi"
	case 0x000a:
		return "arm32-efi-ipxe-legacy.efi"
	case 0x000b:
		return "arm64-efi-ipxe-legacy.efi"
	case 0x0019:
		return "riscv32-efi-ipxe-legacy.efi"
	case 0x001b:
		return "riscv64-efi-ipxe-legacy.efi"
	case 0x0027:
		return "loong64-efi-ipxe-legacy.efi"
	default:
		return "undionly.kpxe"
	}
}
