package tftp

import "testing"

func TestAutoexecIPXE(t *testing.T) {
	const menu = "chain https://boot.netboot.xyz/menu.ipxe\n"

	if got, want := string(autoexecIPXE(false)), "#!ipxe\ndhcp\nset netX/dns6:hex 00\n"+menu; got != want {
		t.Errorf("default autoexec script = %q, want %q", got, want)
	}
	if got, want := string(autoexecIPXE(true)), "#!ipxe\ndhcp\n"+menu; got != want {
		t.Errorf("IPv6 DNS enabled autoexec script = %q, want %q", got, want)
	}
}
