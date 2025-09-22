# pxehost

> _Visit [pxehost.com](https://pxehost.com)!_

`pxehost` is a no-configuration, Go-stdlib-only, rootless PXE server.

It lets you boot a PC over LAN into the [netboot.xyz](https://github.com/netbootxyz/netboot.xyz)
menu.

**This is the easiest way to install Linux.**

- You don't need a USB drive.
- You don't need to figure out PXE boot.
- You don't need to install software to image a USB drive from Windows.
- `pxehost` has literally 0 configuration options - just run it and boot.

## How to use

To use `pxehost`, [download the binary for your platform from Releases](https://github.com/pxehost/pxehost/releases/tag/v0.1.0)
and then run it.

Since `pxehost` does not need root, it will refuse to run as root.

On Linux, `pxehost` needs the `CAP_NET_BIND_SERVICE` capability to bind
ports 67 and 69. You can run `pxehost` with that cap using `systemd-run`:

```bash
sudo systemd-run \
  --property User=$USER \
  --property AmbientCapabilities=CAP_NET_BIND_SERVICE \
  --pty \
  ./pxehost
```

On Windows, you may get a firewall prompt and need to allow pxehost to run.

On macOS (Mojave or newer) it will just work.

## How does it work?

PXE boot uses DHCP and TFTP protocols. Upon booting into PXE, a
computer sends UDP broadcasts on port 67 to get an IP address and
to find out which other computer on the network it can boot from.

`pxehost` is not a real DHCP server; it does not assign IP addresses.
Still, `pxehost` listens for those DHCP broadcasts and
sends a reply with DHCP options `TFTP Server Address` and `Bootfile Name`.

There are actually a few different types of boot files (eg `.kpxe`,
`.efi`). The PXE firmware's DHCP broadcast packets include some
DHCP options which tell pxehost what type of file to use.

The PXE firmware sees the DHCP options that `pxehost` sends, and uses
the TFTP protocol to get the boot file.

TFTP is a UDP-based file transfer protocol. `pxehost` downloads the
boot file from https://netboot.xyz and forwards the file via TFTP to
the boot loader.

The netboot.xyz boot file is a small iPXE blob. It supports HTTPS.
It loads another blob for the netboot.xyz menu.

The netboot.xyz menu has tons of Linux installers, Live CDs, and other
OS's. It downloads and runs the OS files automatically (`pxehost` is not
involved at that point anymore)
