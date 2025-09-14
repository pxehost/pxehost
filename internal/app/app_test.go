package app

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/srcreigh/pxehost/internal/dhcp"
)

// mappedProvider implements tftp.BootfileProvider by mapping
// requested filenames to in-memory random bytes.
type mappedProvider struct {
	files map[string][]byte // requested name -> bytes
}

// AddRandom generates cryptographically random bytes of the given length,
// stores them under the provided filename, and returns a copy for verification.
func (p *mappedProvider) AddRandom(filename string, n int) ([]byte, error) {
	if p.files == nil {
		p.files = make(map[string][]byte)
	}
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	// Store a copy to avoid external mutation.
	p.files[filename] = append([]byte(nil), b...)
	return b, nil
}

func (p *mappedProvider) GetBootfile(filename string) (io.ReadCloser, int64, error) {
	b, ok := p.files[filename]
	if !ok {
		return nil, 0, fmt.Errorf("file not found: %s", filename)
	}
	return io.NopCloser(bytes.NewReader(b)), int64(len(b)), nil
}

// TestReplayAndTFTP starts the app, replays DHCP/PXE packets from capture,
// and performs a manual TFTP transfer (two RRQs with ACKs) verifying bytes.
func TestReplayAndTFTP(t *testing.T) {
	// Bootfile used for TFTP manual transfer: random bytes of a given length.
	const reqName = "netboot.xyz.kpxe"
	const randomLen = 4097 // spans multiple 512B blocks to exercise TFTP
	provider := &mappedProvider{}
	want, err := provider.AddRandom(reqName, randomLen)
	if err != nil {
		t.Fatalf("generate random bootfile bytes: %v", err)
	}

	// Client UDP for DHCP/PXE so broadcasts reply to known port.
	dhcpPXEConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatalf("listen udp client for dhcp+pxe: %v", err)
	}
	t.Cleanup(func() { _ = dhcpPXEConn.Close() })
	bp := 0
	if la, ok := dhcpPXEConn.LocalAddr().(*net.UDPAddr); ok && la != nil {
		bp = la.Port
	}

	// Start server with ephemeral ports
	cfg := NewConfig(
		WithDHCPPort(0),
		WithDHCPBroadcastPort(bp),
		WithPXEPort(0),
		WithTFTPPort(0),
		WithAdvertisedIP(net.ParseIP("192.168.0.31")),
		WithBootfileProvider(provider),
		WithLogger(slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{}))),
	)
	a := New(cfg)
	a.EUID = func() int { return 0 }
	if err := a.Start(); err != nil {
		t.Fatalf("start app: %v", err)
	}
	t.Cleanup(func() { a.Stop() })

	// Wait for bound ports
	var tftpPort, dhcpPort, pxePort int
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if a.tftps != nil {
			tftpPort = a.tftps.BoundPort()
		}
		if a.proxy != nil {
			dhcpPort = a.proxy.BoundDHCPPort()
			pxePort = a.proxy.BoundPXEPort()
		}
		if tftpPort > 0 && dhcpPort > 0 && pxePort > 0 {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if tftpPort == 0 || dhcpPort == 0 || pxePort == 0 {
		t.Fatalf("server ports not bound tftp=%d dhcp=%d pxe=%d", tftpPort, dhcpPort, pxePort)
	}

	// Use a single UDP conn for send/receive.
	c := dhcpPXEConn
	dhcpRaddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: dhcpPort}
	pxeRaddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: pxePort}

	// DHCP Discover exchange
	pkt := dhcp.NewPacket(1, 0x4e0e64de, net.HardwareAddr{0x18, 0xc0, 0x4d, 0x0e, 0x64, 0xde})
	pkt.Secs = 4
	pkt.Flags = 0x8000
	pkt.WithMsgType(dhcp.DHCPDiscover)
	pkt.WithParamRequestList(0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x0b, 0x0c, 0x0d, 0x0f, 0x10, 0x11, 0x12, 0x16, 0x17, 0x1c, 0x28, 0x29, 0x2a, 0x2b, 0x32, 0x33, 0x36, 0x3a, 0x3b, 0x3c, 0x42, 0x43, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87)
	pkt.WithMaxMessageSize(1260)
	pkt.WithClientMachineID([]byte{0x00, 0x18, 0x02, 0xc0, 0x03, 0x4d, 0x04, 0x0e, 0x05, 0x64, 0x06, 0xde, 0x07, 0x00, 0x08, 0x00, 0x09})
	pkt.WithArch(0)
	pkt.WithNIC([]byte{0x01, 0x02, 0x01})
	pkt.WithVendorClassIdent("PXEClient:Arch:00000:UNDI:002001")

	reply := SendPacketAndRead(t, c, dhcpRaddr, pkt)
	assertPXEReplyLike(t, reply, dhcp.DHCPOffer, "netboot.xyz.kpxe")

	// DHCP Request exchange
	pkt = dhcp.NewPacket(1, 0x4e0e64de, net.HardwareAddr{0x18, 0xc0, 0x4d, 0x0e, 0x64, 0xde})
	pkt.Secs = 4
	pkt.Flags = 0x8000
	pkt.WithMsgType(3)
	pkt.WithRequestedIP(net.IPv4(192, 168, 0, 34))
	pkt.WithParamRequestList(0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x0b, 0x0c, 0x0d, 0x0f, 0x10, 0x11, 0x12, 0x16, 0x17, 0x1c, 0x28, 0x29, 0x2a, 0x2b, 0x32, 0x33, 0x36, 0x3a, 0x3b, 0x3c, 0x42, 0x43, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87)
	pkt.WithMaxMessageSize(1260)
	pkt.WithServerID(net.IPv4(192, 168, 0, 1))
	pkt.WithClientMachineID([]byte{0x00, 0x18, 0x02, 0xc0, 0x03, 0x4d, 0x04, 0x0e, 0x05, 0x64, 0x06, 0xde, 0x07, 0x00, 0x08, 0x00, 0x09})
	pkt.WithArch(0)
	pkt.WithNIC([]byte{0x01, 0x02, 0x01})
	pkt.WithVendorClassIdent("PXEClient:Arch:00000:UNDI:002001")

	reply = SendPacketAndRead(t, c, dhcpRaddr, pkt)
	assertPXEReplyLike(t, reply, dhcp.DHCPAck, "netboot.xyz.kpxe")

	// 2nd DHCP Request exchange on PXE port
	pkt = dhcp.NewPacket(1, 0x4e0e64de, net.HardwareAddr{0x18, 0xc0, 0x4d, 0x0e, 0x64, 0xde})
	pkt.Secs = 4
	pkt.Ciaddr = net.IPv4(192, 168, 0, 34)
	pkt.WithMsgType(3)
	pkt.WithParamRequestList(0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x0b, 0x0c, 0x0d, 0x0f, 0x10, 0x11, 0x12, 0x16, 0x17, 0x1c, 0x28, 0x29, 0x2a, 0x2b, 0x32, 0x33, 0x36, 0x3a, 0x3b, 0x3c, 0x42, 0x43, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87)
	pkt.WithMaxMessageSize(1260)
	pkt.WithClientMachineID([]byte{0x00, 0x18, 0x02, 0xc0, 0x03, 0x4d, 0x04, 0x0e, 0x05, 0x64, 0x06, 0xde, 0x07, 0x00, 0x08, 0x00, 0x09})
	pkt.WithArch(0)
	pkt.WithNIC([]byte{0x01, 0x02, 0x01})
	pkt.WithVendorClassIdent("PXEClient:Arch:00000:UNDI:002001")

	reply = SendPacketAndRead(t, c, pxeRaddr, pkt)
	assertPXEReplyLike(t, reply, dhcp.DHCPAck, "netboot.xyz.kpxe")

	// Manual TFTP transfer
	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatalf("tftp client listen: %v", err)
	}
	defer client.Close()
	serverLaddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: tftpPort}

	buildRRQ := func(filename string, opts [][2]string) []byte {
		b := []byte{0x00, 0x01}
		b = append(b, []byte(filename)...)
		b = append(b, 0x00)
		b = append(b, []byte("octet")...)
		b = append(b, 0x00)
		for _, kv := range opts {
			k, v := kv[0], kv[1]
			b = append(b, []byte(k)...)
			b = append(b, 0x00)
			b = append(b, []byte(v)...)
			b = append(b, 0x00)
		}
		return b
	}

	// First RRQ: tsize=0 (probe)
	rrq1 := buildRRQ(reqName, [][2]string{{"tsize", "0"}})
	_ = client.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := client.WriteToUDP(rrq1, serverLaddr); err != nil {
		t.Fatalf("send rrq1: %v", err)
	}
	// Read OACK from session port, do not ACK(0)
	_ = client.SetReadDeadline(time.Now().Add(1 * time.Second))
	var sess1 *net.UDPAddr
	{
		buf := make([]byte, 2048)
		n, raddr, err := client.ReadFromUDP(buf)
		if err != nil {
			t.Fatalf("read oack1: %v", err)
		}
		if n < 2 || buf[0] != 0 || buf[1] != 6 {
			t.Fatalf("expected OACK for rrq1, got op=%d", int(buf[1]))
		}
		sess1 = raddr
		_ = sess1
	}

	// Second RRQ: tsize=0, blksize=1456 (server will OACK blksize=512)
	rrq2 := buildRRQ(reqName, [][2]string{{"tsize", "0"}, {"blksize", "1456"}})
	_ = client.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := client.WriteToUDP(rrq2, serverLaddr); err != nil {
		t.Fatalf("send rrq2: %v", err)
	}
	// Expect OACK from a (new) session
	var sess2 *net.UDPAddr
	for {
		_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 4096)
		n, raddr, err := client.ReadFromUDP(buf)
		if err != nil {
			t.Fatalf("waiting for oack2: %v", err)
		}
		if n >= 2 && buf[0] == 0x00 && buf[1] == 0x06 { // OACK
			if sess1 == nil || raddr.Port != sess1.Port || !raddr.IP.Equal(sess1.IP) {
				sess2 = raddr
				break
			}
			continue // ignore OACK from first session
		}
		// ignore non-OACK
	}
	// Optionally ACK(0)
	ack := func(block uint16) []byte { return []byte{0x00, 0x04, byte(block >> 8), byte(block)} }
	_ = client.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
	_, _ = client.WriteToUDP(ack(0), sess2)

	// Receive data from sess2 only
	var got []byte
	expectedBlock := uint16(1)
	const serverBlockSize = 512
	for {
		_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
		buf := make([]byte, 4096)
		n, raddr, err := client.ReadFromUDP(buf)
		if err != nil {
			t.Fatalf("read data: %v", err)
		}
		if raddr == nil || !raddr.IP.Equal(sess2.IP) || raddr.Port != sess2.Port {
			continue
		}
		if n < 4 {
			continue
		}
		op := uint16(buf[0])<<8 | uint16(buf[1])
		if op != 3 { // only care about DATA
			continue
		}
		blk := uint16(buf[2])<<8 | uint16(buf[3])
		data := append([]byte(nil), buf[4:n]...)
		if blk < expectedBlock {
			_ = client.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
			_, _ = client.WriteToUDP(ack(blk), sess2)
			continue
		}
		if blk > expectedBlock {
			continue
		}
		got = append(got, data...)
		_ = client.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
		_, _ = client.WriteToUDP(ack(blk), sess2)
		if len(data) < serverBlockSize {
			break
		}
		expectedBlock++
		if expectedBlock == 0 {
			expectedBlock = 1
		}
	}

	if !bytes.Equal(got, want) {
		t.Fatalf("tftp payload mismatch: got=%d want=%d", len(got), len(want))
	}

	pkt = dhcp.NewPacket(1, 0xd9cc631d, net.HardwareAddr{0x18, 0xc0, 0x4d, 0x0e, 0x64, 0xde})
	pkt.Secs = 8
	pkt.Flags = 0x8000
	pkt.WithMsgType(1)
	pkt.WithMaxMessageSize(1472)
	pkt.WithArch(0)
	pkt.WithNIC([]byte{0x01, 0x02, 0x01})
	pkt.WithVendorClassIdent("PXEClient:Arch:00000:UNDI:002001")
	pkt.WithUserClass("iPXE")
	pkt.WithParamRequestList(0x01, 0x03, 0x06, 0x07, 0x0c, 0x0f, 0x11, 0x1a, 0x2a, 0x2b, 0x3c, 0x42, 0x43, 0x77, 0x79, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0xaf, 0xcb)
	pkt.AddOption(175, []byte{0xb1, 0x05, 0x01, 0x10, 0xec, 0x81, 0x68, 0xeb, 0x03, 0x01, 0x15, 0x01, 0x17, 0x01, 0x01, 0x27, 0x01, 0x01, 0x22, 0x01, 0x01, 0x13, 0x01, 0x01, 0x14, 0x01, 0x01, 0x11, 0x01, 0x01, 0x19, 0x01, 0x01, 0x29, 0x01, 0x01, 0x10, 0x01, 0x02, 0x21, 0x01, 0x01, 0x15, 0x01, 0x01, 0x18, 0x01, 0x01, 0x23, 0x01, 0x01, 0x1b, 0x01, 0x01, 0x26, 0x01, 0x01, 0x12, 0x01, 0x01})
	pkt.WithClientID(1, net.HardwareAddr{0x18, 0xc0, 0x4d, 0x0e, 0x64, 0xde})
	pkt.WithClientMachineID([]byte{0x00, 0x18, 0x02, 0xc0, 0x03, 0x4d, 0x04, 0x0e, 0x05, 0x64, 0x06, 0xde, 0x07, 0x00, 0x08, 0x00, 0x09})

	reply = SendPacketAndRead(t, c, dhcpRaddr, pkt)
	assertPXEReplyLike(t, reply, dhcp.DHCPOffer, "https://boot.netboot.xyz/menu.ipxe")
}

func SendPacketAndRead(t testing.TB, c *net.UDPConn, raddr *net.UDPAddr, pkt *dhcp.Packet) *dhcp.Packet {
	t.Helper()

	// Serialize
	payload, err := pkt.Serialize()
	if err != nil {
		t.Fatalf("serialize payload: %v", err)
	}

	// Send
	if err := c.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set write deadline: %v", err)
	}
	if _, err := c.WriteToUDP(payload, raddr); err != nil {
		t.Fatalf("send error: %v", err)
	}

	// Read
	if err := c.SetReadDeadline(time.Now().Add(150 * time.Millisecond)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	buf := make([]byte, 8192)
	n, _, err := c.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}

	// Parse
	reply, err := dhcp.Parse(buf[:n])
	if err != nil {
		t.Fatalf("parse reply: %v", err)
	}
	return reply
}

func assertPXEReplyLike(t *testing.T, p *dhcp.Packet, wantMsgType byte, wantBootfile string) {
	t.Helper()

	if p.Op != 2 {
		t.Fatalf("Op=%d, want 2 (reply)", p.Op)
	}

	wantSrv := net.IPv4(192, 168, 0, 31)
	if !p.Siaddr.Equal(wantSrv) {
		t.Fatalf("Siaddr=%v, want %v", p.Siaddr, wantSrv)
	}

	if got := optByte(t, p, dhcp.OptMsgType); got != wantMsgType {
		t.Fatalf("MsgType=%d, want %d", got, wantMsgType)
	}
	if got := optIP(t, p, dhcp.OptServerID); !got.Equal(wantSrv) {
		t.Fatalf("ServerID=%v, want %v", got, wantSrv)
	}
	if got := optString(t, p, dhcp.OptVendorClassIdent); got != "PXEClient" {
		t.Fatalf("VendorClass=%q, want %q", got, "PXEClient")
	}
	if got := optString(t, p, dhcp.OptTFTPServer); got != "192.168.0.31" {
		t.Fatalf("TFTP (66)=%q, want %q", got, "192.168.0.31")
	}
	if got := optString(t, p, dhcp.OptBootfile); got != wantBootfile {
		t.Fatalf("Bootfile (67)=%q, want %q", got, wantBootfile)
	}
}

func mustOpt(t *testing.T, p *dhcp.Packet, code byte) *dhcp.Option {
	t.Helper()
	o := p.GetOption(code)
	if o == nil {
		t.Fatalf("missing option %d", code)
	}
	return o
}

func optByte(t *testing.T, p *dhcp.Packet, code byte) byte {
	t.Helper()
	o := mustOpt(t, p, code)
	if len(o.Data) < 1 {
		t.Fatalf("short option %d", code)
	}
	return o.Data[0]
}

func optIP(t *testing.T, p *dhcp.Packet, code byte) net.IP {
	t.Helper()
	o := mustOpt(t, p, code)
	if len(o.Data) < 4 {
		t.Fatalf("short IP option %d", code)
	}
	return net.IP(o.Data[:4])
}

func optString(t *testing.T, p *dhcp.Packet, code byte) string {
	t.Helper()
	o := mustOpt(t, p, code)
	return string(o.Data)
}
