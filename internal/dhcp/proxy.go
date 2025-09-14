package dhcp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"syscall"
	"time"

	"github.com/srcreigh/pxehost/internal/capture"
)

// ProxyDHCP is a minimal ProxyDHCP responder (PXE Boot Server Discovery).
// It binds to UDP ports and advertises TFTP server and bootfile
// to PXE clients without assigning IPs.
type ProxyDHCP struct {
	TFTPServerIP net.IP

	conn     *net.UDPConn
	conn4011 *net.UDPConn

	// PreboundDHCP, when set, is an already-bound UDP socket for the
	// DHCP port (usually 67). If provided, StartAsync will use it
	// instead of binding the port itself.
	PreboundDHCP *net.UDPConn

	DHCPPort int // canonically 67
	PXEPort  int // canonically 4011

	// PacketLog, when non-nil, receives JSONL entries for UDP packets.
	PacketLog capture.PacketLogger

	// DHCPBroadcastPort is the UDP port used for broadcast replies.
	// Canonically 68.
	DHCPBroadcastPort int

	// Logger must be provided.
	Logger *slog.Logger
}

func (p *ProxyDHCP) StartAsync() error {
	dhcpPort := p.DHCPPort
	pxePort := p.PXEPort
	// Bind IPv4-only to receive IPv4 DHCP broadcasts
	var c67 *net.UDPConn
	if p.PreboundDHCP != nil {
		c67 = p.PreboundDHCP
	} else {
		addr67, err := net.ResolveUDPAddr("udp4", ":"+itoa(dhcpPort))
		if err != nil {
			return fmt.Errorf("proxydhcp: resolve :%d: %w", dhcpPort, err)
		}
		c, err := net.ListenUDP("udp4", addr67)
		if err != nil {
			return fmt.Errorf("proxydhcp: listen :%d: %w", dhcpPort, err)
		}
		c67 = c
	}
	// Bind PXE service port (required)
	addr4011, err := net.ResolveUDPAddr("udp4", ":"+itoa(pxePort))
	if err != nil {
		_ = c67.Close()
		return fmt.Errorf("proxydhcp: resolve :%d: %w", pxePort, err)
	}
	c4011, err := net.ListenUDP("udp4", addr4011)
	if err != nil {
		_ = c67.Close()
		return fmt.Errorf("proxydhcp: listen :%d: %w", pxePort, err)
	}

	p.conn = c67
	p.conn4011 = c4011

	// Allow sending to broadcast address (255.255.255.255)
	if rc, err := p.conn.SyscallConn(); err == nil {
		_ = rc.Control(func(fd uintptr) {
			_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1)
		})
	}
	if rc, err := p.conn4011.SyscallConn(); err == nil {
		_ = rc.Control(func(fd uintptr) {
			_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1)
		})
	}

	p.Logger.Info("ProxyDHCP listening", "dhcp_port", dhcpPort, "pxe_port", pxePort, "tftp", p.TFTPServerIP)
	go p.serve(p.conn, dhcpPort)
	go p.serve(p.conn4011, pxePort)
	return nil
}

func (p *ProxyDHCP) Close() error {
	var err1, err2 error
	if p.conn != nil {
		err1 = p.conn.Close()
	}
	if p.conn4011 != nil {
		err2 = p.conn4011.Close()
	}
	if err1 != nil {
		return fmt.Errorf("proxydhcp: close DHCP socket: %w", err1)
	}
	if err2 != nil {
		return fmt.Errorf("proxydhcp: close PXE socket: %w", err2)
	}
	return nil
}

// BoundDHCPPort returns the actual UDP port bound for the DHCP socket.
// Returns 0 if not started.
func (p *ProxyDHCP) BoundDHCPPort() int {
	if p == nil || p.conn == nil {
		return 0
	}
	if la, ok := p.conn.LocalAddr().(*net.UDPAddr); ok && la != nil {
		return la.Port
	}
	return 0
}

// BoundPXEPort returns the actual UDP port bound for the PXE service socket.
// Returns 0 if not started.
func (p *ProxyDHCP) BoundPXEPort() int {
	if p == nil || p.conn4011 == nil {
		return 0
	}
	if la, ok := p.conn4011.LocalAddr().(*net.UDPAddr); ok && la != nil {
		return la.Port
	}
	return 0
}

func (p *ProxyDHCP) serve(conn *net.UDPConn, port int) {
	buf := make([]byte, 1500)
	for {
		n, raddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			// Suppress expected errors on shutdown when the socket is closed.
			if isNetClosed(err) {
				return
			}
			p.Logger.Error("ProxyDHCP read error", "err", err)
			return
		}
		p.Logger.Debug("ProxyDHCP packet received", "port", port, "bytes", n, "from", raddr.String())
		// Packet capture: inbound packet
		if p.PacketLog != nil {
			lip := ""
			lport := 0
			if la, ok := conn.LocalAddr().(*net.UDPAddr); ok && la != nil {
				lip = la.IP.String()
				lport = la.Port
			}
			p.PacketLog.Log(capture.MakePacket(
				capture.DirIn,
				"DHCP",
				lip, lport,
				raddr.IP.String(), raddr.Port,
				fmt.Sprintf("port=%d", port),
				append([]byte(nil), buf[:n]...),
			))
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		go p.handle(conn, pkt, raddr, port)
	}
}

// isNetClosed reports whether err indicates the UDP socket was closed
// (e.g. during shutdown). It checks errors.Is against net.ErrClosed and
// also matches the common substring used by the Go net package.
func isNetClosed(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, net.ErrClosed) {
		return true
	}
	// Fallback string match used by Go for closed connections.
	// This keeps shutdown logs clean across Go versions/platforms.
	return strings.Contains(err.Error(), "use of closed network connection")
}

func (p *ProxyDHCP) handle(conn *net.UDPConn, req []byte, src *net.UDPAddr, port int) {
	pkt, err := Parse(req)
	if err != nil {
		p.Logger.Debug("ProxyDHCP ignoring non-DHCP/invalid packet", "port", port, "from", src.String(), "len", len(req), "err", err)
		return
	}

	// Build map[code][]byte for logging and lookups
	inOpts := make(map[byte][]byte, len(pkt.Options))
	for _, o := range pkt.Options {
		inOpts[o.Code] = o.Data
	}
	if len(inOpts) > 0 {
		p.Logger.Debug("ProxyDHCP incoming options", "port", port, "from", src.String(), "options", "\n"+formatDHCPOptions(inOpts))
	}

	// Only respond to PXE clients when vendor class contains "PXEClient".
	isPXE := false
	if v, ok := inOpts[OptVendorClassIdent]; ok && containsString(v, "PXEClient") {
		isPXE = true
	}
	if !isPXE {
		p.Logger.Debug("ProxyDHCP non-PXEClient; ignoring", "port", port, "from", src.String())
		return
	}

	// Determine incoming DHCP message type (option 53)
	// If DISCOVER (1) -> respond with OFFER (2)
	// If REQUEST (3) or others -> respond with ACK (5)
	respMsgType := byte(DHCPAck) // default ACK
	if mt, ok := inOpts[OptMsgType]; ok && len(mt) == 1 {
		switch mt[0] {
		case DHCPDiscover:
			respMsgType = DHCPOffer
		case DHCPRequest:
			respMsgType = DHCPAck
		}
	}

	// Determine client architecture (option 93). Default to UEFI x86_64 if unknown.
	arch := uint16(0x0000)
	if v, ok := inOpts[OptClientArch]; ok && len(v) >= 2 {
		arch = uint16(v[0])<<8 | uint16(v[1])
	}

	// First stage - PXE BIOS firmware needs the .efi/.kpxe TFTP bootfile
	// Second stage - iPXE (HTTP-capable) firmware gets HTTPS link to menu.ipxe
	bootfile := ""
	// If client identifies as iPXE via Option 77 (User Class),
	// provide an iPXE script URL over HTTPS instead of TFTP bootfile.
	if uc, ok := inOpts[OptUserClass]; ok && bytes.Contains(uc, []byte("iPXE")) {
		bootfile = "https://boot.netboot.xyz/menu.ipxe"
	} else {
		// PXE BIOS step -- need to specify TFTP filename.
		// Choose bootfile based on arch.
		// 0 = Intel x86PC (BIOS);
		// 7,9 = EFI x86 32/64; many use 9 for x86-64
		bootfile = "netboot.xyz.efi"
		if arch == 0x0000 {
			// For BIOS clients, use the netboot.xyz iPXE chainloader
			bootfile = "netboot.xyz.kpxe"
		}
	}

	mac := net.HardwareAddr(pkt.Chaddr[:pkt.HLen])
	respPkt := NewPacket(BootReply, pkt.Xid, mac).
		WithMsgType(respMsgType).
		WithVendorClassIdent("PXEClient").
		WithBootFile(bootfile)

	respPkt.Siaddr = p.TFTPServerIP
	respPkt.WithServerID(p.TFTPServerIP)
	respPkt.WithTFTPServer(p.TFTPServerIP.String())

	// Log outgoing options in a readable way from respPkt.Options
	if len(respPkt.Options) > 0 {
		outOpts := make(map[byte][]byte, len(respPkt.Options))
		for _, o := range respPkt.Options {
			outOpts[o.Code] = o.Data
		}
		p.Logger.Debug("ProxyDHCP outgoing options", "port", port, "to", src.String(), "options", "\n"+formatDHCPOptions(outOpts))
	}

	// Decide reply destination: broadcast if client requested broadcast
	dst := &net.UDPAddr{IP: net.IPv4bcast, Port: p.DHCPBroadcastPort}
	broadcast := (pkt.Flags & BOOTPFlagBroadcast) != 0
	if ip4 := src.IP.To4(); ip4 != nil && !ip4.Equal(net.IPv4zero) && !broadcast {
		dst = &net.UDPAddr{IP: ip4, Port: src.Port}
	}

	// Serialize and send reply
	resp, err := respPkt.Serialize()
	if err != nil {
		p.Logger.Error("ProxyDHCP serialize error", "err", err)
		return
	}
	if err := conn.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
		p.Logger.Warn("ProxyDHCP set write deadline error", "port", port, "err", err)
	}
	if n, err := conn.WriteToUDP(resp, dst); err != nil {
		p.Logger.Error("ProxyDHCP write error", "err", err)
	} else {
		p.Logger.Info("ProxyDHCP reply sent",
			"port", port,
			"bytes", n,
			"to", dst.String(),
			"type", respMsgType,
			"arch", fmt.Sprintf("0x%04x", arch),
			"next_server", p.TFTPServerIP,
			"boot", bootfile,
		)
		// Packet capture: outbound reply
		if p.PacketLog != nil {
			lip := ""
			lport := 0
			if la, ok := conn.LocalAddr().(*net.UDPAddr); ok && la != nil {
				lip = la.IP.String()
				lport = la.Port
			}
			p.PacketLog.Log(capture.MakePacket(
				capture.DirOut,
				"DHCP",
				lip, lport,
				dst.IP.String(), dst.Port,
				fmt.Sprintf("port=%d", port),
				append([]byte(nil), resp...),
			))
		}
	}
}

// formatDHCPOptions returns a multi-line, human-friendly dump of DHCP options
// including code, canonical name (if known), decoded value, and raw hex bytes.
func formatDHCPOptions(m map[byte][]byte) string {
	if len(m) == 0 {
		return "(none)"
	}
	// To provide stable ordering, collect and sort keys
	keys := make([]int, 0, len(m))
	for k := range m {
		keys = append(keys, int(k))
	}
	// simple insertion sort (tiny set)
	for i := 1; i < len(keys); i++ {
		j := i
		for j > 0 && keys[j-1] > keys[j] {
			keys[j-1], keys[j] = keys[j], keys[j-1]
			j--
		}
	}
	const maxOptionLogChars = 100
	var out string
	for _, ik := range keys {
		k := byte(ik)
		v := m[k]
		name := dhcpOptionName(k)
		decoded := decodeDHCPOption(k, v)
		line := fmt.Sprintf("  - %s (%d): %s | hex=%s", name, k, decoded, hexBytes(v))
		out += truncateString(line, maxOptionLogChars) + "\n"
	}
	return out
}

// truncateString returns s limited to max characters; adds an ellipsis when truncated.
func truncateString(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	// Ensure we do not split in the middle of a multi-byte rune.
	// Walk back to the start of the last full rune if needed.
	// For speed, assume most content is ASCII; only adjust if necessary.
	end := max
	for end > 0 && (s[end]&0xC0) == 0x80 { // continuation byte 10xxxxxx
		end--
	}
	// Add a compact truncation marker to indicate omitted length
	omitted := len([]rune(s[end:]))
	if omitted > 0 {
		return s[:end] + fmt.Sprintf("…(+%d)", omitted)
	}
	return s[:end] + "…"
}

func dhcpOptionName(code byte) string {
	switch code {
	case OptRequestedIP:
		return "Requested IP Address"
	case OptMsgType:
		return "DHCP Message Type"
	case OptServerID:
		return "Server Identifier"
	case OptParamReqList:
		return "Parameter Request List"
	case OptMaxMessageSize:
		return "Maximum DHCP Message Size"
	case OptVendorClassIdent:
		return "Vendor Class Identifier"
	case OptClientID:
		return "Client Identifier"
	case OptTFTPServer:
		return "TFTP Server Name"
	case OptBootfile:
		return "Bootfile Name"
	case OptClientArch:
		return "Client System Architecture"
	case OptClientMachineID:
		return "Client Network Interface Identifier"
	default:
		return fmt.Sprintf("Option %d", code)
	}
}

func decodeDHCPOption(code byte, v []byte) string {
	switch code {
	case OptTFTPServer, OptBootfile, OptVendorClassIdent: // strings
		return safeASCII(v)
	case OptRequestedIP, OptServerID: // IP addresses
		if len(v) == 4 {
			return net.IP(v).String()
		}
	case OptMsgType: // message type
		if len(v) == 1 {
			return fmt.Sprintf("%d (%s)", v[0], dhcpMessageTypeName(v[0]))
		}
	case OptParamReqList: // parameter request list — show raw requested codes
		if len(v) > 0 {
			items := make([]string, 0, len(v))
			for _, c := range v {
				items = append(items, itoa(int(c)))
			}
			return "[" + joinComma(items) + "]"
		}
	case OptMaxMessageSize: // max message size
		if len(v) == 2 {
			return fmt.Sprintf("%d", binary.BigEndian.Uint16(v))
		}
	case OptClientID: // client identifier
		return fmt.Sprintf("%s (ascii=%q)", hexBytes(v), printableASCII(v))
	case OptClientArch: // client arch
		if len(v) >= 2 {
			arch := uint16(v[0])<<8 | uint16(v[1])
			return fmt.Sprintf("0x%04x", arch)
		}
	case OptClientMachineID: // Client Machine Identifier (UUID type 0)
		if len(v) == 17 && v[0] == 0 { // type 0, UUID
			return fmt.Sprintf("uuid=%s", hexBytes(v[1:]))
		}
		return hexBytes(v)
	}
	return fmt.Sprintf("len=%d", len(v))
}

func dhcpMessageTypeName(t byte) string {
	switch t {
	case DHCPDiscover:
		return "DISCOVER"
	case DHCPOffer:
		return "OFFER"
	case DHCPRequest:
		return "REQUEST"
	case DHCPDecline:
		return "DECLINE"
	case DHCPAck:
		return "ACK"
	case DHCPNak:
		return "NAK"
	case 7:
		return "RELEASE"
	case 8:
		return "INFORM"
	default:
		return "UNKNOWN"
	}
}

func hexBytes(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	const hexdigits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, hexdigits[c>>4], hexdigits[c&0x0f])
	}
	// insert colon separators for readability
	// build with minimal allocs
	if len(out) <= 2 {
		return string(out)
	}
	// convert to colon separated without a bytes.Buffer
	n := (len(out)/2 - 1) + len(out)
	res := make([]byte, n)
	ri := 0
	for i := 0; i < len(out); i += 2 {
		if i > 0 {
			res[ri] = ':'
			ri++
		}
		res[ri] = out[i]
		res[ri+1] = out[i+1]
		ri += 2
	}
	return string(res)
}

func safeASCII(b []byte) string {
	// return as Go-escaped string when printable; else hex + printable subset
	p := printableASCII(b)
	if len(p) == len(b) {
		return string(b)
	}
	return fmt.Sprintf("%q (hex=%s)", p, hexBytes(b))
}

func printableASCII(b []byte) []byte {
	out := make([]byte, len(b))
	n := 0
	for _, c := range b {
		if c >= 32 && c <= 126 {
			out[n] = c
			n++
		}
	}
	return out[:n]
}

func joinComma(items []string) string {
	if len(items) == 0 {
		return ""
	}
	// compute length
	n := 0
	for _, s := range items {
		n += len(s)
	}
	n += len(items) - 1
	out := make([]byte, 0, n)
	for i, s := range items {
		if i > 0 {
			out = append(out, ',', ' ')
		}
		out = append(out, s...)
	}
	return string(out)
}

func containsString(b []byte, s string) bool {
	return string(b) == s || (len(b) > len(s) && string(b)[:len(s)] == s)
}

// small, local itoa without pulling strconv to keep deps minimal
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := false
	if i < 0 {
		neg = true
		i = -i
	}
	var buf [20]byte
	n := len(buf)
	for i > 0 {
		n--
		buf[n] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		n--
		buf[n] = '-'
	}
	return string(buf[n:])
}
