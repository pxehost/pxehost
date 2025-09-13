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

// DHCP protocol constants and helpers
const (
	// Fixed BOOTP/DHCP header lengths and offsets
	dhcpFixedHeaderLen = 240 // 236-byte BOOTP + 4-byte magic cookie
	dhcpCookieOffset   = 236

	// BOOTP op codes
	bootpOpRequest = 1
	bootpOpReply   = 2

	// BOOTP flags
	bootpFlagBroadcastMask = 0x8000

	// DHCP option codes (subset used here)
	optPad              = 0
	optEnd              = 255
	optMsgType          = 53
	optServerID         = 54
	optVendorClassID    = 60
	optTFTPServerName   = 66
	optBootfileName     = 67
	optUserClass        = 77
	optClientArch       = 93
	optClientUUID       = 97
	optParamRequestList = 55
	optMaxDHCPMsgSize   = 57
)

// DHCP message type values
const (
	dhcpMsgDiscover = 1
	dhcpMsgOffer    = 2
	dhcpMsgRequest  = 3
	dhcpMsgDecline  = 4
	dhcpMsgAck      = 5
	dhcpMsgNak      = 6
)

// dhcpMagicCookie contains the fixed RFC2132 cookie ("99,130,83,99").
var dhcpMagicCookie = [4]byte{99, 130, 83, 99}

// ProxyDHCP is a minimal ProxyDHCP responder (PXE Boot Server Discovery).
// It binds to UDP ports and advertises TFTP server and bootfile
// to PXE clients without assigning IPs.
type ProxyDHCP struct {
	TFTPServerIP string

	conn     *net.UDPConn
	conn4011 *net.UDPConn

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
	addr67, err := net.ResolveUDPAddr("udp4", ":"+itoa(dhcpPort))
	if err != nil {
		return fmt.Errorf("proxydhcp: resolve :%d: %w", dhcpPort, err)
	}
	c67, err := net.ListenUDP("udp4", addr67)
	if err != nil {
		return fmt.Errorf("proxydhcp: listen :%d: %w", dhcpPort, err)
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
	// Minimal DHCP parse: ensure BOOTP and cookie present, echo xid and chaddr.
	if len(req) < dhcpFixedHeaderLen || !bytes.Equal(req[dhcpCookieOffset:dhcpCookieOffset+4], dhcpMagicCookie[:]) {
		p.Logger.Debug("ProxyDHCP ignoring non-DHCP/invalid packet", "port", port, "from", src.String(), "len", len(req))
		return
	}
	// Only respond to PXE clients when vendor class contains "PXEClient".
	isPXE := false
	opts := parseOptions(req[240:])
	// Log all incoming options in a readable way
	if len(opts) > 0 {
		p.Logger.Debug("ProxyDHCP incoming options", "port", port, "from", src.String(), "options", "\n"+formatDHCPOptions(opts))
	}
	if v, ok := opts[optVendorClassID]; ok && containsString(v, "PXEClient") {
		isPXE = true
	}
	if !isPXE {
		p.Logger.Debug("ProxyDHCP non-PXEClient; ignoring", "port", port, "from", src.String())
		return
	}

	// Determine incoming DHCP message type (option 53)
	// If DISCOVER (1) -> respond with OFFER (2)
	// If REQUEST (3) or others -> respond with ACK (5)
	respMsgType := byte(dhcpMsgAck) // default ACK
	if mt, ok := opts[optMsgType]; ok && len(mt) == 1 {
		switch mt[0] {
		case dhcpMsgDiscover:
			respMsgType = dhcpMsgOffer
		case dhcpMsgRequest:
			respMsgType = dhcpMsgAck
		}
	}

	// Determine client architecture (option 93). Default to UEFI x86_64 if unknown.
	arch := uint16(0x0000)
	if v, ok := opts[optClientArch]; ok && len(v) >= 2 {
		arch = uint16(v[0])<<8 | uint16(v[1])
	}

	// First stage - PXE BIOS firmware needs the .efi/.kpxe TFTP bootfile
	// Second stage - iPXE (HTTP-capable) firmware gets HTTPS link to menu.ipxe
	bootfile := ""
	// If client identifies as iPXE via Option 77 (User Class),
	// provide an iPXE script URL over HTTPS instead of TFTP bootfile.
	if uc, ok := opts[optUserClass]; ok && bytes.Contains(uc, []byte("iPXE")) {
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

	// Build BOOTREPLY (op=2) with DHCP OFFER/ACK and options 60,66,67.
	resp := make([]byte, dhcpFixedHeaderLen)
	resp[0] = bootpOpReply    // op BOOTREPLY
	resp[1] = req[1]          // htype
	resp[2] = req[2]          // hlen
	resp[3] = 0               // hops
	copy(resp[4:8], req[4:8]) // xid
	// secs, flags 0
	// ciaddr/yiaddr/giaddr zeros for proxy
	// siaddr: TFTP server IP
	if ip := net.ParseIP(p.TFTPServerIP).To4(); ip != nil {
		copy(resp[20:24], ip)
	}
	// chaddr
	copy(resp[28:44], req[28:44])
	// BOOTP legacy sname/file fields left empty; use option 67 instead
	// magic cookie
	copy(resp[dhcpCookieOffset:dhcpCookieOffset+4], dhcpMagicCookie[:])

	// Options
	opt := make([]byte, 0, 128)
	// DHCP Message Type (53): OFFER (2) or ACK (5)
	opt = append(opt, optMsgType, 1, respMsgType)
	// DHCP Server Identifier (54): advertise our address (use TFTPServerIP)
	if ip := net.ParseIP(p.TFTPServerIP).To4(); ip != nil {
		opt = append(opt, optServerID, 4)
		opt = append(opt, ip...)
	}
	// Vendor class id (60): PXEClient
	opt = append(opt, optVendorClassID, byte(len("PXEClient")))
	opt = append(opt, []byte("PXEClient")...)
	// TFTP server name (66)
	if p.TFTPServerIP != "" {
		opt = append(opt, optTFTPServerName, byte(len(p.TFTPServerIP)))
		opt = append(opt, []byte(p.TFTPServerIP)...)
	}
	// Bootfile name (67)
	opt = append(opt, optBootfileName, byte(len(bootfile)))
	opt = append(opt, []byte(bootfile)...)
	// End option
	opt = append(opt, optEnd)
	resp = append(resp, opt...)

	// Log outgoing options in a readable way
	if len(opt) > 0 {
		outOpts := parseOptions(opt)
		p.Logger.Debug("ProxyDHCP outgoing options", "port", port, "to", src.String(), "options", "\n"+formatDHCPOptions(outOpts))
	}

	// Decide reply destination: broadcast if client has no IP or requests broadcast
	dstPort := p.DHCPBroadcastPort
	dst := &net.UDPAddr{IP: net.IPv4bcast, Port: dstPort}
	// BOOTP flags (broadcast bit 0x8000) at bytes 10-11
	broadcast := false
	if len(req) >= 12 {
		fl := binary.BigEndian.Uint16(req[10:12])
		broadcast = (fl & bootpFlagBroadcastMask) != 0
	}
	// If source has a unicast IPv4 and did not request broadcast, reply unicast
	if ip4 := src.IP.To4(); ip4 != nil && !ip4.Equal(net.IPv4zero) && !broadcast {
		dst = &net.UDPAddr{IP: ip4, Port: src.Port}
	}
	// Send reply
	if err := conn.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
		p.Logger.Warn("ProxyDHCP set write deadline error", "port", port, "err", err)
	}
	if n, err := conn.WriteToUDP(resp, dst); err != nil {
		p.Logger.Error("ProxyDHCP write error", "err", err)
	} else {
		// Include next-server (siaddr / option 66) for visibility
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

// logger returns the configured logger or the default slog logger.
// logger helper removed; ProxyDHCP requires non-nil Logger.

func parseOptions(b []byte) map[byte][]byte {
	m := make(map[byte][]byte)
	i := 0
	for i < len(b) {
		code := b[i]
		if code == optPad { // pad
			i++
			continue
		}
		if code == optEnd { // end
			break
		}
		if i+1 >= len(b) {
			break
		}
		l := int(b[i+1])
		if i+2+l > len(b) {
			break
		}
		m[code] = b[i+2 : i+2+l]
		i += 2 + l
	}
	return m
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
	case 1:
		return "Subnet Mask"
	case 2:
		return "Time Offset"
	case 3:
		return "Router"
	case 4:
		return "Time Server"
	case 5:
		return "Name Server"
	case 6:
		return "DNS Servers"
	case 12:
		return "Host Name"
	case 13:
		return "Boot File Size"
	case 15:
		return "Domain Name"
	case 28:
		return "Broadcast Address"
	case 42:
		return "NTP Servers"
	case 43:
		return "Vendor Specific"
	case 44:
		return "NetBIOS Name Servers"
	case 45:
		return "NetBIOS Datagram Servers"
	case 46:
		return "NetBIOS Node Type"
	case 47:
		return "NetBIOS Scope ID"
	case 50:
		return "Requested IP Address"
	case 51:
		return "IP Address Lease Time"
	case 52:
		return "Option Overload"
	case 53:
		return "DHCP Message Type"
	case 54:
		return "Server Identifier"
	case 55:
		return "Parameter Request List"
	case 56:
		return "Message"
	case 57:
		return "Maximum DHCP Message Size"
	case 58:
		return "Renewal (T1) Time"
	case 59:
		return "Rebinding (T2) Time"
	case 60:
		return "Vendor Class Identifier"
	case 61:
		return "Client Identifier"
	case 66:
		return "TFTP Server Name"
	case 67:
		return "Bootfile Name"
	case 93:
		return "Client System Architecture"
	case 97:
		return "Client Network Interface Identifier"
	case 119:
		return "Domain Search"
	case 121:
		return "Classless Static Route"
	case 249:
		return "MS Classless Static Route"
	case 252:
		return "WPAD/Proxy Auto-Config"
	default:
		return fmt.Sprintf("Option %d", code)
	}
}

func decodeDHCPOption(code byte, v []byte) string {
	switch code {
	case 1: // subnet mask
		if len(v) == 4 {
			return net.IP(v).String()
		}
	case 3, 6: // router or dns servers
		if len(v)%4 == 0 {
			ips := make([]string, 0, len(v)/4)
			for i := 0; i < len(v); i += 4 {
				ips = append(ips, net.IP(v[i:i+4]).String())
			}
			return joinComma(ips)
		}
	case 12, 15, optTFTPServerName, optBootfileName, optVendorClassID: // strings
		return safeASCII(v)
	case 50, optServerID: // IP addresses
		if len(v) == 4 {
			return net.IP(v).String()
		}
	case 51: // lease time
		if len(v) == 4 {
			sec := binary.BigEndian.Uint32(v)
			return fmt.Sprintf("%ds", sec)
		}
	case optMsgType: // message type
		if len(v) == 1 {
			return fmt.Sprintf("%d (%s)", v[0], dhcpMessageTypeName(v[0]))
		}
	case optParamRequestList: // parameter request list — show raw requested codes
		if len(v) > 0 {
			items := make([]string, 0, len(v))
			for _, c := range v {
				items = append(items, itoa(int(c)))
			}
			return "[" + joinComma(items) + "]"
		}
	case optMaxDHCPMsgSize: // max message size
		if len(v) == 2 {
			return fmt.Sprintf("%d", binary.BigEndian.Uint16(v))
		}
	case 61: // client identifier
		return fmt.Sprintf("%s (ascii=%q)", hexBytes(v), printableASCII(v))
	case optClientArch: // client arch
		if len(v) >= 2 {
			arch := uint16(v[0])<<8 | uint16(v[1])
			return fmt.Sprintf("0x%04x", arch)
		}
	case optClientUUID: // UUID
		if len(v) == 17 && v[0] == 0 { // type 0, UUID
			return fmt.Sprintf("uuid=%s", hexBytes(v[1:]))
		}
		return hexBytes(v)
	}
	return fmt.Sprintf("len=%d", len(v))
}

func dhcpMessageTypeName(t byte) string {
	switch t {
	case dhcpMsgDiscover:
		return "DISCOVER"
	case dhcpMsgOffer:
		return "OFFER"
	case dhcpMsgRequest:
		return "REQUEST"
	case dhcpMsgDecline:
		return "DECLINE"
	case dhcpMsgAck:
		return "ACK"
	case dhcpMsgNak:
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
