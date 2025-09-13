package dhcp

import (
	"bytes"
	"errors"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strings"
	"syscall"
	"time"
)

// ProxyDHCP is a minimal ProxyDHCP responder (PXE Boot Server Discovery).
// It binds to UDP ports 67 and 4011 and advertises TFTP server and bootfile
// to PXE clients without assigning IPs.
type ProxyDHCP struct {
	TFTPServerIP string // IP string advertised in option 66 and siaddr

	conn     *net.UDPConn
	conn4011 *net.UDPConn // listener for PXE service port 4011
}

func (p *ProxyDHCP) StartAsync() error {
	// Bind IPv4-only to receive IPv4 DHCP broadcasts on :67
	addr67, err := net.ResolveUDPAddr("udp4", ":67")
	if err != nil {
		return err
	}
	c67, err := net.ListenUDP("udp4", addr67)
	if err != nil {
		return err
	}
	// Bind PXE service port :4011 (required)
	addr4011, err := net.ResolveUDPAddr("udp4", ":4011")
	if err != nil {
		_ = c67.Close()
		return err
	}
	c4011, err := net.ListenUDP("udp4", addr4011)
	if err != nil {
		_ = c67.Close()
		return err
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

	log.Printf("ProxyDHCP: listening on UDP :67 and :4011 (TFTP=%s)", p.TFTPServerIP)
	go p.serve(p.conn, 67)
	go p.serve(p.conn4011, 4011)
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
		return err1
	}
	return err2
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
            log.Printf("ProxyDHCP read error: %v", err)
            return
        }
        log.Printf("ProxyDHCP:%d received %d bytes from %s", port, n, raddr.String())
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
	if len(req) < 240 || req[236] != 99 || req[237] != 130 || req[238] != 83 || req[239] != 99 {
		log.Printf("ProxyDHCP:%d: ignoring non-DHCP/invalid packet from %s (len=%d)", port, src.String(), len(req))
		return
	}
	// Only respond to PXE clients when vendor class contains "PXEClient".
	isPXE := false
	opts := parseOptions(req[240:])
	// Log all incoming options in a readable way
	if len(opts) > 0 {
		log.Printf("ProxyDHCP:%d: incoming options from %s:\n%s", port, src.String(), formatDHCPOptions(opts))
	}
	if v, ok := opts[60]; ok && containsString(v, "PXEClient") {
		isPXE = true
	}
	if !isPXE {
		log.Printf("ProxyDHCP:%d: DHCP packet from %s is not PXEClient; ignoring", port, src.String())
		return
	}

	// Determine incoming DHCP message type (option 53)
	// If DISCOVER (1) -> respond with OFFER (2)
	// If REQUEST (3) or others -> respond with ACK (5)
	respMsgType := byte(5) // default ACK
	if mt, ok := opts[53]; ok && len(mt) == 1 {
		switch mt[0] {
		case 1: // DISCOVER
			respMsgType = 2 // OFFER
		case 3: // REQUEST
			respMsgType = 5 // ACK
		}
	}

	// Determine client architecture (option 93). Default to UEFI x86_64 if unknown.
	arch := uint16(0x0000)
	if v, ok := opts[93]; ok && len(v) >= 2 {
		arch = uint16(v[0])<<8 | uint16(v[1])
	}

	// First stage - PXE BIOS firmware needs the .efi/.kpxe TFTP bootfile
	// Second stage - iPXE (HTTP-capable) firmware gets HTTPS link to menu.ipxe
	bootfile := ""
	// If client identifies as iPXE via Option 77 (User Class),
	// provide an iPXE script URL over HTTPS instead of TFTP bootfile.
	if uc, ok := opts[77]; ok && bytes.Contains(uc, []byte("iPXE")) {
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
	resp := make([]byte, 240)
	resp[0] = 2               // op BOOTREPLY
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
	resp[236], resp[237], resp[238], resp[239] = 99, 130, 83, 99

	// Options
	opt := make([]byte, 0, 128)
	// DHCP Message Type (53): OFFER (2) or ACK (5)
	opt = append(opt, 53, 1, respMsgType)
	// DHCP Server Identifier (54): advertise our address (use TFTPServerIP)
	if ip := net.ParseIP(p.TFTPServerIP).To4(); ip != nil {
		opt = append(opt, 54, 4)
		opt = append(opt, ip...)
	}
	// Vendor class id (60): PXEClient
	opt = append(opt, 60, byte(len("PXEClient")))
	opt = append(opt, []byte("PXEClient")...)
	// TFTP server name (66)
	if p.TFTPServerIP != "" {
		opt = append(opt, 66, byte(len(p.TFTPServerIP)))
		opt = append(opt, []byte(p.TFTPServerIP)...)
	}
	// Bootfile name (67)
	opt = append(opt, 67, byte(len(bootfile)))
	opt = append(opt, []byte(bootfile)...)
	// End option
	opt = append(opt, 255)
	resp = append(resp, opt...)

	// Log outgoing options in a readable way
	if len(opt) > 0 {
		outOpts := parseOptions(opt)
		log.Printf("ProxyDHCP:%d: outgoing options to %s:\n%s", port, src.String(), formatDHCPOptions(outOpts))
	}

	// Decide reply destination: broadcast if client has no IP or requests broadcast
	dst := &net.UDPAddr{IP: net.IPv4bcast, Port: 68}
	// BOOTP flags (broadcast bit 0x8000) at bytes 10-11
	broadcast := false
	if len(req) >= 12 {
		fl := binary.BigEndian.Uint16(req[10:12])
		broadcast = (fl & 0x8000) != 0
	}
	// If source has a unicast IPv4 and did not request broadcast, reply unicast
	if ip4 := src.IP.To4(); ip4 != nil && !ip4.Equal(net.IPv4zero) && !broadcast {
		dst = &net.UDPAddr{IP: ip4, Port: src.Port}
	}
	// Send reply
	conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if n, err := conn.WriteToUDP(resp, dst); err != nil {
		log.Printf("ProxyDHCP write: %v", err)
	} else {
		// Include next-server (siaddr / option 66) for visibility
		log.Printf(
			"ProxyDHCP:%d: sent %d-byte reply to %s (type=%d arch=0x%04x next-server=%s boot=%s)",
			port, n, dst.String(), respMsgType, arch, p.TFTPServerIP, bootfile,
		)
	}
}

func parseOptions(b []byte) map[byte][]byte {
	m := make(map[byte][]byte)
	i := 0
	for i < len(b) {
		code := b[i]
		if code == 0 { // pad
			i++
			continue
		}
		if code == 255 { // end
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
	case 12, 15, 66, 67, 60: // strings
		return safeASCII(v)
	case 50, 54: // IP addresses
		if len(v) == 4 {
			return net.IP(v).String()
		}
	case 51: // lease time
		if len(v) == 4 {
			sec := binary.BigEndian.Uint32(v)
			return fmt.Sprintf("%ds", sec)
		}
	case 53: // message type
		if len(v) == 1 {
			return fmt.Sprintf("%d (%s)", v[0], dhcpMessageTypeName(v[0]))
		}
	case 55: // parameter request list — show raw requested codes
		if len(v) > 0 {
			items := make([]string, 0, len(v))
			for _, c := range v {
				items = append(items, itoa(int(c)))
			}
			return "[" + joinComma(items) + "]"
		}
	case 57: // max message size
		if len(v) == 2 {
			return fmt.Sprintf("%d", binary.BigEndian.Uint16(v))
		}
	case 61: // client identifier
		return fmt.Sprintf("%s (ascii=%q)", hexBytes(v), printableASCII(v))
	case 93: // client arch
		if len(v) >= 2 {
			arch := uint16(v[0])<<8 | uint16(v[1])
			return fmt.Sprintf("0x%04x", arch)
		}
	case 97: // UUID
		if len(v) == 17 && v[0] == 0 { // type 0, UUID
			return fmt.Sprintf("uuid=%s", hexBytes(v[1:]))
		}
		return hexBytes(v)
	}
	return fmt.Sprintf("len=%d", len(v))
}

func dhcpMessageTypeName(t byte) string {
	switch t {
	case 1:
		return "DISCOVER"
	case 2:
		return "OFFER"
	case 3:
		return "REQUEST"
	case 4:
		return "DECLINE"
	case 5:
		return "ACK"
	case 6:
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
