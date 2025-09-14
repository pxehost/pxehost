package dhcp

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

const (
	// BOOTP op codes
	BootRequest = 1
	BootReply   = 2

	// HW types
	HTYPEEthernet = 1

	// DHCP options
	OptPad              = 0
	OptEnd              = 255
	OptMsgType          = 53
	OptClientID         = 61
	OptParamReqList     = 55
	OptHostName         = 12
	OptVendorClassIdent = 60
	OptServerID         = 54
	OptRequestedIP      = 50
	OptTFTPServer       = 66
	OptBootfile         = 67

	// Message types
	DHCPDiscover = 1
	DHCPOffer    = 2
	DHCPRequest  = 3
	DHCPDecline  = 4
	DHCPAck      = 5
	DHCPNak      = 6
	DHCPRelease  = 7
	DHCPInform   = 8

	// Magic cookie
	magicCookie = 0x63825363
)

// Option is a single DHCP option TLV.
type Option struct {
	Code byte
	Data []byte
}

// Packet is a minimal BOOTP/DHCP packet builder (RFC 2131/2132 layout).
type Packet struct {
	Op     byte // 1=request, 2=reply
	HType  byte // 1=Ethernet
	HLen   byte // MAC length (6)
	Hops   byte
	Xid    uint32
	Secs   uint16
	Flags  uint16
	Ciaddr net.IP // 4 bytes
	Yiaddr net.IP
	Siaddr net.IP
	Giaddr net.IP
	Chaddr [16]byte // client HW addr (first HLen bytes used)
	SName  [64]byte // optional server host name (zero-filled)
	File   [128]byte
	// Options after the 236-byte BOOTP header + magic cookie.
	Options []Option
}

// NewPacket creates a packet with sane defaults.
func NewPacket(op byte, xid uint32, mac net.HardwareAddr) *Packet {
	var ch [16]byte
	copy(ch[:], mac)
	return &Packet{
		Op:     op,
		HType:  HTYPEEthernet,
		HLen:   byte(len(mac)),
		Xid:    xid,
		Ciaddr: net.IPv4zero,
		Yiaddr: net.IPv4zero,
		Siaddr: net.IPv4zero,
		Giaddr: net.IPv4zero,
		Chaddr: ch,
	}
}

func (p *Packet) WithMsgType(t byte) *Packet {
	p.Options = append(p.Options, Option{Code: OptMsgType, Data: []byte{t}})
	return p
}

func (p *Packet) WithHostname(name string) *Packet {
	p.Options = append(p.Options, Option{Code: OptHostName, Data: []byte(name)})
	return p
}

func (p *Packet) WithVendorClassIdent(v string) *Packet {
	p.Options = append(p.Options, Option{Code: OptVendorClassIdent, Data: []byte(v)})
	return p
}

func (p *Packet) WithClientID(hwType byte, mac net.HardwareAddr) *Packet {
	buf := append([]byte{hwType}, []byte(mac)...)
	p.Options = append(p.Options, Option{Code: OptClientID, Data: buf})
	return p
}

func (p *Packet) WithParamRequestList(codes ...byte) *Packet {
	p.Options = append(p.Options, Option{Code: OptParamReqList, Data: append([]byte{}, codes...)})
	return p
}

func (p *Packet) WithRequestedIP(ip net.IP) *Packet {
	ip4 := ip.To4()
	if ip4 == nil {
		return p
	}
	p.Options = append(p.Options, Option{Code: OptRequestedIP, Data: []byte(ip4)})
	return p
}

func (p *Packet) WithServerID(ip net.IP) *Packet {
	ip4 := ip.To4()
	if ip4 == nil {
		return p
	}
	p.Options = append(p.Options, Option{Code: OptServerID, Data: []byte(ip4)})
	return p
}

// WithMaxMessageSize sets option 57 (max DHCP message size).
func (p *Packet) WithMaxMessageSize(size uint16) *Packet {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, size)
	p.Options = append(p.Options, Option{Code: 57, Data: buf})
	return p
}

// WithArch sets option 93 (client system architecture type).
func (p *Packet) WithArch(arch uint16) *Packet {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, arch)
	p.Options = append(p.Options, Option{Code: 93, Data: buf})
	return p
}

// WithNIC sets option 94 (client network interface identifier).
func (p *Packet) WithNIC(data []byte) *Packet {
	p.Options = append(p.Options, Option{Code: 94, Data: append([]byte{}, data...)})
	return p
}

// WithClientMachineID sets option 97 (client machine identifier).
func (p *Packet) WithClientMachineID(data []byte) *Packet {
	p.Options = append(p.Options, Option{Code: 97, Data: append([]byte{}, data...)})
	return p
}

// WithTFTPServer sets option 66 (TFTP server name / next-server).
func (p *Packet) WithTFTPServer(name string) *Packet {
	p.Options = append(p.Options, Option{Code: 66, Data: []byte(name)})
	return p
}

// WithBootFile sets option 67 (bootfile name).
func (p *Packet) WithBootFile(name string) *Packet {
	p.Options = append(p.Options, Option{Code: 67, Data: []byte(name)})
	return p
}

// WithUserClass sets option 77 (user class information).
func (p *Packet) WithUserClass(class string) *Packet {
	p.Options = append(p.Options, Option{Code: 77, Data: []byte(class)})
	return p
}

func (p *Packet) AddOption(code byte, data []byte) *Packet {
	p.Options = append(p.Options, Option{Code: code, Data: append([]byte{}, data...)})
	return p
}

// Serialize marshals to wire format (BOOTP header + magic cookie + options + End).
func (p *Packet) Serialize() ([]byte, error) {
	if p.HType == 0 {
		p.HType = HTYPEEthernet
	}
	if p.HLen == 0 {
		p.HLen = 6
	}
	buf := bytes.NewBuffer(make([]byte, 0, 300))

	// Fixed BOOTP header (236 bytes)
	buf.WriteByte(p.Op)
	buf.WriteByte(p.HType)
	buf.WriteByte(p.HLen)
	buf.WriteByte(p.Hops)

	if err := binary.Write(buf, binary.BigEndian, p.Xid); err != nil {
		return nil, fmt.Errorf("binary write xid: %w", err)
	}
	if err := binary.Write(buf, binary.BigEndian, p.Secs); err != nil {
		return nil, fmt.Errorf("binary write secs: %w", err)
	}
	if err := binary.Write(buf, binary.BigEndian, p.Flags); err != nil {
		return nil, fmt.Errorf("binary write flags: %w", err)
	}

	writeIPv4(buf, p.Ciaddr)
	writeIPv4(buf, p.Yiaddr)
	writeIPv4(buf, p.Siaddr)
	writeIPv4(buf, p.Giaddr)

	buf.Write(p.Chaddr[:]) // 16
	buf.Write(p.SName[:])  // 64
	buf.Write(p.File[:])   // 128

	// Magic cookie
	if err := binary.Write(buf, binary.BigEndian, uint32(magicCookie)); err != nil {
		return nil, fmt.Errorf("binary write cookie: %w", err)
	}

	// Options
	for _, opt := range p.Options {
		if opt.Code == OptPad || opt.Code == OptEnd {
			buf.WriteByte(opt.Code)
			continue
		}
		buf.WriteByte(opt.Code)
		buf.WriteByte(byte(len(opt.Data)))
		buf.Write(opt.Data)
	}
	// Ensure End
	buf.WriteByte(OptEnd)

	return buf.Bytes(), nil
}

func writeIPv4(b *bytes.Buffer, ip net.IP) {
	ip4 := net.IPv4zero
	if ip != nil && ip.To4() != nil {
		ip4 = ip.To4()
	}
	b.Write(ip4.To4()) // always 4 bytes
}

// ToBase64 is a convenience for tests/fixtures.
func (p *Packet) ToBase64() (string, error) {
	raw, err := p.Serialize()
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

// ParseBase64 reads a wire packet from base64 into a Packet (minimal decode).
func ParseBase64(b64 string) (*Packet, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("decode base64: %w", err)
	}
	return Parse(raw)
}

func Parse(raw []byte) (*Packet, error) {
	if len(raw) < 240 { // 236 + cookie
		return nil, fmt.Errorf("short packet: %d bytes", len(raw))
	}
	p := &Packet{}
	p.Op = raw[0]
	p.HType = raw[1]
	p.HLen = raw[2]
	p.Hops = raw[3]
	p.Xid = binary.BigEndian.Uint32(raw[4:8])
	p.Secs = binary.BigEndian.Uint16(raw[8:10])
	p.Flags = binary.BigEndian.Uint16(raw[10:12])

	p.Ciaddr = net.IP(raw[12:16])
	p.Yiaddr = net.IP(raw[16:20])
	p.Siaddr = net.IP(raw[20:24])
	p.Giaddr = net.IP(raw[24:28])

	copy(p.Chaddr[:], raw[28:44])
	copy(p.SName[:], raw[44:108])
	copy(p.File[:], raw[108:236])

	if binary.BigEndian.Uint32(raw[236:240]) != magicCookie {
		return p, fmt.Errorf("missing magic cookie")
	}

	opts := []Option{}
	i := 240
	for i < len(raw) {
		code := raw[i]
		i++
		if code == OptEnd {
			break
		}
		if code == OptPad {
			continue
		}
		if i >= len(raw) {
			break
		}
		l := int(raw[i])
		i++
		if i+l > len(raw) {
			break
		}
		opts = append(opts, Option{Code: code, Data: append([]byte{}, raw[i:i+l]...)})
		i += l
	}
	p.Options = opts
	return p, nil
}

func (p *Packet) ToCodeString() string {
	var sb strings.Builder

	// Constructor with op, xid, mac
	fmt.Fprintf(&sb, "pkt := dhcp.New(%d, 0x%x, %s)\n", p.Op, p.Xid, hwLit(p.Chaddr[:p.HLen]))

	// Non-default header fields
	if p.Hops != 0 {
		fmt.Fprintf(&sb, "pkt.Hops = %d\n", p.Hops)
	}
	if p.Secs != 0 {
		fmt.Fprintf(&sb, "pkt.Secs = %d\n", p.Secs)
	}
	if p.Flags != 0 {
		fmt.Fprintf(&sb, "pkt.Flags = 0x%x\n", p.Flags)
	}
	if !ipZero(p.Ciaddr) {
		fmt.Fprintf(&sb, "pkt.Ciaddr = %s\n", ipLit(p.Ciaddr))
	}
	if !ipZero(p.Yiaddr) {
		fmt.Fprintf(&sb, "pkt.Yiaddr = %s\n", ipLit(p.Yiaddr))
	}
	if !ipZero(p.Siaddr) {
		fmt.Fprintf(&sb, "pkt.Siaddr = %s\n", ipLit(p.Siaddr))
	}
	if !ipZero(p.Giaddr) {
		fmt.Fprintf(&sb, "pkt.Giaddr = %s\n", ipLit(p.Giaddr))
	}

	// Options with readable builders
	for _, o := range p.Options {
		switch o.Code {
		case OptMsgType:
			if len(o.Data) == 1 {
				fmt.Fprintf(&sb, "pkt.WithMsgType(%d)\n", o.Data[0])
			}
		case OptHostName:
			fmt.Fprintf(&sb, "pkt.WithHostname(%q)\n", string(o.Data))
		case OptVendorClassIdent:
			fmt.Fprintf(&sb, "pkt.WithVendorClassIdent(%q)\n", string(o.Data))
		case OptClientID:
			if len(o.Data) >= 1 {
				hwType := o.Data[0]
				mac := net.HardwareAddr(o.Data[1:])
				fmt.Fprintf(&sb, "pkt.WithClientID(%d, %s)\n", hwType, hwAddrLit(mac))
			}
		case OptParamReqList:
			fmt.Fprintf(&sb, "pkt.WithParamRequestList(%s)\n", bytesLit(o.Data))
		case OptRequestedIP:
			if len(o.Data) == 4 {
				fmt.Fprintf(&sb, "pkt.WithRequestedIP(%s)\n", ipLit(net.IP(o.Data)))
			}
		case OptServerID:
			if len(o.Data) == 4 {
				fmt.Fprintf(&sb, "pkt.WithServerID(%s)\n", ipLit(net.IP(o.Data)))
			}
		case 57: // Max message size
			if len(o.Data) == 2 {
				fmt.Fprintf(&sb, "pkt.WithMaxMessageSize(%d)\n", binary.BigEndian.Uint16(o.Data))
			}
		case 93: // Arch
			if len(o.Data) == 2 {
				fmt.Fprintf(&sb, "pkt.WithArch(%d)\n", binary.BigEndian.Uint16(o.Data))
			}
		case 94: // NIC
			fmt.Fprintf(&sb, "pkt.WithNIC([]byte{%s})\n", bytesLit(o.Data))
		case 97: // Client Machine ID
			fmt.Fprintf(&sb, "pkt.WithClientMachineID([]byte{%s})\n", bytesLit(o.Data))
		case OptPad, OptEnd:
			// ignore
		case 66: // TFTP server name
			fmt.Fprintf(&sb, "pkt.WithTFTPServer(%q)\n", string(o.Data))
		case 67: // Boot file name
			fmt.Fprintf(&sb, "pkt.WithBootFile(%q)\n", string(o.Data))
		case 77: // User Class
			fmt.Fprintf(&sb, "pkt.WithUserClass(%q)\n", string(o.Data))
		default:
			fmt.Fprintf(&sb, "pkt.AddOption(%d, []byte{%s})\n", o.Code, bytesLit(o.Data))
		}
	}

	return sb.String()
}

func (p *Packet) GetOption(code byte) *Option {
	for i := range p.Options {
		if p.Options[i].Code == code {
			return &p.Options[i]
		}
	}
	return nil
}

// --- helpers ---

func ipZero(ip net.IP) bool {
	ip4 := ip.To4()
	return ip4 == nil || ip4.Equal(net.IPv4zero)
}

func ipLit(ip net.IP) string {
	ip4 := ip.To4()
	if ip4 == nil {
		return "net.IPv4(0,0,0,0)"
	}
	return fmt.Sprintf("net.IPv4(%d,%d,%d,%d)", ip4[0], ip4[1], ip4[2], ip4[3])
}

func hwLit(b []byte) string {
	return fmt.Sprintf("net.HardwareAddr{%s}", bytesLit(b))
}

func hwAddrLit(mac net.HardwareAddr) string {
	return fmt.Sprintf("net.HardwareAddr{%s}", bytesLit([]byte(mac)))
}

func bytesLit(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	parts := make([]string, len(b))
	for i, v := range b {
		parts[i] = fmt.Sprintf("0x%02x", v)
	}
	return strings.Join(parts, ", ")
}
