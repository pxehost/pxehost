package capture

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// Direction indicates whether the packet was read from or written to the socket.
type Direction string

const (
	DirIn  Direction = "in"
	DirOut Direction = "out"
)

// UDPPacket describes a UDP datagram with metadata sufficient for replay.
type UDPPacket struct {
	// RFC3339Nano timestamp for stable ordering and human readability
	Time string `json:"time"`

	// Direction of travel relative to the server process
	Direction Direction `json:"dir"`

	// Component indicates which subsystem generated/saw the packet (e.g. "DHCP", "PXE", "TFTP")
	Component string `json:"component"`

	// Local/remote addressing
	LocalIP    string `json:"l_ip"`
	LocalPort  int    `json:"l_port"`
	RemoteIP   string `json:"r_ip"`
	RemotePort int    `json:"r_port"`

	// Optional contextual note (e.g., "oack", "data", "ack")
	Note string `json:"note,omitempty"`

	// Payload is base64-encoded for lossless binary capture
	PayloadB64 string `json:"payload_b64"`
}

// PacketLogger records packets. Implementations must be safe for concurrent use.
type PacketLogger interface {
	Log(pkt UDPPacket)
}

// JSONLLogger writes one JSON document per line to a file.
// Safe for concurrent use.
type JSONLLogger struct {
	mu  sync.Mutex
	f   *os.File
	buf *bufio.Writer
}

// NewJSONLLogger creates or truncates the file at path and returns a logger.
func NewJSONLLogger(path string) (*JSONLLogger, error) {
	// #nosec G304 -- path comes from trusted configuration, used to create a log file
	f, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("create packet log: %w", err)
	}
	return &JSONLLogger{f: f, buf: bufio.NewWriterSize(f, 64<<10)}, nil
}

// Close flushes and closes the underlying file.
func (l *JSONLLogger) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.buf != nil {
		_ = l.buf.Flush()
	}
	if l.f != nil {
		if err := l.f.Close(); err != nil {
			return fmt.Errorf("packet log close: %w", err)
		}
	}
	return nil
}

// Log writes a packet entry as a single JSON line.
func (l *JSONLLogger) Log(pkt UDPPacket) {
	if l == nil {
		return
	}
	// Fill timestamp if absent to make callers simpler
	if pkt.Time == "" {
		pkt.Time = time.Now().UTC().Format(time.RFC3339Nano)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	enc := json.NewEncoder(l.buf)
	// Disable HTML escaping for readability
	enc.SetEscapeHTML(false)
	if err := enc.Encode(pkt); err != nil {
		// Best-effort logger: swallow encode errors to keep services running
		return
	}
}

// MakePacket constructs a UDPPacket JSON entry with base64 payload.
func MakePacket(dir Direction, component, lip string, lport int, rip string, rport int, note string, payload []byte) UDPPacket {
	return UDPPacket{
		Time:       time.Now().UTC().Format(time.RFC3339Nano),
		Direction:  dir,
		Component:  component,
		LocalIP:    lip,
		LocalPort:  lport,
		RemoteIP:   rip,
		RemotePort: rport,
		Note:       note,
		PayloadB64: base64.StdEncoding.EncodeToString(payload),
	}
}
