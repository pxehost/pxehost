package app

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/srcreigh/pxehost/internal/capture"
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
	// Hardcoded capture path. Skip test if file missing.
	const capturePath = "/Users/shane/packetlog.json"
	if _, err := os.Stat(capturePath); errors.Is(err, os.ErrNotExist) {
		t.Skipf("capture file not found: %s (skipping)", filepath.Clean(capturePath))
	} else if err != nil {
		t.Fatalf("stat capture: %v", err)
	}

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
		WithPXEPort(0),
		WithTFTPPort(0),
		WithAdvertisedIP("192.168.0.31"),
		WithDHCPBroadcastPort(bp),
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

	type flowKey string
	const (
		flowDHCP flowKey = "dhcp"
		flowPXE  flowKey = "pxe"
	)
	conns := map[flowKey]*net.UDPConn{}
	conns[flowDHCP] = dhcpPXEConn
	conns[flowPXE] = dhcpPXEConn

	getConn := func(f flowKey) *net.UDPConn {
		if c := conns[f]; c != nil {
			return c
		}
		c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
		if err != nil {
			t.Fatalf("listen udp client for %s: %v", f, err)
		}
		conns[f] = c
		t.Cleanup(func() { _ = c.Close() })
		return c
	}

	lastFlow := map[string]flowKey{}

	type compCtx struct {
		lastInLine   int
		lastInSize   int
		lastInNote   string
		lastLocal    string
		lastRemote   string
		lastInPrefix string
	}
	ctxByComp := map[string]*compCtx{}

	totalOutExpected := 0
	outMatched := 0

	// Open the capture file and process line-by-line for DHCP/PXE only
	f, err := os.Open(capturePath)
	if err != nil {
		t.Fatalf("open capture: %v", err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64<<10), 1<<20)

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var pkt capture.UDPPacket
		if err := json.Unmarshal(line, &pkt); err != nil {
			t.Fatalf("decode json line %d: %v", lineNum, err)
		}
		// Skip TFTP entries; we'll do TFTP manually below.
		comp := strings.ToUpper(pkt.Component)
		if comp == "TFTP" {
			continue
		}

		payload, err := base64.StdEncoding.DecodeString(pkt.PayloadB64)
		if err != nil {
			t.Fatalf("decode payload (line %d): %v", lineNum, err)
		}

		// Map to correct flow/addr
		var flow flowKey
		var raddr *net.UDPAddr
		switch comp {
		case "DHCP":
			port := dhcpPort
			if strings.Contains(pkt.Note, "port=4011") || pkt.LocalPort == 4011 {
				port = pxePort
				flow = flowPXE
			} else {
				flow = flowDHCP
			}
			raddr = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}
		default:
			t.Fatalf("unsupported component in capture: %s", comp)
		}

		dir := strings.ToLower(string(pkt.Direction))
		tag := fmt.Sprintf("line=%d comp=%s dir=%s note=%s", lineNum, pkt.Component, dir, pkt.Note)

		switch dir {
		case "in":
			c := getConn(flow)
			if err := c.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
				t.Fatalf("set write deadline: %v", err)
			}
			if _, err := c.WriteToUDP(payload, raddr); err != nil {
				t.Fatalf("send (%s flow=%s) error: %v", tag, flow, err)
			}
			lp := c.LocalAddr().String()
			rp := raddr.String()
			pref := payload
			if len(pref) > 16 {
				pref = pref[:16]
			}
			ucomp := comp
			lastFlow[ucomp] = flow
			cc := ctxByComp[ucomp]
			if cc == nil {
				cc = &compCtx{}
				ctxByComp[ucomp] = cc
			}
			cc.lastInLine = lineNum
			cc.lastInSize = len(payload)
			cc.lastInNote = pkt.Note
			cc.lastLocal = lp
			cc.lastRemote = rp
			cc.lastInPrefix = fmt.Sprintf("%x", pref)
		case "out":
			totalOutExpected++
			flowToUse := lastFlow[comp]
			if flowToUse == "" {
				flowToUse = flow
			}
			c := getConn(flowToUse)
			deadline := time.Now().Add(250 * time.Millisecond)
			matched := false
			var lastErr error
			for !matched && time.Now().Before(deadline) {
				if err := c.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
					t.Fatalf("set read deadline: %v", err)
				}
				buf := make([]byte, 4096)
				n, _, err := c.ReadFromUDP(buf)
				if err != nil {
					lastErr = err
					continue
				}
				got := buf[:n]
				if bytes.Equal(got, payload) {
					matched = true
					outMatched++
					break
				}
			}
			if !matched {
				if cc := ctxByComp[comp]; cc != nil {
					t.Fatalf("recv timeout %s flow=%s on=%s err=%v | last_in: line=%d note=%s from=%s->%s bytes=%d prefix=%s",
						tag, flowToUse, c.LocalAddr().String(), lastErr, cc.lastInLine, cc.lastInNote, cc.lastLocal, cc.lastRemote, cc.lastInSize, cc.lastInPrefix)
				}
				t.Fatalf("recv (%s flow=%s on=%s): %v", tag, flowToUse, c.LocalAddr().String(), lastErr)
			}
		default:
			t.Fatalf("line %d: unknown direction: %q", lineNum, dir)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan capture: %v", err)
	}

	if outMatched != totalOutExpected {
		t.Fatalf("not all expected DHCP/PXE packets were received: matched=%d total_expected=%d", outMatched, totalOutExpected)
	}

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
}
