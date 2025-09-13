package tftp

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"path"
	"strings"
	"sync/atomic"
	"time"

	"github.com/srcreigh/pxehost/internal/capture"
)

// Minimal TFTP server that proxies RRQ (read) requests by fetching the
// requested filename from an upstream base URL (e.g. https://boot.netboot.xyz/ipxe/)
// and streaming it to the client using standard 512-byte TFTP blocks.
//
// It supports:
// - RRQ in mode "octet"
// - Optional OACK for tsize/blksize (blksize fixed to 512)
// - Retries with simple timeouts
//
// This is intentionally small and purpose-built for serving the initial iPXE
// binaries; it is not a full TFTP implementation.

type Server struct {
	// Provider supplies bootfiles by name.
	Provider BootfileProvider

	// Logger is optional. If nil, the package-level log.Printf is used.
	Logger *log.Logger

	conn   *net.UDPConn
	nextID uint64

	Port int

	// PacketLog, when non-nil, receives JSONL entries for UDP packets.
	PacketLog capture.PacketLogger
}

func (s *Server) StartAsync() error {
	if s.Provider == nil {
		return fmt.Errorf("tftp: Provider must be set")
	}
	addr, err := net.ResolveUDPAddr("udp4", fmt.Sprintf(":%d", s.Port))
	if err != nil {
		return fmt.Errorf("tftp: resolve :%d: %w", s.Port, err)
	}
	c, err := net.ListenUDP("udp4", addr)
	if err != nil {
		return fmt.Errorf("tftp: listen :%d: %w", s.Port, err)
	}
	s.conn = c
	s.logf("listening on UDP :%d", s.Port)
	go s.serve()
	return nil
}

func (s *Server) Close() error {
	if s.conn != nil {
		if err := s.conn.Close(); err != nil {
			return fmt.Errorf("tftp: close listener: %w", err)
		}
	}
	return nil
}

func (s *Server) serve() {
	buf := make([]byte, 2048)
	for {
		n, raddr, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			// Suppress expected errors when the socket is closed on shutdown.
			if isNetClosed(err) {
				return
			}
			s.logf("read error: %v", err)
			return
		}
		// Packet capture: inbound request to port 69
		if s.PacketLog != nil {
			lip := ""
			lport := 0
			if la, ok := s.conn.LocalAddr().(*net.UDPAddr); ok && la != nil {
				lip = la.IP.String()
				lport = la.Port
			}
			s.PacketLog.Log(capture.MakePacket(
				capture.DirIn,
				"TFTP",
				lip, lport,
				raddr.IP.String(), raddr.Port,
				"rrq",
				append([]byte(nil), buf[:n]...),
			))
		}
		// Handle each request in its own goroutine
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		go s.handleRRQ(pkt, raddr)
	}
}

// isNetClosed reports whether err indicates the UDP socket was closed.
func isNetClosed(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, net.ErrClosed) {
		return true
	}
	return strings.Contains(err.Error(), "use of closed network connection")
}

const (
	opRRQ   = 1
	opDATA  = 3
	opACK   = 4
	opERROR = 5
	opOACK  = 6 // RFC 2347
)

func (s *Server) handleRRQ(req []byte, client *net.UDPAddr) {
	// Parse minimal RRQ: | 2 bytes opcode | filename 0 | mode 0 | [opt 0 val 0] ...
	if len(req) < 4 || (int(req[0])<<8|int(req[1])) != opRRQ {
		return
	}
	sid := atomic.AddUint64(&s.nextID, 1)
	// Extract zero-terminated strings
	i := 2
	nextz := func() (string, bool) {
		if i >= len(req) {
			return "", false
		}
		j := i
		for j < len(req) && req[j] != 0 {
			j++
		}
		if j >= len(req) {
			return "", false
		}
		s := string(req[i:j])
		i = j + 1
		return s, true
	}
	filename, ok := nextz()
	if !ok || filename == "" {
		s.sendError(client, 0, "malformed RRQ")
		return
	}
	mode, ok := nextz()
	if !ok || mode == "" {
		s.sendError(client, 0, "malformed RRQ mode")
		return
	}
	if strings.ToLower(mode) != "octet" {
		s.logf("sid=%d client=%s unsupported mode=%q for file=%q", sid, client.String(), mode, filename)
		s.sendError(client, 0, "only octet mode supported")
		return
	}

	// Parse any options (key/value zero-terminated pairs)
	opts := map[string]string{}
	for i < len(req) {
		k, ok := nextz()
		if !ok || k == "" {
			break
		}
		v, ok := nextz()
		if !ok {
			break
		}
		opts[strings.ToLower(k)] = v
	}

	// Sanitize path: avoid path traversal; use last element
	cleanName := path.Base(strings.TrimLeft(filename, "/\\"))

	s.logf("sid=%d client=%s rrq file=%q clean=%q mode=%s opts=%v", sid, client.String(), filename, cleanName, strings.ToLower(mode), opts)

	// Obtain bootfile from provider
	body, size, err := s.Provider.GetBootfile(cleanName)
	if err != nil {
		s.logf("sid=%d provider fetch failed file=%q err=%v", sid, cleanName, err)
		s.sendError(client, 1, "file not found")
		return
	}
	defer func() {
		_ = body.Close()
	}()

	// Create session socket bound to ephemeral port
	sessConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		s.logf("sid=%d failed to open session socket: %v", sid, err)
		s.sendError(client, 0, "internal error")
		return
	}
	defer func() {
		_ = sessConn.Close()
	}()
	s.logf("sid=%d session started laddr=%s raddr=%s size=%d", sid, sessConn.LocalAddr().String(), client.String(), size)

	// Option negotiation: if client requested options, send OACK for tsize/blksize
	// We fix blksize=512; if requested a different value, we still respond with 512.
	wantOACK := len(opts) > 0
	if wantOACK {
		oackMap := map[string]string{
			"tsize": fmt.Sprintf("%d", size),
		}
		if _, has := opts["blksize"]; has {
			// echo blksize we can do (512)
			oackMap["blksize"] = "512"
		}
		s.logf("sid=%d oack request opts=%v respond=%v", sid, opts, oackMap)
		oack := buildOACK(oackMap)
		if err := sessConn.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
			s.logf("sid=%d set write deadline (OACK) error: %v", sid, err)
		}
		if _, err := sessConn.WriteToUDP(oack, client); err == nil && s.PacketLog != nil {
			lip := ""
			lport := 0
			if la, ok := sessConn.LocalAddr().(*net.UDPAddr); ok && la != nil {
				lip = la.IP.String()
				lport = la.Port
			}
			s.PacketLog.Log(capture.MakePacket(
				capture.DirOut,
				"TFTP",
				lip, lport,
				client.IP.String(), client.Port,
				"oack",
				append([]byte(nil), oack...),
			))
		}
		// Wait for ACK block 0
		buf := make([]byte, 1500)
		if err := sessConn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			s.logf("sid=%d set read deadline (OACK ACK wait) error: %v", sid, err)
		}
		n, raddr, err := sessConn.ReadFromUDP(buf)
		if err != nil || raddr == nil || !raddr.IP.Equal(client.IP) || raddr.Port != client.Port {
			s.logf("sid=%d no ACK(0) after OACK from %s err=%v", sid, client.String(), err)
			// proceed anyway (some clients may accept data immediately)
		} else if n >= 4 && (int(buf[0])<<8|int(buf[1])) == opACK && int(buf[2]) == 0 && int(buf[3]) == 0 {
			// ok
			s.logf("sid=%d received ACK(0) after OACK", sid)
			if s.PacketLog != nil {
				lip := ""
				lport := 0
				if la, ok := sessConn.LocalAddr().(*net.UDPAddr); ok && la != nil {
					lip = la.IP.String()
					lport = la.Port
				}
				s.PacketLog.Log(capture.MakePacket(
					capture.DirIn,
					"TFTP",
					lip, lport,
					raddr.IP.String(), raddr.Port,
					"ack(0)",
					append([]byte(nil), buf[:n]...),
				))
			}
		}
	}

	// Stream file as 512-byte blocks and await ACKs
	const blockSize = 512
	blockNum := uint16(1)
	tmp := make([]byte, blockSize)
	var total int64
	start := time.Now()
	for {
		// Read next chunk
		n, rerr := io.ReadFull(body, tmp)
		switch rerr {
		case io.ErrUnexpectedEOF:
			// last partial block; use n as is
		case io.EOF:
			n = 0
		case nil:
			// ok
		default:
			s.logf("sid=%d read error from upstream: %v", sid, rerr)
			s.sendError(client, 0, "read error")
			return
		}
		data := tmp[:n]

		// Send DATA and wait for matching ACK
		pkt := make([]byte, 4+len(data))
		pkt[0], pkt[1] = 0, opDATA
		pkt[2] = byte(blockNum >> 8)
		pkt[3] = byte(blockNum)
		copy(pkt[4:], data)

		const maxRetry = 5
		acked := false
		for attempt := 0; attempt < maxRetry; attempt++ {
			if err := sessConn.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
				s.logf("sid=%d set write deadline (DATA) error: %v", sid, err)
			}
			if _, err := sessConn.WriteToUDP(pkt, client); err != nil {
				s.logf("sid=%d write error to %s: %v", sid, client.String(), err)
				// retry on transient errors; next attempt will resend
				continue
			}
			if s.PacketLog != nil {
				lip := ""
				lport := 0
				if la, ok := sessConn.LocalAddr().(*net.UDPAddr); ok && la != nil {
					lip = la.IP.String()
					lport = la.Port
				}
				s.PacketLog.Log(capture.MakePacket(
					capture.DirOut,
					"TFTP",
					lip, lport,
					client.IP.String(), client.Port,
					fmt.Sprintf("data(block=%d)", blockNum),
					append([]byte(nil), pkt...),
				))
			}
			// Wait for ACK
			buf := make([]byte, 1500)
			if err := sessConn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
				s.logf("sid=%d set read deadline (ACK wait) error: %v", sid, err)
			}
			n, raddr, err := sessConn.ReadFromUDP(buf)
			if err != nil {
				if attempt+1 < maxRetry {
					s.logf("sid=%d timeout waiting ACK for block=%d attempt=%d/%d", sid, blockNum, attempt+1, maxRetry)
				}
				// retry
				continue
			}
			if raddr == nil || !raddr.IP.Equal(client.IP) || raddr.Port != client.Port {
				// ignore stray
				attempt--
				continue
			}
			if n >= 4 && (int(buf[0])<<8|int(buf[1])) == opACK {
				ackNum := uint16(buf[2])<<8 | uint16(buf[3])
				if ackNum == blockNum {
					if s.PacketLog != nil {
						lip := ""
						lport := 0
						if la, ok := sessConn.LocalAddr().(*net.UDPAddr); ok && la != nil {
							lip = la.IP.String()
							lport = la.Port
						}
						s.PacketLog.Log(capture.MakePacket(
							capture.DirIn,
							"TFTP",
							lip, lport,
							raddr.IP.String(), raddr.Port,
							fmt.Sprintf("ack(%d)", ackNum),
							append([]byte(nil), buf[:n]...),
						))
					}
					acked = true
					break // proceed to next block
				}
				// duplicate/old ack: retry read for our expected ack
				attempt--
				continue
			}
		}
		if !acked {
			// Give up on this transfer after max retries without ACK
			s.logf("sid=%d no ACK for block=%d from %s after %d attempts; aborting session", sid, blockNum, client.String(), maxRetry)
			return
		}

		// If last block (<512), transfer complete
		if len(data) < blockSize {
			total += int64(len(data))
			dur := time.Since(start)
			rate := float64(total) / dur.Seconds()
			s.logf("sid=%d transfer complete bytes=%d blocks=%d duration=%s rate=%.0fB/s", sid, total, int(blockNum), dur.Truncate(time.Millisecond), rate)
			return
		}
		total += int64(len(data))
		blockNum++
		if blockNum == 0 { // wrap (rare, huge file). TFTP wraps at 65535->0->1
			blockNum = 1
		}
	}
}

func (s *Server) sendError(dst *net.UDPAddr, code int, msg string) {
	if s.conn == nil || dst == nil {
		return
	}
	// ERROR packet: | 0 5 | code(2) | msg | 0 |
	b := make([]byte, 4+len(msg)+1)
	b[0], b[1] = 0, opERROR
	b[2] = byte(code >> 8)
	b[3] = byte(code)
	copy(b[4:], []byte(msg))
	if err := s.conn.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
		s.logf("set write deadline (ERROR pkt) error: %v", err)
	}
	if _, err := s.conn.WriteToUDP(b, dst); err == nil && s.PacketLog != nil {
		lip := ""
		lport := 0
		if la, ok := s.conn.LocalAddr().(*net.UDPAddr); ok && la != nil {
			lip = la.IP.String()
			lport = la.Port
		}
		s.PacketLog.Log(capture.MakePacket(
			capture.DirOut,
			"TFTP",
			lip, lport,
			dst.IP.String(), dst.Port,
			"error",
			append([]byte(nil), b...),
		))
	}
	s.logf("sent ERROR to %s code=%d msg=%q", dst.String(), code, msg)
}

func buildOACK(kv map[string]string) []byte {
	// OACK packet: | 0 6 | k 0 v 0 ... |
	// Note: caller should ensure deterministic key order if needed; not required here.
	out := []byte{0, opOACK}
	for k, v := range kv {
		out = append(out, []byte(k)...)
		out = append(out, 0)
		out = append(out, []byte(v)...)
		out = append(out, 0)
	}
	return out
}

// logf logs via the server's Logger if provided, else the package logger.
func (s *Server) logf(format string, args ...any) {
	if s == nil {
		return
	}
	if s.Logger != nil {
		s.Logger.Printf("TFTP: "+format, args...)
		return
	}
	log.Printf("TFTP: "+format, args...)
}
