package tftp

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
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

type ListenFunc func(network string, laddr *net.UDPAddr) (net.PacketConn, error)

type Server struct {
	// Provider supplies bootfiles by name.
	Provider BootfileProvider

	// Logger must be provided.
	Logger *slog.Logger

	ListenUDP ListenFunc

	conn   net.PacketConn
	nextID uint64

	Port int

	// PacketLog, when non-nil, receives JSONL entries for UDP packets.
	PacketLog capture.PacketLogger
}

// logPacket captures a UDP packet via PacketLog using addressing derived from
// the provided local UDP connection and the given remote address. No-ops if
// PacketLog is nil or inputs are incomplete. Payload is defensively copied.
func (s *Server) logPacket(conn net.PacketConn, dir capture.Direction, remote net.UDPAddr, note string, payload []byte) {
	if s == nil || s.PacketLog == nil || conn == nil {
		return
	}
	lip := ""
	lport := 0
	if la, ok := conn.LocalAddr().(*net.UDPAddr); ok && la != nil {
		lip = la.IP.String()
		lport = la.Port
	}
	rip := remote.IP.String()
	rport := remote.Port
	// Copy payload to decouple from caller's buffer reuse
	cp := append([]byte(nil), payload...)
	s.PacketLog.Log(capture.MakePacket(
		dir,
		"TFTP",
		lip, lport,
		rip, rport,
		note,
		cp,
	))
}

func (s *Server) StartAsync() error {
	if s.Provider == nil {
		return fmt.Errorf("tftp: Provider must be set")
	}
	if s.Logger == nil {
		return fmt.Errorf("tftp: Logger must be set")
	}
	if s.ListenUDP == nil {
		return fmt.Errorf("tftp: ListenUDP must be set")
	}
	addr, err := net.ResolveUDPAddr("udp4", fmt.Sprintf(":%d", s.Port))
	if err != nil {
		return fmt.Errorf("tftp: resolve :%d: %w", s.Port, err)
	}
	c, err := s.ListenUDP("udp4", addr)
	if err != nil {
		return fmt.Errorf("tftp: listen :%d: %w", s.Port, err)
	}
	s.conn = c
	s.Logger.Info(fmt.Sprintf("TFTP: listening on UDP :%d", s.Port))
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

// BoundPort returns the actual UDP port the server is listening on.
// It returns 0 if the server has not been started.
func (s *Server) BoundPort() int {
	if s == nil || s.conn == nil {
		return 0
	}
	if la, ok := s.conn.LocalAddr().(*net.UDPAddr); ok && la != nil {
		return la.Port
	}
	return 0
}

func (s *Server) serve() {
	buf := make([]byte, 2048)
	for {
		pkt, n, raddr, err := readFromConn(s.conn, buf, nil)
		if err != nil {
			// Suppress expected errors when the socket is closed on shutdown.
			if isNetClosed(err) {
				return
			}
			s.Logger.Error(fmt.Sprintf("TFTP: read error: %v", err))
			return
		}
		// Packet capture: inbound request to port 69
		switch rrq := pkt.(type) {
		case *ReadReq:
			s.logPacket(s.conn, capture.DirIn, *raddr, "rrq", buf[:n])
			go s.handleRRQ(rrq, raddr)
		default:
			s.Logger.Warn(fmt.Sprintf("TFTP: ignoring unsupported packet type from %s: %T", raddr.String(), pkt))
		}
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

func readFromConn(conn net.PacketConn, buf []byte, deadline *time.Time) (Packet, int, *net.UDPAddr, error) {
	if deadline != nil {
		if err := conn.SetReadDeadline(*deadline); err != nil {
			return nil, 0, nil, fmt.Errorf("set read deadline: %w", err)
		}
	}
	n, raddr, err := conn.ReadFrom(buf)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("read from: %w", err)
	}
	rudp, ok := raddr.(*net.UDPAddr)
	if !ok || rudp == nil {
		return nil, 0, nil, fmt.Errorf("read from: not UDP raddr")
	}
	pkt, err := ParsePacket(buf[:n])
	if err != nil {
		return nil, 0, nil, fmt.Errorf("parse packet: %w", err)
	}
	return pkt, n, rudp, nil
}

func (s *Server) handleRRQ(req *ReadReq, client *net.UDPAddr) {
	sid := atomic.AddUint64(&s.nextID, 1)
	if strings.ToLower(req.Mode) != "octet" {
		s.Logger.Warn(fmt.Sprintf("TFTP: sid=%d client=%s unsupported mode=%q for file=%q", sid, client.String(), req.Mode, req.Filename))
		s.sendError(client, 0, "only octet mode supported")
		return
	}

	s.Logger.Info(fmt.Sprintf("TFTP: sid=%d client=%s rrq file=%q mode=%s opts=%v", sid, client.String(), req.Filename, strings.ToLower(req.Mode), req.Options))

	// Obtain bootfile from provider
	body, size, err := s.Provider.GetBootfile(req.Filename)
	if err != nil {
		s.Logger.Error(fmt.Sprintf("TFTP: sid=%d provider fetch failed file=%q err=%v", sid, req.Filename, err))
		s.sendError(client, 1, "file not found")
		return
	}
	defer func() {
		_ = body.Close()
	}()

	// Create session socket bound to ephemeral port
	sessConn, err := s.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	s.Logger.Info(fmt.Sprintf("TFTP: sid=%d listening at %s", sid, sessConn.LocalAddr()))
	if err != nil {
		s.Logger.Error(fmt.Sprintf("TFTP: sid=%d failed to open session socket: %v", sid, err))
		s.sendError(client, 0, "internal error")
		return
	}
	defer func() {
		_ = sessConn.Close()
	}()
	s.Logger.Info(fmt.Sprintf("TFTP: sid=%d session started laddr=%s raddr=%s size=%d", sid, sessConn.LocalAddr().String(), client.String(), size))

	// Option negotiation: if client requested options, send OACK for tsize/blksize
	// We fix blksize=512; if requested a different value, we still respond with 512.
	if len(req.Options) > 0 {
		oackMap := map[string]string{}
		if _, has := req.Options["tsize"]; has {
			oackMap["tsize"] = fmt.Sprintf("%d", size)
		}
		if _, has := req.Options["blksize"]; has {
			oackMap["blksize"] = "512"
		}
		s.Logger.Info(fmt.Sprintf("TFTP: sid=%d oack request opts=%v respond=%v", sid, req.Options, oackMap))
		oack := buildOACK(oackMap)
		if err := sessConn.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
			s.Logger.Warn(fmt.Sprintf("TFTP: sid=%d set write deadline (OACK) error: %v", sid, err))
		}
		if _, err := sessConn.WriteTo(oack, client); err == nil {
			s.logPacket(sessConn, capture.DirOut, *client, "oack", oack)
		}
		s.Logger.Info(fmt.Sprintf("TFTP: sid=%d sent oack opts=%v respond=%v", sid, req.Options, oackMap))
		s.Logger.Info(fmt.Sprintf("TFTP: sid=%d waiting for ack(0) opts=%v respond=%v", sid, req.Options, oackMap))
		// Wait for ACK block 0
		buf := make([]byte, 1500)
		deadline := time.Now().Add(100 * time.Millisecond)
		for {
			// readFromConn
			pkt, n, raddr, err := readFromConn(sessConn, buf, &deadline)
			if err != nil {
				if strings.Contains(err.Error(), "i/o timeout") {
					// read timed out
					s.Logger.Info(fmt.Sprintf("TFTP: sid=%d oack read timed out %s", sid, s.conn.LocalAddr().String()))
					break
				}
				if !isNetClosed(err) {
					s.Logger.Warn(fmt.Sprintf("TFTP: sid=%d oack read err=%v", sid, err))
				}
				continue
			}
			switch ack := pkt.(type) {
			case *Ack:
				if ack.Block == 0 {
					s.Logger.Info(fmt.Sprintf("TFTP: sid=%d received ACK(0) after OACK", sid))
					s.logPacket(sessConn, capture.DirIn, *raddr, "ack(0)", buf[:n])
					break
				}
			default:
				s.Logger.Info(fmt.Sprintf("TFTP: sid=%d received wrong pkt type waiting for OACK", sid))
				continue
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
			s.Logger.Error(fmt.Sprintf("TFTP: sid=%d read error from upstream: %v", sid, rerr))
			s.sendError(client, 0, "read error")
			return
		}
		data := tmp[:n]

		// Send DATA and wait for matching ACK
		pkt := make([]byte, 4+len(data))
		pkt[0], pkt[1] = 0, byte(DATA)
		pkt[2] = byte(blockNum >> 8)
		pkt[3] = byte(blockNum)
		copy(pkt[4:], data)

		const maxRetry = 5
		acked := false
		for attempt := 0; attempt < maxRetry; attempt++ {
			if err := sessConn.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
				s.Logger.Warn(fmt.Sprintf("TFTP: sid=%d set write deadline (DATA) error: %v", sid, err))
			}
			if _, err := sessConn.WriteTo(pkt, client); err != nil {
				s.Logger.Warn(fmt.Sprintf("TFTP: sid=%d write error to %s: %v", sid, client.String(), err))
				// retry on transient errors; next attempt will resend
				continue
			}
			s.Logger.Debug("TFTP: sent block", "block", blockNum)
			s.logPacket(sessConn, capture.DirOut, *client, fmt.Sprintf("data(block=%d)", blockNum), pkt)

			// Wait for ACK
			buf := make([]byte, 1500)
			deadline := time.Now().Add(2 * time.Second)
			pkt, n, raddr, err := readFromConn(sessConn, buf, &deadline)
			if err != nil {
				if attempt+1 < maxRetry {
					s.Logger.Warn(fmt.Sprintf("TFTP: sid=%d timeout waiting ACK for block=%d attempt=%d/%d", sid, blockNum, attempt+1, maxRetry))
				}
				// retry
				continue
			}
			if !raddr.IP.Equal(client.IP) || raddr.Port != client.Port {
				// ignore stray
				attempt--
				continue
			}
			switch ack := pkt.(type) {
			case *Ack:
				if ack.Block == blockNum {
					s.logPacket(sessConn, capture.DirIn, *raddr, fmt.Sprintf("ack(%d)", ack.Block), buf[:n])
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
			s.Logger.Warn(fmt.Sprintf("TFTP: sid=%d no ACK for block=%d from %s after %d attempts; aborting session", sid, blockNum, client.String(), maxRetry))
			return
		}

		// If last block (<512), transfer complete
		if len(data) < blockSize {
			total += int64(len(data))
			dur := time.Since(start)
			rate := float64(total) / dur.Seconds()
			s.Logger.Info(fmt.Sprintf("TFTP: sid=%d transfer complete bytes=%d blocks=%d duration=%s rate=%.0fB/s", sid, total, int(blockNum), dur.Truncate(time.Millisecond), rate))
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
	b[0], b[1] = 0, byte(ERROR)
	b[2] = byte(code >> 8)
	b[3] = byte(code)
	copy(b[4:], []byte(msg))
	if err := s.conn.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
		s.Logger.Warn(fmt.Sprintf("TFTP: set write deadline (ERROR pkt) error: %v", err))
	}
	if _, err := s.conn.WriteTo(b, dst); err == nil {
		s.logPacket(s.conn, capture.DirOut, *dst, "error", b)
	}
	s.Logger.Info(fmt.Sprintf("TFTP: sent ERROR to %s code=%d msg=%q", dst.String(), code, msg))
}

func buildOACK(kv map[string]string) []byte {
	// OACK packet: | 0 6 | k 0 v 0 ... |
	// Note: caller should ensure deterministic key order if needed; not required here.
	out := []byte{0, byte(OACK)}
	for k, v := range kv {
		out = append(out, []byte(k)...)
		out = append(out, 0)
		out = append(out, []byte(v)...)
		out = append(out, 0)
	}
	return out
}
