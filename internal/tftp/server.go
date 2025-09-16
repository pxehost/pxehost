package tftp

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
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

type Server struct {
	Provider BootfileProvider
	Logger   *slog.Logger

	conn   *net.UDPConn
	nextID uint64

	Port int

	// nullable
	PacketLog capture.PacketLogger
}

func (s *Server) StartAsync() error {
	if s.Provider == nil {
		return fmt.Errorf("tftp: Provider must be set")
	}
	if s.Logger == nil {
		return fmt.Errorf("tftp: Logger must be set")
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

		switch rrq := pkt.(type) {
		case *ReadReq:
			s.logPacket(s.conn, capture.DirIn, *raddr, "rrq", buf[:n])
			go s.handleRRQ(rrq, raddr)
		default:
			s.logPacket(s.conn, capture.DirIn, *raddr, "???", buf[:n])
			s.Logger.Info(fmt.Sprintf("TFTP: ignoring unsupported packet type from %s: %T", raddr.String(), pkt))
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

func readFromConn(conn *net.UDPConn, buf []byte, deadline *time.Time) (Packet, int, *net.UDPAddr, error) {
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
		s.Logger.Info(fmt.Sprintf("TFTP: sid=%d client=%s unsupported mode=%q for file=%q",
			sid, client.String(), req.Mode, req.Filename))
		s.sendError(client, 0, "only octet mode supported")
		return
	}

	s.Logger.Info(fmt.Sprintf("TFTP: sid=%d received rrq client=%s file=%q opts=%v",
		sid, client.String(), req.Filename, req.Options))

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
	sessConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		s.Logger.Error(fmt.Sprintf("TFTP: sid=%d failed to open session socket: %v", sid, err))
		s.sendError(client, 0, "internal error")
		return
	}
	defer func() {
		_ = sessConn.Close()
	}()
	s.Logger.Info(fmt.Sprintf("TFTP: sid=%d session started laddr=%s raddr=%s size=%d",
		sid, sessConn.LocalAddr().String(), client.String(), size))

	// Option negotiation: if client requested options, send OACK for tsize/blksize
	// We fix blksize=512; if requested a different value, we still respond with 512.
	if len(req.Options) > 0 {
		pkt := OAck{
			Options: map[string]string{},
		}
		if _, has := req.Options["tsize"]; has {
			pkt.Options["tsize"] = fmt.Sprintf("%d", size)
		}
		if _, has := req.Options["blksize"]; has {
			pkt.Options["blksize"] = "512"
		}
		s.Logger.Info(fmt.Sprintf("TFTP: sid=%d oack request opts=%v respond=%v", sid, req.Options, pkt.Options))
		acked := s.retrySendAndAwaitAck(
			sessConn, client, &pkt,
		)

		if !acked {
			s.Logger.Info(fmt.Sprintf("TFTP: sid=%d did not receive ACK(0); closing session", sid))
			return
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
		pkt := Data{
			Block: blockNum,
			Data:  data,
		}

		maxRetries := 5
		acked := s.retrySendAndAwaitAck(sessConn, client, &pkt)

		if !acked {
			// Give up on this transfer after max retries without ACK
			s.Logger.Info(fmt.Sprintf("TFTP: sid=%d no ACK for block=%d from %s after %d attempts; aborting session",
				sid, blockNum, client.String(), maxRetries))
			return
		}

		// If last block (<512), transfer complete
		if len(data) < blockSize {
			total += int64(len(data))
			dur := time.Since(start)
			rate := float64(total) / dur.Seconds()
			s.Logger.Info(fmt.Sprintf("TFTP: sid=%d transfer complete bytes=%d blocks=%d duration=%s rate=%.0fB/s",
				sid, total, int(blockNum), dur.Truncate(time.Millisecond), rate))
			return
		}
		total += int64(len(data))
		blockNum++
		if blockNum == 0 { // wrap (rare, huge file). TFTP wraps at 65535->0->1
			blockNum = 1
		}
	}
}

func (s *Server) retrySendAndAwaitAck(
	conn *net.UDPConn,
	dst *net.UDPAddr,
	pkt Packet,
) bool {
	buf := make([]byte, 1500)
	var blockNum uint16
	var label string
	switch pkt := pkt.(type) {
	case *OAck:
		blockNum = 0
		label = "oack"
	case *Data:
		blockNum = pkt.Block
		label = fmt.Sprintf("data(%d)", pkt.Block)
	default:
		s.Logger.Error(fmt.Sprintf("can't send packet type %T", pkt))
	}

	raw, err := Serialize(pkt)
	if err != nil {
		s.Logger.Error(fmt.Sprintf("serialize packet: %v", err))
		return false
	}

	maxAttempts := 5
	jitter := time.Duration(rand.Int63n(int64(40*time.Millisecond)*2)) - 20*time.Millisecond
	writeDeadline := 200 * time.Millisecond
	readDeadline := 200*time.Millisecond + jitter
	for attempt := 0; attempt < maxAttempts; attempt++ {
		// (re)send
		_ = conn.SetWriteDeadline(time.Now().Add(writeDeadline))
		if _, err := conn.WriteTo(raw, dst); err != nil {
			s.Logger.Warn(fmt.Sprintf("send error to %s: %v", dst.String(), err))
			continue
		}
		s.logPacket(s.conn, capture.DirOut, *dst, label, raw)

		// await response
		deadline := time.Now().Add(readDeadline)
		pkt, n, raddr, err := readFromConn(conn, buf, &deadline)
		if err != nil {
			// timeout → next attempt
			if strings.Contains(err.Error(), "timeout") && attempt+1 < maxAttempts {
				s.Logger.Warn(fmt.Sprintf("timeout waiting for %s attempt=%d/%d", label, attempt+1, maxAttempts))
			}
			continue
		}
		// ignore stray packets without burning an attempt
		if !raddr.IP.Equal(dst.IP) || raddr.Port != dst.Port {
			attempt--
			continue
		}
		switch ack := pkt.(type) {
		case *Ack:
			if ack.Block == blockNum {
				s.logPacket(s.conn, capture.DirIn, *raddr, fmt.Sprintf("ack(%d)", blockNum), buf[:n])
				return true
			}
			attempt--
		default:
			attempt--
		}
	}
	return false
}

func (s *Server) sendError(dst *net.UDPAddr, code uint16, msg string) {
	if s.conn == nil || dst == nil {
		return
	}
	pkt := Err{
		Message: msg,
		Code:    code,
	}
	b, err := Serialize(&pkt)
	if err != nil {
		s.Logger.Error("could not serialize error packet")
		return
	}

	if err := s.conn.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
		s.Logger.Warn(fmt.Sprintf("TFTP: set write deadline (ERROR pkt) error: %v", err))
	}
	if _, err := s.conn.WriteTo(b, dst); err == nil {
		s.logPacket(s.conn, capture.DirOut, *dst, "error", b)
	}
	s.Logger.Info(fmt.Sprintf("TFTP: sent ERROR to %s code=%d msg=%q", dst.String(), code, msg))
}

// logPacket captures a UDP packet via PacketLog using addressing derived from
// the provided local UDP connection and the given remote address. No-ops if
// PacketLog is nil or inputs are incomplete. Payload is defensively copied.
func (s *Server) logPacket(
	conn net.PacketConn,
	dir capture.Direction,
	remote net.UDPAddr,
	note string,
	payload []byte,
) {
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
