package tftp

import (
    "context"
    "errors"
    "fmt"
    "io"
    "log"
    "net"
    "net/http"
    "path"
    "strings"
    "time"
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
    // UpstreamBase is the HTTP(S) base used to fetch files, e.g.
    // "https://boot.netboot.xyz/ipxe/". The requested filename will be joined
    // to this base and fetched via GET.
    UpstreamBase string

    conn *net.UDPConn
}

func (s *Server) StartAsync() error {
    if s.UpstreamBase == "" {
        return errors.New("tftp: UpstreamBase must be set")
    }
    // Normalize base to ensure it ends with '/'
    if !strings.HasSuffix(s.UpstreamBase, "/") {
        s.UpstreamBase += "/"
    }
    addr, err := net.ResolveUDPAddr("udp4", ":69")
    if err != nil {
        return err
    }
    c, err := net.ListenUDP("udp4", addr)
    if err != nil {
        return err
    }
    s.conn = c
    log.Printf("TFTP: listening on UDP :69, proxying to %s", s.UpstreamBase)
    go s.serve()
    return nil
}

func (s *Server) Close() error {
    if s.conn != nil {
        return s.conn.Close()
    }
    return nil
}

func (s *Server) serve() {
    buf := make([]byte, 2048)
    for {
        n, raddr, err := s.conn.ReadFromUDP(buf)
        if err != nil {
            log.Printf("TFTP: read error: %v", err)
            return
        }
        // Handle each request in its own goroutine
        pkt := make([]byte, n)
        copy(pkt, buf[:n])
        go s.handleRRQ(pkt, raddr)
    }
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
    upstream := s.UpstreamBase + cleanName

    // Fetch upstream file into memory
    ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
    defer cancel()
    body, size, err := fetch(ctx, upstream)
    if err != nil {
        log.Printf("TFTP: fetch failed for %q: %v", upstream, err)
        s.sendError(client, 1, "file not found")
        return
    }
    defer body.Close()

    // Create session socket bound to ephemeral port
    sessConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
    if err != nil {
        s.sendError(client, 0, "internal error")
        return
    }
    defer sessConn.Close()

    // Option negotiation: if client requested options, send OACK for tsize/blksize
    // We fix blksize=512; if requested a different value, we still respond with 512.
    wantOACK := len(opts) > 0
    if wantOACK {
        oack := buildOACK(map[string]string{
            "tsize":   fmt.Sprintf("%d", size),
        })
        if _, has := opts["blksize"]; has {
            // echo blksize we can do (512)
            oack = buildOACK(map[string]string{
                "tsize":   fmt.Sprintf("%d", size),
                "blksize": "512",
            })
        }
        sessConn.SetWriteDeadline(time.Now().Add(2 * time.Second))
        _, _ = sessConn.WriteToUDP(oack, client)
        // Wait for ACK block 0
        buf := make([]byte, 1500)
        sessConn.SetReadDeadline(time.Now().Add(5 * time.Second))
        n, raddr, err := sessConn.ReadFromUDP(buf)
        if err != nil || raddr == nil || !raddr.IP.Equal(client.IP) || raddr.Port != client.Port {
            log.Printf("TFTP: no ACK(0) after OACK from %s: %v", client.String(), err)
            // proceed anyway (some clients may accept data immediately)
        } else if n >= 4 && (int(buf[0])<<8|int(buf[1])) == opACK && int(buf[2]) == 0 && int(buf[3]) == 0 {
            // ok
        }
    }

    // Stream file as 512-byte blocks and await ACKs
    const blockSize = 512
    blockNum := uint16(1)
    tmp := make([]byte, blockSize)
    for {
        // Read next chunk
        n, rerr := io.ReadFull(body, tmp)
        if rerr == io.ErrUnexpectedEOF {
            // last partial block
        } else if rerr == io.EOF {
            n = 0
        } else if rerr != nil && rerr != io.ErrUnexpectedEOF {
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
            sessConn.SetWriteDeadline(time.Now().Add(2 * time.Second))
            if _, err := sessConn.WriteToUDP(pkt, client); err != nil {
                log.Printf("TFTP: write error to %s: %v", client.String(), err)
                // retry on transient errors; next attempt will resend
                continue
            }
            // Wait for ACK
            buf := make([]byte, 1500)
            sessConn.SetReadDeadline(time.Now().Add(5 * time.Second))
            n, raddr, err := sessConn.ReadFromUDP(buf)
            if err != nil {
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
            log.Printf("TFTP: no ACK for block %d from %s after %d attempts; aborting session", blockNum, client.String(), maxRetry)
            return
        }

        // If last block (<512), transfer complete
        if len(data) < blockSize {
            return
        }
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
    s.conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
    _, _ = s.conn.WriteToUDP(b, dst)
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

func fetch(ctx context.Context, url string) (io.ReadCloser, int64, error) {
    req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
    if err != nil {
        return nil, 0, err
    }
    // Use default client with a per-request context timeout
    resp, err := http.DefaultClient.Do(req)
    if err != nil {
        return nil, 0, err
    }
    if resp.StatusCode != http.StatusOK {
        resp.Body.Close()
        return nil, 0, fmt.Errorf("unexpected status: %s", resp.Status)
    }
    return resp.Body, resp.ContentLength, nil
}
