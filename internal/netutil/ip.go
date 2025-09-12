package netutil

import (
    "bytes"
    "net"
    "os/exec"
    "strings"
)

// DetectLANIPv4 returns the first non-loopback, RFC1918 IPv4 address and the interface name.
func DetectLANIPv4() (string, string) {
    ifaces, _ := net.Interfaces()
    for _, ifi := range ifaces {
        if (ifi.Flags&net.FlagUp) == 0 || (ifi.Flags&net.FlagLoopback) != 0 {
            continue
        }
        addrs, _ := ifi.Addrs()
        for _, a := range addrs {
            ipnet, ok := a.(*net.IPNet)
            if !ok || ipnet.IP == nil || ipnet.IP.To4() == nil {
                continue
            }
            ip := ipnet.IP.To4()
            if isRFC1918(ip) {
                return ip.String(), ifi.Name
            }
        }
    }
    return "", ""
}

func isRFC1918(ip net.IP) bool {
    // 10.0.0.0/8
    if ip[0] == 10 {
        return true
    }
    // 172.16.0.0/12
    if ip[0] == 172 && ip[1]&0xf0 == 16 {
        return true
    }
    // 192.168.0.0/16
    if ip[0] == 192 && ip[1] == 168 {
        return true
    }
    return false
}

// DetectDefaultGateway tries to detect the default gateway IP (macOS-friendly).
func DetectDefaultGateway() string {
    // macOS: route -n get default
    cmd := exec.Command("route", "-n", "get", "default")
    var out bytes.Buffer
    cmd.Stdout = &out
    if err := cmd.Run(); err == nil {
        lines := strings.Split(out.String(), "\n")
        for _, ln := range lines {
            ln = strings.TrimSpace(ln)
            if strings.HasPrefix(ln, "gateway:") {
                f := strings.Fields(ln)
                if len(f) >= 2 {
                    return f[1]
                }
            }
        }
    }
    // Fallback: netstat -rn | default
    cmd = exec.Command("netstat", "-rn")
    out.Reset()
    cmd.Stdout = &out
    if err := cmd.Run(); err == nil {
        lines := strings.Split(out.String(), "\n")
        for _, ln := range lines {
            ln = strings.TrimSpace(ln)
            if strings.HasPrefix(ln, "default ") {
                f := strings.Fields(ln)
                if len(f) >= 2 {
                    return f[1]
                }
            }
        }
    }
    return ""
}

