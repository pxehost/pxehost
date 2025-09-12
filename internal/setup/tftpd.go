package setup

import (
    "fmt"
    "os"
    "os/exec"
    "syscall"
)

type TFTPDReadiness struct {
    Loaded       bool
    DirExists    bool
    DirWritable  bool
    DirModeMatch bool
    Ready        bool
    CheckError   error
}

// CheckTFTPD verifies macOS tftpd service state and directory readiness.
// It does not attempt to modify the system; it only reports status.
func CheckTFTPD(dir string) TFTPDReadiness {
    r := TFTPDReadiness{}

    // Service loaded? launchctl print returns 0 if loaded, 113 if not.
    cmd := exec.Command("launchctl", "print", "system/com.apple.tftpd")
    if err := cmd.Run(); err != nil {
        if ee, ok := err.(*exec.ExitError); ok {
            if status, ok := ee.Sys().(syscall.WaitStatus); ok {
                if status.ExitStatus() == 0 {
                    r.Loaded = true
                } else if status.ExitStatus() == 113 {
                    r.Loaded = false
                } else {
                    r.CheckError = fmt.Errorf("launchctl exit code %d", status.ExitStatus())
                }
            }
        } else {
            r.CheckError = err
        }
    } else {
        r.Loaded = true
    }

    if fi, err := os.Stat(dir); err == nil {
        r.DirExists = fi.IsDir()
        // Check permissions: want 0777 per user guidance
        if r.DirExists {
            mode := fi.Mode().Perm()
            if mode == 0o777 {
                r.DirModeMatch = true
            }
            // Dir writable by current user? quick check: test bit or os.Access-like attempt
            r.DirWritable = mode&0o222 != 0
        }
    } else if os.IsNotExist(err) {
        r.DirExists = false
    } else {
        r.CheckError = err
    }

    r.Ready = r.Loaded && r.DirExists && r.DirWritable
    return r
}

// PrintTFTPDRemediation prints the exact commands the user can run to fix setup.
func PrintTFTPDRemediation(r TFTPDReadiness) {
    fmt.Println("tftpd setup checks:")
    if !r.Loaded {
        fmt.Println("- Service: not loaded")
        fmt.Println("  Run: sudo launchctl load -F /System/Library/LaunchDaemons/tftp.plist")
    } else {
        fmt.Println("- Service: loaded (com.apple.tftpd)")
    }
    if !r.DirExists {
        fmt.Println("- Directory: missing (/private/tftpboot)")
        fmt.Println("  Run: sudo mkdir -p /private/tftpboot")
    } else {
        fmt.Println("- Directory: exists")
    }
    if r.DirExists && !r.DirModeMatch {
        fmt.Println("- Permissions: not 0777")
        fmt.Println("  Run: sudo chmod 777 /private/tftpboot")
    } else if r.DirExists {
        fmt.Println("- Permissions: 0777 OK")
    }
    if r.Ready {
        fmt.Println("tftpd appears ready. Place boot files in /private/tftpboot.")
    }
}

