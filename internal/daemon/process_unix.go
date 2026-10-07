//go:build unix

package daemon

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
)

// IsRunning reports whether a process with the given pid is alive.
func IsRunning(pid int) bool {
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return process.Signal(syscall.Signal(0)) == nil
}

func terminate(pid int) error {
	process, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	if err := process.Signal(syscall.SIGTERM); err != nil {
		return fmt.Errorf("sending SIGTERM to pid %d: %w", pid, err)
	}
	return nil
}

func processExecutable(pid int) string {
	if runtime.GOOS == "linux" {
		path, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
		if err == nil {
			return strings.TrimSuffix(path, " (deleted)")
		}
	}
	out, err := exec.Command("ps", "-p", fmt.Sprint(pid), "-o", "comm=").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
