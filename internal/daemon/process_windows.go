//go:build windows

package daemon

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// IsRunning reports whether a process with the given pid is alive. Windows
// does not support signal 0; opening the process succeeds only while it
// exists.
func IsRunning(pid int) bool {
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	_ = process.Release()
	return true
}

// terminate ends the process. Windows has no SIGTERM, so active requests are
// not drained.
func terminate(pid int) error {
	process, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return process.Kill()
}

func processExecutable(pid int) string {
	out, err := exec.Command("tasklist", "/FI", "PID eq "+strconv.Itoa(pid), "/FO", "CSV", "/NH").Output()
	if err != nil {
		return ""
	}
	name, _, _ := strings.Cut(strings.TrimSpace(string(out)), ",")
	return strings.Trim(name, `"`)
}
