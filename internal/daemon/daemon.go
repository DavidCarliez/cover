// Package daemon provides simple pidfile-based process management for
// running Cover in the background.
package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// PidFilePath returns the path to Cover's pidfile:
// ~/.local/share/cover/cover.pid
func PidFilePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolving home directory: %w", err)
	}
	return filepath.Join(home, ".local", "share", "cover", "cover.pid"), nil
}

// Write records pid in the pidfile at path, creating parent directories as needed.
func Write(path string, pid int) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("creating pidfile directory: %w", err)
	}
	return os.WriteFile(path, []byte(strconv.Itoa(pid)), 0o644)
}

// Read returns the pid recorded in the pidfile at path.
func Read(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(data)))
}

// Remove deletes the pidfile at path, ignoring a not-exist error.
func Remove(path string) error {
	err := os.Remove(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// IsRunning reports whether a process with the given pid is alive.
func IsRunning(pid int) bool {
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return process.Signal(syscall.Signal(0)) == nil
}

// Stop sends SIGTERM to the process recorded in the pidfile at path and
// removes the pidfile.
func Stop(path string) error {
	pid, err := Read(path)
	if err != nil {
		return fmt.Errorf("Cover is not running (no pidfile)")
	}
	return stopPID(path, pid)
}

// StopIfRunning sends SIGTERM to the running process (if any), waits up to
// timeout for it to exit, and removes the pidfile. Returns nil when nothing
// was running.
func StopIfRunning(path string, timeout time.Duration) error {
	pid, err := Read(path)
	if err != nil {
		return nil
	}
	if !IsRunning(pid) {
		_ = Remove(path)
		return nil
	}
	return stopPIDAndWait(path, pid, timeout)
}

func stopPID(path string, pid int) error {
	if !IsRunning(pid) {
		_ = Remove(path)
		return fmt.Errorf("Cover is not running (stale pidfile removed)")
	}
	process, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	if err := process.Signal(syscall.SIGTERM); err != nil {
		return fmt.Errorf("sending SIGTERM to pid %d: %w", pid, err)
	}
	return Remove(path)
}

func stopPIDAndWait(path string, pid int, timeout time.Duration) error {
	if err := stopPID(path, pid); err != nil {
		return err
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if !IsRunning(pid) {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for Cover (pid %d) to stop", pid)
}
