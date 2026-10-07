// Package daemon provides simple pidfile-based process management for
// running Cover in the background.
package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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

func stopPID(path string, pid int) error {
	if !IsRunning(pid) {
		_ = Remove(path)
		return fmt.Errorf("Cover is not running (stale pidfile removed)")
	}
	// Keep the pidfile while the daemon drains active requests.
	return terminate(pid)
}
