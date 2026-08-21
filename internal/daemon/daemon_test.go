package daemon

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStopIfRunning_NoPidfile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cover.pid")
	if err := StopIfRunning(path, 0); err != nil {
		t.Fatalf("StopIfRunning: %v", err)
	}
}

func TestStopIfRunning_StalePidfile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cover.pid")
	if err := Write(path, 999999); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := StopIfRunning(path, 0); err != nil {
		t.Fatalf("StopIfRunning: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("expected stale pidfile removed, stat err=%v", err)
	}
}
