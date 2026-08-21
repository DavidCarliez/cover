package daemon

import (
	"fmt"
	"net"
	"time"
)

// AddrInUse reports whether something is already listening on addr.
func AddrInUse(addr string) bool {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return true
	}
	_ = ln.Close()
	return false
}

// WaitForListen blocks until addr accepts TCP connections or timeout elapses.
func WaitForListen(addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		lastErr = err
		time.Sleep(50 * time.Millisecond)
	}
	if lastErr != nil {
		return fmt.Errorf("timed out waiting for %s: %w", addr, lastErr)
	}
	return fmt.Errorf("timed out waiting for %s", addr)
}

// StopOrFind stops the process in the pidfile, or finds a listener on
// listenAddr when the pidfile is missing (e.g. after an unclean exit).
func StopOrFind(pidPath, listenAddr string) error {
	if err := Stop(pidPath); err == nil {
		return nil
	}
	pid, err := FindListenerPID(listenAddr)
	if err != nil {
		return fmt.Errorf("Cover is not running (no pidfile)")
	}
	return stopPID(pidPath, pid)
}

// StopOrFindAndWait stops the process in the pidfile or a listener on
// listenAddr, waits for it to exit, and returns nil when nothing was running.
func StopOrFindAndWait(pidPath, listenAddr string, timeout time.Duration) error {
	pid, err := Read(pidPath)
	if err != nil {
		var findErr error
		pid, findErr = FindListenerPID(listenAddr)
		if findErr != nil {
			return nil
		}
	}
	if !IsRunning(pid) {
		_ = Remove(pidPath)
		return nil
	}
	if err := stopPID(pidPath, pid); err != nil {
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
