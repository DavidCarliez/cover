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

// StopOrFindAndWait stops Cover, identified by the pidfile or by the
// listener on listenAddr, waits for it to exit, and returns nil when Cover
// is not running. A process that is not Cover is never signalled.
func StopOrFindAndWait(pidPath, listenAddr string, timeout time.Duration) error {
	pid, found := RunningPID(pidPath, listenAddr)
	if !found {
		if AddrInUse(listenAddr) {
			if _, err := FindListenerPID(listenAddr); err == nil {
				return fmt.Errorf("another program is listening on %s; it is not Cover, so it was not stopped", listenAddr)
			}
		}
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

// RunningPID returns the running Cover process from the pidfile or, after an
// unclean exit, from the listener on listenAddr. A stale pidfile, including
// one whose pid now belongs to another program, is removed.
func RunningPID(pidPath, listenAddr string) (int, bool) {
	if pid, err := Read(pidPath); err == nil {
		if IsCover(pid, listenAddr) {
			return pid, true
		}
		_ = Remove(pidPath)
	}
	if pid, ok := ProbePID(listenAddr, time.Second); ok && IsRunning(pid) {
		return pid, true
	}
	if pid, err := FindListenerPID(listenAddr); err == nil && IsCover(pid, listenAddr) {
		return pid, true
	}
	return 0, false
}
