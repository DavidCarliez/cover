package daemon

import (
	"encoding/json"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestStopWithoutCoverRunning(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cover.pid")
	if err := StopOrFindAndWait(path, "127.0.0.1:1", 0); err != nil {
		t.Fatalf("StopOrFindAndWait: %v", err)
	}
}

func TestStalePidfileIsRemoved(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cover.pid")
	if err := Write(path, 999999); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := StopOrFindAndWait(path, "127.0.0.1:1", 0); err != nil {
		t.Fatalf("StopOrFindAndWait: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("expected stale pidfile removed, stat err=%v", err)
	}
}

// A pidfile whose pid was reused by another program must not be signalled.
func TestPidfileOfAnotherProgramIsNotSignalled(t *testing.T) {
	sleeper := exec.Command("sleep", "30")
	if err := sleeper.Start(); err != nil {
		t.Skip("sleep is unavailable")
	}
	defer sleeper.Process.Kill()
	path := filepath.Join(t.TempDir(), "cover.pid")
	if err := Write(path, sleeper.Process.Pid); err != nil {
		t.Fatal(err)
	}
	if err := StopOrFindAndWait(path, "127.0.0.1:1", time.Second); err != nil {
		t.Fatalf("StopOrFindAndWait: %v", err)
	}
	if !IsRunning(sleeper.Process.Pid) {
		t.Fatal("a process that is not Cover was stopped")
	}
}

func TestHealthEndpointIdentifiesCover(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != HealthEndpoint {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(Health{Service: "cover", PID: os.Getpid()})
	})}
	go srv.Serve(ln)
	defer srv.Close()
	addr := ln.Addr().String()
	if pid, ok := ProbePID(addr, time.Second); !ok || pid != os.Getpid() {
		t.Fatalf("ProbePID=%d,%v", pid, ok)
	}
	if !IsCover(os.Getpid(), addr) {
		t.Fatal("the probed process was not identified as Cover")
	}
	if pid, ok := RunningPID(filepath.Join(t.TempDir(), "cover.pid"), addr); !ok || pid != os.Getpid() {
		t.Fatalf("RunningPID without pidfile=%d,%v", pid, ok)
	}
}
