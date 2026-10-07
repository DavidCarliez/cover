package daemon

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"time"
)

// HealthEndpoint answers loopback requests with the serving process's
// identity, so lifecycle commands only signal a process that is Cover.
const HealthEndpoint = "/__cover/health"

// Health is the HealthEndpoint response.
type Health struct {
	Service string `json:"service"`
	PID     int    `json:"pid"`
}

// ProbePID asks the listener on addr for its process ID.
func ProbePID(addr string, timeout time.Duration) (int, bool) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return 0, false
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+net.JoinHostPort(host, port)+HealthEndpoint, nil)
	if err != nil {
		return 0, false
	}
	response, err := (&http.Client{Transport: &http.Transport{Proxy: nil}}).Do(request)
	if err != nil {
		return 0, false
	}
	defer response.Body.Close()
	var health Health
	if response.StatusCode != http.StatusOK || json.NewDecoder(response.Body).Decode(&health) != nil || health.Service != "cover" {
		return 0, false
	}
	return health.PID, health.PID > 0
}

// IsCover reports whether pid is a running Cover process: the listener on
// addr reports that pid, or the process executable is named cover, which
// also identifies a daemon too old to answer the health endpoint.
func IsCover(pid int, addr string) bool {
	if pid <= 0 || !IsRunning(pid) {
		return false
	}
	if probed, ok := ProbePID(addr, time.Second); ok {
		return probed == pid
	}
	name := strings.ToLower(filepath.Base(processExecutable(pid)))
	return strings.HasPrefix(name, "cover")
}
