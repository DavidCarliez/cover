package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DavidCarliez/cover/internal/config"
)

func TestCheckRedactionEngineRoundTrip(t *testing.T) {
	var report doctorReport
	var key [config.PseudonymKeySize]byte
	key[0] = 1
	checkRedactionEngine(&report, key)
	if report.Passed != 1 || report.Failed != 0 {
		t.Fatalf("unexpected report: %+v", report)
	}
}

func TestCheckLiveProxyRequiresFailClosedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "request rejected", http.StatusUnprocessableEntity)
	}))
	defer server.Close()
	var report doctorReport
	checkLiveProxy(t.Context(), &report, strings.TrimPrefix(server.URL, "http://"), time.Second)
	if report.Passed != 1 || report.Failed != 0 {
		t.Fatalf("unexpected report: %+v", report)
	}
}

func TestCheckCodexDoesNotExposeWrongProviderURL(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CODEX_HOME", "")
	path := filepath.Join(home, ".codex", "config.toml")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	const secretURL = "https://credentials.example/private-route"
	body := "model_provider = \"direct\"\n[model_providers.direct]\nbase_url = \"" + secretURL + "\"\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	var report doctorReport
	checkCodex(&report, "127.0.0.1:8317")
	if report.Failed != 2 {
		t.Fatalf("unexpected report: %+v", report)
	}
	for _, check := range report.Checks {
		if strings.Contains(check.Detail, secretURL) || strings.Contains(check.Detail, "private-route") {
			t.Fatalf("doctor exposed provider URL: %+v", check)
		}
	}
}

func TestUpstreamLoopDetection(t *testing.T) {
	if !upstreamLoopsToCover("http://127.0.0.1:8317/v1", "127.0.0.1:8317") {
		t.Fatal("looping upstream was not detected")
	}
	if upstreamLoopsToCover("http://127.0.0.1:4102/v1", "127.0.0.1:8317") {
		t.Fatal("distinct upstream was treated as a loop")
	}
}

func TestLoopbackListenerDetection(t *testing.T) {
	for _, listen := range []string{"127.0.0.1:8317", "[::1]:8317", "localhost:8317"} {
		if !isLoopbackListen(listen) {
			t.Fatalf("loopback listener %q was not recognized", listen)
		}
	}
	if isLoopbackListen("0.0.0.0:8317") {
		t.Fatal("remote listener was treated as loopback")
	}
}
