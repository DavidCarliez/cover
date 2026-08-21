package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestSafeUpstreamDisplay(t *testing.T) {
	tests := map[string]string{
		"https://api.openai.com":                                   "https://api.openai.com",
		"https://user:password@router.example/credential/path?q=1": "https://router.example/<redacted>",
		"http://127.0.0.1:4102/secret-route/v1":                    "http://127.0.0.1:4102/<redacted>",
		"not a URL":                                                "<configured>",
	}
	for input, want := range tests {
		if got := safeUpstreamDisplay(input); got != want {
			t.Errorf("safeUpstreamDisplay(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestStatusNeverPrintsUpstreamCredentials(t *testing.T) {
	var out bytes.Buffer
	printStatus(&out, statusDisplay{
		Running:  true,
		Listen:   "127.0.0.1:8317",
		Upstream: "https://user:password@router.example/credential/path?q=secret",
	})
	for _, secret := range []string{"user", "password", "credential", "secret"} {
		if strings.Contains(out.String(), secret) {
			t.Fatalf("status exposed %q: %s", secret, out.String())
		}
	}
}
