package activity

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseAllowlistedMetadataOnly(t *testing.T) {
	line := "2026/08/21 12:34:56 status=200 transformed=2 sent_bytes=123 returned_bytes=456 duration_ms=789 categories=email,customer path=/secret query=token raw=private"
	event, ok := Parse(line)
	if !ok {
		t.Fatal("safe event was not parsed")
	}
	if event.Status != 200 || event.Transformed != 2 || event.SentBytes == nil || *event.SentBytes != 123 || event.ReturnedBytes == nil || *event.ReturnedBytes != 456 || event.DurationMS == nil || *event.DurationMS != 789 {
		t.Fatalf("unexpected event: %+v", event)
	}
	encoded := event.Time.String() + strings.Join(event.Categories, ",")
	for _, secret := range []string{"/secret", "token", "private"} {
		if strings.Contains(encoded, secret) {
			t.Fatalf("event retained non-allowlisted value %q", secret)
		}
	}
}

func TestParseSuppressesDuplicateUpstreamDiagnostic(t *testing.T) {
	line := "2026/08/21 12:34:56 upstream error status=429 request-id=sensitive-id"
	if _, ok := Parse(line); ok {
		t.Fatal("upstream diagnostic should not create a duplicate monitor event")
	}
}

func TestRunRecentAndFollow(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	initial := "2026/08/21 12:00:00 status=200 transformed=0\n" +
		"2026/08/21 12:00:01 status=201 transformed=1 categories=email\n"
	if err := os.WriteFile(path, []byte(initial), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var out bytes.Buffer
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, &out, path, Options{Lines: 1, Follow: true, Interval: 5 * time.Millisecond})
	}()
	time.Sleep(20 * time.Millisecond)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString("2026/08/21 12:00:02 status=202 transformed=2 sent_bytes=10 returned_bytes=20 duration_ms=3\n")
	_ = f.Close()
	time.Sleep(30 * time.Millisecond)
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	got := out.String()
	if strings.Contains(got, "12:00:00") || !strings.Contains(got, "12:00:01") || !strings.Contains(got, "12:00:02") {
		t.Fatalf("unexpected monitor output:\n%s", got)
	}
}
