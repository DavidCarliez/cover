package proxy

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DavidCarliez/cover/internal/redact"
	"github.com/DavidCarliez/cover/internal/redact/detectors"
)

func benchProxy(b *testing.B) (*Proxy, []byte) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	}))
	b.Cleanup(upstream.Close)

	d, err := detectors.NewRegexDetector(detectors.BuiltinCategories(), nil)
	if err != nil {
		b.Fatalf("NewRegexDetector: %v", err)
	}
	redactor := redact.New(redact.NewStore(), 0, redact.RedactorOptions{
		Cache: redact.NewDetectionCache(10000),
	}, d)
	p, err := New(upstream.URL, redactor, nil, Options{})
	if err != nil {
		b.Fatalf("New: %v", err)
	}
	return p, redact.BenchFixtureChat20Msg()
}

func BenchmarkProxy_ServeHTTP_Chat20Msg(b *testing.B) {
	p, body := benchProxy(b)
	req, err := http.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(string(body)))
	if err != nil {
		b.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rec := httptest.NewRecorder()
		p.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			b.Fatalf("status = %d", rec.Code)
		}
	}
}

func BenchmarkProxy_ServeHTTP_Chat20Msg_Cached(b *testing.B) {
	p, body := benchProxy(b)
	req, err := http.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(string(body)))
	if err != nil {
		b.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Warm cache.
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rec := httptest.NewRecorder()
		p.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			b.Fatalf("status = %d", rec.Code)
		}
	}
}

// BenchFixtureChat20Msg exposes the 20-message chat fixture for proxy benchmarks.
func BenchmarkProxy_GuardNoteOverhead(b *testing.B) {
	d, _ := detectors.NewRegexDetector([]string{"aws_access_key"}, nil)
	store := redact.NewStore()
	r := redact.New(store, 0, redact.RedactorOptions{Cache: redact.NewDetectionCache(1000)}, d)
	body := []byte(fmt.Sprintf(`{"model":"claude","messages":[{"role":"user","content":"key %s"}]}`, "AKIAIOSFODNN7EXAMPLE"))

	b.Run("Redact", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			r.Redact(body)
		}
	})
	b.Run("RedactForProxy", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			r.RedactForProxy(body)
		}
	})
}
