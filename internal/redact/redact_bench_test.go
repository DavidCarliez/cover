package redact

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/DavidCarliez/cover/internal/redact/detectors"
)

func benchmarkMappedRedactor(b *testing.B, entries int) (*Redactor, string) {
	b.Helper()
	store := NewStoreWithOptions(StoreOptions{MaxEntriesPerSession: entries + 1})
	target := ""
	for i := 0; i < entries; i++ {
		original := fmt.Sprintf("secret-%d", i)
		fake, err := store.Map("benchmark", original, nil, func(int) (string, error) {
			return fmt.Sprintf("COVER_FAKE_%08d", i), nil
		})
		if err != nil {
			b.Fatal(err)
		}
		if i == entries/2 {
			target = fake
		}
	}
	return New(store, 0, RedactorOptions{}), target
}

func BenchmarkRestoreForSession_MappingScale(b *testing.B) {
	for _, entries := range []int{1, 100, 1000, 5000} {
		b.Run(fmt.Sprintf("entries_%d", entries), func(b *testing.B) {
			r, target := benchmarkMappedRedactor(b, entries)
			data := []byte("delta before " + target + " after")
			// Build the lazy snapshot outside the timed region.
			r.RestoreForSession(data, "benchmark")
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				r.RestoreForSession(data, "benchmark")
			}
		})
	}
}

func BenchmarkSafeStreamCut_MappingScale(b *testing.B) {
	for _, entries := range []int{1, 100, 1000, 5000} {
		b.Run(fmt.Sprintf("entries_%d", entries), func(b *testing.B) {
			r, _ := benchmarkMappedRedactor(b, entries)
			data := []byte("ordinary streaming response text without a mapping")
			r.SafeStreamCut(data, "benchmark")
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				r.SafeStreamCut(data, "benchmark")
			}
		})
	}
}

func BenchmarkTransform_OpaqueImage1MiB(b *testing.B) {
	d, err := detectors.NewRegexDetector([]string{"phone_intl"}, nil)
	if err != nil {
		b.Fatal(err)
	}
	r := New(NewStore(), 0, RedactorOptions{}, d)
	imageURL := "data:image/png;base64," + strings.Repeat("+1234567", 131072)
	body, err := json.Marshal(map[string]any{
		"input": []any{map[string]any{"type": "input_image", "image_url": imageURL}},
	})
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := r.Transform(body, "image", false, "allow")
		if err != nil || result.Transformed != 0 {
			b.Fatalf("opaque image transform: result=%+v err=%v", result, err)
		}
	}
}

func benchRedactor(b *testing.B) *Redactor {
	d, err := detectors.NewRegexDetector(detectors.BuiltinCategories(), nil)
	if err != nil {
		b.Fatalf("NewRegexDetector: %v", err)
	}
	return New(NewStore(), 0, RedactorOptions{
		Cache: NewDetectionCache(10000),
	}, d)
}

func BenchmarkRedact_SmallChat(b *testing.B) {
	r := benchRedactor(b)
	body := benchFixtures.SmallChat
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.Redact(body)
	}
}

func BenchmarkRedact_Chat20Msg(b *testing.B) {
	r := benchRedactor(b)
	body := benchFixtures.Chat20Msg
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.Redact(body)
	}
}

func BenchmarkRedact_LargeSystem(b *testing.B) {
	r := benchRedactor(b)
	body := benchFixtures.LargeSystem
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.Redact(body)
	}
}

func BenchmarkRedact_NoMatch(b *testing.B) {
	r := benchRedactor(b)
	body := benchFixtures.NoMatch
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.Redact(body)
	}
}

func BenchmarkRedact_WithSecrets(b *testing.B) {
	r := benchRedactor(b)
	body := benchFixtures.WithSecrets
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.Redact(body)
	}
}

func BenchmarkRedact_Chat20Msg_Cached(b *testing.B) {
	r := benchRedactor(b)
	body := benchFixtures.Chat20Msg
	// Warm cache.
	r.Redact(body)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.Redact(body)
	}
}

func BenchmarkTransform_KnownValueScale(b *testing.B) {
	history := strings.Repeat("The deployment finished and the service answered every health check. ", 2000)
	body, err := json.Marshal(map[string]any{"messages": []any{
		map[string]any{"role": "user", "content": history},
		map[string]any{"role": "assistant", "content": "use known-secret-42 next"},
	}})
	if err != nil {
		b.Fatal(err)
	}
	for _, entries := range []int{0, 100, 10000} {
		b.Run(fmt.Sprintf("entries_%d", entries), func(b *testing.B) {
			r := New(NewStore(), 0, RedactorOptions{FieldRules: []FieldRule{{
				Name: "secret", Keys: []string{"secret"}, Action: string(ActionRedact), Priority: 1,
			}}})
			for i := 0; i < entries; i++ {
				r.store.known.remember(fmt.Sprintf("known-secret-%d", i), detectors.Match{Rule: "secret", Action: string(ActionRedact)})
			}
			b.SetBytes(int64(len(body)))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := r.Transform(body, "bench", false, "allow"); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkTransform_ManyDistinctMatches(b *testing.B) {
	d, err := detectors.NewRegexDetector([]string{"email"}, nil)
	if err != nil {
		b.Fatal(err)
	}
	var text strings.Builder
	for i := range 3000 {
		fmt.Fprintf(&text, "user%d@corp.example sent a long status line with ordinary words in it. ", i)
	}
	body, _ := json.Marshal(map[string]string{"input": text.String()})
	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		r := New(NewStoreWithOptions(StoreOptions{MaxEntriesPerSession: 5000}), 0, RedactorOptions{}, d)
		if _, err := r.Transform(body, "bench", false, "allow"); err != nil {
			b.Fatal(err)
		}
	}
}
