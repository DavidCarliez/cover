package redact

import (
	"fmt"
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
