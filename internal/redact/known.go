package redact

import (
	"encoding/json"
	"html"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/DavidCarliez/cover/internal/redact/detectors"
)

const (
	// Shorter originals are too ambiguous to protect wherever they appear.
	minKnownValueLen = 4
	// Shorter originals are only protected as whole words.
	unboundedKnownValueLen = 8
	// JSON numbers shorter than this stay unchanged even when they equal a
	// protected value, so counts, ports and limits keep their meaning.
	minKnownNumberLen = 6

	defaultMaxKnownValues = 50000
	defaultKnownValueTTL  = 24 * time.Hour
)

// knownValueEncodings lists the escapings under which a protected original is
// also recognized when no parser decodes its context.
var knownValueEncodings = []string{"", "json", "json_html", "html", "query", "path"}

func encodeKnownValue(encoding, value string) string {
	switch encoding {
	case "json", "json_html":
		var b strings.Builder
		enc := json.NewEncoder(&b)
		enc.SetEscapeHTML(encoding == "json_html")
		_ = enc.Encode(value)
		quoted := strings.TrimSuffix(b.String(), "\n")
		return quoted[1 : len(quoted)-1]
	case "html":
		return html.EscapeString(value)
	case "query":
		return url.QueryEscape(value)
	case "path":
		return url.PathEscape(value)
	default:
		return value
	}
}

func decodeKnownValue(encoding, value string) (string, bool) {
	switch encoding {
	case "":
		return value, true
	case "json", "json_html":
		var decoded string
		if json.Unmarshal([]byte(`"`+value+`"`), &decoded) != nil {
			return "", false
		}
		return decoded, true
	case "html":
		return html.UnescapeString(value), true
	case "query":
		decoded, err := url.QueryUnescape(value)
		return decoded, err == nil
	case "path":
		decoded, err := url.PathUnescape(value)
		return decoded, err == nil
	default:
		return "", false
	}
}

type knownValue struct {
	template detectors.Match
	seen     time.Time
}

// knownValues remembers originals that a policy protected, across sessions
// and requests, so the same value is protected again wherever it reappears:
// in prose after response restoration, in a compacted summary, or in another
// field of the same request. Entries live only in process memory.
type knownValues struct {
	mu       sync.RWMutex
	values   map[string]*knownValue
	snapshot *knownSnapshot
	max      int
	ttl      time.Duration
	now      func() time.Time
}

type knownSnapshot struct {
	matcher   *literalMatcher
	templates []detectors.Match
	numbers   map[string]detectors.Match
}

func newKnownValues(max int, ttl time.Duration, now func() time.Time) *knownValues {
	if max <= 0 {
		max = defaultMaxKnownValues
	}
	if ttl <= 0 {
		ttl = defaultKnownValueTTL
	}
	return &knownValues{values: map[string]*knownValue{}, max: max, ttl: ttl, now: now}
}

// remember records original under template and reports whether it was new.
func (k *knownValues) remember(original string, template detectors.Match) bool {
	if len(original) < minKnownValueLen || strings.TrimSpace(original) == "" {
		return false
	}
	template.Value, template.Start, template.End, template.Encoding = "", 0, 0, ""
	now := k.now()
	k.mu.Lock()
	defer k.mu.Unlock()
	if existing, ok := k.values[original]; ok {
		existing.seen = now
		return false
	}
	k.expireLocked(now)
	if len(k.values) >= k.max {
		k.evictOldestLocked(len(k.values) - k.max + 1 + k.max/10)
	}
	k.values[original] = &knownValue{template: template, seen: now}
	k.snapshot = nil
	return true
}

func (k *knownValues) expireLocked(now time.Time) {
	for original, value := range k.values {
		if now.Sub(value.seen) > k.ttl {
			delete(k.values, original)
			k.snapshot = nil
		}
	}
}

func (k *knownValues) evictOldestLocked(n int) {
	type aged struct {
		original string
		seen     time.Time
	}
	all := make([]aged, 0, len(k.values))
	for original, value := range k.values {
		all = append(all, aged{original, value.seen})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].seen.Before(all[j].seen) })
	for i := 0; i < n && i < len(all); i++ {
		delete(k.values, all[i].original)
	}
	k.snapshot = nil
}

func (k *knownValues) current() *knownSnapshot {
	k.mu.RLock()
	snapshot := k.snapshot
	empty := len(k.values) == 0
	k.mu.RUnlock()
	if snapshot != nil || empty {
		return snapshot
	}

	k.mu.Lock()
	defer k.mu.Unlock()
	if k.snapshot != nil {
		return k.snapshot
	}
	k.expireLocked(k.now())
	if len(k.values) == 0 {
		return nil
	}
	var literals []string
	var templates []detectors.Match
	var bounded []bool
	numbers := map[string]detectors.Match{}
	seen := map[string]bool{}
	for original, value := range k.values {
		// A number inside a longer number is a different number.
		numeric := isJSONNumberText(original) && json.Valid([]byte(original))
		for _, encoding := range knownValueEncodings {
			literal := encodeKnownValue(encoding, original)
			if seen[literal] {
				continue
			}
			seen[literal] = true
			template := value.template
			template.Encoding = encoding
			literals = append(literals, literal)
			templates = append(templates, template)
			bounded = append(bounded, numeric || len(original) < unboundedKnownValueLen)
		}
		if numeric {
			if len(original) >= minKnownNumberLen {
				numbers[original] = value.template
			}
		}
	}
	k.snapshot = &knownSnapshot{
		matcher:   newLiteralMatcher(literals, func(i int) bool { return bounded[i] }),
		templates: templates,
		numbers:   numbers,
	}
	return k.snapshot
}

func isJSONNumberText(text string) bool {
	if text == "" {
		return false
	}
	first := text[0]
	return first == '-' || first >= '0' && first <= '9'
}

// matches returns every protected original in text. Their spans are leftmost
// longest and do not overlap one another.
func (s *knownSnapshot) matches(text string) []detectors.Match {
	if s == nil {
		return nil
	}
	var out []detectors.Match
	for pos := 0; ; {
		start, end, index, ok := s.matcher.find(text, pos)
		if !ok {
			return out
		}
		match := s.templates[index]
		match.Value, match.Start, match.End = text[start:end], start, end
		out = append(out, match)
		pos = end
	}
}
