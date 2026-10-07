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
//
// Matching uses a large base matcher, rebuilt only after many additions or
// any removal, and a small matcher for values added since, so adding values
// does not rebuild a matcher over every remembered value.
type knownValues struct {
	mu       sync.RWMutex
	values   map[string]*knownValue
	base     *knownMatcher
	pending  []string
	delta    *knownMatcher
	rebase   bool
	snapshot *knownSnapshot
	max      int
	ttl      time.Duration
	now      func() time.Time
	// expired records the last full expiry sweep, which runs at most once a
	// minute so adding many values stays linear.
	expired time.Time
}

type knownMatcher struct {
	matcher   *literalMatcher
	templates []detectors.Match
	numbers   map[string]detectors.Match
}

// knownSnapshot is immutable; a transform pass uses one snapshot throughout.
type knownSnapshot struct {
	parts []*knownMatcher
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
	k.pending = append(k.pending, original)
	k.delta, k.snapshot = nil, nil
	if len(k.pending) > max(512, len(k.values)/4) {
		k.rebase = true
	}
	return true
}

func (k *knownValues) expireLocked(now time.Time) {
	if now.Sub(k.expired) < time.Minute && len(k.values) < k.max {
		return
	}
	k.expired = now
	for original, value := range k.values {
		if now.Sub(value.seen) > k.ttl {
			delete(k.values, original)
			k.rebase, k.snapshot = true, nil
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
	k.rebase, k.snapshot = true, nil
}

func (k *knownValues) current() *knownSnapshot {
	now := k.now()
	k.mu.RLock()
	snapshot := k.snapshot
	empty := len(k.values) == 0
	swept := now.Sub(k.expired) < time.Minute
	k.mu.RUnlock()
	if empty || snapshot != nil && swept {
		return snapshot
	}

	k.mu.Lock()
	defer k.mu.Unlock()
	// Expiry clears the snapshot when it removes a value.
	k.expireLocked(now)
	if k.snapshot != nil {
		return k.snapshot
	}
	if len(k.values) == 0 {
		k.base, k.delta, k.pending, k.rebase = nil, nil, nil, false
		return nil
	}
	if k.base == nil || k.rebase {
		all := make([]string, 0, len(k.values))
		for original := range k.values {
			all = append(all, original)
		}
		k.base, k.delta, k.pending, k.rebase = k.buildLocked(all), nil, nil, false
	}
	if k.delta == nil && len(k.pending) > 0 {
		k.delta = k.buildLocked(k.pending)
	}
	k.snapshot = &knownSnapshot{parts: []*knownMatcher{k.base}}
	if k.delta != nil {
		k.snapshot.parts = append(k.snapshot.parts, k.delta)
	}
	return k.snapshot
}

func (k *knownValues) buildLocked(originals []string) *knownMatcher {
	var literals []string
	var templates []detectors.Match
	var bounded []bool
	numbers := map[string]detectors.Match{}
	seen := map[string]bool{}
	for _, original := range originals {
		value, ok := k.values[original]
		if !ok {
			continue
		}
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
		if numeric && len(original) >= minKnownNumberLen {
			numbers[original] = value.template
		}
	}
	return &knownMatcher{
		matcher:   newLiteralMatcher(literals, func(i int) bool { return bounded[i] }),
		templates: templates,
		numbers:   numbers,
	}
}

// number returns the template of a protected original equal to number.
func (s *knownSnapshot) number(number string) (detectors.Match, bool) {
	if s == nil {
		return detectors.Match{}, false
	}
	for _, part := range s.parts {
		if template, ok := part.numbers[number]; ok {
			return template, true
		}
	}
	return detectors.Match{}, false
}

func isJSONNumberText(text string) bool {
	if text == "" {
		return false
	}
	first := text[0]
	return first == '-' || first >= '0' && first <= '9'
}

// matches returns every protected original in text. Literals may overlap:
// one that starts inside another is reported when it extends past it, and a
// blocked literal is always reported, so the policy resolver sees every
// protected byte and every block. Overlapping literals of the same rule are
// merged into one span.
func (s *knownSnapshot) matches(text string) []detectors.Match {
	if s == nil {
		return nil
	}
	var out []detectors.Match
	for _, part := range s.parts {
		var spans, blocks []detectors.Match
		for pos := 0; ; {
			start, _, _, ok := part.matcher.find(text, pos)
			if !ok {
				break
			}
			pos = start + 1
			end, index := -1, -1
			part.matcher.eachAt(text, start, func(e, i int) {
				if Action(part.templates[i].Action) == ActionBlock {
					blocks = part.addSpan(blocks, text, start, e, i)
				}
				end, index = e, i
			})
			spans = part.addSpan(spans, text, start, end, index)
		}
		out = append(append(out, spans...), blocks...)
	}
	return out
}

// addSpan appends a literal unless the last span already covers it, and
// extends the last span when both come from the same rule. Span ends
// strictly increase, so the last span reaches furthest.
func (m *knownMatcher) addSpan(spans []detectors.Match, text string, start, end, index int) []detectors.Match {
	if n := len(spans); n > 0 && start < spans[n-1].End {
		last := &spans[n-1]
		if end <= last.End {
			return spans
		}
		if sameKnownTemplate(*last, m.templates[index]) {
			last.End, last.Value = end, text[last.Start:end]
			return spans
		}
	}
	return append(spans, m.match(text, start, end, index))
}

func (m *knownMatcher) match(text string, start, end, index int) detectors.Match {
	match := m.templates[index]
	match.Value, match.Start, match.End = text[start:end], start, end
	return match
}

func sameKnownTemplate(a, b detectors.Match) bool {
	return a.Category == b.Category && a.Rule == b.Rule && a.Action == b.Action &&
		a.Generator == b.Generator && a.Priority == b.Priority && a.Encoding == b.Encoding
}
