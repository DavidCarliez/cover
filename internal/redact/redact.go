package redact

import (
	"bytes"
	"context"
	"encoding/json"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/DavidCarliez/cover/internal/redact/detectors"
)

var placeholderRe = regexp.MustCompile(placeholderOpen + `([0-9a-f]{8})` + placeholderClose)

// ContextDetector is an optional interface a Detector can implement to
// receive a context with a deadline. The Redactor uses this to bound the
// total time spent in slow (e.g. LLM-backed) detectors across a single
// Redact call, regardless of how many string fields are scanned.
type ContextDetector interface {
	DetectWithContext(ctx context.Context, text string) []detectors.Match
}

// BatchContextDetector is an optional interface for detectors that can score
// multiple strings in one remote call.
type BatchContextDetector interface {
	DetectBatchWithContext(ctx context.Context, texts []string) [][]detectors.Match
}

// RedactorOptions configures optional redactor behavior.
type RedactorOptions struct {
	Cache                 *DetectionCache
	SkipLLMIfRegexMatched bool
	LLMConcurrency        int
	LLMBatchSize          int
}

// Redactor scans and rewrites request/response bodies using a set of
// detectors backed by a shared mapping Store.
type Redactor struct {
	detectors             []detectors.Detector
	store                 *Store
	llmBudget             time.Duration
	cache                 *DetectionCache
	skipLLMIfRegexMatched bool
	llmConcurrency        int
	llmBatchSize          int
}

// New creates a Redactor backed by store, applying the given detectors in
// order. llmBudget bounds the total time (across an entire Redact call)
// available to detectors implementing ContextDetector; pass 0 if no such
// detectors are configured.
func New(store *Store, llmBudget time.Duration, opts RedactorOptions, dets ...detectors.Detector) *Redactor {
	if opts.LLMConcurrency <= 0 {
		opts.LLMConcurrency = 4
	}
	if opts.LLMBatchSize <= 0 {
		opts.LLMBatchSize = 8
	}
	return &Redactor{
		detectors:             dets,
		store:                 store,
		llmBudget:             llmBudget,
		cache:                 opts.Cache,
		skipLLMIfRegexMatched: opts.SkipLLMIfRegexMatched,
		llmConcurrency:        opts.LLMConcurrency,
		llmBatchSize:          opts.LLMBatchSize,
	}
}

// Redact scans body for sensitive substrings and returns the rewritten body
// along with the list of categories that were matched (for logging).
func (r *Redactor) Redact(body []byte) ([]byte, []string) {
	return r.redactBody(body, false)
}

// RedactForProxy is like Redact but injects the Cover system note when
// redactions occurred.
func (r *Redactor) RedactForProxy(body []byte) ([]byte, []string) {
	return r.redactBody(body, true)
}

func (r *Redactor) redactBody(body []byte, injectNote bool) ([]byte, []string) {
	ctx := context.Background()
	if r.llmBudget > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, r.llmBudget)
		defer cancel()
	}

	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()

	var data any
	if err := dec.Decode(&data); err != nil {
		redacted, cats := r.redactString(ctx, string(body), false, nil)
		return []byte(redacted), cats
	}

	llmResults := r.prefetchLLMResults(ctx, data)

	var categories []string
	changed := false
	walked := r.walk(ctx, data, &categories, false, &changed, llmResults)

	if !changed {
		if injectNote && len(categories) > 0 {
			// categories only set when changed; unreachable
		}
		return body, categories
	}

	if injectNote && len(categories) > 0 {
		if root, ok := walked.(map[string]any); ok {
			injectGuardNoteIntoData(root, categories)
		}
	}

	out, err := json.Marshal(walked)
	if err != nil {
		return body, categories
	}
	return out, categories
}

// Restore replaces any placeholder tokens in data with the original values
// recorded during Redact. Unknown placeholders are left untouched.
func (r *Redactor) Restore(data []byte) []byte {
	return r.RestoreForSession(data, defaultSessionID)
}

func (r *Redactor) RestoreForSession(data []byte, session string) []byte {
	mappings := r.store.ReverseMappings(session)
	if len(mappings) == 0 {
		return data
	}
	pairs := make([]string, 0, len(mappings)*2)
	for _, fake := range sortedFakeKeys(mappings) {
		pairs = append(pairs, fake, mappings[fake])
	}
	return []byte(strings.NewReplacer(pairs...).Replace(string(data)))
}

func (r *Redactor) StreamReserve(session string) int {
	max := r.store.MaxFakeLen(session)
	if max <= 1 {
		return 0
	}
	return max - 1
}

func (r *Redactor) EndSession(session string) { r.store.DeleteSession(session) }

func (r *Redactor) SafeStreamCut(data []byte, session string) int {
	reserve := r.StreamReserve(session)
	if len(data) <= reserve {
		return 0
	}
	cut := len(data) - reserve
	for fake := range r.store.ReverseMappings(session) {
		start := 0
		for {
			i := bytes.Index(data[start:], []byte(fake))
			if i < 0 {
				break
			}
			i += start
			if i < cut && i+len(fake) > cut {
				cut = i
			}
			start = i + 1
		}
	}
	return cut
}

var protocolKeys = map[string]bool{
	"model":         true,
	"name":          true,
	"type":          true,
	"role":          true,
	"id":            true,
	"tool_use_id":   true,
	"stop_reason":   true,
	"stop_sequence": true,
	"cache_control": true,
	"tools":         true,
	"tool_choice":   true,
}

var llmSkipKeys = map[string]bool{
	"system": true,
}

type llmWork struct {
	hash [32]byte
	text string
}

func (r *Redactor) prefetchLLMResults(ctx context.Context, data any) map[[32]byte][]detectors.Match {
	var llmDet ContextDetector
	var batchDet BatchContextDetector
	for _, det := range r.detectors {
		if cd, ok := det.(ContextDetector); ok {
			llmDet = cd
			batchDet, _ = det.(BatchContextDetector)
			break
		}
	}
	if llmDet == nil {
		return nil
	}

	seen := make(map[[32]byte]string)
	r.collectLLMStrings(data, false, seen)
	if len(seen) == 0 {
		return nil
	}

	work := make([]llmWork, 0, len(seen))
	for hash, text := range seen {
		if isTestDataContext(text) {
			continue
		}
		if r.skipLLMIfRegexMatched && r.regexMatched(text) {
			continue
		}
		work = append(work, llmWork{hash: hash, text: text})
	}
	if len(work) == 0 {
		return nil
	}

	results := make(map[[32]byte][]detectors.Match, len(work))

	if batchDet != nil && r.llmBatchSize > 1 {
		for i := 0; i < len(work); i += r.llmBatchSize {
			end := i + r.llmBatchSize
			if end > len(work) {
				end = len(work)
			}
			batch := work[i:end]
			texts := make([]string, len(batch))
			for j, w := range batch {
				texts[j] = w.text
			}
			batchMatches := batchDet.DetectBatchWithContext(ctx, texts)
			for j, w := range batch {
				if j < len(batchMatches) {
					results[w.hash] = batchMatches[j]
				}
			}
		}
		return results
	}

	sem := make(chan struct{}, r.llmConcurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, w := range work {
		wg.Add(1)
		go func(w llmWork) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			matches := llmDet.DetectWithContext(ctx, w.text)
			mu.Lock()
			results[w.hash] = matches
			mu.Unlock()
		}(w)
	}
	wg.Wait()
	return results
}

func (r *Redactor) regexMatched(text string) bool {
	for _, det := range r.detectors {
		if _, ok := det.(ContextDetector); ok {
			continue
		}
		if len(det.Detect(text)) > 0 {
			return true
		}
	}
	return false
}

func (r *Redactor) collectLLMStrings(v any, skipLLM bool, seen map[[32]byte]string) {
	switch val := v.(type) {
	case string:
		if skipLLM {
			return
		}
		hash := contentHash(val)
		if _, ok := seen[hash]; !ok {
			seen[hash] = val
		}
	case map[string]any:
		for k, vv := range val {
			if protocolKeys[k] {
				continue
			}
			r.collectLLMStrings(vv, skipLLM || llmSkipKeys[k], seen)
		}
	case []any:
		for _, vv := range val {
			r.collectLLMStrings(vv, skipLLM, seen)
		}
	}
}

func (r *Redactor) walk(ctx context.Context, v any, categories *[]string, skipLLM bool, changed *bool, llmResults map[[32]byte][]detectors.Match) any {
	switch val := v.(type) {
	case string:
		redacted, cats := r.redactString(ctx, val, skipLLM, llmResults)
		*categories = append(*categories, cats...)
		if redacted != val {
			*changed = true
		}
		return redacted
	case map[string]any:
		for k, vv := range val {
			if protocolKeys[k] {
				continue
			}
			val[k] = r.walk(ctx, vv, categories, skipLLM || llmSkipKeys[k], changed, llmResults)
		}
		return val
	case []any:
		for i, vv := range val {
			val[i] = r.walk(ctx, vv, categories, skipLLM, changed, llmResults)
		}
		return val
	default:
		return v
	}
}

func (r *Redactor) redactString(ctx context.Context, s string, skipLLM bool, llmResults map[[32]byte][]detectors.Match) (string, []string) {
	hash := contentHash(s)
	if r.cache != nil {
		if redacted, cats, ok := r.cache.Get(hash, skipLLM); ok {
			return redacted, cats
		}
	}

	var all []detectors.Match
	var regexMatched bool
	for _, det := range r.detectors {
		if cd, ok := det.(ContextDetector); ok {
			if skipLLM || isTestDataContext(s) {
				continue
			}
			if r.skipLLMIfRegexMatched && regexMatched {
				continue
			}
			if llmResults != nil {
				if matches, ok := llmResults[hash]; ok {
					all = append(all, matches...)
					continue
				}
			}
			all = append(all, cd.DetectWithContext(ctx, s)...)
			continue
		}
		matches := det.Detect(s)
		if len(matches) > 0 {
			regexMatched = true
		}
		all = append(all, matches...)
	}
	all = filterTestExemptMatches(s, all)
	if len(all) == 0 {
		if r.cache != nil {
			r.cache.Put(hash, skipLLM, s, nil)
		}
		return s, nil
	}

	sort.Slice(all, func(i, j int) bool {
		if all[i].Start != all[j].Start {
			return all[i].Start < all[j].Start
		}
		return all[i].End > all[j].End
	})

	var b strings.Builder
	var categories []string
	last := 0
	for _, m := range all {
		if m.Start < last {
			continue
		}
		b.WriteString(s[last:m.Start])
		b.WriteString(r.store.PlaceholderFor(m.Value))
		categories = append(categories, m.Category)
		last = m.End
	}
	b.WriteString(s[last:])
	redacted := b.String()

	if r.cache != nil {
		r.cache.Put(hash, skipLLM, redacted, categories)
	}
	return redacted, categories
}
