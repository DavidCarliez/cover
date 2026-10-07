package redact

import (
	"context"
	"sort"
	"time"

	"github.com/DavidCarliez/cover/internal/redact/detectors"
)

// ContextDetector is an optional interface a Detector can implement to
// receive a context with a deadline. The Redactor uses this to bound the
// total time spent in slow (e.g. LLM-backed) detectors across a single
// Redact call, regardless of how many string fields are scanned.
type ContextDetector interface {
	DetectWithContext(ctx context.Context, text string) []detectors.Match
}

// RedactorOptions configures optional redactor behavior.
type RedactorOptions struct {
	FieldRules []FieldRule
}

// Redactor scans and rewrites request/response bodies using a set of
// detectors backed by a shared mapping Store.
type Redactor struct {
	detectors       []detectors.Detector
	store           *Store
	llmBudget       time.Duration
	fieldRules      []FieldRule
	textSelectors   []textSelector
	fieldRulesValid bool
	hasKeyRules     bool
	hasHeaderRules  bool
	hasCookieRules  bool
	hasQueryRules   bool
	hasFormRules    bool
}

// New creates a Redactor backed by store, applying the given detectors in
// order. llmBudget bounds the total time (across an entire Redact call)
// available to detectors implementing ContextDetector; pass 0 if no such
// detectors are configured.
func New(store *Store, llmBudget time.Duration, opts RedactorOptions, dets ...detectors.Detector) *Redactor {
	fieldRules := append([]FieldRule(nil), opts.FieldRules...)
	sort.SliceStable(fieldRules, func(i, j int) bool {
		if fieldRules[i].Priority != fieldRules[j].Priority {
			return fieldRules[i].Priority > fieldRules[j].Priority
		}
		return fieldRules[i].Name < fieldRules[j].Name
	})
	fieldRulesValid := true
	var hasKeyRules, hasHeaderRules, hasCookieRules, hasQueryRules, hasFormRules bool
	for _, rule := range fieldRules {
		kinds := 0
		if len(rule.Keys) > 0 {
			hasKeyRules = true
			kinds++
		}
		if len(rule.Headers) > 0 {
			hasHeaderRules = true
			kinds++
		}
		if len(rule.Cookies) > 0 {
			hasCookieRules = true
			kinds++
		}
		if len(rule.QueryParams) > 0 {
			hasQueryRules = true
			kinds++
		}
		if len(rule.FormFields) > 0 {
			hasFormRules = true
			kinds++
		}
		if kinds != 1 {
			fieldRulesValid = false
		}
	}
	return &Redactor{
		detectors:       dets,
		store:           store,
		llmBudget:       llmBudget,
		fieldRules:      fieldRules,
		textSelectors:   buildTextSelectors(fieldRules),
		fieldRulesValid: fieldRulesValid,
		hasKeyRules:     hasKeyRules,
		hasHeaderRules:  hasHeaderRules,
		hasCookieRules:  hasCookieRules,
		hasQueryRules:   hasQueryRules,
		hasFormRules:    hasFormRules,
	}
}

// Restore replaces any placeholder tokens in data with the original values
// recorded during Redact. Unknown placeholders are left untouched.
func (r *Redactor) Restore(data []byte) []byte {
	return r.RestoreForSession(data, defaultSessionID)
}

func (r *Redactor) RestoreForSession(data []byte, session string) []byte {
	snapshot := r.store.restorationSnapshot(session)
	if snapshot == nil {
		return data
	}
	if len(snapshot.numbers) > 0 {
		return r.restoreJSONOrRawWithSnapshot(data, snapshot)
	}
	restored, _ := snapshot.restoreBytes(data)
	return restored
}

func (r *Redactor) EndSession(session string) { r.store.DeleteSession(session) }

// HasMappingsForSession reports whether response restoration has any work for
// session. Streaming writers use it to preserve and forward untouched events
// immediately when a request created no reversible mappings.
func (r *Redactor) HasMappingsForSession(session string) bool {
	return r.store.restorationSnapshot(session) != nil
}

func (r *Redactor) SafeStreamCut(data []byte, session string) int {
	snapshot := r.store.restorationSnapshot(session)
	if snapshot == nil {
		return len(data)
	}
	return snapshot.safeCut(data)
}
