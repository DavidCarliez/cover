package redact

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/DavidCarliez/cover/internal/redact/detectors"
)

var (
	ErrMalformedJSON = errors.New("request body is not valid JSON")
	ErrUnsafeRequest = errors.New("request could not be safely transformed")
)

type MatchReport struct {
	Rule      string `json:"rule"`
	Category  string `json:"category"`
	Action    string `json:"action"`
	Generator string `json:"generator,omitempty"`
}

type TransformResult struct {
	Body        []byte        `json:"-"`
	Categories  []string      `json:"categories"`
	Matches     []MatchReport `json:"matches"`
	Transformed int           `json:"transformed"`
	Blocked     bool          `json:"blocked"`
	Warnings    []string      `json:"warnings,omitempty"`
}

// FieldRule applies a policy to an entire JSON string value when its object
// key matches one of Keys. Key matching is case-insensitive unless
// CaseSensitive is true.
type FieldRule struct {
	Name          string
	Keys          []string
	Category      string
	Action        string
	Generator     string
	Priority      int
	CaseSensitive bool
}

type ErrorDetector interface {
	DetectE(text string) ([]detectors.Match, error)
}

type ContextErrorDetector interface {
	DetectWithContextE(ctx context.Context, text string) ([]detectors.Match, error)
}

// Transform validates JSON and applies policy. Any inspection failure returns
// an error and no body suitable for forwarding.
func (r *Redactor) Transform(body []byte, session string, injectNote bool, mediaPolicy string) (TransformResult, error) {
	var result TransformResult
	if len(bytes.TrimSpace(body)) == 0 {
		result.Body = body
		return result, nil
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var data any
	if err := dec.Decode(&data); err != nil {
		return result, ErrMalformedJSON
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return result, ErrMalformedJSON
	}

	policy := strings.ToLower(mediaPolicy)
	if policy == "" {
		policy = "allow"
	}
	containsMedia := detectImageMedia(data)
	if containsMedia {
		switch policy {
		case "block":
			result.Blocked = true
			result.Warnings = append(result.Warnings, "image media blocked; image pixels are not inspected")
		case "warn":
			result.Warnings = append(result.Warnings, "image media allowed; image pixels are not inspected")
		case "allow":
		default:
			return result, fmt.Errorf("%w: invalid media policy", ErrUnsafeRequest)
		}
	}

	occupied := map[string]struct{}{}
	collectStrings(data, occupied)
	ctx := context.Background()
	var cancel context.CancelFunc
	if r.llmBudget > 0 {
		ctx, cancel = context.WithTimeout(ctx, r.llmBudget)
		defer cancel()
	}
	changed := false
	walked, err := r.walkPolicy(ctx, data, session, nil, occupied, &result, &changed)
	if err != nil {
		return TransformResult{}, err
	}
	if injectNote && result.Transformed > 0 {
		if root, ok := walked.(map[string]any); ok {
			injectGuardNoteIntoData(root, result.Categories)
		}
	}
	if !changed {
		result.Body = body
		return result, nil
	}
	out, err := json.Marshal(walked)
	if err != nil {
		return TransformResult{}, fmt.Errorf("%w: encoding transformed request", ErrUnsafeRequest)
	}
	result.Body = out
	return result, nil
}

func collectStrings(v any, out map[string]struct{}) {
	switch val := v.(type) {
	case string:
		out[val] = struct{}{}
	case map[string]any:
		for _, vv := range val {
			collectStrings(vv, out)
		}
	case []any:
		for _, vv := range val {
			collectStrings(vv, out)
		}
	}
}

// Only structural routing identifiers are excluded. Text-bearing protocol
// fields (instructions, system, arguments, results, content, output, metadata)
// are deliberately scanned.
func excludedProtocolField(object map[string]any, path []string, key string) bool {
	switch key {
	case "model", "role", "type", "id", "tool_use_id", "call_id", "item_id", "stop_reason", "stop_sequence":
		return true
	case "name":
		if typ, _ := object["type"].(string); strings.Contains(typ, "tool") || strings.Contains(typ, "function") {
			return true
		}
		if role, _ := object["role"].(string); role == "tool" {
			return true
		}
		for _, part := range path {
			if part == "tools" || part == "tool_calls" || part == "function" || part == "custom" {
				return true
			}
		}
		return false
	default:
		return false
	}
}

func (r *Redactor) walkPolicy(ctx context.Context, v any, session string, path []string, occupied map[string]struct{}, result *TransformResult, changed *bool) (any, error) {
	switch val := v.(type) {
	case string:
		return r.transformString(ctx, val, session, occupied, result, changed)
	case map[string]any:
		for k, vv := range val {
			if excludedProtocolField(val, path, k) {
				continue
			}
			if text, ok := vv.(string); ok {
				if rule, matched := r.fieldRule(k); matched {
					nv, err := r.transformFieldString(text, session, occupied, result, changed, rule)
					if err != nil {
						return nil, err
					}
					val[k] = nv
					continue
				}
			}
			nv, err := r.walkPolicy(ctx, vv, session, append(path, k), occupied, result, changed)
			if err != nil {
				return nil, err
			}
			val[k] = nv
		}
		return val, nil
	case []any:
		for i, vv := range val {
			nv, err := r.walkPolicy(ctx, vv, session, path, occupied, result, changed)
			if err != nil {
				return nil, err
			}
			val[i] = nv
		}
		return val, nil
	default:
		return v, nil
	}
}

func (r *Redactor) fieldRule(key string) (FieldRule, bool) {
	for _, rule := range r.fieldRules {
		for _, candidate := range rule.Keys {
			if rule.CaseSensitive {
				if key == candidate {
					return rule, true
				}
				continue
			}
			if strings.EqualFold(key, candidate) {
				return rule, true
			}
		}
	}
	return FieldRule{}, false
}

func safeDetect(ctx context.Context, det detectors.Detector, text string) (matches []detectors.Match, err error) {
	defer func() {
		if recover() != nil {
			matches = nil
			err = fmt.Errorf("detector failed")
		}
	}()
	if d, ok := det.(ContextErrorDetector); ok {
		return d.DetectWithContextE(ctx, text)
	}
	if d, ok := det.(ErrorDetector); ok {
		return d.DetectE(text)
	}
	if d, ok := det.(ContextDetector); ok {
		return d.DetectWithContext(ctx, text), nil
	}
	return det.Detect(text), nil
}

func selectNonOverlapping(matches []detectors.Match) []detectors.Match {
	sort.SliceStable(matches, func(i, j int) bool {
		if matches[i].Priority != matches[j].Priority {
			return matches[i].Priority > matches[j].Priority
		}
		if matches[i].End-matches[i].Start != matches[j].End-matches[j].Start {
			return matches[i].End-matches[i].Start > matches[j].End-matches[j].Start
		}
		return matches[i].Start < matches[j].Start
	})
	selected := make([]detectors.Match, 0, len(matches))
	for _, m := range matches {
		if m.Start < 0 || m.End <= m.Start {
			continue
		}
		overlap := false
		for _, s := range selected {
			if m.Start < s.End && s.Start < m.End {
				overlap = true
				break
			}
		}
		if !overlap {
			selected = append(selected, m)
		}
	}
	sort.Slice(selected, func(i, j int) bool { return selected[i].Start < selected[j].Start })
	return selected
}

func (r *Redactor) transformString(ctx context.Context, text, session string, occupied map[string]struct{}, result *TransformResult, changed *bool) (string, error) {
	var all []detectors.Match
	for _, det := range r.detectors {
		matches, err := safeDetect(ctx, det, text)
		if err != nil {
			return "", fmt.Errorf("%w: detector error", ErrUnsafeRequest)
		}
		all = append(all, matches...)
	}
	return r.transformMatches(text, session, occupied, result, changed, all)
}

func (r *Redactor) transformFieldString(text, session string, occupied map[string]struct{}, result *TransformResult, changed *bool, rule FieldRule) (string, error) {
	if text == "" {
		return text, nil
	}
	category := rule.Category
	if category == "" {
		category = rule.Name
	}
	return r.transformMatches(text, session, occupied, result, changed, []detectors.Match{{
		Category:  category,
		Value:     text,
		Start:     0,
		End:       len(text),
		Rule:      rule.Name,
		Action:    rule.Action,
		Generator: rule.Generator,
		Priority:  rule.Priority,
	}})
}

func (r *Redactor) transformMatches(text, session string, occupied map[string]struct{}, result *TransformResult, changed *bool, matches []detectors.Match) (string, error) {
	for _, m := range matches {
		if m.Start < 0 || m.End <= m.Start || m.End > len(text) || text[m.Start:m.End] != m.Value {
			return "", fmt.Errorf("%w: detector returned invalid span", ErrUnsafeRequest)
		}
	}
	if len(matches) == 0 {
		return text, nil
	}
	selected := selectNonOverlapping(matches)
	var b strings.Builder
	last := 0
	for _, m := range selected {
		action := m.Action
		if action == "" {
			action = string(ActionPlaceholder)
		}
		result.Categories = append(result.Categories, m.Category)
		result.Matches = append(result.Matches, MatchReport{Rule: m.Rule, Category: m.Category, Action: action, Generator: m.Generator})
		b.WriteString(text[last:m.Start])
		replacement := m.Value
		switch Action(action) {
		case ActionAllow:
		case ActionPlaceholder:
			var err error
			replacement, err = r.store.PlaceholderForSession(session, m.Value, occupied)
			if err != nil {
				return "", fmt.Errorf("%w: mapping failed", ErrUnsafeRequest)
			}
			result.Transformed++
		case ActionPseudonymize:
			if err := ValidateAction(action, m.Generator); err != nil {
				return "", fmt.Errorf("%w: invalid rule policy", ErrUnsafeRequest)
			}
			var err error
			replacement, err = r.store.Map(session, m.Value, occupied, func(attempt int) (string, error) {
				return generateReplacement(r.store.key[:], m.Generator, m.Value, attempt)
			})
			if err != nil {
				return "", fmt.Errorf("%w: generator or mapping failed", ErrUnsafeRequest)
			}
			result.Transformed++
		case ActionMask:
			replacement = maskValue(m.Value)
			result.Transformed++
		case ActionRedact:
			replacement = "[REDACTED]"
			result.Transformed++
		case ActionBlock:
			replacement = "[BLOCKED]"
			result.Blocked = true
			result.Transformed++
		default:
			return "", fmt.Errorf("%w: unknown action", ErrUnsafeRequest)
		}
		b.WriteString(replacement)
		if replacement != m.Value {
			*changed = true
		}
		last = m.End
	}
	b.WriteString(text[last:])
	return b.String(), nil
}

func detectImageMedia(v any) bool {
	switch val := v.(type) {
	case string:
		return strings.HasPrefix(strings.ToLower(strings.TrimSpace(val)), "data:image/")
	case map[string]any:
		if typ, _ := val["type"].(string); strings.Contains(strings.ToLower(typ), "image") {
			return true
		}
		for k, vv := range val {
			lk := strings.ToLower(k)
			if lk == "image_url" || lk == "input_image" || lk == "image" {
				return true
			}
			if detectImageMedia(vv) {
				return true
			}
		}
	case []any:
		for _, vv := range val {
			if detectImageMedia(vv) {
				return true
			}
		}
	}
	return false
}
