package redact

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
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

// CaptureReport contains sensitive values and is populated only by the
// explicit live-content monitor path. It must never be logged or persisted.
type CaptureReport struct {
	Rule        string `json:"rule"`
	Category    string `json:"category"`
	Action      string `json:"action"`
	Original    string `json:"original"`
	Replacement string `json:"replacement"`
}

type TransformResult struct {
	Body        []byte          `json:"-"`
	Categories  []string        `json:"categories"`
	Matches     []MatchReport   `json:"matches"`
	Transformed int             `json:"transformed"`
	Blocked     bool            `json:"blocked"`
	Warnings    []string        `json:"warnings,omitempty"`
	Captures    []CaptureReport `json:"-"`

	// newKnownValues counts originals this transform protected for the
	// first time. Earlier strings may contain them, so the request is
	// transformed once more.
	newKnownValues int
}

// FieldRule applies a policy to one selector kind. Keys select JSON object
// fields and HTML attributes/form identities. FormFields also selects HTML
// form identities. HTTP selectors apply to captured content, not API transport
// headers. Header names always match case-insensitively.
type FieldRule struct {
	Name          string
	Keys          []string
	Headers       []string
	Cookies       []string
	QueryParams   []string
	FormFields    []string
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
	return r.transform(body, session, injectNote, mediaPolicy, false)
}

// TransformWithCaptures is used only by the authenticated, live-only content
// monitor. Ordinary proxying and inspection never retain original match values
// in TransformResult.
func (r *Redactor) TransformWithCaptures(body []byte, session string, injectNote bool, mediaPolicy string) (TransformResult, error) {
	return r.transform(body, session, injectNote, mediaPolicy, true)
}

func (r *Redactor) transform(body []byte, session string, injectNote bool, mediaPolicy string, capture bool) (TransformResult, error) {
	var result TransformResult
	if !r.fieldRulesValid {
		return result, fmt.Errorf("%w: invalid field selector policy", ErrUnsafeRequest)
	}
	if len(bytes.TrimSpace(body)) == 0 {
		result.Body = body
		return result, nil
	}
	data, err := decodeRequestJSON(body)
	if err != nil {
		return result, err
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
	if len(r.detectors) == 0 && len(r.fieldRules) == 0 {
		result.Body = body
		return result, nil
	}

	occupiedValues := map[string]struct{}{}
	r.collectOccupied(data, protocolBusiness, "", occupiedValues)
	occupied := newOccupiedSet(occupiedValues)
	ctx := context.Background()
	var cancel context.CancelFunc
	if r.llmBudget > 0 {
		ctx, cancel = context.WithTimeout(ctx, r.llmBudget)
		defer cancel()
	}
	initial := result
	changed := false
	walked, err := r.walkPolicy(r.withKnownSnapshot(ctx), data, session, occupied, &result, &changed, capture, &transformBudget{}, 0, 0, nil, protocolBusiness, "")
	if err != nil {
		return TransformResult{}, genericUnsafeError(err)
	}
	if result.newKnownValues > 0 && !result.Blocked {
		// A value first protected late in the walk may also occur in a string
		// visited earlier. Mappings are deterministic, so a second walk over
		// the original request protects every occurrence with the same fakes.
		if data, err = decodeRequestJSON(body); err != nil {
			return TransformResult{}, err
		}
		result, changed = initial, false
		walked, err = r.walkPolicy(r.withKnownSnapshot(ctx), data, session, occupied, &result, &changed, capture, &transformBudget{}, 0, 0, nil, protocolBusiness, "")
		if err != nil {
			return TransformResult{}, genericUnsafeError(err)
		}
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

func decodeRequestJSON(body []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var data any
	if err := dec.Decode(&data); err != nil {
		return nil, ErrMalformedJSON
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return nil, ErrMalformedJSON
	}
	return data, nil
}

func genericUnsafeError(err error) error {
	if errors.Is(err, ErrMalformedJSON) {
		return ErrMalformedJSON
	}
	if errors.Is(err, ErrUnsafeRequest) {
		return fmt.Errorf("%w: content inspection failed", ErrUnsafeRequest)
	}
	return fmt.Errorf("%w: content inspection failed", ErrUnsafeRequest)
}

func (r *Redactor) collectOccupied(v any, parent protocolObjectKind, edge string, out map[string]struct{}) {
	r.collectOccupiedValue(v, parent, edge, out, 0, 0, false)
}

func (r *Redactor) collectOccupiedValue(v any, parent protocolObjectKind, edge string, out map[string]struct{}, depth, embeddedDepth int, forceBusiness bool) {
	if depth > maxPolicyDepth {
		return
	}
	switch val := v.(type) {
	case string:
		out[val] = struct{}{}
		r.collectDecodedOccupied(val, out, depth, embeddedDepth, forceBusiness)
	case json.Number:
		out[val.String()] = struct{}{}
	case map[string]any:
		kind := classifyProtocolObject(val, parent, edge)
		if forceBusiness {
			kind = protocolStructuredBusiness
		}
		for key, vv := range val {
			if protocolSchemaField(kind, val, key) {
				collectProtocolSchemaOccupied(vv, out, depth+1)
				continue
			}
			if opaqueProtocolField(kind, val, key, vv) || protocolRoutingField(kind, val, key) {
				continue
			}
			childForce := forceBusiness
			if _, matched := r.fieldRule(selectorKeys, key); matched {
				childForce = true
			}
			r.collectOccupiedValue(vv, kind, key, out, depth+1, embeddedDepth, childForce)
		}
	case []any:
		for _, vv := range val {
			r.collectOccupiedValue(vv, parent, edge, out, depth+1, embeddedDepth, forceBusiness)
		}
	}
}

func (r *Redactor) collectDecodedOccupied(text string, out map[string]struct{}, depth, embeddedDepth int, forceBusiness bool) {
	if depth > maxPolicyDepth || embeddedDepth > maxEmbeddedJSONDepth || len(text) > maxEmbeddedJSONBytes {
		return
	}
	if looksLikeHTMLContent(text) && r.collectHTMLOccupied(text, out, depth, embeddedDepth, false) {
		return
	}
	_, handled, err := protectHTTPContent(text, httpContentPolicy{
		Transform: func(selector, name, value string) (string, error) {
			out[value] = struct{}{}
			selected := forceBusiness
			if _, matched := r.fieldRule(selector, name); matched {
				selected = true
			}
			r.collectDecodedOccupied(value, out, depth+1, embeddedDepth+1, selected)
			return value, nil
		},
		JSON: func(value string) (string, error) {
			if decoded, ok := decodeJSONDocument(value); ok {
				r.collectOccupiedValue(decoded, protocolStructuredBusiness, "", out, depth+1, embeddedDepth+1, true)
			}
			return value, nil
		},
		HTML: func(value string) (string, error) {
			r.collectHTMLOccupied(value, out, depth+1, embeddedDepth+1, true)
			return value, nil
		},
		Text: func(value string) (string, error) {
			if r.collectHTMLOccupied(value, out, depth+1, embeddedDepth+1, false) {
				return value, nil
			}
			out[value] = struct{}{}
			return value, nil
		},
		HasHeaders: true,
		HasCookies: true,
		HasQuery:   true,
		HasForm:    true,
		HasJSON:    true,
	})
	if handled || err != nil {
		return
	}
	if r.collectHTMLOccupied(text, out, depth, embeddedDepth, false) {
		return
	}
	candidate, status := locateEmbeddedJSON(text)
	if status == embeddedJSONParsed {
		r.collectOccupiedValue(candidate.value, protocolStructuredBusiness, "", out, depth+1, embeddedDepth+1, true)
		r.collectDecodedOccupied(text[:candidate.start], out, depth+1, embeddedDepth+1, forceBusiness)
		r.collectDecodedOccupied(text[candidate.end:], out, depth+1, embeddedDepth+1, forceBusiness)
	}
}

func (r *Redactor) walkPolicy(
	ctx context.Context,
	v any,
	session string,
	occupied *occupiedSet,
	result *TransformResult,
	changed *bool,
	capture bool,
	budget *transformBudget,
	depth int,
	embeddedDepth int,
	inherited *FieldRule,
	parent protocolObjectKind,
	edge string,
) (any, error) {
	if err := budget.visit(depth); err != nil {
		return nil, err
	}
	switch val := v.(type) {
	case string:
		if inherited != nil {
			return r.transformFieldString(val, session, occupied, result, changed, *inherited, capture)
		}
		return r.transformUnselectedContent(ctx, val, session, occupied, result, changed, capture, budget, depth, embeddedDepth)
	case json.Number:
		if inherited == nil {
			rule, known := r.knownNumberRule(ctx, val.String())
			if !known {
				return val, nil
			}
			return r.transformFieldNumber(val, session, occupied, result, changed, rule, capture)
		}
		return r.transformFieldNumber(val, session, occupied, result, changed, *inherited, capture)
	case bool:
		if inherited == nil {
			return val, nil
		}
		return r.transformFieldBool(val, result, *inherited, capture)
	case nil:
		// JSON null carries no secret value and remains null under every field
		// policy, preserving the schema and avoiding a false transformation.
		return nil, nil
	case map[string]any:
		kind := classifyProtocolObject(val, parent, edge)
		if inherited != nil {
			kind = protocolStructuredBusiness
		}
		keys := make([]string, 0, len(val))
		for key := range val {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			vv := val[key]
			if protocolSchemaField(kind, val, key) {
				if err := validateProtocolSchema(vv, budget, depth+1); err != nil {
					return nil, err
				}
				continue
			}
			if opaqueProtocolField(kind, val, key, vv) || protocolRoutingField(kind, val, key) {
				continue
			}
			selected := inherited
			if direct, matched := r.fieldRule(selectorKeys, key); matched && (selected == nil || fieldRuleBefore(direct, *selected)) {
				directCopy := direct
				selected = &directCopy
			}
			nv, err := r.walkPolicy(ctx, vv, session, occupied, result, changed, capture, budget, depth+1, embeddedDepth, selected, kind, key)
			if err != nil {
				return nil, err
			}
			val[key] = nv
		}
		return val, nil
	case []any:
		for i, vv := range val {
			nv, err := r.walkPolicy(ctx, vv, session, occupied, result, changed, capture, budget, depth+1, embeddedDepth, inherited, parent, edge)
			if err != nil {
				return nil, err
			}
			val[i] = nv
		}
		return val, nil
	default:
		if inherited != nil {
			return nil, fmt.Errorf("%w: unsupported selected JSON value", ErrUnsafeRequest)
		}
		return v, nil
	}
}

// Image payloads and references are opaque only when their containing object
// is recognized as a protocol image block.
func isImageDataURL(value string) bool {
	value = strings.TrimLeft(value, " \t\r\n")
	const prefix = "data:image/"
	return len(value) >= len(prefix) && strings.EqualFold(value[:len(prefix)], prefix)
}

const (
	selectorKeys        = "keys"
	selectorHeaders     = "headers"
	selectorCookies     = "cookies"
	selectorQueryParams = "query_params"
	selectorFormFields  = "form_fields"
)

func (r *Redactor) fieldRule(selector, name string) (FieldRule, bool) {
	for _, rule := range r.fieldRules {
		var candidates []string
		switch selector {
		case selectorKeys:
			candidates = rule.Keys
		case selectorHeaders:
			candidates = rule.Headers
		case selectorCookies:
			candidates = rule.Cookies
		case selectorQueryParams:
			candidates = rule.QueryParams
		case selectorFormFields:
			candidates = rule.FormFields
		default:
			return FieldRule{}, false
		}
		for _, candidate := range candidates {
			caseSensitive := rule.CaseSensitive && selector != selectorHeaders
			if caseSensitive && name == candidate || !caseSensitive && strings.EqualFold(name, candidate) {
				return rule, true
			}
		}
	}
	return FieldRule{}, false
}

func fieldRuleBefore(left, right FieldRule) bool {
	if left.Priority != right.Priority {
		return left.Priority > right.Priority
	}
	return left.Name < right.Name
}

func (r *Redactor) transformUnselectedContent(
	ctx context.Context,
	text, session string,
	occupied *occupiedSet,
	result *TransformResult,
	changed *bool,
	capture bool,
	budget *transformBudget,
	depth int,
	embeddedDepth int,
) (string, error) {
	if len(r.detectors) == 0 && len(r.fieldRules) == 0 {
		return text, nil
	}
	if looksLikeHTMLContent(text) {
		if output, handled, err := r.transformHTMLString(ctx, text, session, occupied, result, changed, capture, budget, depth, embeddedDepth, false); handled || err != nil {
			return output, err
		}
	}
	hasTextPolicy := len(r.detectors) > 0 || r.knownSnapshot(ctx) != nil
	httpOutput, handled, err := protectHTTPContent(text, httpContentPolicy{
		Transform: func(selector, name, value string) (string, error) {
			if rule, matched := r.fieldRule(selector, name); matched {
				return r.transformSelectedString(value, session, occupied, result, changed, rule, capture)
			}
			if output, handled, err := r.transformHTMLString(ctx, value, session, occupied, result, changed, capture, budget, depth+1, embeddedDepth+1, false); handled || err != nil {
				return output, err
			}
			if output, embedded, embeddedErr := r.transformEmbeddedString(ctx, value, session, occupied, result, changed, capture, budget, depth+1, embeddedDepth+1); embedded || embeddedErr != nil {
				return output, embeddedErr
			}
			if selector == selectorQueryParams || selector == selectorFormFields {
				if output, handled, err := r.transformAssignmentValue(ctx, name, value, session, occupied, result, changed, capture); handled || err != nil {
					return output, err
				}
			}
			return r.transformString(ctx, value, session, occupied, result, changed, capture)
		},
		JSON: func(value string) (string, error) {
			return r.transformJSONDocument(ctx, value, session, occupied, result, changed, capture, budget, depth+1, embeddedDepth+1)
		},
		HTML: func(value string) (string, error) {
			output, _, err := r.transformHTMLString(ctx, value, session, occupied, result, changed, capture, budget, depth+1, embeddedDepth+1, true)
			return output, err
		},
		// Text around and between messages, after a declared body, and in
		// non-JSON bodies receives the complete unselected pipeline: it can
		// hold JSON, a form or a URL that the framing did not claim.
		Text: func(value string) (string, error) {
			if err := budget.visit(depth + 1); err != nil {
				return "", err
			}
			return r.transformUnselectedContent(ctx, value, session, occupied, result, changed, capture, budget, depth+1, embeddedDepth+1)
		},
		HeaderSelected: func(name string) bool {
			_, matched := r.fieldRule(selectorHeaders, name)
			return matched
		},
		Selected: func(selector, name string) bool {
			_, matched := r.fieldRule(selector, name)
			return matched
		},
		HasHeaders: hasTextPolicy || r.hasHeaderRules,
		HasCookies: hasTextPolicy || r.hasCookieRules,
		HasQuery:   hasTextPolicy || r.hasQueryRules,
		HasForm:    hasTextPolicy || r.hasFormRules,
		HasJSON:    hasTextPolicy || r.hasKeyRules,
	})
	if err != nil {
		return "", err
	}
	if handled {
		return httpOutput, nil
	}
	if output, handled, err := r.transformHTMLString(ctx, text, session, occupied, result, changed, capture, budget, depth, embeddedDepth, false); handled || err != nil {
		return output, err
	}
	if output, embedded, err := r.transformEmbeddedString(ctx, text, session, occupied, result, changed, capture, budget, depth+1, embeddedDepth+1); embedded || err != nil {
		return output, err
	}
	return r.transformString(ctx, text, session, occupied, result, changed, capture)
}

func (r *Redactor) transformJSONDocument(
	ctx context.Context,
	text, session string,
	occupied *occupiedSet,
	result *TransformResult,
	changed *bool,
	capture bool,
	budget *transformBudget,
	depth int,
	embeddedDepth int,
) (string, error) {
	value, ok := decodeJSONDocument(text)
	if !ok {
		return "", fmt.Errorf("%w: malformed embedded JSON", ErrUnsafeRequest)
	}
	if err := budget.embedded(len(text), embeddedDepth); err != nil {
		return "", err
	}
	localChanged := false
	walked, err := r.walkDecodedEmbedded(ctx, value, session, occupied, result, &localChanged, capture, budget, depth, embeddedDepth)
	if err != nil {
		return "", err
	}
	if !localChanged {
		return text, nil
	}
	output, err := marshalEmbeddedValue(walked)
	if err != nil {
		return "", fmt.Errorf("%w: encoding embedded JSON", ErrUnsafeRequest)
	}
	*changed = true
	return output, nil
}

func (r *Redactor) transformEmbeddedString(
	ctx context.Context,
	text, session string,
	occupied *occupiedSet,
	result *TransformResult,
	changed *bool,
	capture bool,
	budget *transformBudget,
	depth int,
	embeddedDepth int,
) (string, bool, error) {
	if len(text) > maxEmbeddedJSONBytes-budget.embeddedBytes {
		if looksLikeEmbeddedJSON(text) {
			return "", true, fmt.Errorf("%w: embedded JSON limit exceeded", ErrUnsafeRequest)
		}
		return "", false, nil
	}
	candidate, status := locateEmbeddedJSON(text)
	if status == embeddedJSONNone {
		return "", false, nil
	}
	if status == embeddedJSONMalformed {
		if r.selectedJSONFieldNeedsParser(embeddedCandidateInspectionText(text, candidate)) {
			return "", true, fmt.Errorf("%w: malformed selected embedded JSON", ErrUnsafeRequest)
		}
		return "", false, nil
	}
	if err := budget.embedded(candidate.end-candidate.start, embeddedDepth); err != nil {
		return "", true, err
	}

	candidateChanged := false
	walked, err := r.walkDecodedEmbedded(ctx, candidate.value, session, occupied, result, &candidateChanged, capture, budget, depth, embeddedDepth)
	if err != nil {
		return "", true, err
	}
	frameChanged := false
	prefix, err := r.transformEmbeddedFrame(ctx, text[:candidate.start], session, occupied, result, &frameChanged, capture, budget, depth+1, embeddedDepth+1)
	if err != nil {
		return "", true, err
	}
	suffix, err := r.transformEmbeddedFrame(ctx, text[candidate.end:], session, occupied, result, &frameChanged, capture, budget, depth+1, embeddedDepth+1)
	if err != nil {
		return "", true, err
	}
	if !candidateChanged && !frameChanged {
		return text, true, nil
	}
	encoded := text[candidate.start:candidate.end]
	if candidateChanged {
		encoded, err = marshalEmbeddedCandidate(candidate, walked)
		if err != nil {
			return "", true, fmt.Errorf("%w: encoding embedded JSON", ErrUnsafeRequest)
		}
	}
	*changed = true
	return prefix + encoded + suffix, true, nil
}

func (r *Redactor) transformEmbeddedFrame(
	ctx context.Context,
	text, session string,
	occupied *occupiedSet,
	result *TransformResult,
	changed *bool,
	capture bool,
	budget *transformBudget,
	depth int,
	embeddedDepth int,
) (string, error) {
	if output, handled, err := r.transformEmbeddedString(ctx, text, session, occupied, result, changed, capture, budget, depth, embeddedDepth); handled || err != nil {
		return output, err
	}
	return r.transformString(ctx, text, session, occupied, result, changed, capture)
}

func (r *Redactor) walkDecodedEmbedded(
	ctx context.Context,
	value any,
	session string,
	occupied *occupiedSet,
	result *TransformResult,
	changed *bool,
	capture bool,
	budget *transformBudget,
	depth int,
	embeddedDepth int,
) (any, error) {
	if text, ok := value.(string); ok {
		output, handled, err := r.transformEmbeddedString(ctx, text, session, occupied, result, changed, capture, budget, depth+1, embeddedDepth+1)
		if err != nil {
			return nil, err
		}
		if handled {
			return output, nil
		}
		return r.transformString(ctx, text, session, occupied, result, changed, capture)
	}
	return r.walkPolicy(ctx, value, session, occupied, result, changed, capture, budget, depth, embeddedDepth, nil, protocolStructuredBusiness, "")
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

// selectNonOverlapping resolves overlapping matches without exposing any byte
// that a protective match selected. An allow match only exempts protective
// matches that it fully contains and that do not outrank it. Overlapping
// protective matches form one cluster: a block wins, otherwise the
// highest-priority match covering the whole cluster is used, and a cluster
// that no single match covers becomes one placeholder.
func selectNonOverlapping(text string, matches []detectors.Match) (selected, protected []detectors.Match) {
	byPriority := func(list []detectors.Match) {
		sort.SliceStable(list, func(i, j int) bool {
			if list[i].Priority != list[j].Priority {
				return list[i].Priority > list[j].Priority
			}
			if list[i].End-list[i].Start != list[j].End-list[j].Start {
				return list[i].End-list[i].Start > list[j].End-list[j].Start
			}
			return list[i].Start < list[j].Start
		})
	}
	var allows, protective []detectors.Match
	for _, m := range matches {
		if m.Start < 0 || m.End <= m.Start {
			continue
		}
		if Action(m.Action) == ActionAllow {
			allows = append(allows, m)
		} else {
			protective = append(protective, m)
		}
	}
	kept := protective[:0]
	for _, m := range protective {
		exempt := false
		for _, a := range allows {
			if a.Start <= m.Start && m.End <= a.End && a.Priority >= m.Priority {
				exempt = true
				break
			}
		}
		if !exempt {
			kept = append(kept, m)
		}
	}
	sort.SliceStable(kept, func(i, j int) bool { return kept[i].Start < kept[j].Start })

	for i := 0; i < len(kept); {
		start, end := kept[i].Start, kept[i].End
		j := i + 1
		for j < len(kept) && kept[j].Start < end {
			end = max(end, kept[j].End)
			j++
		}
		cluster := append([]detectors.Match(nil), kept[i:j]...)
		byPriority(cluster)
		selected = append(selected, chooseClusterMatch(text, cluster, start, end))
		i = j
	}

	byPriority(allows)
	for _, a := range allows {
		overlap := false
		for _, s := range selected {
			if a.Start < s.End && s.Start < a.End {
				overlap = true
				break
			}
		}
		if !overlap {
			selected = append(selected, a)
		}
	}
	sort.Slice(selected, func(i, j int) bool { return selected[i].Start < selected[j].Start })
	return selected, kept
}

func chooseClusterMatch(text string, cluster []detectors.Match, start, end int) detectors.Match {
	for _, m := range cluster {
		if Action(m.Action) == ActionBlock {
			return m
		}
	}
	for _, m := range cluster {
		if m.Start == start && m.End == end {
			return m
		}
	}
	top := cluster[0]
	return detectors.Match{
		Category: top.Category, Rule: top.Rule, Priority: top.Priority,
		Value: text[start:end], Start: start, End: end,
		Action: string(ActionPlaceholder),
	}
}

func (r *Redactor) policyTextMatches(ctx context.Context, text string) ([]detectors.Match, error) {
	all, err := r.knownSnapshot(ctx).matches(text)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnsafeRequest, err)
	}
	all = append(all, r.textSelectorMatches(text)...)
	for _, det := range r.detectors {
		matches, err := safeDetect(ctx, det, text)
		if err != nil {
			return nil, fmt.Errorf("%w: detector error", ErrUnsafeRequest)
		}
		all = append(all, matches...)
	}
	return all, nil
}

func (r *Redactor) transformString(ctx context.Context, text, session string, occupied *occupiedSet, result *TransformResult, changed *bool, capture bool) (string, error) {
	all, err := r.policyTextMatches(ctx, text)
	if err != nil {
		return "", err
	}
	return r.transformMatches(text, session, occupied, result, changed, all, capture)
}

// transformAssignmentValue preserves detector context without mapping the
// parameter name or its delimiter. Matches are projected onto the original
// decoded value before priority resolution and mapping, never onto an alias.
func (r *Redactor) transformAssignmentValue(ctx context.Context, name, value, session string, occupied *occupiedSet, result *TransformResult, changed *bool, capture bool) (string, bool, error) {
	if value == "" || len(r.detectors) == 0 {
		return value, false, nil
	}
	assignment := name + "=" + value
	valueStart := len(name) + 1
	contextMatches, err := r.policyTextMatches(ctx, assignment)
	if err != nil {
		return "", true, err
	}
	var projected []detectors.Match
	for _, match := range contextMatches {
		if match.Start < 0 || match.End <= match.Start || match.End > len(assignment) || assignment[match.Start:match.End] != match.Value {
			return "", true, fmt.Errorf("%w: detector returned invalid span", ErrUnsafeRequest)
		}
		if match.End <= valueStart {
			continue
		}
		match.Start = max(match.Start-valueStart, 0)
		match.End -= valueStart
		match.Value = value[match.Start:match.End]
		projected = append(projected, match)
	}
	if len(projected) == 0 {
		return value, false, nil
	}
	valueMatches, err := r.policyTextMatches(ctx, value)
	if err != nil {
		return "", true, err
	}
	projected = append(projected, valueMatches...)
	output, err := r.transformMatches(value, session, occupied, result, changed, projected, capture)
	return output, true, err
}

func (r *Redactor) transformFieldString(text, session string, occupied *occupiedSet, result *TransformResult, changed *bool, rule FieldRule, capture bool) (string, error) {
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
	}}, capture)
}

func (r *Redactor) transformFieldNumber(number json.Number, session string, occupied *occupiedSet, result *TransformResult, changed *bool, rule FieldRule, capture bool) (json.Number, error) {
	original := number.String()
	action := rule.Action
	if action == "" {
		action = string(ActionPlaceholder)
	}
	category := rule.Category
	if category == "" {
		category = rule.Name
	}
	result.Categories = append(result.Categories, category)
	result.Matches = append(result.Matches, MatchReport{Rule: rule.Name, Category: category, Action: action, Generator: rule.Generator})
	if Action(action) != ActionAllow && r.store.known.remember(original, detectors.Match{
		Category: category, Rule: rule.Name, Action: action, Generator: rule.Generator, Priority: rule.Priority,
	}) {
		result.newKnownValues++
	}

	replacement := original
	switch Action(action) {
	case ActionAllow:
	case ActionPseudonymize:
		if rule.Generator != "number" {
			return "", fmt.Errorf("%w: selected number requires number generator", ErrUnsafeRequest)
		}
		var err error
		replacement, err = r.store.MapNumber(session, original, occupied, func(attempt int) (string, error) {
			return generateReplacement(r.store.key[:], "number", original, attempt)
		})
		if err != nil {
			return "", fmt.Errorf("%w: numeric mapping failed", ErrUnsafeRequest)
		}
		result.Transformed++
	case ActionBlock:
		result.Blocked = true
		result.Transformed++
	default:
		return "", fmt.Errorf("%w: selected number policy does not preserve JSON type", ErrUnsafeRequest)
	}
	if capture {
		result.Captures = append(result.Captures, CaptureReport{
			Rule: rule.Name, Category: category, Action: action,
			Original: original, Replacement: replacement,
		})
	}
	if replacement != original {
		*changed = true
	}
	return json.Number(replacement), nil
}

func (r *Redactor) transformFieldBool(value bool, result *TransformResult, rule FieldRule, capture bool) (bool, error) {
	action := rule.Action
	if action == "" {
		action = string(ActionPlaceholder)
	}
	if Action(action) != ActionAllow && Action(action) != ActionBlock {
		return false, fmt.Errorf("%w: selected boolean policy does not preserve JSON type", ErrUnsafeRequest)
	}
	category := rule.Category
	if category == "" {
		category = rule.Name
	}
	result.Categories = append(result.Categories, category)
	result.Matches = append(result.Matches, MatchReport{Rule: rule.Name, Category: category, Action: action, Generator: rule.Generator})
	if Action(action) == ActionBlock {
		result.Blocked = true
		result.Transformed++
	}
	if capture {
		original := strconv.FormatBool(value)
		result.Captures = append(result.Captures, CaptureReport{
			Rule: rule.Name, Category: category, Action: action,
			Original: original, Replacement: original,
		})
	}
	return value, nil
}

func (r *Redactor) transformMatches(text, session string, occupied *occupiedSet, result *TransformResult, changed *bool, matches []detectors.Match, capture bool) (string, error) {
	var b strings.Builder
	last := 0
	err := r.applyPolicyMatches(text, session, occupied, result, changed, matches, capture, func(m detectors.Match, replacement string) {
		b.WriteString(text[last:m.Start])
		b.WriteString(replacement)
		last = m.End
	})
	if err != nil {
		return "", err
	}
	if last == 0 {
		return text, nil
	}
	b.WriteString(text[last:])
	return b.String(), nil
}

// applyPolicyMatches shares policy decisions between ordinary text and HTML
// span editing so detector priority, blocking and mappings have one owner.
func (r *Redactor) applyPolicyMatches(text, session string, occupied *occupiedSet, result *TransformResult, changed *bool, matches []detectors.Match, capture bool, emit func(detectors.Match, string)) error {
	for _, m := range matches {
		if m.Start < 0 || m.End <= m.Start || m.End > len(text) || text[m.Start:m.End] != m.Value {
			return fmt.Errorf("%w: detector returned invalid span", ErrUnsafeRequest)
		}
	}
	if len(matches) == 0 {
		return nil
	}
	selected, protected := selectNonOverlapping(text, matches)
	for _, m := range selected {
		action := m.Action
		if action == "" {
			action = string(ActionPlaceholder)
		}
		original, ok := decodeKnownValue(m.Encoding, m.Value)
		if !ok {
			return fmt.Errorf("%w: invalid encoded match", ErrUnsafeRequest)
		}
		result.Categories = append(result.Categories, m.Category)
		result.Matches = append(result.Matches, MatchReport{Rule: m.Rule, Category: m.Category, Action: action, Generator: m.Generator})
		replacement := original
		switch Action(action) {
		case ActionAllow:
		case ActionPlaceholder:
			var err error
			replacement, err = r.store.PlaceholderForSession(session, original, occupied)
			if err != nil {
				return fmt.Errorf("%w: mapping failed", ErrUnsafeRequest)
			}
			result.Transformed++
		case ActionPseudonymize:
			if err := ValidateAction(action, m.Generator); err != nil {
				return fmt.Errorf("%w: invalid rule policy", ErrUnsafeRequest)
			}
			var err error
			replacement, err = r.store.Map(session, original, occupied, func(attempt int) (string, error) {
				return generateReplacement(r.store.key[:], m.Generator, original, attempt)
			})
			if err != nil {
				return fmt.Errorf("%w: generator or mapping failed", ErrUnsafeRequest)
			}
			// A short or numeric fake continuing a word here, as in
			// dbprimary01_backup, would not be restored there, so an
			// unambiguous placeholder stands in for this occurrence.
			if ambiguousFake(replacement) && !replacementFitsAt(text, m.Start, m.End, encodeKnownValue(m.Encoding, replacement)) {
				replacement, err = r.store.GluedPlaceholderForSession(session, original, occupied)
				if err != nil {
					return fmt.Errorf("%w: mapping failed", ErrUnsafeRequest)
				}
			}
			result.Transformed++
		case ActionMask:
			replacement = maskValue(original)
			result.Transformed++
		case ActionRedact:
			replacement = "[REDACTED]"
			result.Transformed++
		case ActionBlock:
			replacement = "[BLOCKED]"
			result.Blocked = true
			result.Transformed++
		default:
			return fmt.Errorf("%w: unknown action", ErrUnsafeRequest)
		}
		if Action(action) != ActionAllow && r.store.known.remember(original, m) {
			result.newKnownValues++
		}
		if capture {
			result.Captures = append(result.Captures, CaptureReport{
				Rule: m.Rule, Category: m.Category, Action: action,
				Original: original, Replacement: replacement,
			})
		}
		if replacement != original {
			replacement = encodeKnownValue(m.Encoding, replacement)
		} else {
			replacement = m.Value
		}
		emit(m, replacement)
		if replacement != m.Value {
			*changed = true
		}
	}
	r.store.known.renew(protected)
	return nil
}

type knownSnapshotKey struct{}

// withKnownSnapshot fixes the protected values for one transform pass, so
// values added during the pass do not rebuild matchers mid-request. A second
// pass sees them.
func (r *Redactor) withKnownSnapshot(ctx context.Context) context.Context {
	return context.WithValue(ctx, knownSnapshotKey{}, r.store.known.current())
}

func (r *Redactor) knownSnapshot(ctx context.Context) *knownSnapshot {
	if snapshot, ok := ctx.Value(knownSnapshotKey{}).(*knownSnapshot); ok {
		return snapshot
	}
	return r.store.known.current()
}

// knownNumberRule returns the policy for an unselected JSON number that equals
// a protected original. Numbers keep their JSON type through the number
// generator unless the original was blocked.
func (r *Redactor) knownNumberRule(ctx context.Context, number string) (FieldRule, bool) {
	template, ok := r.knownSnapshot(ctx).number(number)
	if !ok {
		return FieldRule{}, false
	}
	rule := FieldRule{Name: template.Rule, Category: template.Category, Priority: template.Priority,
		Action: string(ActionPseudonymize), Generator: "number"}
	if Action(template.Action) == ActionBlock {
		rule.Action, rule.Generator = string(ActionBlock), ""
	}
	return rule, true
}

func detectImageMedia(v any) bool {
	switch val := v.(type) {
	case string:
		return isImageDataURL(val)
	case map[string]any:
		if typ, _ := val["type"].(string); strings.Contains(strings.ToLower(typ), "image") {
			return true
		}
		for k, vv := range val {
			lk := strings.ToLower(k)
			if lk == "image_url" || lk == "input_image" || lk == "image" || lk == "b64_json" {
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
