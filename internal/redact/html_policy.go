package redact

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/DavidCarliez/cover/internal/redact/detectors"
)

// transformSelectedString preserves numeric mapping identity across JSON,
// HTTP and HTML string-valued representations of the same identifier.
func (r *Redactor) transformSelectedString(value, session string, occupied *occupiedSet, result *TransformResult, changed *bool, rule FieldRule, capture bool) (string, error) {
	if rule.Action == string(ActionPseudonymize) && rule.Generator == "number" {
		number, err := r.transformFieldNumber(json.Number(value), session, occupied, result, changed, rule, capture)
		return number.String(), err
	}
	return r.transformFieldString(value, session, occupied, result, changed, rule, capture)
}

func (r *Redactor) htmlFieldRule(names []string) (FieldRule, bool) {
	var selected FieldRule
	found := false
	for _, name := range names {
		for _, selector := range []string{selectorKeys, selectorFormFields} {
			if rule, ok := r.fieldRule(selector, name); ok && (!found || fieldRuleBefore(rule, selected)) {
				selected, found = rule, true
			}
		}
	}
	return selected, found
}

func htmlURLAttribute(name string) bool {
	switch strings.TrimPrefix(strings.ToLower(name), "xlink:") {
	case "href", "src", "action", "formaction", "poster", "cite", "background", "longdesc":
		return true
	}
	return false
}

func (r *Redactor) transformHTMLString(ctx context.Context, text, session string, occupied *occupiedSet, result *TransformResult, changed *bool, capture bool, budget *transformBudget, depth, embeddedDepth int, force bool) (string, bool, error) {
	charged := false
	check := func() error {
		if err := ctx.Err(); err != nil {
			return ErrUnsafeRequest
		}
		if !charged {
			if err := budget.embedded(len(text), embeddedDepth); err != nil {
				return err
			}
			charged = true
		}
		return budget.visit(depth)
	}
	unselected := func(value string) (string, error) {
		return r.transformUnselectedContent(ctx, value, session, occupied, result, changed, capture, budget, depth+1, embeddedDepth+1)
	}
	urlPolicy := httpContentPolicy{
		Transform: func(selector, name, value string) (string, error) {
			if rule, ok := r.fieldRule(selector, name); ok {
				return r.transformSelectedString(value, session, occupied, result, changed, rule, capture)
			}
			if output, handled, err := r.transformAssignmentValue(ctx, name, value, session, occupied, result, changed, capture); handled || err != nil {
				return output, err
			}
			return unselected(value)
		},
		Text: func(value string) (string, error) {
			return r.transformString(ctx, value, session, occupied, result, changed, capture)
		},
		HasQuery: true,
	}
	output, handled, err := protectHTMLContent(text, htmlContentPolicy{
		Force: force,
		Field: func(names []string, value string) (string, error) {
			if err := check(); err != nil {
				return "", err
			}
			if rule, ok := r.htmlFieldRule(names); ok {
				return r.transformSelectedString(value, session, occupied, result, changed, rule, capture)
			}
			return unselected(value)
		},
		Attribute: func(name, value string) (string, error) {
			if err := check(); err != nil {
				return "", err
			}
			if rule, ok := r.fieldRule(selectorKeys, name); ok {
				return r.transformSelectedString(value, session, occupied, result, changed, rule, capture)
			}
			// data-password carries the same field as a password key.
			if len(name) > 5 && strings.EqualFold(name[:5], "data-") {
				if rule, ok := r.fieldRule(selectorKeys, name[5:]); ok {
					return r.transformSelectedString(value, session, occupied, result, changed, rule, capture)
				}
			}
			if strings.EqualFold(name, "srcdoc") {
				output, _, err := r.transformHTMLString(ctx, value, session, occupied, result, changed, capture, budget, depth+1, embeddedDepth+1, true)
				return output, err
			}
			if htmlURLAttribute(name) {
				output, _, err := transformURLQuery(value, urlPolicy, false)
				return output, err
			}
			return unselected(value)
		},
		Text: func(value string) ([]htmlTextEdit, error) {
			if err := check(); err != nil {
				return nil, err
			}
			matches, err := r.policyTextMatches(ctx, value)
			if err != nil {
				return nil, err
			}
			var edits []htmlTextEdit
			err = r.applyPolicyMatches(value, session, occupied, result, changed, matches, capture, func(match detectors.Match, replacement string) {
				if replacement != match.Value {
					edits = append(edits, htmlTextEdit{start: match.Start, end: match.End, replacement: replacement})
				}
			})
			return edits, err
		},
		JSON: func(value string) (string, error) {
			if err := check(); err != nil {
				return "", err
			}
			return r.transformJSONDocument(ctx, value, session, occupied, result, changed, capture, budget, depth+1, embeddedDepth+1)
		},
	})
	if err == nil && handled && !charged {
		err = check()
	}
	if err != nil {
		return "", handled, err
	}
	if handled && output != text {
		*changed = true
	}
	return output, handled, nil
}

// Reserve decoded values before allocating pseudonyms; entities and split
// text nodes must not hide literal strings that could collide with a fake.
func (r *Redactor) collectHTMLOccupied(text string, out map[string]struct{}, depth, embeddedDepth int, force bool) bool {
	if depth > maxPolicyDepth || embeddedDepth > maxEmbeddedJSONDepth || len(text) > maxEmbeddedJSONBytes {
		return false
	}
	collect := func(value string) {
		out[value] = struct{}{}
		r.collectDecodedOccupied(value, out, depth+1, embeddedDepth+1, true)
	}
	_, handled, _ := protectHTMLContent(text, htmlContentPolicy{
		Force: force,
		Field: func(_ []string, value string) (string, error) {
			collect(value)
			return value, nil
		},
		Attribute: func(name, value string) (string, error) {
			if strings.EqualFold(name, "srcdoc") {
				r.collectHTMLOccupied(value, out, depth+1, embeddedDepth+1, true)
			} else {
				collect(value)
			}
			return value, nil
		},
		Text: func(value string) ([]htmlTextEdit, error) {
			out[value] = struct{}{}
			return nil, nil
		},
		JSON: func(value string) (string, error) {
			if decoded, ok := decodeJSONDocument(value); ok {
				r.collectOccupiedValue(decoded, protocolStructuredBusiness, "", out, depth+1, embeddedDepth+1, true)
			}
			return value, nil
		},
	})
	return handled
}
