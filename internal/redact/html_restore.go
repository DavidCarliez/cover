package redact

import "strings"

// HTML restoration uses the same parsing and escaping boundary as protection.
// Each inserted replacement occupies one text node; restoring nodes separately
// preserves surrounding markup without rescanning every stored mapping.
func (r *Redactor) restoreHTMLString(text string, snapshot *restorationSnapshot, depth int, nodes *int, force bool) (string, bool, bool, bool) {
	check := func() error {
		if depth > maxPolicyDepth || *nodes >= maxPolicyNodes {
			return ErrUnsafeRequest
		}
		*nodes++
		return nil
	}
	restoreValue := func(value string) (string, error) {
		if err := check(); err != nil {
			return "", err
		}
		if restored, ok := snapshot.restoreNumber(value); ok {
			return restored, nil
		}
		restored, _, safe := r.walkRestoreValues(value, snapshot, protocolStructuredBusiness, "", depth+1, nodes)
		if !safe {
			return "", ErrUnsafeRequest
		}
		return restored.(string), nil
	}
	urlPolicy := httpContentPolicy{
		Transform: func(_, _ string, value string) (string, error) { return restoreValue(value) },
		Text:      func(value string) (string, error) { return snapshot.restoreHTTPText(value), nil },
		HasQuery:  true,
	}
	output, handled, err := protectHTMLContent(text, htmlContentPolicy{
		Force:     force,
		TextNodes: true,
		Field:     func(_ []string, value string) (string, error) { return restoreValue(value) },
		Attribute: func(name, value string) (string, error) {
			if err := check(); err != nil {
				return "", err
			}
			if strings.EqualFold(name, "srcdoc") {
				restored, _, _, safe := r.restoreHTMLString(value, snapshot, depth+1, nodes, true)
				if !safe {
					return "", ErrUnsafeRequest
				}
				return restored, nil
			}
			if htmlURLAttribute(name) {
				restored, _, err := transformURLQuery(value, urlPolicy, false)
				return restored, err
			}
			return restoreValue(value)
		},
		Text: func(value string) ([]htmlTextEdit, error) {
			if err := check(); err != nil {
				return nil, err
			}
			restored := snapshot.restoreHTTPText(value)
			if restored == value {
				return nil, nil
			}
			return []htmlTextEdit{{start: 0, end: len(value), replacement: restored}}, nil
		},
		JSON: func(value string) (string, error) {
			if err := check(); err != nil {
				return "", err
			}
			restored, _, safe := r.restoreJSONDocument(value, snapshot, depth+1, nodes)
			if !safe {
				return "", ErrUnsafeRequest
			}
			return restored, nil
		},
	})
	if err != nil {
		return text, true, false, false
	}
	return output, handled, output != text, true
}
