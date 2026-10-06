package redact

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
)

// RestoreResponse replaces placeholder tokens in an upstream response body.
// JSON and SSE payloads are parsed so restored values are re-encoded with
// proper escaping; other bodies use byte-level restoration.
func (r *Redactor) RestoreResponse(body []byte, contentType string) []byte {
	return r.RestoreResponseForSession(body, contentType, defaultSessionID)
}

func (r *Redactor) RestoreResponseForSession(body []byte, contentType, session string) []byte {
	if isSSEContentType(contentType) {
		return r.restoreSSE(body, session)
	}
	return r.restoreJSONOrRaw(body, session)
}

func isSSEContentType(contentType string) bool {
	return bytes.Contains([]byte(contentType), []byte("text/event-stream"))
}

func (r *Redactor) restoreJSONOrRaw(body []byte, session string) []byte {
	snapshot := r.store.restorationSnapshot(session)
	if snapshot == nil {
		return body
	}
	return r.restoreJSONOrRawWithSnapshot(body, snapshot)
}

func (r *Redactor) restoreJSONOrRawWithSnapshot(body []byte, snapshot *restorationSnapshot) []byte {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return body
	}
	first := trimmed[0]
	if first == '{' || first == '[' || first == '"' || first == '-' || first >= '0' && first <= '9' {
		decoder := json.NewDecoder(bytes.NewReader(trimmed))
		decoder.UseNumber()
		var value, trailing any
		if decoder.Decode(&value) == nil && decoder.Decode(&trailing) == io.EOF {
			nodes := 0
			walked, changed, safe := r.walkRestoreValues(value, snapshot, protocolBusiness, "", 0, &nodes)
			if !safe || !changed {
				return body
			}
			if output, err := json.Marshal(walked); err == nil {
				return output
			}
			return body
		}
	}
	nodes := 0
	text := string(body)
	if restored, handled, changed, safe := r.restoreContentString(text, snapshot, 0, &nodes); handled {
		if !safe || !changed {
			return body
		}
		return []byte(restored)
	}
	if restored, handled, changed := r.restoreEmbeddedString(text, snapshot, 0, &nodes); handled {
		if !changed {
			return body
		}
		return []byte(restored)
	}
	restored, _ := snapshot.restoreBytes(body)
	return restored
}

func (r *Redactor) walkRestoreValues(v any, snapshot *restorationSnapshot, parent protocolObjectKind, edge string, depth int, nodes *int) (any, bool, bool) {
	if depth > maxPolicyDepth || *nodes >= maxPolicyNodes {
		return v, false, false
	}
	*nodes++
	switch val := v.(type) {
	case string:
		if restored, handled, changed, safe := r.restoreContentString(val, snapshot, depth+1, nodes); handled {
			return restored, changed, safe
		}
		if restored, handled, changed := r.restoreEmbeddedString(val, snapshot, depth+1, nodes); handled {
			return restored, changed, true
		}
		restored, changed := snapshot.restoreString(val)
		return restored, changed, true
	case json.Number:
		restored, changed := snapshot.restoreNumber(val.String())
		if !changed {
			return val, false, true
		}
		return json.Number(restored), true, true
	case map[string]any:
		kind := classifyProtocolObject(val, parent, edge)
		changed := false
		for key, vv := range val {
			if protocolSchemaField(kind, val, key) {
				budget := transformBudget{nodes: *nodes}
				if err := validateProtocolSchema(vv, &budget, depth+1); err != nil {
					return v, false, false
				}
				*nodes = budget.nodes
				continue
			}
			if opaqueProtocolField(kind, val, key, vv) || protocolRoutingField(kind, val, key) {
				continue
			}
			childParent := kind
			if _, matched := r.fieldRule(selectorKeys, key); matched {
				childParent = protocolStructuredBusiness
			}
			restored, fieldChanged, safe := r.walkRestoreValues(vv, snapshot, childParent, key, depth+1, nodes)
			if !safe {
				return v, false, false
			}
			val[key] = restored
			changed = changed || fieldChanged
		}
		return val, changed, true
	case []any:
		changed := false
		for i, vv := range val {
			restored, itemChanged, safe := r.walkRestoreValues(vv, snapshot, parent, edge, depth+1, nodes)
			if !safe {
				return v, false, false
			}
			val[i] = restored
			changed = changed || itemChanged
		}
		return val, changed, true
	default:
		return v, false, true
	}
}

// Whole HTML owns its markup. Otherwise HTTP framing owns the surrounding
// headers, including when its body contains an HTML fence.
func (r *Redactor) restoreContentString(text string, snapshot *restorationSnapshot, depth int, nodes *int) (string, bool, bool, bool) {
	if looksLikeHTMLContent(text) {
		if restored, handled, changed, safe := r.restoreHTMLString(text, snapshot, depth, nodes, false); handled {
			return restored, handled, changed, safe
		}
	}
	if restored, handled, changed, safe := r.restoreHTTPString(text, snapshot, depth, nodes); handled {
		return restored, handled, changed, safe
	}
	return r.restoreHTMLString(text, snapshot, depth, nodes, false)
}

func (r *Redactor) restoreHTTPString(text string, snapshot *restorationSnapshot, depth int, nodes *int) (string, bool, bool, bool) {
	if depth > maxPolicyDepth {
		return text, true, false, false
	}
	output, handled, err := protectHTTPContent(text, httpContentPolicy{
		Transform: func(_, _ string, value string) (string, error) {
			if restored, ok := snapshot.restoreNumber(value); ok {
				return restored, nil
			}
			if restored, handled, _, safe := r.restoreContentString(value, snapshot, depth+1, nodes); handled {
				if !safe {
					return "", ErrUnsafeRequest
				}
				return restored, nil
			}
			if restored, embedded, changed := r.restoreEmbeddedString(value, snapshot, depth+1, nodes); embedded {
				if changed {
					return restored, nil
				}
				return value, nil
			}
			restored, _ := snapshot.restoreString(value)
			return restored, nil
		},
		JSON: func(value string) (string, error) {
			restored, _, safe := r.restoreJSONDocument(value, snapshot, depth+1, nodes)
			if !safe {
				return "", ErrUnsafeRequest
			}
			return restored, nil
		},
		HTML: func(value string) (string, error) {
			restored, _, _, safe := r.restoreHTMLString(value, snapshot, depth+1, nodes, true)
			if !safe {
				return "", ErrUnsafeRequest
			}
			return restored, nil
		},
		Text: func(value string) (string, error) {
			if restored, handled, _, safe := r.restoreHTMLString(value, snapshot, depth+1, nodes, false); handled {
				if !safe {
					return "", ErrUnsafeRequest
				}
				return restored, nil
			}
			return snapshot.restoreHTTPText(value), nil
		},
		HasHeaders: true,
		HasCookies: true,
		HasQuery:   true,
		HasForm:    true,
		HasJSON:    true,
	})
	if err != nil {
		return text, true, false, false
	}
	if !handled {
		return text, false, false, true
	}
	return output, true, output != text, true
}

func (snapshot *restorationSnapshot) restoreHTTPText(value string) string {
	if restored, changed := snapshot.restoreString(value); changed {
		return restored
	}
	if restored, ok := snapshot.restoreNumber(value); ok {
		return restored
	}
	if !strings.HasPrefix(value, "/") && !strings.HasPrefix(value, "http://") && !strings.HasPrefix(value, "https://") {
		return value
	}
	var output strings.Builder
	last := 0
	for start := 0; start < len(value); {
		end := strings.IndexByte(value[start:], '/')
		if end < 0 {
			end = len(value)
		} else {
			end += start
		}
		if restored, ok := snapshot.restoreNumber(value[start:end]); ok {
			if output.Len() == 0 {
				output.Grow(len(value))
			}
			output.WriteString(value[last:start])
			output.WriteString(restored)
			last = end
		}
		start = end + 1
	}
	if last == 0 {
		return value
	}
	output.WriteString(value[last:])
	return output.String()
}

func (r *Redactor) restoreJSONDocument(text string, snapshot *restorationSnapshot, depth int, nodes *int) (string, bool, bool) {
	value, ok := decodeJSONDocument(text)
	if !ok {
		return text, false, false
	}
	walked, changed, safe := r.walkRestoreValues(value, snapshot, protocolStructuredBusiness, "", depth+1, nodes)
	if !safe || !changed {
		return text, false, safe
	}
	encoded, err := marshalEmbeddedValue(walked)
	if err != nil {
		return text, false, false
	}
	return encoded, true, true
}

func (r *Redactor) restoreEmbeddedString(text string, snapshot *restorationSnapshot, depth int, nodes *int) (string, bool, bool) {
	if depth > maxPolicyDepth {
		_, status := locateEmbeddedJSON(text)
		return text, status != embeddedJSONNone, false
	}
	candidate, status := locateEmbeddedJSON(text)
	if status != embeddedJSONParsed {
		return text, false, false
	}

	var walked any
	var changed, safe bool
	if nested, ok := candidate.value.(string); ok {
		var handled bool
		var restored string
		restored, handled, changed = r.restoreEmbeddedString(nested, snapshot, depth+1, nodes)
		if !handled {
			restored, changed = snapshot.restoreString(nested)
		}
		walked, safe = restored, true
	} else {
		walked, changed, safe = r.walkRestoreValues(candidate.value, snapshot, protocolStructuredBusiness, "", depth+1, nodes)
	}
	if !safe {
		return text, true, false
	}
	prefix, prefixChanged := r.restoreEmbeddedFrame(text[:candidate.start], snapshot, depth+1, nodes)
	suffix, suffixChanged := r.restoreEmbeddedFrame(text[candidate.end:], snapshot, depth+1, nodes)
	if !changed && !prefixChanged && !suffixChanged {
		return text, true, false
	}
	encoded, err := marshalEmbeddedCandidate(candidate, walked)
	if err != nil {
		return text, true, false
	}
	if !changed {
		encoded = text[candidate.start:candidate.end]
	}
	return prefix + encoded + suffix, true, true
}

func (r *Redactor) restoreEmbeddedFrame(text string, snapshot *restorationSnapshot, depth int, nodes *int) (string, bool) {
	if restored, handled, changed := r.restoreEmbeddedString(text, snapshot, depth, nodes); handled {
		return restored, changed
	}
	return snapshot.restoreString(text)
}

// RestoreSSEEvent restores placeholders inside a single SSE event block.
func (r *Redactor) RestoreSSEEvent(event []byte) []byte {
	return r.RestoreSSEEventForSession(event, defaultSessionID)
}

func (r *Redactor) RestoreSSEEventForSession(event []byte, session string) []byte {
	var out bytes.Buffer
	for start := 0; start < len(event); {
		end := start
		for end < len(event) && event[end] != '\r' && event[end] != '\n' {
			end++
		}
		line := event[start:end]
		next := end
		if next < len(event) {
			if event[next] == '\r' && next+1 < len(event) && event[next+1] == '\n' {
				next += 2
			} else {
				next++
			}
		}

		if bytes.HasPrefix(line, []byte("data:")) {
			rawPayload := line[5:]
			payload := bytes.TrimSpace(rawPayload)
			if len(payload) > 0 && (payload[0] == '{' || payload[0] == '[') {
				leftTrim := bytes.Index(rawPayload, payload)
				payloadStart := 5 + leftTrim
				out.Write(line[:payloadStart])
				out.Write(r.restoreJSONOrRaw(payload, session))
				out.Write(line[payloadStart+len(payload):])
				out.Write(event[end:next])
				start = next
				continue
			}
		}

		out.Write(line)
		out.Write(event[end:next])
		start = next
	}
	return out.Bytes()
}

func (r *Redactor) restoreSSE(body []byte, session string) []byte {
	if !bytes.Contains(body, []byte("\n\n")) {
		return r.RestoreSSEEventForSession(body, session)
	}
	var out bytes.Buffer
	rest := body
	for {
		idx := bytes.Index(rest, []byte("\n\n"))
		if idx < 0 {
			out.Write(r.RestoreSSEEventForSession(rest, session))
			break
		}
		out.Write(r.RestoreSSEEventForSession(rest[:idx+2], session))
		rest = rest[idx+2:]
	}
	return out.Bytes()
}
