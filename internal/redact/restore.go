package redact

import (
	"bytes"
	"encoding/json"
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
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 || (trimmed[0] != '{' && trimmed[0] != '[') {
		return r.RestoreForSession(body, session)
	}

	var data any
	if err := json.Unmarshal(trimmed, &data); err != nil {
		return r.RestoreForSession(body, session)
	}

	walked := r.walkRestoreStrings(data, session)
	out, err := json.Marshal(walked)
	if err != nil {
		return r.RestoreForSession(body, session)
	}
	return out
}

func (r *Redactor) walkRestoreStrings(v any, session string) any {
	switch val := v.(type) {
	case string:
		return r.restoreString(val, session)
	case map[string]any:
		for k, vv := range val {
			if immutableProtocolField(k) {
				continue
			}
			val[k] = r.walkRestoreStrings(vv, session)
		}
		return val
	case []any:
		for i, vv := range val {
			val[i] = r.walkRestoreStrings(vv, session)
		}
		return val
	default:
		return v
	}
}

func (r *Redactor) restoreString(s, session string) string {
	return string(r.RestoreForSession([]byte(s), session))
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
