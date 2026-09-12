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
	if len(trimmed) == 0 || (trimmed[0] != '{' && trimmed[0] != '[' && trimmed[0] != '"') {
		restored, _ := snapshot.restoreBytes(body)
		return restored
	}

	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.UseNumber()
	var data any
	if err := dec.Decode(&data); err != nil {
		restored, _ := snapshot.restoreBytes(body)
		return restored
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		restored, _ := snapshot.restoreBytes(body)
		return restored
	}

	walked, changed := r.walkRestoreStrings(data, snapshot)
	if !changed {
		return body
	}
	out, err := json.Marshal(walked)
	if err != nil {
		restored, _ := snapshot.restoreBytes(body)
		return restored
	}
	return out
}

func (r *Redactor) walkRestoreStrings(v any, snapshot *restorationSnapshot) (any, bool) {
	switch val := v.(type) {
	case string:
		if isImageDataURL(val) {
			return val, false
		}
		restored, changed := snapshot.restoreString(val)
		return restored, changed
	case map[string]any:
		changed := false
		for k, vv := range val {
			if immutableProtocolField(k) || opaqueImageProtocolField(val, k, vv) {
				continue
			}
			if text, ok := vv.(string); ok && k == "arguments" && json.Valid([]byte(text)) {
				restored := r.restoreJSONOrRawWithSnapshot([]byte(text), snapshot)
				val[k] = string(restored)
				changed = changed || string(restored) != text
				continue
			}
			restored, fieldChanged := r.walkRestoreStrings(vv, snapshot)
			val[k] = restored
			changed = changed || fieldChanged
		}
		return val, changed
	case []any:
		changed := false
		for i, vv := range val {
			restored, itemChanged := r.walkRestoreStrings(vv, snapshot)
			val[i] = restored
			changed = changed || itemChanged
		}
		return val, changed
	default:
		return v, false
	}
}

// JSONStreamState tracks the lexical context of streamed tool arguments.
// Callers retain incomplete replacement tokens before passing fragments here.
type JSONStreamState struct {
	InString bool
	Escaped  bool
}

func (r *Redactor) RestoreJSONFragment(data []byte, session string, state *JSONStreamState) []byte {
	snapshot := r.store.restorationSnapshot(session)
	if snapshot == nil {
		return data
	}
	replacer := snapshot.jsonReplacer
	var out strings.Builder
	start := 0
	for i, b := range data {
		if state.InString {
			if state.Escaped {
				state.Escaped = false
				continue
			}
			if b == '\\' {
				state.Escaped = true
				continue
			}
			if b == '"' {
				out.WriteString(replacer.Replace(string(data[start:i])))
				out.WriteByte(b)
				start = i + 1
				state.InString = false
			}
		} else if b == '"' {
			out.Write(data[start : i+1])
			start = i + 1
			state.InString = true
		}
	}
	if state.InString {
		out.WriteString(replacer.Replace(string(data[start:])))
	} else {
		out.Write(data[start:])
	}
	return []byte(out.String())
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
