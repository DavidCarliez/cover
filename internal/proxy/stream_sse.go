package proxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/DavidCarliez/cover/internal/redact"
)

const defaultSSEEventLimit = int64(4 << 20)

var ErrSSEEventTooLarge = errors.New("SSE event exceeds configured limit")

// SSERestoringWriter buffers complete SSE events and restores placeholder
// tokens inside JSON data lines with proper escaping.
type SSERestoringWriter struct {
	w        io.Writer
	flusher  http.Flusher
	redactor *redact.Redactor
	session  string
	buf      []byte
	pending  *sseFragmentEvent
	maxEvent int64
}

// sseFragmentEvent is one provider delta event held back by at most one
// logical fragment. Keeping the event itself lets Close flush a final partial
// value without inventing a duplicate SSE event or sequence number.
type sseFragmentEvent struct {
	event        []byte
	payloadStart int
	payloadEnd   int
	payload      any
	channel      string
	text         string
	setText      func(string)
}

// NewSSERestoringWriter wraps w for text/event-stream responses.
func NewSSERestoringWriter(w io.Writer, redactor *redact.Redactor) *SSERestoringWriter {
	return NewSSERestoringWriterForSession(w, redactor, "")
}

func NewSSERestoringWriterForSession(w io.Writer, redactor *redact.Redactor, session string) *SSERestoringWriter {
	return NewSSERestoringWriterForSessionWithLimit(w, redactor, session, defaultSSEEventLimit)
}

func NewSSERestoringWriterForSessionWithLimit(w io.Writer, redactor *redact.Redactor, session string, maxEvent int64) *SSERestoringWriter {
	f, _ := w.(http.Flusher)
	if maxEvent <= 0 {
		maxEvent = defaultSSEEventLimit
	}
	return &SSERestoringWriter{w: w, flusher: f, redactor: redactor, session: session, maxEvent: maxEvent}
}

// Write implements io.Writer.
func (rw *SSERestoringWriter) Write(p []byte) (int, error) {
	rw.buf = append(rw.buf, p...)
	for {
		end := nextSSEEventEnd(rw.buf)
		if end < 0 {
			if int64(len(rw.buf)) > rw.maxEvent {
				rw.buf = nil
				return 0, ErrSSEEventTooLarge
			}
			break
		}
		if int64(end) > rw.maxEvent {
			rw.buf = nil
			return 0, ErrSSEEventTooLarge
		}
		event := append([]byte(nil), rw.buf[:end]...)
		rw.buf = rw.buf[end:]
		if err := rw.writeEvent(event); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

// Close flushes any buffered partial event.
func (rw *SSERestoringWriter) Close() error {
	if int64(len(rw.buf)) > rw.maxEvent {
		rw.buf = nil
		return ErrSSEEventTooLarge
	}
	if err := rw.flushPending(); err != nil {
		return err
	}
	if len(rw.buf) > 0 {
		restored := rw.redactor.RestoreSSEEventForSession(rw.buf, rw.session)
		if err := rw.emit(restored); err != nil {
			return err
		}
		rw.buf = nil
	}
	if rw.flusher != nil {
		rw.flusher.Flush()
	}
	return nil
}

func (rw *SSERestoringWriter) writeEvent(event []byte) error {
	if !rw.redactor.HasMappingsForSession(rw.session) {
		return rw.emit(event)
	}
	fragment, ok := parseSSEFragmentEvent(event)
	if !ok {
		if err := rw.flushPending(); err != nil {
			return err
		}
		return rw.emit(rw.redactor.RestoreSSEEventForSession(event, rw.session))
	}

	if rw.pending == nil {
		rw.pending = fragment
		return nil
	}
	if rw.pending.channel != fragment.channel {
		if err := rw.flushPending(); err != nil {
			return err
		}
		rw.pending = fragment
		return nil
	}

	combined := rw.pending.text + fragment.text
	cut := rw.redactor.SafeStreamCut([]byte(combined), rw.session)
	if int64(len(combined)-cut) > rw.maxEvent {
		rw.pending = nil
		return ErrSSEEventTooLarge
	}
	output := rw.redactor.RestoreForSession([]byte(combined[:cut]), rw.session)
	if err := rw.emit(rw.pending.render(output, rw.redactor, rw.session)); err != nil {
		return err
	}
	fragment.text = combined[cut:]
	rw.pending = fragment
	return nil
}

func (rw *SSERestoringWriter) flushPending() error {
	if rw.pending == nil {
		return nil
	}
	pending := rw.pending
	rw.pending = nil
	text := rw.redactor.RestoreForSession([]byte(pending.text), rw.session)
	return rw.emit(pending.render(text, rw.redactor, rw.session))
}

func (rw *SSERestoringWriter) emit(data []byte) error {
	if _, err := rw.w.Write(data); err != nil {
		return err
	}
	if rw.flusher != nil {
		rw.flusher.Flush()
	}
	return nil
}

func (event *sseFragmentEvent) render(text []byte, redactor *redact.Redactor, session string) []byte {
	event.setText(string(text))
	payload, err := json.Marshal(event.payload)
	if err != nil {
		return redactor.RestoreSSEEventForSession(event.event, session)
	}
	payload = redactor.RestoreResponseForSession(payload, "application/json", session)
	rendered := make([]byte, 0, len(event.event)-event.payloadEnd+event.payloadStart+len(payload))
	rendered = append(rendered, event.event[:event.payloadStart]...)
	rendered = append(rendered, payload...)
	rendered = append(rendered, event.event[event.payloadEnd:]...)
	return rendered
}

// nextSSEEventEnd recognizes all line endings allowed by the SSE format.
func nextSSEEventEnd(data []byte) int {
	end := -1
	for _, separator := range [][]byte{[]byte("\n\n"), []byte("\r\n\r\n"), []byte("\r\r")} {
		if idx := bytes.Index(data, separator); idx >= 0 {
			candidate := idx + len(separator)
			if end < 0 || candidate < end {
				end = candidate
			}
		}
	}
	return end
}

func parseSSEFragmentEvent(event []byte) (*sseFragmentEvent, bool) {
	payloadStart := -1
	payloadEnd := -1
	var payload any
	for start := 0; start < len(event); {
		end := start
		for end < len(event) && event[end] != '\r' && event[end] != '\n' {
			end++
		}
		line := event[start:end]
		if !bytes.HasPrefix(line, []byte("data:")) {
			start = skipSSELineEnding(event, end)
			continue
		}
		rawData := line[5:]
		data := bytes.TrimSpace(rawData)
		if len(data) > 0 && (data[0] == '{' || data[0] == '[') {
			if payloadStart >= 0 {
				return nil, false
			}
			dec := json.NewDecoder(bytes.NewReader(data))
			dec.UseNumber()
			if dec.Decode(&payload) != nil {
				return nil, false
			}
			var trailing any
			if dec.Decode(&trailing) != io.EOF {
				return nil, false
			}
			leftTrim := bytes.Index(rawData, data)
			payloadStart = start + 5 + leftTrim
			payloadEnd = payloadStart + len(data)
		}
		start = skipSSELineEnding(event, end)
	}
	if payloadStart < 0 {
		return nil, false
	}

	candidates := findSSEFragments(payload)
	if len(candidates) != 1 {
		return nil, false
	}
	candidate := candidates[0]
	return &sseFragmentEvent{
		event: event, payloadStart: payloadStart, payloadEnd: payloadEnd, payload: payload,
		channel: candidate.channel, text: candidate.text, setText: candidate.setText,
	}, true
}

func skipSSELineEnding(event []byte, at int) int {
	if at >= len(event) {
		return at
	}
	if event[at] == '\r' && at+1 < len(event) && event[at+1] == '\n' {
		return at + 2
	}
	return at + 1
}

type sseFragment struct {
	channel string
	text    string
	setText func(string)
}

func findSSEFragments(payload any) []sseFragment {
	root, ok := payload.(map[string]any)
	if !ok {
		return nil
	}

	// OpenAI Responses and compatible APIs use a top-level delta string.
	if eventType, _ := root["type"].(string); strings.HasSuffix(eventType, ".delta") {
		if delta, ok := root["delta"].(string); ok {
			return []sseFragment{{
				channel: responseDeltaChannel(eventType, root),
				text:    delta,
				setText: func(text string) { root["delta"] = text },
			}}
		}
	}

	// Anthropic Messages streams text and tool JSON inside content-block deltas.
	if eventType, _ := root["type"].(string); eventType == "content_block_delta" {
		index := jsonIdentity(root["index"])
		if delta, ok := root["delta"].(map[string]any); ok {
			for _, field := range []string{"text", "partial_json"} {
				if text, ok := delta[field].(string); ok {
					field := field
					return []sseFragment{{
						channel: "anthropic:" + index + ":" + field,
						text:    text,
						setText: func(text string) { delta[field] = text },
					}}
				}
			}
		}
	}

	// OpenAI Chat Completions nests content and tool-argument deltas by choice.
	choices, _ := root["choices"].([]any)
	var fragments []sseFragment
	for choicePosition, rawChoice := range choices {
		choice, ok := rawChoice.(map[string]any)
		if !ok {
			continue
		}
		choiceID := jsonIdentity(choice["index"])
		if choiceID == "" {
			choiceID = strconv.Itoa(choicePosition)
		}
		delta, ok := choice["delta"].(map[string]any)
		if !ok {
			continue
		}
		if content, ok := delta["content"].(string); ok {
			delta := delta
			fragments = append(fragments, sseFragment{
				channel: "chat:" + choiceID + ":content",
				text:    content,
				setText: func(text string) { delta["content"] = text },
			})
		}
		toolCalls, _ := delta["tool_calls"].([]any)
		for toolPosition, rawTool := range toolCalls {
			tool, ok := rawTool.(map[string]any)
			if !ok {
				continue
			}
			function, ok := tool["function"].(map[string]any)
			if !ok {
				continue
			}
			arguments, ok := function["arguments"].(string)
			if !ok {
				continue
			}
			toolID := jsonIdentity(tool["index"])
			if toolID == "" {
				toolID = strconv.Itoa(toolPosition)
			}
			functionMap := function
			fragments = append(fragments, sseFragment{
				channel: fmt.Sprintf("chat:%s:tool:%s", choiceID, toolID),
				text:    arguments,
				setText: func(text string) { functionMap["arguments"] = text },
			})
		}
	}
	return fragments
}

func responseDeltaChannel(eventType string, payload map[string]any) string {
	parts := []string{"responses", eventType}
	for _, key := range []string{"item_id", "call_id", "output_index", "content_index", "summary_index"} {
		if value := jsonIdentity(payload[key]); value != "" {
			parts = append(parts, key+"="+value)
		}
	}
	return strings.Join(parts, ":")
}

func jsonIdentity(value any) string {
	switch value := value.(type) {
	case string:
		return value
	case float64:
		return strconv.FormatFloat(value, 'f', -1, 64)
	case json.Number:
		return value.String()
	default:
		return ""
	}
}
