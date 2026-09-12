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
	w           io.Writer
	flusher     http.Flusher
	redactor    *redact.Redactor
	session     string
	buf         []byte
	pending     map[string]*sseFragmentEvent
	queue       []*sseFragmentEvent
	queuedBytes int64
	jsonStates  map[string]*redact.JSONStreamState
	maxEvent    int64
}

// A channel retains its last delta until the next fragment or its end event.
// The bounded queue preserves provider event order across interleaved channels.
type sseFragmentEvent struct {
	event         []byte
	payloadStart  int
	payloadEnd    int
	payload       any
	channel       string
	text          string
	setText       func(string)
	ready         bool
	output        []byte
	jsonArguments bool
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
	return &SSERestoringWriter{w: w, flusher: f, redactor: redactor, session: session, maxEvent: maxEvent,
		pending: make(map[string]*sseFragmentEvent), jsonStates: make(map[string]*redact.JSONStreamState)}
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
		if heartbeatSSEEvent(event) {
			return rw.emit(event)
		}
		if err := rw.finishChannels(event); err != nil {
			return err
		}
		if terminalSSEEvent(event) {
			if err := rw.flushPending(); err != nil {
				return err
			}
		}
		rw.queue = append(rw.queue, &sseFragmentEvent{event: event, ready: true, output: rw.redactor.RestoreSSEEventForSession(event, rw.session)})
		rw.queuedBytes += int64(len(event))
		return rw.drain()
	}
	if previous := rw.pending[fragment.channel]; previous != nil {
		combined := previous.text + fragment.text
		cut := rw.redactor.SafeStreamCut([]byte(combined), rw.session)
		previous.output = previous.render(rw.restoreFragment(previous, []byte(combined[:cut])), rw.redactor, rw.session)
		previous.ready = true
		fragment.text = combined[cut:]
	}
	rw.pending[fragment.channel] = fragment
	rw.queue = append(rw.queue, fragment)
	rw.queuedBytes += int64(len(event))
	return rw.drain()
}

func (rw *SSERestoringWriter) flushPending() error {
	for channel, pending := range rw.pending {
		pending.output = pending.render(rw.restoreFragment(pending, []byte(pending.text)), rw.redactor, rw.session)
		pending.ready = true
		delete(rw.pending, channel)
	}
	return rw.drain()
}

// Finish only the channel identified by an end event. Other channels may
// still have incomplete replacement tokens waiting for their next delta.
func (rw *SSERestoringWriter) finishChannels(event []byte) error {
	for _, line := range strings.Split(strings.ReplaceAll(string(event), "\r", "\n"), "\n") {
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		var payload map[string]any
		dec := json.NewDecoder(strings.NewReader(strings.TrimSpace(line[5:])))
		dec.UseNumber()
		if dec.Decode(&payload) != nil {
			continue
		}
		typ, _ := payload["type"].(string)
		channels := []string{}
		if strings.HasSuffix(typ, ".done") {
			channels = append(channels, responseDeltaChannel(strings.TrimSuffix(typ, ".done")+".delta", payload))
		}
		if typ == "content_block_stop" {
			prefix := "anthropic:" + jsonIdentity(payload["index"]) + ":"
			for channel := range rw.pending {
				if strings.HasPrefix(channel, prefix) {
					channels = append(channels, channel)
				}
			}
		}
		if choices, ok := payload["choices"].([]any); ok {
			for position, raw := range choices {
				choice, ok := raw.(map[string]any)
				if !ok || choice["finish_reason"] == nil {
					continue
				}
				id := jsonIdentity(choice["index"])
				if id == "" {
					id = strconv.Itoa(position)
				}
				for channel := range rw.pending {
					if strings.HasPrefix(channel, "chat:"+id+":") {
						channels = append(channels, channel)
					}
				}
			}
		}
		for _, channel := range channels {
			if pending := rw.pending[channel]; pending != nil {
				pending.output = pending.render(rw.restoreFragment(pending, []byte(pending.text)), rw.redactor, rw.session)
				pending.ready = true
				delete(rw.pending, channel)
				delete(rw.jsonStates, channel)
			}
		}
	}
	return rw.drain()
}

func heartbeatSSEEvent(event []byte) bool {
	for _, line := range strings.Split(strings.ReplaceAll(string(event), "\r", "\n"), "\n") {
		if line != "" && !strings.HasPrefix(line, ":") {
			return false
		}
	}
	return true
}

func (rw *SSERestoringWriter) restoreFragment(event *sseFragmentEvent, text []byte) []byte {
	if !event.jsonArguments {
		return rw.redactor.RestoreForSession(text, rw.session)
	}
	state := rw.jsonStates[event.channel]
	if state == nil {
		state = &redact.JSONStreamState{}
		rw.jsonStates[event.channel] = state
	}
	return rw.redactor.RestoreJSONFragment(text, rw.session, state)
}

func (rw *SSERestoringWriter) drain() error {
	for len(rw.queue) > 0 && rw.queue[0].ready {
		event := rw.queue[0]
		if err := rw.emit(event.output); err != nil {
			return err
		}
		rw.queuedBytes -= int64(len(event.event))
		rw.queue[0] = nil
		rw.queue = rw.queue[1:]
	}
	if rw.queuedBytes > rw.maxEvent || len(rw.pending) > 128 {
		return ErrSSEEventTooLarge
	}
	return nil
}

func terminalSSEEvent(event []byte) bool {
	for _, line := range strings.Split(strings.ReplaceAll(string(event), "\r", "\n"), "\n") {
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if data == "[DONE]" {
			return true
		}
		var payload struct {
			Type string `json:"type"`
		}
		if json.Unmarshal([]byte(data), &payload) != nil {
			continue
		}
		switch payload.Type {
		case "response.completed", "response.failed", "response.incomplete", "message_stop", "error":
			return true
		}
	}
	return false
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
	// Restore metadata separately; the fragment already has its inner escaping.
	event.setText("")
	if snapshotPayload, err := json.Marshal(event.payload); err == nil {
		restored := redactor.RestoreResponseForSession(snapshotPayload, "application/json", session)
		var payload any
		dec := json.NewDecoder(bytes.NewReader(restored))
		dec.UseNumber()
		if dec.Decode(&payload) == nil {
			fragments := findSSEFragments(payload)
			if len(fragments) == 1 {
				fragments[0].setText(string(text))
				event.payload = payload
			}
		}
	}
	payload, err := json.Marshal(event.payload)
	if err != nil {
		return redactor.RestoreSSEEventForSession(event.event, session)
	}
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
		jsonArguments: strings.Contains(candidate.channel, "function_call_arguments") || strings.HasSuffix(candidate.channel, ":partial_json") || strings.Contains(candidate.channel, ":tool:"),
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
