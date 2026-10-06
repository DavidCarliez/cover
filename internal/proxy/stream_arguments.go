package proxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"
)

var errSSEArguments = errors.New("invalid streamed tool arguments")

type sseArgumentPiece struct {
	event *sseFragmentEvent
	index int
}

type sseArgumentBuffer struct {
	pieces []sseArgumentPiece
	bytes  int
}

func isJSONArgumentChannel(channel string) bool {
	return strings.Contains(channel, "function_call_arguments") || strings.HasSuffix(channel, ":partial_json") || strings.Contains(channel, ":tool:")
}

// Tool arguments must be restored as a complete JSON document: a string field
// can itself contain a curl command, URL, or serialized JSON. Restoring arbitrary
// fragments cannot determine the required inner quoting or numeric context.
func (rw *SSERestoringWriter) queueArguments(event *sseFragmentEvent) error {
	if rw.queuedBytes+int64(len(event.event)) > rw.maxEvent {
		return ErrSSEEventTooLarge
	}
	for _, field := range event.argumentFields {
		field.setText("")
	}
	metadata, err := json.Marshal(event.payload)
	if err != nil {
		return errSSEArguments
	}
	metadata = rw.redactor.RestoreResponseForSession(metadata, "application/json", rw.session)
	decoder := json.NewDecoder(bytes.NewReader(metadata))
	decoder.UseNumber()
	if decoder.Decode(&event.payload) != nil {
		return errSSEArguments
	}
	index := 0
	for _, field := range findSSEFragments(event.payload) {
		if !isJSONArgumentChannel(field.channel) {
			continue
		}
		if index >= len(event.argumentFields) || field.channel != event.argumentFields[index].channel {
			return errSSEArguments
		}
		field.text = event.argumentFields[index].text
		event.argumentFields[index] = field
		index++
	}
	if index != len(event.argumentFields) {
		return errSSEArguments
	}
	event.remainingArguments = index
	rw.queue = append(rw.queue, event)
	rw.queuedBytes += int64(len(event.event))
	for index, field := range event.argumentFields {
		buffer := rw.arguments[field.channel]
		if buffer == nil {
			buffer = &sseArgumentBuffer{}
			rw.arguments[field.channel] = buffer
		}
		buffer.pieces = append(buffer.pieces, sseArgumentPiece{event: event, index: index})
		buffer.bytes += len(field.text)
	}
	return rw.drain()
}

func (rw *SSERestoringWriter) finishArguments(channel string) error {
	buffer := rw.arguments[channel]
	if buffer == nil {
		return nil
	}
	var document strings.Builder
	document.Grow(buffer.bytes)
	nonempty := 0
	for _, piece := range buffer.pieces {
		document.WriteString(piece.event.argumentFields[piece.index].text)
		if piece.event.argumentFields[piece.index].text != "" {
			nonempty++
		}
	}
	arguments := document.String()
	if strings.TrimSpace(arguments) != "" && !json.Valid([]byte(arguments)) {
		return errSSEArguments
	}
	restored := strings.TrimSpace(string(rw.redactor.RestoreResponseForSession([]byte(arguments), "application/json", rw.session)))
	delete(rw.arguments, channel)
	nonspace := 0
	for _, value := range restored {
		if !unicode.IsSpace(value) {
			nonspace++
		}
	}
	for _, piece := range buffer.pieces {
		field := &piece.event.argumentFields[piece.index]
		if field.text != "" {
			// Divide the restored document into useful, UTF-8-safe deltas.
			// Counting non-whitespace code points prevents whitespace inside
			// JSON strings from becoming a burst of no-progress events.
			count := (nonspace + nonempty - 1) / nonempty
			end := 0
			for count > 0 {
				value, size := utf8.DecodeRuneInString(restored[end:])
				end += size
				if !unicode.IsSpace(value) {
					count--
					nonspace--
				}
			}
			field.text = restored[:end]
			restored = restored[end:]
			nonempty--
		}
		field.setText(field.text)
		piece.event.remainingArguments--
		if piece.event.remainingArguments == 0 {
			if piece.event.compactArgumentDeltas() {
				output, err := piece.event.marshalPayload()
				if err != nil {
					return errSSEArguments
				}
				piece.event.output = output
			}
			piece.event.ready = true
		}
	}
	return nil
}

// Normalization can leave fewer useful code points than upstream deltas.
// Remove redundant argument updates, not lifecycle events or mixed content.
// Unknown metadata is retained conservatively.
func (event *sseFragmentEvent) compactArgumentDeltas() bool {
	root, ok := event.payload.(map[string]any)
	if !ok {
		return true
	}
	typ, _ := root["type"].(string)
	if typ == "response.function_call_arguments.delta" {
		return root["delta"] != "" || !onlySSEKeys(root, "type", "delta", "item_id", "call_id", "output_index", "content_index", "summary_index", "sequence_number")
	}
	if typ == "content_block_delta" {
		delta, _ := root["delta"].(map[string]any)
		return delta["partial_json"] != "" || !onlySSEKeys(delta, "type", "partial_json") || !onlySSEKeys(root, "type", "index", "delta")
	}
	choices, ok := root["choices"].([]any)
	if !ok {
		return true
	}
	retainedChoices := choices[:0]
	for _, rawChoice := range choices {
		choice, ok := rawChoice.(map[string]any)
		if !ok {
			retainedChoices = append(retainedChoices, rawChoice)
			continue
		}
		delta, _ := choice["delta"].(map[string]any)
		if calls, ok := delta["tool_calls"].([]any); ok {
			retainedCalls := calls[:0]
			for _, rawCall := range calls {
				call, _ := rawCall.(map[string]any)
				function, _ := call["function"].(map[string]any)
				if arguments, ok := function["arguments"].(string); ok && arguments == "" {
					delete(function, "arguments")
					if len(function) == 0 {
						delete(call, "function")
					}
					if onlySSEKeys(call, "index") {
						continue
					}
				}
				retainedCalls = append(retainedCalls, rawCall)
			}
			if len(retainedCalls) == 0 {
				delete(delta, "tool_calls")
			} else {
				delta["tool_calls"] = retainedCalls
			}
		}
		if len(delta) == 0 && choice["finish_reason"] == nil && choice["logprobs"] == nil &&
			onlySSEKeys(choice, "index", "delta", "finish_reason", "logprobs") {
			continue
		}
		retainedChoices = append(retainedChoices, rawChoice)
	}
	root["choices"] = retainedChoices
	return len(retainedChoices) > 0 || root["usage"] != nil ||
		!onlySSEKeys(root, "choices", "id", "object", "created", "model", "system_fingerprint", "service_tier", "usage")
}

func onlySSEKeys(object map[string]any, keys ...string) bool {
	for key := range object {
		known := false
		for _, allowed := range keys {
			if key == allowed {
				known = true
				break
			}
		}
		if !known {
			return false
		}
	}
	return true
}

func (rw *SSERestoringWriter) channelsWithPrefix(prefix string) []string {
	var channels []string
	for channel := range rw.pending {
		if strings.HasPrefix(channel, prefix) {
			channels = append(channels, channel)
		}
	}
	for channel := range rw.arguments {
		if strings.HasPrefix(channel, prefix) {
			channels = append(channels, channel)
		}
	}
	return channels
}

func (event *sseFragmentEvent) marshalPayload() ([]byte, error) {
	payload, err := json.Marshal(event.payload)
	if err != nil {
		return nil, err
	}
	rendered := make([]byte, 0, len(event.event)-event.payloadEnd+event.payloadStart+len(payload))
	rendered = append(rendered, event.event[:event.payloadStart]...)
	rendered = append(rendered, payload...)
	rendered = append(rendered, event.event[event.payloadEnd:]...)
	return rendered, nil
}
