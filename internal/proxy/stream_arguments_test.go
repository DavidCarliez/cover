package proxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/DavidCarliez/cover/internal/redact"
)

func TestSSEInterleavedToolArgumentsRestoreNestedJSONAndPreserveRouting(t *testing.T) {
	const original = "cedar'quoted\\value"
	r := redact.New(redact.NewStore(), 0, redact.RedactorOptions{FieldRules: []redact.FieldRule{
		{Name: "number", Keys: []string{"customer_number"}, Action: "pseudonymize", Generator: "number"},
		{Name: "credential", Keys: []string{"credential"}, Action: "pseudonymize", Generator: "alias"},
	}})
	request, _ := json.Marshal(map[string]any{"customer_number": 937165, "credential": original})
	protected, err := r.Transform(request, "arguments", false, "allow")
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(protected.Body, &fields); err != nil {
		t.Fatal(err)
	}
	var fake string
	if err := json.Unmarshal(fields["credential"], &fake); err != nil {
		t.Fatal(err)
	}
	firstArgs, _ := json.Marshal(map[string]string{"payload": string(protected.Body)})
	larger := string(fields["customer_number"]) + "0"
	secondArgs := []byte(fmt.Sprintf(`{"customer_number":%s,"control":%s}`, fields["customer_number"], larger))
	makeDelta := func(a, b string, first bool) string {
		calls := []any{}
		for index, args := range []string{a, b} {
			function := map[string]any{"arguments": args}
			call := map[string]any{"index": index, "function": function}
			if first {
				call["id"], call["type"], function["name"] = fake, "function", fake
			}
			calls = append(calls, call)
		}
		payload, _ := json.Marshal(map[string]any{"choices": []any{map[string]any{"index": 0, "delta": map[string]any{"tool_calls": calls}, "finish_reason": nil}}})
		return "data: " + string(payload) + "\n\n"
	}
	aSplit, bSplit := len(firstArgs)/2, len(secondArgs)/2
	stream := makeDelta(string(firstArgs[:aSplit]), string(secondArgs[:bSplit]), true) + ": keepalive\n\n" +
		makeDelta(string(firstArgs[aSplit:]), string(secondArgs[bSplit:]), false) +
		"data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\ndata: [DONE]\n\n"
	var output bytes.Buffer
	writer := NewSSERestoringWriterForSession(&output, r, "arguments")
	wire := []byte(stream)
	for index := range wire {
		if _, err := writer.Write(wire[index : index+1]); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	arguments := make(map[int]string)
	for _, line := range strings.Split(output.String(), "\n") {
		if !strings.HasPrefix(line, "data: {") {
			continue
		}
		var event struct {
			Choices []struct {
				Delta struct {
					Calls []struct {
						Index    int    `json:"index"`
						ID       string `json:"id"`
						Function struct {
							Name      string `json:"name"`
							Arguments string `json:"arguments"`
						} `json:"function"`
					} `json:"tool_calls"`
				} `json:"delta"`
			} `json:"choices"`
		}
		if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &event); err != nil {
			t.Fatal(err)
		}
		for _, choice := range event.Choices {
			for _, call := range choice.Delta.Calls {
				if call.ID != "" && (call.ID != fake || call.Function.Name != fake) {
					t.Fatal("restoration rewrote provider routing metadata")
				}
				arguments[call.Index] += call.Function.Arguments
			}
		}
	}
	var first struct {
		Payload string `json:"payload"`
	}
	if err := json.Unmarshal([]byte(arguments[0]), &first); err != nil {
		t.Fatal(err)
	}
	var nested struct {
		Number     json.Number `json:"customer_number"`
		Credential string      `json:"credential"`
	}
	if err := json.Unmarshal([]byte(first.Payload), &nested); err != nil {
		t.Fatal(err)
	}
	if nested.Number.String() != "937165" || nested.Credential != original {
		t.Fatalf("nested JSON restoration failed: %s", first.Payload)
	}
	var second map[string]json.Number
	if err := json.Unmarshal([]byte(arguments[1]), &second); err != nil {
		t.Fatal(err)
	}
	if second["customer_number"].String() != "937165" || second["control"].String() != larger {
		t.Fatalf("numeric token boundaries changed: %s", arguments[1])
	}
}

func TestSSEArgumentsRejectTruncationAndCumulativeOverflow(t *testing.T) {
	r, fake := aliasPseudonym(t, "bounds")
	t.Run("truncated", func(t *testing.T) {
		var output bytes.Buffer
		writer := NewSSERestoringWriterForSession(&output, r, "bounds")
		if _, err := writer.Write([]byte(chatToolDeltaEvent(`{"value":"`+fake, 0, 0))); err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); !errors.Is(err, errSSEArguments) || output.Len() != 0 {
			t.Fatalf("incomplete arguments were emitted: err=%v output=%s", err, output.Bytes())
		}
	})
	t.Run("cumulative limit", func(t *testing.T) {
		var output bytes.Buffer
		writer := NewSSERestoringWriterForSessionWithLimit(&output, r, "bounds", 512)
		var err error
		for range 10 {
			_, err = writer.Write([]byte(chatToolDeltaEvent(strings.Repeat("x", 80), 0, 0)))
			if err != nil {
				break
			}
		}
		if !errors.Is(err, ErrSSEEventTooLarge) || output.Len() != 0 {
			t.Fatalf("cumulative arguments exceeded the bound: err=%v output=%s", err, output.Bytes())
		}
	})
}

func TestSSEArgumentsKeepConsumerProgressAfterRestoration(t *testing.T) {
	r, fake := aliasPseudonym(t, "progress")
	providers := []struct {
		name  string
		delta func(string, int) string
		start string
		stop  string
	}{
		{
			name: "responses",
			delta: func(text string, sequence int) string {
				return responseDeltaEventWithItem("response.function_call_arguments.delta", "call-1", text, sequence)
			},
			start: "data: {\"type\":\"response.output_item.added\",\"item\":{\"id\":\"call-1\",\"type\":\"function_call\",\"name\":\"lookup\"}}\n\n",
			stop:  "data: {\"type\":\"response.function_call_arguments.done\",\"item_id\":\"call-1\"}\n\ndata: [DONE]\n\n",
		},
		{
			name: "anthropic",
			delta: func(text string, _ int) string {
				payload, _ := json.Marshal(map[string]any{
					"type": "content_block_delta", "index": 2,
					"delta": map[string]any{"type": "input_json_delta", "partial_json": text},
				})
				return "data: " + string(payload) + "\n\n"
			},
			start: "data: {\"type\":\"content_block_start\",\"index\":2,\"content_block\":{\"type\":\"tool_use\",\"id\":\"call-1\",\"name\":\"lookup\",\"input\":{}}}\n\n",
			stop:  "data: {\"type\":\"content_block_stop\",\"index\":2}\n\ndata: {\"type\":\"message_stop\"}\n\n",
		},
		{
			name: "chat",
			delta: func(text string, _ int) string {
				return chatToolDeltaEvent(text, 0, 0)
			},
			start: "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call-1\",\"type\":\"function\",\"function\":{\"name\":\"lookup\",\"arguments\":\"\"}}]}}]}\n\n",
			stop:  "data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\ndata: [DONE]\n\n",
		},
	}
	for _, provider := range providers {
		for _, shortened := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/shortened=%t", provider.name, shortened), func(t *testing.T) {
				note := strings.Repeat("λ😀  ", 180)
				if shortened {
					note = "λ😀"
				}
				command := "curl 'https://example.test/?customer=" + fake + "'"
				document, _ := json.Marshal(map[string]string{"value": fake, "note": note, "command": command})
				if shortened {
					document = append([]byte("{"+strings.Repeat(" \t\n", 400)), document[1:]...)
				}
				var stream strings.Builder
				stream.WriteString(provider.start)
				sequence := 1
				for _, value := range string(document) {
					// Include original empty chunks as well as many nonempty
					// fragments, including Unicode and normalization whitespace.
					if sequence%19 == 0 {
						stream.WriteString(provider.delta("", sequence))
						sequence++
					}
					stream.WriteString(provider.delta(string(value), sequence))
					sequence++
				}
				stream.WriteString(provider.stop)
				out := restoreSSEForTest(t, r, "progress", stream.String())
				var joined strings.Builder
				emptyRun, lastSequence := 0, 0
				for _, payload := range sseJSONPayloads(t, out) {
					var fragment string
					isArgument := false
					switch provider.name {
					case "responses":
						if payload["type"] == "response.function_call_arguments.delta" {
							isArgument = true
							fragment, _ = payload["delta"].(string)
							current := int(payload["sequence_number"].(float64))
							if current <= lastSequence || payload["item_id"] != "call-1" {
								t.Fatalf("argument routing/order changed: %v", payload)
							}
							lastSequence = current
						}
					case "anthropic":
						if payload["type"] == "content_block_delta" {
							isArgument = true
							if payload["index"] != float64(2) {
								t.Fatalf("block routing changed: %v", payload)
							}
							fragment, _ = payload["delta"].(map[string]any)["partial_json"].(string)
						}
					case "chat":
						for _, rawChoice := range payload["choices"].([]any) {
							choice := rawChoice.(map[string]any)
							delta := choice["delta"].(map[string]any)
							calls, _ := delta["tool_calls"].([]any)
							for _, rawCall := range calls {
								call := rawCall.(map[string]any)
								function := call["function"].(map[string]any)
								if args, ok := function["arguments"].(string); ok {
									isArgument, fragment = true, args
									if choice["index"] != float64(0) || call["index"] != float64(0) {
										t.Fatalf("tool routing changed: %v", payload)
									}
								}
							}
						}
					}
					if !isArgument {
						continue
					}
					if !utf8.ValidString(fragment) {
						t.Fatalf("invalid Unicode fragment: %q", fragment)
					}
					if strings.TrimSpace(fragment) == "" {
						emptyRun++
						if emptyRun >= 256 {
							t.Fatal("consumer rejected 256 consecutive empty/whitespace argument deltas")
						}
					} else {
						emptyRun = 0
					}
					joined.WriteString(fragment)
				}
				var restored map[string]string
				if err := json.Unmarshal([]byte(joined.String()), &restored); err != nil {
					t.Fatalf("consumer could not decode arguments: %v", err)
				}
				if restored["value"] != "CUSTOMER-ALPHA" || restored["note"] != note ||
					restored["command"] != "curl 'https://example.test/?customer=CUSTOMER-ALPHA'" {
					t.Fatalf("restored argument values changed: %v", restored)
				}
				if !strings.Contains(out, `"name":"lookup"`) || !strings.Contains(out, `"call-1"`) {
					t.Fatalf("tool lifecycle metadata lost: %s", out)
				}
				payloads := sseJSONPayloads(t, out)
				last := payloads[len(payloads)-1]
				switch provider.name {
				case "responses":
					if last["type"] != "response.function_call_arguments.done" || last["item_id"] != "call-1" {
						t.Fatalf("argument completion lost: %v", last)
					}
				case "anthropic":
					if last["type"] != "message_stop" || payloads[len(payloads)-2]["type"] != "content_block_stop" {
						t.Fatalf("block/message completion lost: %v", payloads)
					}
				case "chat":
					choice := last["choices"].([]any)[0].(map[string]any)
					if choice["finish_reason"] != "tool_calls" {
						t.Fatalf("tool completion lost: %v", last)
					}
				}
				if provider.name != "anthropic" && !strings.HasSuffix(out, "data: [DONE]\n\n") {
					t.Fatal("stream terminator lost")
				}
			})
		}
	}
}

func TestSSEChatArgumentsCompactOnlyRedundantUpdates(t *testing.T) {
	r, fake := aliasPseudonym(t, "mixed-progress")
	longDocument, _ := json.Marshal(map[string]string{"value": fake, "note": strings.Repeat("😀λ", 200)})
	shortDocument := `{"value":` + strings.Repeat(" ", utf8.RuneCount(longDocument)) + fmt.Sprintf("%q}", fake)
	documents := [][]rune{[]rune(string(longDocument)), []rune(shortDocument)}
	var stream strings.Builder
	for index := range max(len(documents[0]), len(documents[1])) {
		var calls []any
		for tool, document := range documents {
			arguments := ""
			if index < len(document) {
				arguments = string(document[index])
			}
			function := map[string]any{"arguments": arguments}
			call := map[string]any{"index": tool, "function": function}
			if index == 0 {
				call["id"], call["type"], function["name"] = fmt.Sprintf("call-%d", tool), "function", "lookup"
			}
			calls = append(calls, call)
		}
		delta := map[string]any{"tool_calls": calls}
		if index == 300 {
			delta["content"] = "keep this content"
		}
		choices := []any{map[string]any{"index": 0, "delta": delta}}
		if index == 310 {
			choices = append(choices, map[string]any{"index": 1, "delta": map[string]any{"content": "keep other choice"}})
		}
		event, _ := json.Marshal(map[string]any{"id": "completion-1", "object": "chat.completion.chunk", "choices": choices})
		stream.WriteString("data: " + string(event) + "\n\n")
	}
	stream.WriteString("data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\ndata: [DONE]\n\n")
	out := restoreSSEForTest(t, r, "mixed-progress", stream.String())
	var arguments [2]string
	var identified [2]bool
	var content strings.Builder
	for _, event := range sseJSONPayloads(t, out) {
		for _, rawChoice := range event["choices"].([]any) {
			choice := rawChoice.(map[string]any)
			delta := choice["delta"].(map[string]any)
			text, _ := delta["content"].(string)
			content.WriteString(text)
			calls, _ := delta["tool_calls"].([]any)
			for _, rawCall := range calls {
				call := rawCall.(map[string]any)
				tool := int(call["index"].(float64))
				function := call["function"].(map[string]any)
				if id, ok := call["id"].(string); ok {
					if id != fmt.Sprintf("call-%d", tool) || call["type"] != "function" || function["name"] != "lookup" {
						t.Fatalf("lost tool identity: %v", call)
					}
					identified[tool] = true
				}
				if fragment, ok := function["arguments"].(string); ok {
					if strings.TrimSpace(fragment) == "" {
						t.Fatalf("redundant argument update retained alongside another channel: %v", call)
					}
					arguments[tool] += fragment
				}
			}
		}
	}
	for tool, document := range arguments {
		var restored map[string]string
		if err := json.Unmarshal([]byte(document), &restored); err != nil {
			t.Fatalf("tool %d arguments invalid: %v", tool, err)
		}
		if !identified[tool] || restored["value"] != "CUSTOMER-ALPHA" {
			t.Fatalf("tool %d identity/value lost: %v", tool, restored)
		}
		if tool == 0 && restored["note"] != strings.Repeat("😀λ", 200) {
			t.Fatal("long channel changed while compacting short channel")
		}
	}
	if content.String() != "keep this contentkeep other choice" {
		t.Fatalf("mixed content or choice order changed: %q", content.String())
	}
}

func TestSSEArgumentCompactionPropagatesWriterErrors(t *testing.T) {
	r, fake := aliasPseudonym(t, "argument-write-error")
	reader, destination := io.Pipe()
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	defer destination.Close()
	writer := NewSSERestoringWriterForSession(destination, r, "argument-write-error")
	if _, err := writer.Write([]byte(chatToolDeltaEvent(`{"value":"`+fake+`"}`, 0, 0))); err != nil {
		t.Fatalf("arguments should remain buffered until complete: %v", err)
	}
	if err := writer.Close(); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("downstream write failure lost: %v", err)
	}
}

func TestSSEArgumentsPreserveInterleavedCompletionOrder(t *testing.T) {
	r, fake := aliasPseudonym(t, "argument-order")
	const typ = "response.function_call_arguments.delta"
	stream := responseDeltaEventWithItem(typ, "first", `{"value":"`, 1) +
		responseDeltaEventWithItem(typ, "second", `{"value":"`+fake+`"}`, 2) +
		responseDeltaEventWithItem(typ, "second", "", 3) +
		"data: {\"type\":\"response.function_call_arguments.done\",\"item_id\":\"second\",\"sequence_number\":4}\n\n" +
		"data: {\"type\":\"response.output_item.done\",\"item\":{\"id\":\"second\"},\"sequence_number\":5}\n\n" +
		responseDeltaEventWithItem(typ, "first", fake+`"}`, 6) +
		"data: {\"type\":\"response.function_call_arguments.done\",\"item_id\":\"first\",\"sequence_number\":7}\n\ndata: [DONE]\n\n"
	out := restoreSSEForTest(t, r, "argument-order", stream)
	arguments := make(map[string]string)
	var completed []string
	lastSequence := 0
	itemDone := false
	for _, event := range sseJSONPayloads(t, out) {
		sequence := int(event["sequence_number"].(float64))
		if sequence <= lastSequence {
			t.Fatalf("interleaved event order changed: %v", event)
		}
		lastSequence = sequence
		id, _ := event["item_id"].(string)
		switch event["type"] {
		case typ:
			arguments[id] += event["delta"].(string)
		case "response.function_call_arguments.done":
			completed = append(completed, id)
		case "response.output_item.done":
			itemDone = event["item"].(map[string]any)["id"] == "second"
		}
	}
	if strings.Join(completed, ",") != "second,first" || !itemDone {
		t.Fatalf("interleaved lifecycle events lost: completed=%v itemDone=%t", completed, itemDone)
	}
	for _, id := range []string{"first", "second"} {
		var document map[string]string
		if err := json.Unmarshal([]byte(arguments[id]), &document); err != nil || document["value"] != "CUSTOMER-ALPHA" {
			t.Fatalf("arguments crossed channels for %s: %q (%v)", id, arguments[id], err)
		}
	}
}
