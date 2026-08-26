package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DavidCarliez/cover/internal/redact"
	"github.com/DavidCarliez/cover/internal/redact/detectors"
)

func TestSSERestoringWriterRestoresResponseDeltaAcrossEvents(t *testing.T) {
	r := policyProxyRedactor(t, detectors.CustomPattern{
		Name:      "customer",
		Pattern:   `CUSTOMER-ALPHA`,
		Action:    "pseudonymize",
		Generator: "alias",
	})
	result, err := r.Transform([]byte(`{"input":"CUSTOMER-ALPHA"}`), "sse-cross-event", false, "allow")
	if err != nil {
		t.Fatal(err)
	}
	var transformed map[string]string
	if err := json.Unmarshal(result.Body, &transformed); err != nil {
		t.Fatal(err)
	}
	fake := transformed["input"]
	if len(fake) < 2 || fake == "CUSTOMER-ALPHA" {
		t.Fatalf("unexpected pseudonym %q", fake)
	}

	for split := 1; split < len(fake); split++ {
		events := sseDeltaEvent("response.output_text.delta", fake[:split], 1) +
			sseDeltaEvent("response.output_text.delta", fake[split:], 2) +
			"data: [DONE]\n\n"
		out := restoreSSEForTest(t, r, "sse-cross-event", events)
		if got := joinedTopLevelDeltas(t, out); got != "CUSTOMER-ALPHA" {
			t.Fatalf("split=%d joined delta=%q, want CUSTOMER-ALPHA; stream=%q", split, got, out)
		}
		if strings.Count(out, "sequence_number") != 2 || !strings.HasSuffix(out, "data: [DONE]\n\n") {
			t.Fatalf("split=%d event metadata or terminator changed: %q", split, out)
		}
	}
}

func TestSSERestoringWriterPreservesEventsWithoutMappingsExactly(t *testing.T) {
	r := redact.New(redact.NewStore(), 0, redact.RedactorOptions{})
	stream := "event: response.output_text.delta\r\ndata: { \"type\": \"response.output_text.delta\", \"delta\": \"hello\", \"sequence_number\": 9007199254740993 }\r\n\r\n"
	out := restoreSSEForTest(t, r, "no-mappings", stream)
	if out != stream {
		t.Fatalf("event without mappings changed:\n got: %q\nwant: %q", out, stream)
	}
}

func TestSSERestoringWriterPreservesLargeNumericMetadata(t *testing.T) {
	r, fake := aliasPseudonym(t, "large-number")
	stream := fmt.Sprintf("data: {\"type\":\"response.output_text.delta\",\"delta\":%q,\"sequence_number\":9007199254740993}\n\n", fake)
	out := restoreSSEForTest(t, r, "large-number", stream)
	if !strings.Contains(out, `"sequence_number":9007199254740993`) {
		t.Fatalf("large numeric metadata changed: %s", out)
	}
	if got := joinedTopLevelDeltas(t, out); got != "CUSTOMER-ALPHA" {
		t.Fatalf("joined delta=%q; stream=%q", got, out)
	}
}

func TestSSERestoringWriterRestoresFunctionArgumentsAcrossEvents(t *testing.T) {
	const original = "10.20.30.40"
	r := policyProxyRedactor(t, detectors.CustomPattern{
		Name: "private_ip", Pattern: `10\.20\.30\.40`, Action: "pseudonymize", Generator: "ipv4",
	})
	result, err := r.Transform([]byte(`{"arguments":"{\"target\":\"10.20.30.40\"}"}`), "function-args", false, "allow")
	if err != nil {
		t.Fatal(err)
	}
	var transformed map[string]string
	if err := json.Unmarshal(result.Body, &transformed); err != nil {
		t.Fatal(err)
	}
	fake := strings.TrimSuffix(strings.TrimPrefix(transformed["arguments"], `{"target":"`), `"}`)
	if fake == original || len(fake) < 2 {
		t.Fatalf("unexpected transformed arguments %q", transformed["arguments"])
	}

	for split := 1; split < len(fake); split++ {
		first := `{"target":"` + fake[:split]
		second := fake[split:] + `"}`
		events := responseDeltaEventWithItem("response.function_call_arguments.delta", "call-1", first, 1) +
			responseDeltaEventWithItem("response.function_call_arguments.delta", "call-1", second, 2) +
			"data: [DONE]\n\n"
		out := restoreSSEForTest(t, r, "function-args", events)
		if got := joinedTopLevelDeltas(t, out); got != `{"target":"10.20.30.40"}` {
			t.Fatalf("split=%d joined arguments=%q; stream=%q", split, got, out)
		}
	}
}

func TestSSERestoringWriterEscapesRestoredValueAcrossEvents(t *testing.T) {
	const original = `api_key = "anasbdn198h291ebkhjabsdbbasbd"`
	r := newTestRedactorWithCategories(t, []string{"generic_api_key_assignment"})
	request, err := json.Marshal(map[string]string{"input": original})
	if err != nil {
		t.Fatal(err)
	}
	result, err := r.Transform(request, "escaped", false, "allow")
	if err != nil {
		t.Fatal(err)
	}
	var transformed map[string]string
	if err := json.Unmarshal(result.Body, &transformed); err != nil {
		t.Fatal(err)
	}
	fake := transformed["input"]
	split := len(fake) / 2
	stream := sseDeltaEvent("response.output_text.delta", fake[:split], 1) +
		sseDeltaEvent("response.output_text.delta", fake[split:], 2) +
		"data: [DONE]\n\n"
	out := restoreSSEForTest(t, r, "escaped", stream)
	if got := joinedTopLevelDeltas(t, out); got != original {
		t.Fatalf("joined delta=%q, want %q; stream=%q", got, original, out)
	}
}

func TestSSERestoringWriterRestoresAnthropicDeltaAcrossEvents(t *testing.T) {
	r, fake := aliasPseudonym(t, "anthropic")
	for split := 1; split < len(fake); split++ {
		first := anthropicDeltaEvent(fake[:split], 0)
		second := anthropicDeltaEvent(fake[split:], 0)
		out := restoreSSEForTest(t, r, "anthropic", first+second+"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
		if got := joinedAnthropicDeltas(t, out); got != "CUSTOMER-ALPHA" {
			t.Fatalf("split=%d joined delta=%q; stream=%q", split, got, out)
		}
	}
}

func TestSSERestoringWriterRestoresChatContentAcrossEvents(t *testing.T) {
	r, fake := aliasPseudonym(t, "chat")
	for split := 1; split < len(fake); split++ {
		first := chatContentDeltaEvent(fake[:split], 0)
		second := chatContentDeltaEvent(fake[split:], 0)
		out := restoreSSEForTest(t, r, "chat", first+second+"data: [DONE]\n\n")
		if got := joinedChatContent(t, out); got != "CUSTOMER-ALPHA" {
			t.Fatalf("split=%d joined content=%q; stream=%q", split, got, out)
		}
	}
}

func TestSSERestoringWriterRestoresChatToolArgumentsAcrossEvents(t *testing.T) {
	r, fake := aliasPseudonym(t, "chat-tool")
	for split := 1; split < len(fake); split++ {
		first := chatToolDeltaEvent(`{"customer":"`+fake[:split], 0, 0)
		second := chatToolDeltaEvent(fake[split:]+`"}`, 0, 0)
		out := restoreSSEForTest(t, r, "chat-tool", first+second+"data: [DONE]\n\n")
		if got := joinedChatToolArguments(t, out); got != `{"customer":"CUSTOMER-ALPHA"}` {
			t.Fatalf("split=%d joined arguments=%q; stream=%q", split, got, out)
		}
	}
}

func TestSSERestoringWriterHandlesEveryNetworkSplitAcrossEvents(t *testing.T) {
	r, fake := aliasPseudonym(t, "network-and-events")
	semanticSplit := len(fake) / 2
	stream := sseDeltaEvent("response.output_text.delta", fake[:semanticSplit], 1) +
		sseDeltaEvent("response.output_text.delta", fake[semanticSplit:], 2) +
		"data: [DONE]\n\n"
	for networkSplit := 0; networkSplit <= len(stream); networkSplit++ {
		var out bytes.Buffer
		rw := NewSSERestoringWriterForSession(&out, r, "network-and-events")
		if _, err := rw.Write([]byte(stream[:networkSplit])); err != nil {
			t.Fatalf("network split=%d first write: %v", networkSplit, err)
		}
		if _, err := rw.Write([]byte(stream[networkSplit:])); err != nil {
			t.Fatalf("network split=%d second write: %v", networkSplit, err)
		}
		if err := rw.Close(); err != nil {
			t.Fatalf("network split=%d close: %v", networkSplit, err)
		}
		if got := joinedTopLevelDeltas(t, out.String()); got != "CUSTOMER-ALPHA" {
			t.Fatalf("network split=%d joined delta=%q; stream=%q", networkSplit, got, out.String())
		}
	}
}

func TestSSERestoringWriterRestoresRepeatedPseudonymAcrossThreeEvents(t *testing.T) {
	r, fake := aliasPseudonym(t, "repeated")
	combined := fake + "/" + fake
	firstCut := len(fake) / 2
	secondCut := len(fake) + 2
	stream := sseDeltaEvent("response.output_text.delta", combined[:firstCut], 1) +
		sseDeltaEvent("response.output_text.delta", combined[firstCut:secondCut], 2) +
		sseDeltaEvent("response.output_text.delta", combined[secondCut:], 3) +
		"data: [DONE]\n\n"
	out := restoreSSEForTest(t, r, "repeated", stream)
	if got := joinedTopLevelDeltas(t, out); got != "CUSTOMER-ALPHA/CUSTOMER-ALPHA" {
		t.Fatalf("joined delta=%q; stream=%q", got, out)
	}
}

func TestSSERestoringWriterFlushesFinalFragmentAtEOF(t *testing.T) {
	r, fake := aliasPseudonym(t, "eof")
	out := restoreSSEForTest(t, r, "eof", sseDeltaEvent("response.output_text.delta", fake, 1))
	if got := joinedTopLevelDeltas(t, out); got != "CUSTOMER-ALPHA" {
		t.Fatalf("joined delta=%q; stream=%q", got, out)
	}
}

func TestSSERestoringWriterLeavesEncryptedContentImmutable(t *testing.T) {
	r, fake := aliasPseudonym(t, "encrypted")
	split := len(fake) / 2
	makeEvent := func(delta string, sequence int) string {
		payload, _ := json.Marshal(map[string]any{
			"type": "response.output_text.delta", "delta": delta,
			"encrypted_content": fake, "sequence_number": sequence,
		})
		return fmt.Sprintf("data: %s\n\n", payload)
	}
	out := restoreSSEForTest(t, r, "encrypted", makeEvent(fake[:split], 1)+makeEvent(fake[split:], 2)+"data: [DONE]\n\n")
	if got := joinedTopLevelDeltas(t, out); got != "CUSTOMER-ALPHA" {
		t.Fatalf("joined delta=%q; stream=%q", got, out)
	}
	for _, payload := range sseJSONPayloads(t, out) {
		if payload["encrypted_content"] != fake {
			t.Fatalf("encrypted_content changed: got=%q want=%q", payload["encrypted_content"], fake)
		}
	}
}

func TestSSERestoringWriterDoesNotJoinDifferentChannels(t *testing.T) {
	r, fake := aliasPseudonym(t, "channels")
	split := len(fake) / 2
	stream := responseDeltaEventWithItem("response.output_text.delta", "item-a", fake[:split], 1) +
		responseDeltaEventWithItem("response.output_text.delta", "item-b", fake[split:], 2) +
		"data: [DONE]\n\n"
	out := restoreSSEForTest(t, r, "channels", stream)
	if strings.Contains(out, "CUSTOMER-ALPHA") {
		t.Fatalf("unrelated channels were joined and restored: %q", out)
	}
	if !strings.Contains(out, fake[:split]) || !strings.Contains(out, fake[split:]) {
		t.Fatalf("unrelated channel fragments were lost: %q", out)
	}
}

func TestSSERestoringWriterPreservesCRLFEvents(t *testing.T) {
	r, fake := aliasPseudonym(t, "crlf")
	split := len(fake) / 2
	first := strings.ReplaceAll(sseDeltaEvent("response.output_text.delta", fake[:split], 1), "\n", "\r\n")
	second := strings.ReplaceAll(sseDeltaEvent("response.output_text.delta", fake[split:], 2), "\n", "\r\n")
	done := "data: [DONE]\r\n\r\n"
	out := restoreSSEForTest(t, r, "crlf", first+second+done)
	if got := joinedTopLevelDeltas(t, strings.ReplaceAll(out, "\r\n", "\n")); got != "CUSTOMER-ALPHA" {
		t.Fatalf("joined delta=%q; stream=%q", got, out)
	}
	if strings.Contains(strings.ReplaceAll(out, "\r\n", ""), "\n") {
		t.Fatalf("writer introduced bare LF into CRLF stream: %q", out)
	}
}

func TestProxyRestoresPseudonymSplitAcrossSSEEventsEndToEnd(t *testing.T) {
	const original = "CUSTOMER-ALPHA"
	var upstreamBody []byte
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		upstreamBody, _ = io.ReadAll(req.Body)
		var body map[string]string
		if err := json.Unmarshal(upstreamBody, &body); err != nil {
			t.Errorf("upstream request: %v", err)
			return
		}
		fake := body["input"]
		split := len(fake) / 2
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, sseDeltaEvent("response.output_text.delta", fake[:split], 1))
		w.(http.Flusher).Flush()
		_, _ = io.WriteString(w, sseDeltaEvent("response.output_text.delta", fake[split:], 2))
		w.(http.Flusher).Flush()
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
		w.(http.Flusher).Flush()
	}))
	defer upstream.Close()

	r := policyProxyRedactor(t, detectors.CustomPattern{
		Name: "customer", Pattern: original, Action: "pseudonymize", Generator: "alias",
	})
	p, err := New(upstream.URL, r, nil, Options{SessionHeader: "X-Cover-Session"})
	if err != nil {
		t.Fatal(err)
	}
	front := httptest.NewServer(p)
	defer front.Close()

	req, _ := http.NewRequest(http.MethodPost, front.URL+"/v1/responses", strings.NewReader(`{"input":"CUSTOMER-ALPHA"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Cover-Session", "proxy-sse")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(upstreamBody, []byte(original)) {
		t.Fatalf("provider received original bytes: %s", upstreamBody)
	}
	if got := joinedTopLevelDeltas(t, string(body)); got != original {
		t.Fatalf("client joined delta=%q; response=%q", got, body)
	}
}

func sseDeltaEvent(eventType, delta string, sequence int) string {
	payload, _ := json.Marshal(map[string]any{
		"type":            eventType,
		"delta":           delta,
		"sequence_number": sequence,
	})
	return fmt.Sprintf("data: %s\n\n", payload)
}

func responseDeltaEventWithItem(eventType, itemID, delta string, sequence int) string {
	payload, _ := json.Marshal(map[string]any{
		"type": eventType, "item_id": itemID, "delta": delta, "sequence_number": sequence,
	})
	return fmt.Sprintf("data: %s\n\n", payload)
}

func anthropicDeltaEvent(text string, index int) string {
	payload, _ := json.Marshal(map[string]any{
		"type": "content_block_delta", "index": index,
		"delta": map[string]any{"type": "text_delta", "text": text},
	})
	return fmt.Sprintf("event: content_block_delta\ndata: %s\n\n", payload)
}

func chatContentDeltaEvent(text string, index int) string {
	payload, _ := json.Marshal(map[string]any{
		"choices": []any{map[string]any{"index": index, "delta": map[string]any{"content": text}}},
	})
	return fmt.Sprintf("data: %s\n\n", payload)
}

func chatToolDeltaEvent(arguments string, choiceIndex, toolIndex int) string {
	payload, _ := json.Marshal(map[string]any{
		"choices": []any{map[string]any{
			"index": choiceIndex,
			"delta": map[string]any{"tool_calls": []any{map[string]any{
				"index": toolIndex, "function": map[string]any{"arguments": arguments},
			}}},
		}},
	})
	return fmt.Sprintf("data: %s\n\n", payload)
}

func aliasPseudonym(t *testing.T, session string) (*redact.Redactor, string) {
	t.Helper()
	r := policyProxyRedactor(t, detectors.CustomPattern{
		Name: "customer", Pattern: `CUSTOMER-ALPHA`, Action: "pseudonymize", Generator: "alias",
	})
	result, err := r.Transform([]byte(`{"input":"CUSTOMER-ALPHA"}`), session, false, "allow")
	if err != nil {
		t.Fatal(err)
	}
	var transformed map[string]string
	if err := json.Unmarshal(result.Body, &transformed); err != nil {
		t.Fatal(err)
	}
	return r, transformed["input"]
}

func restoreSSEForTest(t *testing.T, r *redact.Redactor, session, stream string) string {
	t.Helper()
	var out bytes.Buffer
	rw := NewSSERestoringWriterForSession(&out, r, session)
	if _, err := rw.Write([]byte(stream)); err != nil {
		t.Fatal(err)
	}
	if err := rw.Close(); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

func joinedTopLevelDeltas(t *testing.T, stream string) string {
	t.Helper()
	var joined strings.Builder
	for _, event := range strings.Split(stream, "\n\n") {
		line := strings.TrimSpace(event)
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if data == "[DONE]" {
			continue
		}
		var payload map[string]any
		if err := json.Unmarshal([]byte(data), &payload); err != nil {
			t.Fatalf("invalid SSE JSON %q: %v", data, err)
		}
		if delta, ok := payload["delta"].(string); ok {
			joined.WriteString(delta)
		}
	}
	return joined.String()
}

func joinedAnthropicDeltas(t *testing.T, stream string) string {
	t.Helper()
	var joined strings.Builder
	for _, payload := range sseJSONPayloads(t, stream) {
		if payload["type"] != "content_block_delta" {
			continue
		}
		delta, _ := payload["delta"].(map[string]any)
		text, _ := delta["text"].(string)
		joined.WriteString(text)
	}
	return joined.String()
}

func joinedChatContent(t *testing.T, stream string) string {
	t.Helper()
	var joined strings.Builder
	for _, payload := range sseJSONPayloads(t, stream) {
		choices, _ := payload["choices"].([]any)
		for _, rawChoice := range choices {
			choice, _ := rawChoice.(map[string]any)
			delta, _ := choice["delta"].(map[string]any)
			content, _ := delta["content"].(string)
			joined.WriteString(content)
		}
	}
	return joined.String()
}

func joinedChatToolArguments(t *testing.T, stream string) string {
	t.Helper()
	var joined strings.Builder
	for _, payload := range sseJSONPayloads(t, stream) {
		choices, _ := payload["choices"].([]any)
		for _, rawChoice := range choices {
			choice, _ := rawChoice.(map[string]any)
			delta, _ := choice["delta"].(map[string]any)
			toolCalls, _ := delta["tool_calls"].([]any)
			for _, rawTool := range toolCalls {
				tool, _ := rawTool.(map[string]any)
				function, _ := tool["function"].(map[string]any)
				arguments, _ := function["arguments"].(string)
				joined.WriteString(arguments)
			}
		}
	}
	return joined.String()
}

func sseJSONPayloads(t *testing.T, stream string) []map[string]any {
	t.Helper()
	stream = strings.ReplaceAll(stream, "\r\n", "\n")
	stream = strings.ReplaceAll(stream, "\r", "\n")
	var payloads []map[string]any
	for _, event := range strings.Split(stream, "\n\n") {
		for _, line := range strings.Split(event, "\n") {
			if !strings.HasPrefix(line, "data:") {
				continue
			}
			data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
			if data == "" || data == "[DONE]" {
				continue
			}
			var payload map[string]any
			if err := json.Unmarshal([]byte(data), &payload); err != nil {
				t.Fatalf("invalid SSE JSON %q: %v", data, err)
			}
			payloads = append(payloads, payload)
		}
	}
	return payloads
}
