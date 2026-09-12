package redact

import (
	"encoding/json"
	"testing"

	"github.com/DavidCarliez/cover/internal/redact/detectors"
)

func TestOpaqueImagesSurviveBothDirections(t *testing.T) {
	r := policyRedactor(t, detectors.CustomPattern{Name: "collision", Pattern: "YWJj", Action: "placeholder"})
	for _, body := range []string{
		`{"content":[{"type":"image","source":{"type":"base64","media_type":"image/png","data":"YWJj"}}]}`,
		`{"image_url":"data:image/png;base64,YWJj"}`,
		`{"data":[{"b64_json":"YWJj"}]}`,
		`{"type":"image_generation_call","result":"YWJj"}`,
	} {
		result, err := r.Transform([]byte(body), "image", false, "allow")
		if err != nil || string(result.Body) != body {
			t.Fatalf("image changed on request: %s, %v", result.Body, err)
		}
		// Force a collision with an existing fake on the return path.
		_, err = r.store.Map("image", "original", nil, func(int) (string, error) { return "YWJj", nil })
		if err != nil {
			t.Fatal(err)
		}
		got := r.RestoreResponseForSession([]byte(body), "application/json", "image")
		if string(got) != body {
			t.Fatalf("image changed on response: %s", got)
		}
	}
	body := []byte(`{"type":"image","source":{"type":"base64","data":"YWJj"}}`)
	blocked, err := r.Transform(body, "image", false, "block")
	if err != nil || !blocked.Blocked {
		t.Fatalf("image block policy lost: %v", err)
	}
}

func TestToolArgumentsRestoreInnerJSONEscaping(t *testing.T) {
	for _, original := range []string{"a\"b", `C:\private\new`, "first\nsecond", "é\t☃"} {
		r := policyRedactor(t)
		_, err := r.store.Map("args", original, nil, func(int) (string, error) { return "FAKE", nil })
		if err != nil {
			t.Fatal(err)
		}
		result := r.RestoreResponseForSession([]byte(`{"arguments":"{\"path\":\"FAKE\"}"}`), "application/json", "args")
		var outer map[string]string
		if err := json.Unmarshal(result, &outer); err != nil {
			t.Fatal(err)
		}
		var args map[string]string
		if err := json.Unmarshal([]byte(outer["arguments"]), &args); err != nil {
			t.Fatal(err)
		}
		if args["path"] != original {
			t.Fatalf("got %q want %q", args["path"], original)
		}
	}
}
