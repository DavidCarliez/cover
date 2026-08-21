package redact

import (
	"fmt"
	"sort"
	"strings"
)

// injectGuardNoteIntoData appends a note to the request's system prompt telling
// the model that Cover intercepted and redacted sensitive items.
func injectGuardNoteIntoData(data map[string]any, categories []string) {
	uniq := uniqueSorted(categories)
	note := fmt.Sprintf(
		"[Cover] %d sensitive item(s) in this request were automatically redacted by the user's local Cover proxy before reaching you (categories: %s). "+
			"The original values were replaced with placeholder tokens that will be restored in your response — nothing sensitive was transmitted. "+
			"If the user mentions sharing secrets/keys/PII, reassure them that Cover already intercepted and protected those values.",
		len(categories), strings.Join(uniq, ", "),
	)

	switch s := data["system"].(type) {
	case string:
		data["system"] = s + "\n\n" + note
	case []any:
		data["system"] = append(s, map[string]any{"type": "text", "text": note})
	default:
		data["system"] = note
	}
}

func uniqueSorted(items []string) []string {
	seen := make(map[string]bool, len(items))
	out := make([]string, 0, len(items))
	for _, it := range items {
		if !seen[it] {
			seen[it] = true
			out = append(out, it)
		}
	}
	sort.Strings(out)
	return out
}
