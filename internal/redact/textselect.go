package redact

import (
	"encoding/json"
	"net/url"
	"regexp"
	"strings"

	"github.com/DavidCarliez/cover/internal/redact/detectors"
)

// textSelector applies a named selector to assignments written as plain
// text, such as `"password": "x"` in an unparsed JSON fragment, `password: x`
// in YAML, `PASSWORD=x` in an env file, `?token=x` in a URL inside prose, or
// `Authorization: Bearer x` in a log line. Parsers handle every structure they
// recognize; this net protects the selected values in everything else.
type textSelector struct {
	rule FieldRule
	re   *regexp.Regexp
}

const (
	textAssignmentValue = `(?:"((?:[^"\\\r\n]|\\.)*)"|'([^'\r\n]*)'|([^\s"'<>&;,(){}\[\]][^\s"'<>&;,()}\]]*))`
	textHeaderValue     = `([^\r\n'"]*[^\s'"])`
)

func buildTextSelectors(rules []FieldRule) []textSelector {
	var selectors []textSelector
	for _, rule := range rules {
		var names []string
		header := false
		switch {
		case len(rule.Headers) > 0:
			names, header = rule.Headers, true
		case len(rule.Keys) > 0:
			names = rule.Keys
		case len(rule.Cookies) > 0:
			names = rule.Cookies
		case len(rule.QueryParams) > 0:
			names = rule.QueryParams
		case len(rule.FormFields) > 0:
			names = rule.FormFields
		}
		quoted := make([]string, 0, len(names))
		for _, name := range names {
			if name != "" {
				quoted = append(quoted, regexp.QuoteMeta(name))
			}
		}
		if len(quoted) == 0 {
			continue
		}
		flags := "(?i)"
		if rule.CaseSensitive && !header {
			flags = ""
		}
		alternatives := "(?:" + strings.Join(quoted, "|") + ")"
		var pattern string
		if header {
			pattern = flags + `(?:^|[\s'"])` + alternatives + `[ \t]*:[ \t]*` + textHeaderValue
		} else {
			pattern = flags + `(?:^|[^A-Za-z0-9_.])["']?` + alternatives + `["']?[ \t]*[:=][ \t]*` + textAssignmentValue
		}
		selectors = append(selectors, textSelector{rule: rule, re: regexp.MustCompile(pattern)})
	}
	return selectors
}

func (r *Redactor) textSelectorMatches(text string) []detectors.Match {
	if len(r.textSelectors) == 0 || !strings.ContainsAny(text, ":=") {
		return nil
	}
	var matches []detectors.Match
	for _, selector := range r.textSelectors {
		for _, loc := range selector.re.FindAllStringSubmatchIndex(text, -1) {
			start, end, unquoted := -1, -1, false
			for group := 1; group*2+1 < len(loc); group++ {
				if loc[group*2] >= 0 {
					start, end = loc[group*2], loc[group*2+1]
					unquoted = group == 3 && len(selector.rule.Headers) == 0
					break
				}
			}
			if start < 0 || end <= start {
				continue
			}
			value := text[start:end]
			// Literals, shell variables and function calls are code, not values.
			if unquoted && (value == "true" || value == "false" || value == "null" ||
				value[0] == '$' || end < len(text) && text[end] == '(') {
				continue
			}
			rule := selector.rule
			category := rule.Category
			if category == "" {
				category = rule.Name
			}
			match := detectors.Match{
				Category: category, Value: value, Start: start, End: end,
				Rule: rule.Name, Action: rule.Action, Generator: rule.Generator, Priority: rule.Priority,
			}
			// The value is protected exactly as written, escapes included, so
			// restoration reproduces the surrounding text byte for byte.
			if Action(match.Action) == ActionPseudonymize && !generatorAccepts(match.Generator, value) {
				match.Action, match.Generator = string(ActionPlaceholder), ""
			}
			matches = append(matches, match)
		}
	}
	return matches
}

// generatorAccepts reports whether a generator can derive a fake from value.
// Assignments found in free text are not type-checked by a parser, so a value
// that does not fit falls back to an opaque placeholder instead of failing.
func generatorAccepts(generator, value string) bool {
	switch generator {
	case "number":
		return isJSONNumberText(value) && json.Valid([]byte(value))
	case "url":
		u, err := url.Parse(value)
		return err == nil && u.Scheme != "" && u.Hostname() != ""
	default:
		return true
	}
}
