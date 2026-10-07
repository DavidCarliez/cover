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
	// literals are the selected names, lowercased unless case-sensitive. A
	// text that contains none of them cannot match, so the regular
	// expressions are skipped. Nil means always scan.
	literals []string
	names    map[string]bool // lowercase names for HTML field identities
	part     *regexp.Regexp  // multipart form-data part with a selected name
}

var (
	textHTMLFieldTag  = regexp.MustCompile(`(?is)<(?:input|meta|param|button|option|data)\b[^>]*>`)
	textHTMLAttribute = regexp.MustCompile(`(?s)([a-zA-Z_:][-a-zA-Z0-9_:.]*)[ \t\r\n]*=[ \t\r\n]*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>` + "`" + `]+))`)
)

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
		selector := textSelector{rule: rule}
		caseSensitive := rule.CaseSensitive && !header
		for _, name := range names {
			if !isASCII(name) {
				selector.literals = nil
				break
			}
			if !caseSensitive {
				name = strings.ToLower(name)
			}
			selector.literals = append(selector.literals, name)
		}
		if header {
			pattern = flags + `(?:^|[\s'"])` + alternatives + `[ \t]*:[ \t]*` + textHeaderValue
		} else {
			pattern = flags + `(?:^|[^A-Za-z0-9_.])["']?` + alternatives + `["']?[ \t]*[:=][ \t]*` + textAssignmentValue
		}
		selector.re = regexp.MustCompile(pattern)
		if len(rule.Keys) > 0 || len(rule.FormFields) > 0 {
			selector.names = map[string]bool{}
			for _, name := range names {
				selector.names[strings.ToLower(name)] = true
			}
			selector.part = regexp.MustCompile(flags + `content-disposition:[ \t]*form-data;[^\r\n]*\bname="` + alternatives +
				`"[^\r\n]*\r?\n(?:[^\r\n]+\r?\n)*\r?\n([^\r\n]*)`)
		}
		selectors = append(selectors, selector)
	}
	return selectors
}

func (r *Redactor) textSelectorMatches(text string) []detectors.Match {
	if len(r.textSelectors) == 0 || !strings.ContainsAny(text, ":=") {
		return nil
	}
	var matches []detectors.Match
	var fieldTags [][]int
	if strings.Contains(text, "<") {
		fieldTags = textHTMLFieldTag.FindAllStringIndex(text, -1)
	}
	for _, selector := range r.textSelectors {
		if !selector.mentioned(text) {
			continue
		}
		for _, span := range selector.htmlFieldValues(text, fieldTags) {
			matches = append(matches, selector.match(text, span[0], span[1]))
		}
		if selector.part != nil {
			for _, loc := range selector.part.FindAllStringSubmatchIndex(text, -1) {
				if loc[3] > loc[2] {
					matches = append(matches, selector.match(text, loc[2], loc[3]))
				}
			}
		}
		// Assignments and header lines never span lines, so only lines that
		// mention a selected name are scanned.
		for _, line := range selector.mentioningLines(text) {
			for _, loc := range selector.re.FindAllStringSubmatchIndex(text[line[0]:line[1]], -1) {
				for i := range loc {
					if loc[i] >= 0 {
						loc[i] += line[0]
					}
				}
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
				matches = append(matches, selector.match(text, start, end))
			}
		}
	}
	return matches
}

// mentioningLines returns runs of consecutive lines that mention a name.
func (selector textSelector) mentioningLines(text string) [][2]int {
	if selector.literals == nil {
		return [][2]int{{0, len(text)}}
	}
	var spans [][2]int
	open := -1
	for start := 0; start <= len(text); {
		end := strings.IndexByte(text[start:], '\n')
		if end < 0 {
			end = len(text)
		} else {
			end += start
		}
		if selector.mentioned(text[start:end]) {
			if open < 0 {
				open = start
			}
		} else if open >= 0 {
			spans = append(spans, [2]int{open, start - 1})
			open = -1
		}
		start = end + 1
	}
	if open >= 0 {
		spans = append(spans, [2]int{open, len(text)})
	}
	return spans
}

// mentioned reports whether text contains one of the selector's names; an
// HTML field, multipart part or assignment always does.
func (selector textSelector) mentioned(text string) bool {
	if selector.literals == nil {
		return true
	}
	fold := !selector.rule.CaseSensitive || len(selector.rule.Headers) > 0
	for _, name := range selector.literals {
		if fold && containsFoldASCII(text, name) || !fold && strings.Contains(text, name) {
			return true
		}
	}
	return false
}

func isASCII(text string) bool {
	for i := 0; i < len(text); i++ {
		if text[i] >= 0x80 {
			return false
		}
	}
	return true
}

// containsFoldASCII reports whether text contains lowerNeedle, ignoring ASCII
// case.
func containsFoldASCII(text, lowerNeedle string) bool {
	n := len(lowerNeedle)
	if n == 0 {
		return true
	}
	first, upper := lowerNeedle[0], lowerNeedle[0]
	if 'a' <= first && first <= 'z' {
		upper = first - ('a' - 'A')
	}
	for i := 0; i+n <= len(text); i++ {
		if c := text[i]; c != first && c != upper {
			continue
		}
		j := 1
		for ; j < n; j++ {
			c := text[i+j]
			if 'A' <= c && c <= 'Z' {
				c += 'a' - 'A'
			}
			if c != lowerNeedle[j] {
				break
			}
		}
		if j == n {
			return true
		}
	}
	return false
}

// match protects text[start:end] exactly as written, escapes included, so
// restoration reproduces the surrounding text byte for byte.
func (selector textSelector) match(text string, start, end int) detectors.Match {
	rule := selector.rule
	category := rule.Category
	if category == "" {
		category = rule.Name
	}
	match := detectors.Match{
		Category: category, Value: text[start:end], Start: start, End: end,
		Rule: rule.Name, Action: rule.Action, Generator: rule.Generator, Priority: rule.Priority,
	}
	if Action(match.Action) == ActionPseudonymize && !generatorAccepts(match.Generator, match.Value) {
		match.Action, match.Generator = string(ActionPlaceholder), ""
	}
	return match
}

// htmlFieldValues returns the value or content attribute spans of HTML field
// tags whose name, id or label is selected. The HTML parser owns documents it
// recognizes; this covers tags in unparsed text, comments and raw-text
// elements such as noscript.
func (selector textSelector) htmlFieldValues(text string, tags [][]int) [][2]int {
	if selector.names == nil {
		return nil
	}
	var spans [][2]int
	for _, tag := range tags {
		selected := false
		var values [][2]int
		for _, attr := range textHTMLAttribute.FindAllStringSubmatchIndex(text[tag[0]:tag[1]], -1) {
			start, end := -1, -1
			for group := 2; group <= 4; group++ {
				if attr[group*2] >= 0 {
					start, end = tag[0]+attr[group*2], tag[0]+attr[group*2+1]
					break
				}
			}
			name := strings.ToLower(text[tag[0]+attr[2] : tag[0]+attr[3]])
			switch name {
			case "name", "id", "aria-label", "property", "itemprop":
				identity := text[start:end]
				if selector.rule.CaseSensitive {
					for _, candidate := range selector.rule.Keys {
						selected = selected || candidate == identity
					}
					for _, candidate := range selector.rule.FormFields {
						selected = selected || candidate == identity
					}
				} else {
					selected = selected || selector.names[strings.ToLower(identity)]
				}
			case "value", "content":
				if end > start {
					values = append(values, [2]int{start, end})
				}
			}
		}
		if selected {
			spans = append(spans, values...)
		}
	}
	return spans
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
