// Package detectors provides pluggable sensitive-data detectors used by the
// redaction engine. The built-in RegexDetector covers common secret formats;
// additional detectors (e.g. a local LLM-based semantic detector) can
// implement the same Detector interface.
package detectors

import (
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

// Match represents a single detected sensitive substring within a piece of text.
type Match struct {
	Category  string
	Value     string
	Start     int
	End       int
	Rule      string
	Action    string
	Generator string
	Priority  int
	// Encoding names the escaping through which Value represents the
	// protected original, such as "json" or "query". Empty means Value is the
	// original itself.
	Encoding string
}

// Detector finds sensitive substrings within a block of text.
type Detector interface {
	Name() string
	Detect(text string) []Match
}

// CustomPattern is a user-supplied regex pattern loaded from config.
type CustomPattern struct {
	Name          string   `yaml:"name,omitempty"`
	Detector      string   `yaml:"detector,omitempty"`
	Pattern       string   `yaml:"pattern,omitempty"`
	Keys          []string `yaml:"keys,omitempty"`
	Headers       []string `yaml:"headers,omitempty"`
	Cookies       []string `yaml:"cookies,omitempty"`
	QueryParams   []string `yaml:"query_params,omitempty"`
	FormFields    []string `yaml:"form_fields,omitempty"`
	Category      string   `yaml:"category,omitempty"`
	Action        string   `yaml:"action,omitempty"`
	Generator     string   `yaml:"generator,omitempty"`
	Priority      int      `yaml:"priority,omitempty"`
	Enabled       *bool    `yaml:"enabled,omitempty"`
	CaseSensitive *bool    `yaml:"case_sensitive,omitempty"`
	CaptureGroup  string   `yaml:"capture_group,omitempty"`
}

// builtinPatterns maps a category name to the regex used to detect it.
// Patterns are intentionally conservative gitleaks-style signatures for
// common credential formats.
var builtinPatterns = map[string]string{
	"aws_access_key":             `AKIA[0-9A-Z]{16}`,
	"aws_secret_key":             `(?i)aws_secret_access_key[ \t]*[=:][ \t]*['"]?[A-Za-z0-9/+=]{40}['"]?`,
	"gcp_api_key":                `AIza[0-9A-Za-z\-_]{35}`,
	"github_token":               `gh[pousr]_[A-Za-z0-9]{36,255}`,
	"gitlab_token":               `glpat-[A-Za-z0-9\-_]{20}`,
	"slack_token":                `xox[baprs]-[A-Za-z0-9-]{10,}`,
	"stripe_key":                 `sk_live_[0-9a-zA-Z]{24,}`,
	"anthropic_key":              `sk-ant-[A-Za-z0-9_-]{20,}`,
	"private_key_block":          `-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----`,
	"jwt":                        `eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`,
	"generic_api_key_assignment": `(?i)(api[_-]?key(?:_\w+)*|secret|token|password|passwd|pwd)[ \t]*[=:][ \t]*['"]?[A-Za-z0-9_\-/+=]{8,}['"]?`,
	"email":                      `[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`,
	"ssn":                        `\b\d{3}[- \t]\d{2}[- \t]\d{4}\b`,
	"credit_card":                `\b(?:4[0-9]{3}[- \t]?[0-9]{4}[- \t]?[0-9]{4}[- \t]?[0-9]{4}|5[1-5][0-9]{2}[- \t]?[0-9]{4}[- \t]?[0-9]{4}[- \t]?[0-9]{4}|3[47][0-9]{2}[- \t]?[0-9]{6}[- \t]?[0-9]{5}|6(?:011|5[0-9]{2})[- \t]?[0-9]{4}[- \t]?[0-9]{4}[- \t]?[0-9]{4})\b`,
	"phone_us":                   `(?:\+?1[-. \t]?)?(?:\([2-9]\d{2}\)[-. \t]*|\b[2-9]\d{2}[-. \t]+)\d{3}[-. \t]+\d{4}\b`,
	"phone_intl":                 `\+[1-9]\d{6,14}\b`,
	"iban":                       `\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b`,
	"ipv4":                       `\b(?:\d{1,3}\.){3}\d{1,3}\b`,
	"ipv6":                       `\b[0-9A-Fa-f:]{2,39}\b`,
	"hostname":                   `\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\b`,
	"domain":                     `\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}\b`,
	"uuid":                       `\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b`,
	"url":                        `(?i:https?)://[^\s<>"']+`,
}

// BuiltinCategories returns the names of all available built-in categories.
func BuiltinCategories() []string {
	cats := make([]string, 0, len(builtinPatterns))
	for c := range builtinPatterns {
		switch c {
		case "ipv4", "ipv6", "hostname", "domain", "uuid", "url":
			continue // available to explicit rules, but too broad for legacy defaults
		}
		cats = append(cats, c)
	}
	sort.Strings(cats)
	return cats
}

type namedPattern struct {
	category   string
	rule       string
	action     string
	generator  string
	priority   int
	valueGroup int
	re         *regexp.Regexp
	triggers   []string
	lineFilter func(string) bool
}

// builtinTriggers lists cheap literal substrings, compared case-insensitively,
// of which at least one must appear for a pattern to possibly match. Every
// trigger list must be implied by its pattern; a list that is not would
// silently skip real matches. Patterns with no triggers always run.
var builtinTriggers = map[string][]string{
	"aws_access_key":             {"AKIA"},
	"aws_secret_key":             {"aws_secret"},
	"gcp_api_key":                {"AIza"},
	"github_token":               {"ghp_", "gho_", "ghu_", "ghs_", "ghr_"},
	"gitlab_token":               {"glpat-"},
	"slack_token":                {"xox"},
	"stripe_key":                 {"sk_live_"},
	"anthropic_key":              {"sk-ant-"},
	"private_key_block":          {"-----BEGIN"},
	"jwt":                        {"eyJ"},
	"generic_api_key_assignment": {"api", "key", "secret", "token", "password", "passwd", "pwd"},
	"email":                      {"@"},
	"ssn":                        {},
	"credit_card":                {},
	"phone_us":                   {},
	"phone_intl":                 {"+"},
	"iban":                       {},
	"ipv4":                       {"."},
	"ipv6":                       {":"},
	"hostname":                   {},
	"domain":                     {"."},
	"uuid":                       {"-"},
	"url":                        {"http://", "https://"},
}

// builtinLineFilters let a pattern without a literal prefix scan only the
// lines that can contain a match. Every pattern listed here matches within a
// single line, so skipping other lines never misses a match.
var builtinLineFilters = map[string]func(line string) bool{
	"generic_api_key_assignment": func(line string) bool {
		return containsFoldASCII(line, "api") || containsFoldASCII(line, "secret") || containsFoldASCII(line, "token") ||
			containsFoldASCII(line, "password") || containsFoldASCII(line, "passwd") || containsFoldASCII(line, "pwd")
	},
	"aws_secret_key": func(line string) bool { return containsFoldASCII(line, "aws_secret_access_key") },
	"email":          func(line string) bool { return strings.IndexByte(line, '@') >= 0 },
	"ssn":            func(line string) bool { return hasDigitRun(line, 3) },
	"phone_us":       func(line string) bool { return hasDigitRun(line, 3) },
	"credit_card":    func(line string) bool { return hasDigitRun(line, 4) },
	"iban":           func(line string) bool { return hasDigitRun(line, 2) },
	"ipv4":           func(line string) bool { return strings.IndexByte(line, '.') >= 0 },
	"uuid":           func(line string) bool { return strings.IndexByte(line, '-') >= 0 },
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

func hasDigitRun(text string, n int) bool {
	run := 0
	for i := 0; i < len(text); i++ {
		if text[i] >= '0' && text[i] <= '9' {
			if run++; run >= n {
				return true
			}
		} else {
			run = 0
		}
	}
	return false
}

// candidateSpans returns maximal runs of consecutive lines that pass filter.
func candidateSpans(text string, filter func(string) bool) [][2]int {
	var spans [][2]int
	open := -1
	for start := 0; start <= len(text); {
		end := strings.IndexByte(text[start:], '\n')
		if end < 0 {
			end = len(text)
		} else {
			end += start
		}
		if filter(text[start:end]) {
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

// categories requiring post-regex validation before accepting a match.
var postValidators = map[string]func(string) bool{
	"credit_card": luhnValid,
	"ssn":         ssnValid,
	"ipv4":        func(s string) bool { return net.ParseIP(s) != nil && !strings.Contains(s, ":") },
	"ipv6":        func(s string) bool { return net.ParseIP(s) != nil && strings.Contains(s, ":") },
}

// RegexDetector applies a configured set of built-in and custom regex
// patterns to a block of text.
type RegexDetector struct {
	patterns []namedPattern
}

// NewRegexDetector builds a RegexDetector from the requested built-in
// category names plus any custom patterns. Unknown category names or
// invalid custom patterns produce an error.
func NewRegexDetector(categories []string, custom []CustomPattern) (*RegexDetector, error) {
	d := &RegexDetector{}

	for _, cat := range categories {
		pat, ok := builtinPatterns[cat]
		if !ok {
			return nil, fmt.Errorf("unknown regex detector category %q", cat)
		}
		re, err := regexp.Compile(pat)
		if err != nil {
			return nil, fmt.Errorf("compiling builtin pattern %q: %w", cat, err)
		}
		d.patterns = append(d.patterns, namedPattern{
			category:   cat,
			rule:       cat,
			action:     "placeholder",
			re:         re,
			triggers:   builtinTriggers[cat],
			lineFilter: builtinLineFilters[cat],
		})
	}

	for _, c := range custom {
		if c.Enabled != nil && !*c.Enabled {
			continue
		}
		selectors := 0
		for _, names := range [...][]string{c.Keys, c.Headers, c.Cookies, c.QueryParams, c.FormFields} {
			if len(names) > 0 {
				selectors++
			}
		}
		if selectors > 0 {
			if selectors != 1 || c.Pattern != "" || c.Detector != "" || c.CaptureGroup != "" {
				return nil, fmt.Errorf("custom rule %q must use exactly one selector kind without pattern, detector, or capture_group", c.Name)
			}
			continue
		}
		pattern := c.Pattern
		var lineFilter func(string) bool
		if c.Detector != "" {
			cat := strings.TrimPrefix(c.Detector, "builtin_")
			if cat == "fqdn" {
				cat = "domain"
			}
			var ok bool
			pattern, ok = builtinPatterns[cat]
			if !ok {
				return nil, fmt.Errorf("unknown builtin detector %q", c.Detector)
			}
			lineFilter = builtinLineFilters[cat]
		}
		if pattern == "" {
			return nil, fmt.Errorf("custom rule %q has no pattern or detector", c.Name)
		}
		if c.CaseSensitive != nil && !*c.CaseSensitive && !strings.HasPrefix(pattern, "(?i)") {
			pattern = "(?i)" + pattern
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("compiling custom pattern %q: %w", c.Name, err)
		}
		category := c.Category
		if category == "" {
			category = c.Name
		}
		action := c.Action
		if action == "" {
			action = "placeholder"
		}
		group := c.CaptureGroup
		if group == "" && re.SubexpIndex("value") >= 0 {
			group = "value"
		}
		groupIndex := 0
		if group != "" {
			groupIndex = re.SubexpIndex(group)
			if groupIndex < 0 {
				return nil, fmt.Errorf("custom rule %q references missing capture group %q", c.Name, group)
			}
		}
		d.patterns = append(d.patterns, namedPattern{
			category:   category,
			rule:       c.Name,
			action:     action,
			generator:  c.Generator,
			priority:   c.Priority,
			valueGroup: groupIndex,
			re:         re,
			// User policy must favor correctness over a speculative fast path;
			// built-in detectors keep their exact line filters.
			triggers:   nil,
			lineFilter: lineFilter,
		})
	}

	return d, nil
}

// Name implements Detector.
func (d *RegexDetector) Name() string { return "regex" }

// Detect implements Detector. Overlapping matches across different patterns
// are all reported; the caller (Redactor) is responsible for resolving
// overlaps when substituting placeholders.
func (d *RegexDetector) Detect(text string) []Match {
	var matches []Match
	lower := ""
	for _, p := range d.patterns {
		if len(p.triggers) > 0 && lower == "" {
			lower = strings.ToLower(text)
		}
		if !triggersMatch(lower, p.triggers) {
			continue
		}
		validate := postValidators[p.category]
		spans := [][2]int{{0, len(text)}}
		if p.lineFilter != nil {
			spans = candidateSpans(text, p.lineFilter)
		}
		for _, span := range spans {
			offset := span[0]
			for _, locs := range p.re.FindAllStringSubmatchIndex(text[span[0]:span[1]], -1) {
				for i := range locs {
					if locs[i] >= 0 {
						locs[i] += offset
					}
				}
				matches = p.appendMatch(matches, text, locs, validate)
			}
		}
	}
	return matches
}

// appendMatch adds the match at locs, or its value group, when it validates.
func (p namedPattern) appendMatch(matches []Match, text string, locs []int, validate func(string) bool) []Match {
	loc := locs[:2]
	if p.valueGroup > 0 {
		i := p.valueGroup * 2
		if i+1 >= len(locs) || locs[i] < 0 {
			return matches
		}
		loc = locs[i : i+2]
	}
	value := text[loc[0]:loc[1]]
	if validate != nil && !validate(value) {
		return matches
	}
	return append(matches, Match{
		Category:  p.category,
		Value:     value,
		Start:     loc[0],
		End:       loc[1],
		Rule:      p.rule,
		Action:    p.action,
		Generator: p.generator,
		Priority:  p.priority,
	})
}

// triggersMatch reports whether lower, the lowercased text, contains a
// trigger.
func triggersMatch(lower string, triggers []string) bool {
	if len(triggers) == 0 {
		return true
	}
	for _, trig := range triggers {
		if strings.Contains(lower, strings.ToLower(trig)) {
			return true
		}
	}
	return false
}

func digitsOnly(s string) string {
	var b strings.Builder
	for _, r := range s {
		if unicode.IsDigit(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// luhnValid reports whether s contains a credit-card number that passes the
// Luhn checksum (after stripping separators).
func luhnValid(s string) bool {
	digits := digitsOnly(s)
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}
	sum := 0
	alt := false
	for i := len(digits) - 1; i >= 0; i-- {
		n := int(digits[i] - '0')
		if alt {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
		alt = !alt
	}
	return sum%10 == 0
}

// ssnValid rejects obviously invalid US Social Security numbers.
func ssnValid(s string) bool {
	parts := strings.FieldsFunc(s, func(r rune) bool {
		return r == '-' || r == ' ' || r == '\t'
	})
	if len(parts) != 3 || len(parts[0]) != 3 || len(parts[1]) != 2 || len(parts[2]) != 4 {
		return false
	}
	area, group, serial := parts[0], parts[1], parts[2]
	if area == "000" || area == "666" || area[0] == '9' {
		return false
	}
	if group == "00" || serial == "0000" {
		return false
	}
	return true
}
