package redact

import (
	"regexp"

	"github.com/DavidCarliez/cover/internal/redact/detectors"
)

// testDataDisclaimerRe matches phrasing that explicitly marks content as
// synthetic, example, or non-production data. When present in a string field,
// secret-style regex matches are dropped so labeled test fixtures can reach
// the upstream model; structured PII categories are always redacted.
var testDataDisclaimerRe = regexp.MustCompile(`(?i)\b(` +
	`test\s+data|not\s+real|fake\s+data|example\s+data|synthetic\s+data|dummy\s+data|` +
	`placeholder\s+data|for\s+testing\s+only|demo\s+data|sample\s+data|not\s+actual|` +
	`mock\s+data|sandbox\s+data|just\s+an?\s+example|just\s+examples|not\s+production|` +
	`fictional|made\s+up|not\s+a\s+real` +
	`)\b`)

// alwaysRedactCategories are redacted even when the surrounding text is
// explicitly labeled as test or example data.
var alwaysRedactCategories = map[string]bool{
	"ssn":         true,
	"credit_card": true,
	"phone_us":    true,
	"phone_intl":  true,
	"iban":        true,
	"email":       true,
}

func isTestDataContext(text string) bool {
	return testDataDisclaimerRe.MatchString(text)
}

func filterTestExemptMatches(text string, matches []detectors.Match) []detectors.Match {
	if !isTestDataContext(text) {
		return matches
	}
	filtered := make([]detectors.Match, 0, len(matches))
	for _, m := range matches {
		if alwaysRedactCategories[m.Category] {
			filtered = append(filtered, m)
		}
	}
	return filtered
}
