package redact

import (
	"strings"
	"testing"

	"github.com/DavidCarliez/cover/internal/redact/detectors"
)

// validIBAN checks an IBAN the standard way: the first four characters are
// moved to the end, letters become two digits, and the number is 1 modulo 97.
func validIBAN(t *testing.T, iban string) bool {
	t.Helper()
	var compact []byte
	for i := 0; i < len(iban); i++ {
		if isASCIIAlnum(iban[i]) {
			compact = append(compact, iban[i])
		}
	}
	if len(compact) < minIBANLen {
		return false
	}
	rearranged := strings.ToUpper(string(compact[4:]) + string(compact[:4]))
	rem := 0
	for i := 0; i < len(rearranged); i++ {
		c := rearranged[i]
		if isASCIIDigit(c) {
			rem = (rem*10 + int(c-'0')) % 97
		} else {
			rem = (rem*100 + int(c-'A') + 10) % 97
		}
	}
	return rem == 1
}

func validBelgianAccount(iban string) bool {
	var digits []byte
	for i := 0; i < len(iban); i++ {
		if isASCIIDigit(iban[i]) {
			digits = append(digits, iban[i])
		}
	}
	if len(digits) != 14 {
		return false
	}
	rem := 0
	for _, c := range digits[2:12] {
		rem = (rem*10 + int(c-'0')) % 97
	}
	if rem == 0 {
		rem = 97
	}
	return int(digits[12]-'0')*10+int(digits[13]-'0') == rem
}

func assertSameLayout(t *testing.T, original, fake string, keep func(byte) bool) {
	t.Helper()
	if len(fake) != len(original) {
		t.Fatalf("%q: fake %q has another length", original, fake)
	}
	for i := 0; i < len(original); i++ {
		if keep(original[i]) {
			if !keep(fake[i]) || isASCIIDigit(original[i]) != isASCIIDigit(fake[i]) {
				t.Fatalf("%q: byte %d changed class in %q", original, i, fake)
			}
		} else if fake[i] != original[i] {
			t.Fatalf("%q: separator %d changed in %q", original, i, fake)
		}
	}
}

func TestIBANGeneratorKeepsCountryAndLayoutWithValidCheckDigits(t *testing.T) {
	key := []byte("test-key")
	for _, original := range []string{
		"BE68 5390 0754 7034",
		"BE68539007547034",
		"be68 5390 0754 7034",
		"BE68-5390-0754-7034",
		"DE89 3704 0044 0532 0130 00",
		"GB29 NWBK 6016 1331 9268 19",
		"FR76 3000 6000 0112 3456 7890 189",
		"NO93 8601 1117 947",
		"MT84 MALT 0110 0001 2345 MTLC AST0 01S",
	} {
		fake, err := generateReplacement(key, "iban", original, 0)
		if err != nil {
			t.Fatalf("%q: %v", original, err)
		}
		assertSameLayout(t, original, fake, isASCIIAlnum)
		if !strings.EqualFold(fake[:2], original[:2]) || fake[:2] != original[:2] {
			t.Fatalf("%q: country changed in %q", original, fake)
		}
		if !validIBAN(t, fake) {
			t.Fatalf("%q: fake %q is not a valid IBAN", original, fake)
		}
		for i := 4; i < len(original); i++ {
			if isASCIIAlnum(original[i]) && original[i] == fake[i] {
				t.Fatalf("%q: account character %d unchanged in %q", original, i, fake)
			}
		}
		if strings.HasPrefix(strings.ToUpper(original), "BE") && !validBelgianAccount(fake) {
			t.Fatalf("%q: fake %q fails the Belgian account check", original, fake)
		}
		if again, _ := generateReplacement(key, "iban", original, 0); again != fake {
			t.Fatalf("%q: not deterministic: %q vs %q", original, fake, again)
		}
		if other, _ := generateReplacement(key, "iban", original, 1); other == fake {
			t.Fatalf("%q: attempt 1 repeats %q", original, fake)
		}
	}
	for _, invalid := range []string{"BE68", "1234 5678 9012 3456", "BE6X 5390 0754 7034", "", "BE68 5390 0754 7034 1234 5678 9012 3456 789"} {
		if fake, err := generateReplacement(key, "iban", invalid, 0); err == nil {
			t.Fatalf("%q: accepted as %q", invalid, fake)
		}
	}
}

func TestPhoneGeneratorKeepsPrefixAndLayout(t *testing.T) {
	key := []byte("test-key")
	for _, tc := range []struct{ original, prefix string }{
		{"+32 471 23 45 67", "+32 4"},
		{"+32 (0)471 23.45.67", "+32 (0)4"},
		{"+32471234567", "+324"},
		{"0032 471 23 45 67", "0032 4"},
		{"0471234567", "04"},
		{"0471/23.45.67", "04"},
		{"02 123 45 67", "02"},
		{"+1 (555) 123-4567", "+1 (5"},
		{"+353 1 234 5678", "+353 1"},
		{"+44 20 7946 0958", "+44 2"},
		{"555-123-4567", "5"},
	} {
		fake, err := generateReplacement(key, "phone", tc.original, 0)
		if err != nil {
			t.Fatalf("%q: %v", tc.original, err)
		}
		assertSameLayout(t, tc.original, fake, isASCIIDigit)
		if !strings.HasPrefix(fake, tc.prefix) {
			t.Fatalf("%q: fake %q does not keep prefix %q", tc.original, fake, tc.prefix)
		}
		for i := len(tc.prefix); i < len(tc.original); i++ {
			if isASCIIDigit(tc.original[i]) && tc.original[i] == fake[i] {
				t.Fatalf("%q: digit %d unchanged in %q", tc.original, i, fake)
			}
		}
		if again, _ := generateReplacement(key, "phone", tc.original, 0); again != fake {
			t.Fatalf("%q: not deterministic: %q vs %q", tc.original, fake, again)
		}
		if other, _ := generateReplacement(key, "phone", tc.original, 1); other == fake {
			t.Fatalf("%q: attempt 1 repeats %q", tc.original, fake)
		}
	}
	for _, invalid := range []string{"", "+32 4", "123", "0471", "+32 (0)4 12", "123456789012345678901"} {
		if fake, err := generateReplacement(key, "phone", invalid, 0); err == nil {
			t.Fatalf("%q: accepted as %q", invalid, fake)
		}
	}
}

func TestFormatGeneratorsProtectPatternRuleValuesAndRestore(t *testing.T) {
	r := policyRedactor(t,
		detectors.CustomPattern{Name: "iban", Pattern: `\b[A-Z]{2}[0-9]{2}(?: ?[0-9A-Z]{4}){2,7}(?: ?[0-9A-Z]{1,4})?\b`, Action: "pseudonymize", Generator: "iban"},
		detectors.CustomPattern{Name: "phone", Pattern: `\+[0-9]{2}(?: [0-9]{2,3}){4}`, Action: "pseudonymize", Generator: "phone"},
	)
	const text = "pay BE68 5390 0754 7034 or call +32 471 23 45 67 today"
	out, _ := transformText(t, r, "s", text)
	if strings.Contains(out, "5390 0754 7034") || strings.Contains(out, "471 23 45 67") {
		t.Fatalf("values leaked: %q", out)
	}
	if !strings.HasPrefix(out, "pay BE") || !strings.Contains(out, " or call +32 4") || !strings.HasSuffix(out, " today") {
		t.Fatalf("fakes do not keep the layout: %q", out)
	}
	if !validIBAN(t, strings.Fields(out)[1]+strings.Fields(out)[2]+strings.Fields(out)[3]+strings.Fields(out)[4]) {
		t.Fatalf("fake IBAN is invalid: %q", out)
	}
	if restored := string(r.RestoreForSession([]byte(out), "s")); restored != text {
		t.Fatalf("restored %q, want %q", restored, text)
	}
}

func TestDigitsGeneratorKeepsLayoutAndChangesEveryDigit(t *testing.T) {
	key := []byte("test-key")
	for _, original := range []string{"BE0123.456.749", "BE 0123 456 749", "85.07.30-033.28", "order #2024-00017", "0123456789012345678901234567890123456789"} {
		fake, err := generateReplacement(key, "digits", original, 0)
		if err != nil {
			t.Fatalf("%q: %v", original, err)
		}
		assertSameLayout(t, original, fake, isASCIIDigit)
		for i := 0; i < len(original); i++ {
			if isASCIIDigit(original[i]) && original[i] == fake[i] {
				t.Fatalf("%q: digit %d unchanged in %q", original, i, fake)
			}
		}
		if again, _ := generateReplacement(key, "digits", original, 0); again != fake {
			t.Fatalf("%q: not deterministic", original)
		}
		if other, _ := generateReplacement(key, "digits", original, 1); other == fake {
			t.Fatalf("%q: attempt 1 repeats %q", original, fake)
		}
	}
	for _, invalid := range []string{"", "abc", "v1.2", "BE 123"} {
		if fake, err := generateReplacement(key, "digits", invalid, 0); err == nil {
			t.Fatalf("%q: accepted as %q", invalid, fake)
		}
	}
}

func TestFormatGeneratorsAreValidRuleGenerators(t *testing.T) {
	for _, generator := range []string{"iban", "phone", "digits"} {
		if err := ValidateAction(string(ActionPseudonymize), generator); err != nil {
			t.Fatalf("%s: %v", generator, err)
		}
	}
}
