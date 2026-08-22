package detectors

import "testing"

func TestRegexDetector_Builtin(t *testing.T) {
	// Built at runtime so secret scanners don't flag a contiguous sk_live_ literal.
	stripeSample := "sk_" + "live_" + "1234567890abcdefghijklmnop"

	cases := []struct {
		category string
		sample   string
	}{
		{"aws_access_key", "AKIAIOSFODNN7EXAMPLE"},
		{"aws_secret_key", `aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"`},
		{"gcp_api_key", "AIzaSyXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"},
		{"github_token", "ghp_1234567890abcdefghijklmnopqrstuvwxyz12"},
		{"gitlab_token", "glpat-XXXXXXXXXXXXXXXXXXXX"},
		{"slack_token", "xoxb-1234567890123"},
		{"stripe_key", stripeSample},
		{"anthropic_key", "sk-ant-api03XXXXXXXXXXXXXXXXXXXXXXXX"},
		{"private_key_block", "-----BEGIN RSA PRIVATE KEY-----\nMIIBVQIBADANBgkqhkiG\n-----END RSA PRIVATE KEY-----"},
		{"jwt", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dGVzdHNpZ25hdHVyZQ"},
		{"generic_api_key_assignment", "api_key=abcd1234efgh5678"},
		{"email", "alice@example.com"},
		{"ssn", "123-45-6789"},
		{"credit_card", "4111 1111 1111 1111"},
		{"phone_us", "(555) 123-4567"},
		{"phone_intl", "+442079460123"},
		{"iban", "GB33BUKB20201555555555"},
	}

	for _, tc := range cases {
		t.Run(tc.category, func(t *testing.T) {
			d, err := NewRegexDetector([]string{tc.category}, nil)
			if err != nil {
				t.Fatalf("NewRegexDetector: %v", err)
			}
			text := "prefix " + tc.sample + " suffix"
			matches := d.Detect(text)
			if len(matches) == 0 {
				t.Fatalf("category %s: expected a match in %q, got none", tc.category, text)
			}
			found := false
			for _, m := range matches {
				if m.Category == tc.category && m.Value == tc.sample {
					found = true
				}
			}
			if !found {
				t.Errorf("category %s: expected match value %q, got %+v", tc.category, tc.sample, matches)
			}
		})
	}
}

func TestOpenAIKeyIsNotABuiltinCategory(t *testing.T) {
	if _, err := NewRegexDetector([]string{"openai_key"}, nil); err == nil {
		t.Fatal("openai_key must not be available as a built-in detector")
	}
}

func TestRegexDetector_GenericAPIKeySuffix(t *testing.T) {
	d, err := NewRegexDetector([]string{"generic_api_key_assignment"}, nil)
	if err != nil {
		t.Fatalf("NewRegexDetector: %v", err)
	}
	sample := `api_key_database = "1231asdnashbdkahasdas"`
	text := "my " + sample + " do you see this?"
	matches := d.Detect(text)
	if len(matches) == 0 {
		t.Fatalf("expected a match in %q, got none", text)
	}
	if matches[0].Value != sample {
		t.Fatalf("expected match %q, got %+v", sample, matches)
	}
}

func TestNewRegexDetector_UnknownCategory(t *testing.T) {
	if _, err := NewRegexDetector([]string{"not_a_real_category"}, nil); err == nil {
		t.Fatal("expected error for unknown category, got nil")
	}
}

func TestLuhnValid(t *testing.T) {
	if !luhnValid("4111 1111 1111 1111") {
		t.Fatal("expected valid Visa test number")
	}
	if luhnValid("4111 1111 1111 1112") {
		t.Fatal("expected invalid number to fail Luhn")
	}
}

func TestNewRegexDetector_CustomPattern(t *testing.T) {
	d, err := NewRegexDetector(nil, []CustomPattern{{Name: "internal_proj", Pattern: `PROJ-[0-9]{4,6}`}})
	if err != nil {
		t.Fatalf("NewRegexDetector: %v", err)
	}
	matches := d.Detect("see ticket PROJ-12345 for details")
	if len(matches) != 1 || matches[0].Value != "PROJ-12345" || matches[0].Category != "internal_proj" {
		t.Fatalf("unexpected matches: %+v", matches)
	}
}

func TestNewRegexDetector_KeyOnlyRule(t *testing.T) {
	if _, err := NewRegexDetector(nil, []CustomPattern{{Name: "password_fields", Keys: []string{"password"}, Action: "pseudonymize", Generator: "password"}}); err != nil {
		t.Fatalf("key-only rule should be handled outside the regex detector: %v", err)
	}
	if _, err := NewRegexDetector(nil, []CustomPattern{{Name: "mixed", Keys: []string{"password"}, Pattern: "secret"}}); err == nil {
		t.Fatal("expected keys combined with pattern to fail")
	}
}
