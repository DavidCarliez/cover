package detectors

import (
	"regexp"
	"strings"
	"testing"
)

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

func TestOpenAIKeyDoesNotClaimOtherVendorsKeys(t *testing.T) {
	d, err := NewRegexDetector([]string{"openai_key", "anthropic_key", "stripe_key"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for text, want := range map[string]string{
		"sk-" + "proj-Ab3dE6fG9hJ2kL5mN8pQ1rS4tU7vW0xY3zA6bC9dE2f":      "openai_key",
		"sk-" + "svcacct-Ab3dE6fG9hJ2kL5mN8pQ1rS4tU7vW0xY3zA6":          "openai_key",
		"sk-" + "Ab3dE6fG9hJ2kL5mN8pQ1rS4tU7vW0xY3zA6bC9dE2fG5hJ8":      "openai_key",
		"sk-" + "ant-api03-Ab3dE6fG9hJ2kL5mN8pQ1rS4tU7vW0xY3zA6bC9dE2f": "anthropic_key",
		"sk_" + "live_4eC39HqLyjWDarjtT1zdp7dc":                         "stripe_key",
	} {
		matches := d.Detect("key " + text + " end")
		if len(matches) != 1 || matches[0].Category != want || matches[0].Value != text {
			t.Fatalf("%q: matches=%+v, want one %s", text, matches, want)
		}
	}
}

func TestCLIAndFilePasswordDetectorsSelectOnlyTheValue(t *testing.T) {
	d, err := NewRegexDetector([]string{"cli_password_flag", "pgpass_line", "netrc_password"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for text, want := range map[string]string{
		"mysql -h db -P 3306 -u root -pS3cretPass -e 'show databases'": "S3cretPass",
		"mysqldump -u root -p'S3cret Pass' app > dump.sql":             "S3cret",
		"docker login registry -u deploy --password hunter2abc":        "hunter2abc",
		"huggingface-cli login --token hf_abcdefghij":                  "hf_abcdefghij",
		"sshpass -p s3cretpw ssh deploy@host":                          "s3cretpw",
		"redis-cli -h cache -a s3cretpw ping":                          "s3cretpw",
		"sqlcmd -S db -U sa -P p4ssw0rd -Q 'select 1'":                 "p4ssw0rd",
		"mongosh --username app --password p4ssw0rd":                   "p4ssw0rd",
		"db.internal:5432:app:app:Xk9pLm2qRtVw7Zs":                     "Xk9pLm2qRtVw7Zs",
		"machine api.github.com login alice password ghp_abcdefgh":     "ghp_abcdefgh",
		"  password s3cretpw":                                          "s3cretpw",
		"default login anonymous password me@example.com":              "me@example.com",
	} {
		matches := d.Detect(text)
		if len(matches) != 1 || matches[0].Value != want || text[matches[0].Start:matches[0].End] != want {
			t.Errorf("%q: matches=%+v, want value %q", text, matches, want)
		}
	}
	for _, text := range []string{
		"mysql -u root -p mydb",
		"mysql -h db -P 3306 -u root",
		"mkdir -p build && ssh -p 2222 host",
		"docker login --password-stdin registry",
		"docker login --password $REGISTRY_PASSWORD",
		"tool --token --help",
		"meeting at 12:30",
		"password manager tips",
		"The password reset flow",
	} {
		if matches := d.Detect(text); len(matches) != 0 {
			t.Errorf("%q: unexpected matches %+v", text, matches)
		}
	}
}

func TestBuiltinPatternsSkipLookalikes(t *testing.T) {
	d, err := NewRegexDetector([]string{"generic_api_key_assignment", "iban", "phone_intl"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{
		"token_type: Bearer",
		"password_hash: $2b$12$abcdefghijklmnopqrstuv",
		"secret: ${SECRET_VALUE}",
		"iban AB12 CDEF GHIJ KLMN",
		"iban DE89 3704 0044 0532 0130 01",
		"delta +3.14159265 and +12.3456789",
		"range +1-10 or +2024-10-08",
	} {
		if matches := d.Detect(text); len(matches) != 0 {
			t.Errorf("%q: unexpected matches %+v", text, matches)
		}
	}
	for text, want := range map[string]string{
		`secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYzQ9KmLp2Vt"`:  `secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYzQ9KmLp2Vt"`,
		"SENDGRID_API_KEY=SG.Ab3dE6fG9hJ2kL5mN8pQ1w.Ab3dE6fG9hJ2k": "API_KEY=SG.Ab3dE6fG9hJ2kL5mN8pQ1w.Ab3dE6fG9hJ2k",
		"password: hunter2abc. Next sentence":                      "password: hunter2abc",
		"pay DE89 3704 0044 0532 0130 00 now":                      "DE89 3704 0044 0532 0130 00",
		"pay BE68 5390 0754 7034 now":                              "BE68 5390 0754 7034",
		"call +32 471 23 45 67 now":                                "+32 471 23 45 67",
		"call +32 (0)2 123 45 67 now":                              "+32 (0)2 123 45 67",
		"call +44 20 7946 0958 now":                                "+44 20 7946 0958",
		"call +1 212 555 0123 now":                                 "+1 212 555 0123",
		"call +32-471-23-45-67 now":                                "+32-471-23-45-67",
		"call +442071838750 now":                                   "+442071838750",
	} {
		matches := d.Detect(text)
		if len(matches) != 1 || matches[0].Value != want {
			t.Errorf("%q: matches=%+v, want %q", text, matches, want)
		}
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

func TestBuiltinTriggersNeverSkipRealMatches(t *testing.T) {
	// Token samples are concatenated so secret scanners do not flag them.
	samples := map[string][]string{
		"aws_access_key":             {"key AKIAIOSFODNN7EXAMPLE here"},
		"aws_secret_key":             {"AWS_SECRET_ACCESS_KEY = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEYab"},
		"gcp_api_key":                {"AIza" + "SyA-1234567890abcdefghijklmnopqrstu"},
		"github_token":               {"ghp" + "_abcdefghijklmnopqrstuvwxyz0123456789"},
		"gitlab_token":               {"glpat" + "-abcdefghij0123456789"},
		"slack_token":                {"xox" + "b-1234567890-abcdef"},
		"stripe_key":                 {"sk_" + "live_abcdefghijklmnopqrstuvwx"},
		"anthropic_key":              {"sk-" + "ant-abcdefghijklmnopqrstu"},
		"private_key_block":          {"-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----"},
		"jwt":                        {"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc_DEF-123"},
		"generic_api_key_assignment": {"API_KEY=abcdef123456", "Password: hunter2hunter2", "PWD=abcdefgh"},
		"email":                      {"mail alice@corp.example.com"},
		"ssn":                        {"ssn 123-45-6789", "ssn 123 45 6789"},
		"credit_card":                {"card 4111 1111 1111 1111", "card 4111111111111111"},
		"phone_us":                   {"call 212-555-0123 now", "call 212.555.0123", "call (212) 555-0123", "call +1 212 555 0123"},
		"phone_intl":                 {"call +442071838750", "call +32 471 23 45 67", "call +32 (0)2 123 45 67"},
		"iban":                       {"iban DE89370400440532013000", "iban DE89 3704 0044 0532 0130 00"},
		"openai_key":                 {"sk-" + "proj-Ab3dE6fG9hJ2kL5mN8pQ1rS4tU7vW0xY3zA6bC9dE2f", "sk-" + "Ab3dE6fG9hJ2kL5mN8pQ1rS4tU7vW0xY3zA6bC9dE2fG5hJ8"},
		"huggingface_token":          {"hf_" + "Ab3dE6fG9hJ2kL5mN8pQ1rS4tU7vW0xY3zA6b"},
		"digitalocean_token":         {"dop_" + "v1_" + strings.Repeat("a1b2c3d4", 8)},
		"vault_token":                {"hvs." + "CAESIJx7K2pL9vN4rT8wY1zB3cF6hJ0dA5gE8uI2oS4kM7nP1q"},
		"sendgrid_key":               {"SG." + "Ab3dE6fG9hJ2kL5mN8pQ1w.Ab3dE6fG9hJ2kL5mN8pQ1rS4tU7vW0xY3zA6bC9dE2fG5hJ8k"},
		"npm_token":                  {"npm_" + "Ab3dE6fG9hJ2kL5mN8pQ1rS4tU7vW0xY3zA6"},
		"pypi_token":                 {"pypi-" + "AgEIcHlwaS5vcmc" + strings.Repeat("Ab3dE6fG9hJ2", 5)},
		"google_oauth_secret":        {"GOCSPX-" + "Ab3dE6fG9hJ2kL5mN8pQ1rS4tU7v"},
		"shopify_token":              {"shpat_" + "f3a9c1e7b2d4a6f8c0e2b4d6a8f0c2e4"},
		"azure_storage_key":          {"AccountKey=" + strings.Repeat("Qx7mK2pL9vN4rT8w", 5) + "Qx7mK2==", "SharedAccessKey=" + strings.Repeat("Qx7mK2pL9vN4rT8w", 3)},
		"pem_base64":                 {"LS0tLS1CRUdJTi" + "BSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFb3dJQkFBS0NBUUVBdTd2WThRMnhL"},
		"cli_password_flag":          {"mysql -u root -pS3cretPass", "docker login --password hunter2abc", "sshpass -p s3cret ssh host", "redis-cli -a s3cret ping", "sqlcmd -S s -U u -P p4ssw0rd", "mongosh --password p4ssw0rd", "cli --api-key abcdef123"},
		"pgpass_line":                {"db.internal:5432:app:app:Xk9pLm2qRtVw7Zs", "x\nlocalhost:*:*:postgres:secretpw\ny"},
		"netrc_password":             {"machine api.example login alice password s3cret", "machine x\n  login y\n  password s3cret\n"},
		"ipv4":                       {"host 10.20.30.40"},
		"ipv6":                       {"host 2001:db8::1"},
		"domain":                     {"see db.corp.example.com"},
		"uuid":                       {"id 550e8400-e29b-41d4-a716-446655440000"},
		"url":                        {"open HTTPS://example.com/x"},
	}
	for category, texts := range samples {
		pattern := regexp.MustCompile(builtinPatterns[category])
		d, err := NewRegexDetector([]string{category}, nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, text := range texts {
			if !pattern.MatchString(text) {
				t.Fatalf("%s sample %q does not match its pattern", category, text)
			}
			if len(d.Detect(text)) == 0 {
				t.Errorf("%s: detector skipped %q, which its pattern matches", category, text)
			}
		}
	}
}

// Scanning only candidate lines finds exactly what scanning the whole text
// finds, for every built-in pattern with a line filter.
func FuzzLineFiltersMatchWholeText(f *testing.F) {
	for _, seed := range []string{
		"password = hunter2hunter2\nmail a.b@c.io",
		"call 212-555-0123\nssn 123 45 6789 card 4111 1111 1111 1111",
		"iban DE89370400440532013000\n\nip 10.0.0.1 id 550e8400-e29b-41d4-a716-446655440000",
		"AWS_SECRET_ACCESS_KEY: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEYab",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, text string) {
		for category, filter := range builtinLineFilters {
			re := regexp.MustCompile(builtinPatterns[category])
			whole := re.FindAllStringIndex(text, -1)
			var lines [][]int
			for _, span := range candidateSpans(text, filter) {
				for _, loc := range re.FindAllStringIndex(text[span[0]:span[1]], -1) {
					lines = append(lines, []int{loc[0] + span[0], loc[1] + span[0]})
				}
			}
			if len(whole) != len(lines) {
				t.Fatalf("%s: whole=%v lines=%v", category, whole, lines)
			}
			for i := range whole {
				if whole[i][0] != lines[i][0] || whole[i][1] != lines[i][1] {
					t.Fatalf("%s: whole=%v lines=%v", category, whole, lines)
				}
			}
		}
	})
}
