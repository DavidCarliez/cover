package redact

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

type Action string

const (
	ActionAllow        Action = "allow"
	ActionPlaceholder  Action = "placeholder"
	ActionPseudonymize Action = "pseudonymize"
	ActionMask         Action = "mask"
	ActionRedact       Action = "redact"
	ActionBlock        Action = "block"
)

var validGenerators = map[string]bool{
	"ipv4": true, "ipv6": true, "hostname": true, "domain": true,
	"fqdn": true, "email": true, "username": true, "password": true,
	"secret": true, "uuid": true, "url": true, "alias": true,
	"number": true, "iban": true, "phone": true, "digits": true,
}

func ValidateAction(action, generator string) error {
	switch Action(action) {
	case ActionAllow, ActionPlaceholder, ActionMask, ActionRedact, ActionBlock:
		if generator != "" && Action(action) != ActionPlaceholder {
			return fmt.Errorf("action %q does not accept generator %q", action, generator)
		}
		return nil
	case ActionPseudonymize:
		if !validGenerators[generator] {
			return fmt.Errorf("unknown pseudonym generator %q", generator)
		}
		return nil
	default:
		return fmt.Errorf("unknown rule action %q", action)
	}
}

func keyedDigest(key []byte, domain, original string, attempt int) [32]byte {
	mac := hmac.New(sha256.New, key)
	_, _ = fmt.Fprintf(mac, "cover:v1:%s:%d:", domain, attempt)
	_, _ = mac.Write([]byte(original))
	var sum [32]byte
	copy(sum[:], mac.Sum(nil))
	return sum
}

func generateReplacement(key []byte, generator, original string, attempt int) (string, error) {
	if generator == "number" {
		return generateNumberReplacement(key, original, attempt)
	}
	h := keyedDigest(key, "pseudonym:"+generator, original, attempt)
	switch generator {
	case "ipv4":
		return fmt.Sprintf("10.%d.%d.%d", 1+int(h[0])%223, int(h[1]), 1+int(h[2])%254), nil
	case "ipv6":
		ip := net.IP(make([]byte, net.IPv6len))
		copy(ip, h[:16])
		ip[0], ip[1] = 0xfd, h[1]
		return ip.String(), nil
	case "hostname":
		return "host-" + pseudonymToken(h[:], 6), nil
	case "domain", "fqdn":
		return "host-" + pseudonymToken(h[:], 6) + ".example." + reservedSuffix(original), nil
	case "email":
		domain := ""
		if at := strings.LastIndexByte(original, '@'); at >= 0 {
			domain = original[at+1:]
		}
		return pseudonymPerson(h[:], ".") + "@example." + reservedSuffix(domain), nil
	case "username":
		sep := "_"
		if strings.Contains(original, ".") {
			sep = "."
		} else if strings.Contains(original, "-") {
			sep = "-"
		}
		return pseudonymPerson(h[:], sep), nil
	case "password", "secret":
		alphabet := "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%"
		n := len(original)
		if n < 12 {
			n = 12
		}
		if n > 64 {
			n = 64
		}
		var b strings.Builder
		for i := 0; i < n; i++ {
			b.WriteByte(alphabet[int(h[i%len(h)])%len(alphabet)])
		}
		return b.String(), nil
	case "uuid":
		b := append([]byte(nil), h[:16]...)
		b[6] = (b[6] & 0x0f) | 0x40
		b[8] = (b[8] & 0x3f) | 0x80
		x := hex.EncodeToString(b)
		return x[:8] + "-" + x[8:12] + "-" + x[12:16] + "-" + x[16:20] + "-" + x[20:], nil
	case "url":
		u, err := url.Parse(original)
		if err != nil || u.Scheme == "" || u.Hostname() == "" {
			return "", fmt.Errorf("invalid URL")
		}
		hostGen := "domain"
		if ip := net.ParseIP(u.Hostname()); ip != nil {
			if ip.To4() != nil {
				hostGen = "ipv4"
			} else {
				hostGen = "ipv6"
			}
		}
		fakeHost, err := generateReplacement(key, hostGen, u.Hostname(), attempt)
		if err != nil {
			return "", err
		}
		if strings.Contains(fakeHost, ":") {
			fakeHost = "[" + fakeHost + "]"
		}
		if port := u.Port(); port != "" {
			fakeHost += ":" + port
		}
		u.Host = fakeHost
		return pseudonymizeURLParts(key, u), nil
	case "alias":
		return "alias-" + strconv.FormatUint(uint64(h[0])<<24|uint64(h[1])<<16|uint64(h[2])<<8|uint64(h[3]), 36), nil
	case "iban":
		return generateIBANReplacement(original, h)
	case "phone":
		return generatePhoneReplacement(original, h)
	case "digits":
		return generateDigitsReplacement(original, h)
	default:
		return "", fmt.Errorf("unknown pseudonym generator")
	}
}

func generateNumberReplacement(key []byte, original string, attempt int) (string, error) {
	if original == "" || !json.Valid([]byte(original)) {
		return "", fmt.Errorf("invalid JSON number")
	}
	first := 0
	if original[0] == '-' {
		first = 1
	}
	if first >= len(original) || original[first] < '0' || original[first] > '9' {
		return "", fmt.Errorf("invalid JSON number")
	}

	// Use a canonical integer that is exactly representable by IEEE-754
	// binary64. A parser may therefore re-serialize a fake originating from a
	// fraction or exponent without changing the reverse-mapping key.
	h := keyedDigest(key, "pseudonym:number", original, attempt)
	raw := uint64(h[0])<<40 | uint64(h[1])<<32 | uint64(h[2])<<24 |
		uint64(h[3])<<16 | uint64(h[4])<<8 | uint64(h[5])
	const span = uint64(8_000_000_000_000)
	replacement := strconv.FormatUint(1_000_000_000_000+raw%span, 10)
	if original[0] == '-' {
		replacement = "-" + replacement
	}
	return replacement, nil
}

// maskValue keeps at most a sixth of the value visible at its edges and
// masks short values completely.
func maskValue(value string) string {
	r := []rune(value)
	keep := min(len(r)/6, 2)
	if len(r) < 6 {
		keep = 0
	}
	return string(r[:keep]) + strings.Repeat("*", len(r)-2*keep) + string(r[len(r)-keep:])
}

const pseudonymAlphabet = "abcdefghijkmnpqrstuvwxyz23456789"

// pseudonymToken returns n characters drawn from h. Lowercase letters and
// digits without look-alike characters keep tokens valid in host names.
func pseudonymToken(h []byte, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = pseudonymAlphabet[int(h[i%len(h)])%len(pseudonymAlphabet)]
	}
	return string(b)
}

var (
	pseudonymFirstNames = []string{
		"alex", "avery", "blake", "cameron", "casey", "dakota", "drew", "emery",
		"finley", "harper", "hayden", "jamie", "jordan", "kendall", "logan", "morgan",
		"parker", "peyton", "quinn", "reese", "riley", "rowan", "sage", "taylor",
	}
	pseudonymLastNames = []string{
		"adams", "baker", "carter", "clark", "collins", "evans", "foster", "graham",
		"hayes", "hughes", "kelly", "lee", "martin", "miller", "morris", "parker",
		"price", "reed", "ross", "shaw", "turner", "walsh", "ward", "young",
	}
)

// pseudonymPerson returns a realistic name-based identifier from a space of
// more than half a million values.
func pseudonymPerson(h []byte, sep string) string {
	n := (int(h[2])<<8 | int(h[3])) % 1000
	return fmt.Sprintf("%s%s%s%03d", pseudonymFirstNames[int(h[0])%len(pseudonymFirstNames)], sep,
		pseudonymLastNames[int(h[1])%len(pseudonymLastNames)], n)
}

// reservedSuffix keeps a private-use suffix such as "internal" and otherwise
// uses "com", so a fake domain under "example." never names a real
// registrable domain such as example.de.
func reservedSuffix(domain string) string {
	labels := strings.Split(strings.TrimSuffix(strings.ToLower(domain), "."), ".")
	switch suffix := labels[len(labels)-1]; suffix {
	case "internal", "local", "lan", "home", "corp", "intranet", "private", "test", "invalid", "localhost":
		if len(labels) > 1 {
			return suffix
		}
	}
	return "com"
}

// pseudonymizeURLParts replaces credentials, path segments, query values and
// the fragment of u. The scheme, port, segment count and query keys remain so
// the fake still reads as a URL of the same shape.
func pseudonymizeURLParts(key []byte, u *url.URL) string {
	part := func(kind, value string, n int) string {
		h := keyedDigest(key, "pseudonym:url-"+kind, value, 0)
		return pseudonymToken(h[:], n)
	}
	if u.User != nil {
		username := "user-" + part("user", u.User.Username(), 6)
		if password, ok := u.User.Password(); ok {
			u.User = url.UserPassword(username, part("password", password, 16))
		} else {
			u.User = url.User(username)
		}
	}
	if u.Path != "" {
		segments := strings.Split(u.EscapedPath(), "/")
		for i, segment := range segments {
			if segment != "" {
				segments[i] = "p-" + part("path", segment, 6)
			}
		}
		u.RawPath = ""
		u.Path = strings.Join(segments, "/")
	}
	if u.RawQuery != "" {
		pairs := strings.Split(u.RawQuery, "&")
		for i, pair := range pairs {
			name, value, hasValue := strings.Cut(pair, "=")
			if hasValue && value != "" {
				pairs[i] = name + "=v-" + part("query", value, 6)
			}
		}
		u.RawQuery = strings.Join(pairs, "&")
	}
	if u.Fragment != "" {
		u.Fragment, u.RawFragment = "f-"+part("fragment", u.EscapedFragment(), 6), ""
	}
	return u.String()
}
