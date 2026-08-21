package redact

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
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
		return fmt.Sprintf("host%d", 10+int(h[0])%90), nil
	case "domain", "fqdn":
		parts := strings.Split(strings.TrimSuffix(original, "."), ".")
		suffix := "internal"
		if len(parts) > 1 {
			suffix = parts[len(parts)-1]
		}
		return fmt.Sprintf("host%d.example.%s", 10+int(h[0])%90, suffix), nil
	case "email":
		parts := strings.SplitN(original, "@", 2)
		tld := "com"
		if len(parts) == 2 {
			domainParts := strings.Split(parts[1], ".")
			if len(domainParts) > 1 {
				tld = domainParts[len(domainParts)-1]
			}
		}
		n := 100 + int(h[0])*4 + int(h[1])%4
		return fmt.Sprintf("user%d@example.%s", n, tld), nil
	case "username":
		first := []string{"alex", "casey", "jordan", "morgan", "riley", "taylor"}
		last := []string{"martin", "lee", "miller", "parker", "reed", "young"}
		sep := "_"
		if strings.Contains(original, ".") {
			sep = "."
		} else if strings.Contains(original, "-") {
			sep = "-"
		}
		return first[int(h[0])%len(first)] + sep + last[int(h[1])%len(last)], nil
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
		return u.String(), nil
	case "alias":
		return "alias-" + strconv.FormatUint(uint64(h[0])<<24|uint64(h[1])<<16|uint64(h[2])<<8|uint64(h[3]), 36), nil
	default:
		return "", fmt.Errorf("unknown pseudonym generator")
	}
}

func maskValue(value string) string {
	r := []rune(value)
	if len(r) <= 4 {
		return strings.Repeat("*", len(r))
	}
	keep := 2
	return string(r[:keep]) + strings.Repeat("*", len(r)-2*keep) + string(r[len(r)-keep:])
}
