package redact

import (
	"encoding/json"
	"errors"
	"mime"
	"strings"
)

type curlWord struct {
	start, end int
	value      string
	dynamic    bool
}

// errCurlUnsupported marks a command the curl parser cannot rewrite safely,
// such as shell composition or a dynamic word that would need requoting.
var errCurlUnsupported = errors.New("unsupported curl command")

// protectCurlContent protects literal HTTP values in commands that an agent
// stores in conversation history after response restoration. It never executes
// a shell or reads @file arguments. A command it cannot rewrite is left to the
// plain-text pipeline, which protects values in place without requoting.
func protectCurlContent(text string, policy httpContentPolicy) (string, bool, error) {
	left, right := trimHTTPOuterSpace(text)
	if strings.HasPrefix(text[left:right], "$ ") {
		left += 2
	}
	if !strings.HasPrefix(text[left:right], "curl ") && !strings.HasPrefix(text[left:right], "curl\t") {
		return text, false, nil
	}
	if !policy.hasWork() {
		return text, true, nil
	}
	output, err := transformCurlCommand(text, left, right, policy)
	if errors.Is(err, errCurlUnsupported) {
		return text, false, nil
	}
	if err != nil {
		return "", true, err
	}
	return output, true, nil
}

func transformCurlCommand(text string, left, right int, policy httpContentPolicy) (string, error) {
	words, err := parseCurlWords(text, left+4, right)
	if err != nil {
		return "", errCurlUnsupported
	}
	for _, word := range words {
		if word.value == "--" {
			return "", errCurlUnsupported
		}
	}
	query := false
	for _, word := range words {
		if word.value == "-G" || word.value == "--get" {
			query = true
		}
	}
	mediaType := ""
	for index := 0; index < len(words); index++ {
		option, value, _, consumed := curlOption(words, index)
		if option == "-H" || option == "--header" {
			if name, field, found := strings.Cut(value, ":"); found && strings.EqualFold(strings.TrimSpace(name), "Content-Type") {
				parsed, _, parseErr := mime.ParseMediaType(strings.TrimSpace(field))
				if parseErr != nil {
					return "", errCurlUnsupported
				}
				mediaType = parsed
			}
		}
		index += consumed
	}
	var edits []httpEdit
	for index := 0; index < len(words); index++ {
		option, value, prefix, consumed := curlOption(words, index)
		word := words[index+consumed]
		transformed := value
		switch option {
		case "-H", "--header":
			name, field, found := strings.Cut(value, ":")
			if !found {
				transformed, err = callHTTPBody(policy.Text, value)
				break
			}
			name = strings.TrimSpace(name)
			if !validHTTPHeaderName(name) {
				return "", errCurlUnsupported
			}
			trimmed := strings.TrimSpace(field)
			mapped, transformErr := transformHTTPHeader(httpHeader{name: name, lowerName: strings.ToLower(name), value: trimmed}, policy)
			if transformErr != nil || structuralHTTPHeader(strings.ToLower(name)) && mapped != trimmed {
				return "", unsafeHTTPContentError()
			}
			if mapped != trimmed {
				transformed = name + ": " + mapped
			}
		case "-u", "--user", "--oauth2-bearer", "--proxy-user", "-U":
			if word.dynamic {
				// Preserve expansion syntax before any mapping can remember it.
				return "", errCurlUnsupported
			}
			// Credentials become an Authorization header, so an explicit
			// Authorization policy owns them; detectors inspect them otherwise.
			if policy.HeaderSelected != nil && policy.HeaderSelected("Authorization") {
				transformed, err = transformHTTPHeader(httpHeader{name: "Authorization", lowerName: "authorization", value: value}, policy)
			} else {
				transformed, err = callHTTPBody(policy.Text, value)
			}
		case "-F", "--form", "--form-string":
			name, field, found := strings.Cut(value, "=")
			if !found || option != "--form-string" && (strings.HasPrefix(field, "@") || strings.HasPrefix(field, "<")) {
				transformed, err = callHTTPBody(policy.Text, value)
				break
			}
			mapped, transformErr := callHTTPTransform(policy, selectorFormFields, name, field, policy.HasForm)
			err = transformErr
			transformed = name + "=" + mapped
		case "-b", "--cookie":
			if strings.Contains(value, "=") {
				transformed, err = transformHTTPHeader(httpHeader{name: "Cookie", lowerName: "cookie", value: value}, policy)
			} else {
				transformed, err = callHTTPBody(policy.Text, value)
			}
		case "--url":
			transformed, _, err = transformURLQuery(value, policy, false)
		case "-d", "--data", "--data-raw", "--data-binary", "--json":
			trimmed := strings.TrimSpace(value)
			if strings.HasPrefix(trimmed, "@") && option != "--data-raw" {
				transformed, err = callHTTPBody(policy.Text, value)
			} else if option == "--json" || isJSONMediaType(mediaType) || strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
				if !json.Valid([]byte(value)) {
					// Malformed JSON data is judged by the embedded JSON and
					// plain-text pipeline, which rejects only what it cannot protect.
					return "", errCurlUnsupported
				}
				transformed, err = transformHTTPBody(value, "application/json", policy)
			} else if mediaType == "text/html" || mediaType == "application/xhtml+xml" || strings.HasPrefix(trimmed, "<") {
				transformed, err = transformHTTPBody(value, "text/html", policy)
			} else if query && strings.Contains(value, "=") {
				transformed, _, err = transformParameterString(value, selectorQueryParams, policy, policy.HasQuery)
			} else if strings.Contains(value, "=") || mediaType == "application/x-www-form-urlencoded" {
				transformed, _, err = transformParameterString(value, selectorFormFields, policy, policy.HasForm)
			} else {
				transformed, err = callHTTPBody(policy.Text, value)
			}
		case "--data-urlencode":
			if name, field, found := strings.Cut(value, "="); found {
				mapped, transformErr := callHTTPTransform(policy, selectorFormFields, name, field, policy.HasForm)
				err = transformErr
				transformed = name + "=" + mapped
			} else {
				transformed, err = callHTTPBody(policy.Text, value)
			}
		default:
			if hasHTTPScheme(value) {
				transformed, _, err = transformURLQuery(value, policy, false)
			} else {
				transformed, err = callHTTPBody(policy.Text, value)
			}
		}
		if err != nil {
			return "", unsafeHTTPContentError()
		}
		if transformed != value {
			if word.dynamic {
				return "", errCurlUnsupported
			}
			quoted := "'" + strings.ReplaceAll(prefix+transformed, "'", "'\\''") + "'"
			edits = append(edits, httpEdit{start: word.start, end: word.end, replacement: quoted})
		}
		index += consumed
	}
	return applyHTTPEdits(text, 0, len(text), edits)
}

func hasHTTPScheme(value string) bool {
	return len(value) >= 7 && strings.EqualFold(value[:7], "http://") ||
		len(value) >= 8 && strings.EqualFold(value[:8], "https://")
}

// curlShortValueOptions lists argument-taking short options as two-byte names.
// Both structured and in-place scanning use the same option grammar.
const curlShortValueOptions = "-A-b-c-C-d-D-e-E-F-H-K-m-o-P-Q-r-t-T-u-U-w-x-X-y-Y-z"

const curlFlagOptions = "aBfFgGiIjJkKlLMnNOpqRsSvVZ012346:#"

// curlValueOption returns the option and the start of its attached argument.
// An offset at the end of word means that the next word is the argument.
func curlValueOption(word string) (option string, offset int) {
	if strings.HasPrefix(word, "--") {
		if name, _, found := strings.Cut(word, "="); found {
			return name, len(name) + 1
		}
		// Argument-taking long options from curl --help all. Flag options
		// do not consume the next word, including their --no- variants.
		switch word {
		case "--abstract-unix-socket", "--alt-svc", "--aws-sigv4",
			"--cacert", "--capath", "--cert", "--cert-type", "--ciphers",
			"--config", "--connect-timeout", "--connect-to", "--continue-at",
			"--cookie", "--cookie-jar", "--create-file-mode", "--crlfile", "--curves",
			"--data", "--data-ascii", "--data-binary", "--data-raw", "--data-urlencode",
			"--delegation", "--dns-interface", "--dns-ipv4-addr", "--dns-ipv6-addr", "--dns-servers",
			"--doh-url", "--dump-header", "--ech", "--egd-file", "--engine",
			"--etag-compare", "--etag-save", "--expect100-timeout", "--form", "--form-string",
			"--ftp-account", "--ftp-alternative-to-user", "--ftp-method", "--ftp-port", "--ftp-ssl-ccc-mode",
			"--happy-eyeballs-timeout-ms", "--haproxy-clientip", "--header", "--help",
			"--hostpubmd5", "--hostpubsha256", "--hsts", "--interface", "--ip-tos", "--ipfs-gateway",
			"--json", "--keepalive-cnt", "--keepalive-time", "--key", "--key-type", "--knownhosts", "--krb",
			"--libcurl", "--limit-rate", "--local-port", "--login-options", "--mail-auth", "--mail-from", "--mail-rcpt",
			"--max-filesize", "--max-redirs", "--max-time", "--netrc-file", "--noproxy", "--oauth2-bearer",
			"--output", "--output-dir", "--parallel-max", "--parallel-max-host", "--pass", "--pinnedpubkey",
			"--preproxy", "--proto", "--proto-default", "--proto-redir", "--proxy", "--proxy-cacert", "--proxy-capath",
			"--proxy-cert", "--proxy-cert-type", "--proxy-ciphers", "--proxy-crlfile", "--proxy-header",
			"--proxy-key", "--proxy-key-type", "--proxy-pass", "--proxy-pinnedpubkey", "--proxy-service-name",
			"--proxy-tls13-ciphers", "--proxy-tlsauthtype", "--proxy-tlspassword", "--proxy-tlsuser", "--proxy-user", "--proxy1.0",
			"--pubkey", "--quote", "--random-file", "--range", "--rate", "--referer", "--request",
			"--request-target", "--resolve", "--retry", "--retry-delay", "--retry-max-time",
			"--sasl-authzid", "--service-name", "--sigalgs", "--socks4", "--socks4a", "--socks5",
			"--socks5-gssapi-service", "--socks5-hostname", "--speed-limit", "--speed-time", "--ssl-sessions",
			"--stderr", "--telnet-option", "--tftp-blksize", "--time-cond", "--tls-max", "--tls13-ciphers",
			"--tlsauthtype", "--tlspassword", "--tlsuser", "--trace", "--trace-ascii", "--trace-config",
			"--unix-socket", "--upload-file", "--upload-flags", "--url", "--url-query", "--user", "--user-agent",
			"--variable", "--vlan-priority", "--write-out":
			return word, len(word)
		}
	} else if len(word) > 1 && word[0] == '-' {
		for i := 1; i < len(word); i++ {
			if index := strings.IndexByte(curlShortValueOptions, word[i]); index >= 0 && index%2 == 1 {
				return curlShortValueOptions[index-1 : index+1], i + 1
			}
			if strings.IndexByte(curlFlagOptions, word[i]) < 0 {
				break
			}
		}
	}
	return "", 0
}

func curlOption(words []curlWord, index int) (option, value, prefix string, consumed int) {
	word := words[index].value
	if option, offset := curlValueOption(word); option != "" {
		if offset < len(word) || strings.HasSuffix(word, "=") {
			return option, word[offset:], word[:offset], 0
		}
		if index+1 < len(words) {
			return option, words[index+1].value, "", 1
		}
	}
	return "", word, "", 0
}

func parseCurlWords(text string, position, end int) ([]curlWord, error) {
	var words []curlWord
	for position < end {
		for position < end && strings.ContainsRune(" \t\r\n", rune(text[position])) {
			position++
		}
		if position == end {
			break
		}
		word := curlWord{start: position}
		var value strings.Builder
		quote := byte(0)
		for position < end {
			character := text[position]
			if quote == 0 && strings.ContainsRune(" \t\r\n", rune(character)) {
				break
			}
			if quote == 0 && strings.ContainsRune(";|&<>()", rune(character)) {
				return nil, unsafeHTTPContentError()
			}
			if character == '\'' || character == '"' {
				if quote == 0 {
					quote = character
					position++
					continue
				}
				if quote == character {
					quote = 0
					position++
					continue
				}
			}
			if character == '\\' && quote != '\'' {
				position++
				if position == end {
					return nil, unsafeHTTPContentError()
				}
				escaped := text[position]
				if escaped != '\n' {
					if quote == '"' && !strings.ContainsRune("\\\"$`", rune(escaped)) {
						value.WriteByte('\\')
					}
					value.WriteByte(escaped)
				}
				position++
				continue
			}
			if quote != '\'' && (character == '$' || character == '`') {
				word.dynamic = true
			}
			value.WriteByte(character)
			position++
		}
		if quote != 0 || len(words) == maxHTTPParameters {
			return nil, unsafeHTTPContentError()
		}
		word.end, word.value = position, value.String()
		words = append(words, word)
	}
	return words, nil
}
