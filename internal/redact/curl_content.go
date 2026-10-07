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

// curlValueOptions take the next word as their value.
const curlValueOptions = "HbduUeFAxoT"

// curlFlagOptions take no value and may precede a value option in one word.
const curlFlagOptions = "sSkvLfiIgGjJNOqRZ46"

func curlOption(words []curlWord, index int) (option, value, prefix string, consumed int) {
	word := words[index].value
	if strings.HasPrefix(word, "--") {
		if name, field, found := strings.Cut(word, "="); found {
			return name, field, name + "=", 0
		}
	} else if len(word) > 2 && word[0] == '-' && word[1] != '-' {
		// Combined short flags such as -sSH take the next word for their
		// final value option.
		last := word[len(word)-1]
		combined := strings.IndexByte(curlValueOptions, last) >= 0
		for i := 1; combined && i < len(word)-1; i++ {
			combined = strings.IndexByte(curlFlagOptions, word[i]) >= 0
		}
		if combined && index+1 < len(words) {
			return "-" + string(last), words[index+1].value, "", 1
		}
		if strings.IndexByte("Hbdu", word[1]) >= 0 {
			return word[:2], word[2:], word[:2], 0
		}
	}
	switch word {
	case "-H", "--header", "-b", "--cookie", "--url", "-d", "--data", "--data-raw", "--data-binary", "--json", "--data-urlencode",
		"-u", "--user", "-U", "--proxy-user", "--oauth2-bearer", "-F", "--form", "--form-string":
		if index+1 < len(words) {
			return word, words[index+1].value, "", 1
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
