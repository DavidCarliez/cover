package redact

import (
	"mime"
	"strings"
)

type curlWord struct {
	start, end int
	value      string
	dynamic    bool
}

// protectCurlContent protects literal HTTP values in commands that an agent
// stores in conversation history after response restoration. It never executes
// a shell or reads @file arguments. Unsupported shell composition fails closed.
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
	words, err := parseCurlWords(text, left+4, right)
	if err != nil {
		return "", true, err
	}
	mediaType := ""
	for index := 0; index < len(words); index++ {
		option, value, _, consumed := curlOption(words, index)
		if option == "-H" || option == "--header" {
			if name, field, found := strings.Cut(value, ":"); found && strings.EqualFold(strings.TrimSpace(name), "Content-Type") {
				parsed, _, parseErr := mime.ParseMediaType(strings.TrimSpace(field))
				if parseErr != nil {
					return "", true, unsafeHTTPContentError()
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
			if name, field, found := strings.Cut(value, ":"); found {
				name = strings.TrimSpace(name)
				if !validHTTPHeaderName(name) {
					return "", true, unsafeHTTPContentError()
				}
				trimmed := strings.TrimSpace(field)
				mapped, transformErr := transformHTTPHeader(httpHeader{name: name, lowerName: strings.ToLower(name), value: trimmed}, policy)
				if transformErr != nil || structuralHTTPHeader(strings.ToLower(name)) && mapped != trimmed {
					return "", true, unsafeHTTPContentError()
				}
				if mapped != trimmed {
					transformed = name + ": " + mapped
				}
			}
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
				transformed, err = transformHTTPBody(value, "application/json", policy)
			} else if mediaType == "text/html" || mediaType == "application/xhtml+xml" || strings.HasPrefix(trimmed, "<") {
				transformed, err = transformHTTPBody(value, "text/html", policy)
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
			if strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://") {
				transformed, _, err = transformURLQuery(value, policy, false)
			} else {
				transformed, err = callHTTPBody(policy.Text, value)
			}
		}
		if err != nil {
			return "", true, unsafeHTTPContentError()
		}
		if transformed != value {
			if word.dynamic {
				return "", true, unsafeHTTPContentError()
			}
			quoted := "'" + strings.ReplaceAll(prefix+transformed, "'", "'\\''") + "'"
			edits = append(edits, httpEdit{start: word.start, end: word.end, replacement: quoted})
		}
		index += consumed
	}
	output, err := applyHTTPEdits(text, 0, len(text), edits)
	return output, true, err
}

func curlOption(words []curlWord, index int) (option, value, prefix string, consumed int) {
	word := words[index].value
	if strings.HasPrefix(word, "--") {
		if name, field, found := strings.Cut(word, "="); found {
			return name, field, name + "=", 0
		}
	} else if len(word) > 2 && (strings.HasPrefix(word, "-H") || strings.HasPrefix(word, "-b") || strings.HasPrefix(word, "-d")) {
		return word[:2], word[2:], word[:2], 0
	}
	switch word {
	case "-H", "--header", "-b", "--cookie", "--url", "-d", "--data", "--data-raw", "--data-binary", "--json", "--data-urlencode":
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
