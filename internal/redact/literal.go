package redact

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// literalMatcher finds leftmost-longest occurrences of a fixed set of
// literals. Literals marked as bounded only match when they do not continue a
// word on either side, so a short alias such as "host62" is not found inside
// "host620" or "myhost62".
type literalMatcher struct {
	nodes []literalNode
	first [256]bool
	// pairs holds the first two bytes of every literal longer than one
	// byte, so most candidate positions are rejected without a tree walk.
	pairs    [256 * 256 / 64]uint64
	single   bool
	bounded  []bool
	literals []string
	maxLen   int
}

type literalNode struct {
	next  map[byte]int32
	entry int32 // literal index + 1; zero when no literal ends here
}

func newLiteralMatcher(literals []string, bounded func(int) bool) *literalMatcher {
	m := &literalMatcher{nodes: []literalNode{{}}, literals: literals, bounded: make([]bool, len(literals))}
	for i, literal := range literals {
		if literal == "" {
			continue
		}
		m.bounded[i] = bounded != nil && bounded(i)
		m.first[literal[0]] = true
		if len(literal) == 1 {
			m.single = true
		} else {
			pair := int(literal[0])<<8 | int(literal[1])
			m.pairs[pair/64] |= 1 << (pair % 64)
		}
		if len(literal) > m.maxLen {
			m.maxLen = len(literal)
		}
		node := int32(0)
		for j := 0; j < len(literal); j++ {
			next, ok := m.nodes[node].next[literal[j]]
			if !ok {
				if m.nodes[node].next == nil {
					m.nodes[node].next = map[byte]int32{}
				}
				next = int32(len(m.nodes))
				m.nodes = append(m.nodes, literalNode{})
				m.nodes[node].next[literal[j]] = next
			}
			node = next
		}
		if m.nodes[node].entry == 0 {
			m.nodes[node].entry = int32(i + 1)
		}
	}
	return m
}

// longestAt returns the longest literal that starts at start and satisfies
// its boundary requirement.
func (m *literalMatcher) longestAt(text string, start int) (int, int, bool) {
	node := int32(0)
	end, index := -1, -1
	for i := start; i < len(text); i++ {
		next, ok := m.nodes[node].next[text[i]]
		if !ok {
			break
		}
		node = next
		if entry := m.nodes[node].entry; entry != 0 {
			literal := int(entry - 1)
			if !m.bounded[literal] || wordBoundaryMatch(text, start, i+1) {
				end, index = i+1, literal
			}
		}
	}
	return end, index, end >= 0
}

// eachAt calls fn for every literal that starts at start and satisfies its
// boundary requirement, shortest first.
func (m *literalMatcher) eachAt(text string, start int, fn func(end, index int)) {
	node := int32(0)
	for i := start; i < len(text); i++ {
		next, ok := m.nodes[node].next[text[i]]
		if !ok {
			return
		}
		node = next
		if entry := m.nodes[node].entry; entry != 0 {
			literal := int(entry - 1)
			if !m.bounded[literal] || wordBoundaryMatch(text, start, i+1) {
				fn(i+1, literal)
			}
		}
	}
}

// find returns the leftmost-longest literal at or after from.
func (m *literalMatcher) find(text string, from int) (start, end, index int, ok bool) {
	for i := from; i < len(text); i++ {
		if !m.first[text[i]] {
			continue
		}
		if !m.single {
			if i+1 >= len(text) {
				break
			}
			if pair := int(text[i])<<8 | int(text[i+1]); m.pairs[pair/64]&(1<<(pair%64)) == 0 {
				continue
			}
		}
		if end, index, ok := m.longestAt(text, i); ok {
			return i, end, index, true
		}
	}
	return 0, 0, 0, false
}

// replace substitutes every non-overlapping literal with replacement(index).
func (m *literalMatcher) replace(text string, replacement func(int) string) (string, bool) {
	if m == nil || m.maxLen == 0 {
		return text, false
	}
	var b strings.Builder
	last := 0
	for pos := 0; ; {
		start, end, index, ok := m.find(text, pos)
		if !ok {
			break
		}
		if b.Len() == 0 {
			b.Grow(len(text))
		}
		b.WriteString(text[last:start])
		b.WriteString(replacement(index))
		last, pos = end, end
	}
	if last == 0 {
		return text, false
	}
	b.WriteString(text[last:])
	return b.String(), true
}

// spansCut reports whether a literal starting at start reaches cut or beyond,
// ignoring boundaries so streaming callers hold back every candidate.
func (m *literalMatcher) spansCut(data []byte, start, cut int) bool {
	node := int32(0)
	for i := start; i < len(data); i++ {
		next, ok := m.nodes[node].next[data[i]]
		if !ok {
			return false
		}
		node = next
		if m.nodes[node].entry != 0 && i+1 >= cut {
			return true
		}
	}
	return false
}

func isWordRune(r rune) bool {
	return r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r)
}

// wordBoundaryMatch reports whether text[start:end] does not continue a word
// across either edge. Edges that are not word characters always qualify.
func wordBoundaryMatch(text string, start, end int) bool {
	if start > 0 {
		before, _ := utf8.DecodeLastRuneInString(text[:start])
		first, _ := utf8.DecodeRuneInString(text[start:end])
		if isWordRune(before) && isWordRune(first) {
			return false
		}
	}
	if end < len(text) {
		last, _ := utf8.DecodeLastRuneInString(text[start:end])
		after, _ := utf8.DecodeRuneInString(text[end:])
		if isWordRune(last) && isWordRune(after) {
			return false
		}
	}
	return true
}
