package redact

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"index/suffixarray"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

const (
	placeholderOpen    = "⟦RG:"
	placeholderClose   = "⟧"
	placeholderHashLen = 8
	defaultSessionID   = "default"
)

var PlaceholderMaxLen = len(placeholderOpen) + placeholderHashLen + len(placeholderClose)

type StoreOptions struct {
	MaxSessions          int
	MaxEntriesPerSession int
	SessionTTL           time.Duration
	Now                  func() time.Time
	PseudonymKey         [32]byte
	// MaxKnownValues and KnownValueTTL bound the process-wide memory of
	// protected originals that are protected again wherever they reappear.
	MaxKnownValues int
	KnownValueTTL  time.Duration
}

type sessionMappings struct {
	forward map[string]string
	reverse map[string]string
	numeric map[string]bool
	restore *restorationSnapshot
	// updated is read and refreshed under a read lock while a response
	// streams, so it is atomic.
	updated atomic.Int64
}

func (m *sessionMappings) touch(now time.Time) { m.updated.Store(now.UnixNano()) }

func (m *sessionMappings) lastUsed() time.Time { return time.Unix(0, m.updated.Load()) }

// restorationSnapshot is immutable after construction, so callers can use it
// without holding Store.mu. A session invalidates its snapshot whenever a new
// mapping is added.
type restorationSnapshot struct {
	matcher    *literalMatcher
	originals  []string
	numbers    map[string]string
	maxFakeLen int
}

func (s *restorationSnapshot) restoreBytes(data []byte) ([]byte, bool) {
	restored, changed := s.restoreString(string(data))
	if !changed {
		return data, false
	}
	return []byte(restored), true
}

// restoreString replaces every whole-word fake. A fake glued to surrounding
// word characters is a different token and stays unchanged.
func (s *restorationSnapshot) restoreString(value string) (string, bool) {
	return s.matcher.replace(value, func(index int) string { return s.originals[index] })
}

// safeCut returns how many leading bytes of data can be restored now. A fake
// that reaches the end of data, or the cut itself, is held back so the next
// byte can decide its word boundary.
func (s *restorationSnapshot) safeCut(data []byte) int {
	reserve := s.maxFakeLen
	if len(data) <= reserve {
		return 0
	}
	cut := len(data) - reserve
	for moved := true; moved; {
		moved = false
		for start := max(0, cut-s.maxFakeLen+1); start < cut; start++ {
			if s.matcher.first[data[start]] && s.matcher.spansCut(data, start, cut) {
				cut, moved = start, true
				break
			}
		}
	}
	return cut
}

func (s *restorationSnapshot) restoreNumber(value string) (string, bool) {
	original, ok := s.numbers[value]
	return original, ok
}

// Store owns bounded, in-memory-only, bijective mappings separated by session.
type Store struct {
	mu       sync.RWMutex
	sessions map[string]*sessionMappings
	opts     StoreOptions
	key      [32]byte
	known    *knownValues
}

func NewStore() *Store { return NewStoreWithOptions(StoreOptions{}) }

func NewStoreWithOptions(opts StoreOptions) *Store {
	if opts.MaxSessions <= 0 {
		opts.MaxSessions = 128
	}
	if opts.MaxEntriesPerSession <= 0 {
		opts.MaxEntriesPerSession = 10000
	}
	if opts.SessionTTL <= 0 {
		opts.SessionTTL = time.Hour
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.PseudonymKey == ([32]byte{}) {
		if _, err := rand.Read(opts.PseudonymKey[:]); err != nil {
			panic(fmt.Sprintf("generating ephemeral pseudonym key: %v", err))
		}
	}
	return &Store{
		sessions: make(map[string]*sessionMappings), opts: opts, key: opts.PseudonymKey,
		known: newKnownValues(opts.MaxKnownValues, opts.KnownValueTTL, opts.Now),
	}
}

func normalizeSession(session string) string {
	if session == "" {
		return defaultSessionID
	}
	return session
}

func (s *Store) cleanupLocked(now time.Time) {
	for id, m := range s.sessions {
		if now.Sub(m.lastUsed()) > s.opts.SessionTTL {
			delete(s.sessions, id)
		}
	}
}

func (s *Store) sessionLocked(id string, create bool) *sessionMappings {
	id = normalizeSession(id)
	now := s.opts.Now()
	s.cleanupLocked(now)
	if m, ok := s.sessions[id]; ok {
		m.touch(now)
		return m
	}
	if !create {
		return nil
	}
	if len(s.sessions) >= s.opts.MaxSessions {
		// Evict the least recently used session rather than refusing new
		// conversations. Its later responses can no longer be restored.
		oldest, oldestUsed := "", now
		for candidate, m := range s.sessions {
			if used := m.lastUsed(); oldest == "" || used.Before(oldestUsed) {
				oldest, oldestUsed = candidate, used
			}
		}
		delete(s.sessions, oldest)
	}
	m := &sessionMappings{forward: map[string]string{}, reverse: map[string]string{}, numeric: map[string]bool{}}
	m.touch(now)
	s.sessions[id] = m
	return m
}

// Map returns a stable reversible text fake. generate receives a collision
// retry number.
func (s *Store) Map(session, original string, occupied *occupiedSet, generate func(int) (string, error)) (string, error) {
	return s.mapValue(session, original, original, false, occupied, generate)
}

// MapNumber keeps numeric mappings in a separate forward namespace so a JSON
// number and a JSON string with the same spelling can coexist in one session.
func (s *Store) MapNumber(session, original string, occupied *occupiedSet, generate func(int) (string, error)) (string, error) {
	return s.mapValue(session, numberMappingIdentity(original), original, true, occupied, generate)
}

func numberMappingIdentity(original string) string {
	return "\x00number:" + original
}

func (s *Store) mapValue(session, identity, original string, numeric bool, occupied *occupiedSet, generate func(int) (string, error)) (string, error) {
	existing := func() (string, bool) {
		s.mu.Lock()
		defer s.mu.Unlock()
		fake, ok := s.sessionLocked(session, true).forward[identity]
		return fake, ok
	}
	// The request may already contain an existing fake, for example in
	// history that a client kept unrestored. It still denotes the same value.
	if fake, ok := existing(); ok {
		return fake, nil
	}
	for attempt := range 256 {
		fake, err := generate(attempt)
		if err != nil {
			return "", fmt.Errorf("replacement generation failed")
		}
		// Search the request outside the store lock; it can be large.
		if fake == "" || fake == original || occupied.contains(fake) {
			continue
		}
		s.mu.Lock()
		m := s.sessionLocked(session, true)
		if current, ok := m.forward[identity]; ok {
			s.mu.Unlock()
			return current, nil
		}
		if len(m.forward) >= s.opts.MaxEntriesPerSession {
			s.mu.Unlock()
			return "", fmt.Errorf("mapping entry capacity reached")
		}
		_, isTextOriginal := m.forward[fake]
		_, isNumberOriginal := m.forward[numberMappingIdentity(fake)]
		_, exists := m.reverse[fake]
		if !isTextOriginal && !isNumberOriginal && !exists {
			m.forward[identity] = fake
			m.reverse[fake] = original
			if numeric {
				m.numeric[fake] = true
			}
			m.restore = nil
			s.mu.Unlock()
			return fake, nil
		}
		s.mu.Unlock()
	}
	return "", fmt.Errorf("could not allocate collision-free replacement")
}

// occupiedSet holds every string of one request. A new fake must not occur
// inside any of them, or restoration could not tell the fake from content
// that the request already carried.
type occupiedSet struct {
	values map[string]struct{}
	mu     sync.Mutex
	corpus []byte
	index  *suffixarray.Index
	checks int
}

func newOccupiedSet(values map[string]struct{}) *occupiedSet {
	return &occupiedSet{values: values}
}

func (o *occupiedSet) contains(candidate string) bool {
	if o == nil || len(o.values) == 0 {
		return false
	}
	if _, ok := o.values[candidate]; ok {
		return true
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.corpus == nil {
		size := 0
		for value := range o.values {
			size += len(value) + 1
		}
		o.corpus = make([]byte, 0, size)
		for value := range o.values {
			o.corpus = append(append(o.corpus, value...), 0)
		}
	}
	// A linear search of even a large request takes microseconds. Index it
	// only when it needs enough searches that one index build costs less,
	// so allocating thousands of fakes stays linear.
	o.checks++
	if o.index == nil && o.checks*len(o.corpus) > 256<<20 {
		o.index = suffixarray.New(o.corpus)
	}
	if o.index != nil {
		return len(o.index.Lookup([]byte(candidate), 1)) > 0
	}
	return bytes.Contains(o.corpus, []byte(candidate))
}

func (s *Store) PlaceholderFor(value string) string {
	fake, err := s.PlaceholderForSession(defaultSessionID, value, nil)
	if err != nil {
		return placeholderOpen + s.hashValue(value, 0) + placeholderClose
	}
	return fake
}

func (s *Store) PlaceholderForSession(session, value string, occupied *occupiedSet) (string, error) {
	return s.Map(session, value, occupied, func(attempt int) (string, error) {
		return placeholderOpen + s.hashValue(value, attempt) + placeholderClose, nil
	})
}

// Lookup preserves the original placeholder-hash API.
func (s *Store) Lookup(hash string) (string, bool) {
	return s.LookupFake(defaultSessionID, placeholderOpen+hash+placeholderClose)
}

func (s *Store) LookupFake(session, fake string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	m := s.sessions[normalizeSession(session)]
	if m == nil {
		return "", false
	}
	v, ok := m.reverse[fake]
	return v, ok
}

func (s *Store) ReverseMappings(session string) map[string]string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := map[string]string{}
	if m := s.sessions[normalizeSession(session)]; m != nil {
		for k, v := range m.reverse {
			out[k] = v
		}
	}
	return out
}

func (s *Store) MaxFakeLen(session string) int {
	snapshot := s.restorationSnapshot(session)
	if snapshot == nil {
		return 0
	}
	return snapshot.maxFakeLen
}

func (s *Store) restorationSnapshot(session string) *restorationSnapshot {
	id := normalizeSession(session)
	s.mu.RLock()
	m := s.sessions[id]
	if m == nil || len(m.reverse) == 0 {
		s.mu.RUnlock()
		return nil
	}
	// Restoring a response keeps its session alive for the whole stream.
	m.touch(s.opts.Now())
	if m.restore != nil {
		snapshot := m.restore
		s.mu.RUnlock()
		return snapshot
	}
	s.mu.RUnlock()

	s.mu.Lock()
	defer s.mu.Unlock()
	m = s.sessions[id]
	if m == nil || len(m.reverse) == 0 {
		return nil
	}
	if m.restore != nil {
		return m.restore
	}

	keys := sortedFakeKeys(m.reverse)
	literals := make([]string, 0, len(keys))
	originals := make([]string, 0, len(keys))
	var bounded []bool
	numbers := make(map[string]string, len(m.numeric))
	maxFakeLen := 0
	for _, fake := range keys {
		original := m.reverse[fake]
		if m.numeric[fake] {
			numbers[fake] = original
		}
		// A fake that a response or URL percent-encoded, such as a
		// placeholder in a query string, restores to the encoded original.
		for _, encoding := range []string{"", "query", "path"} {
			literal := encodeKnownValue(encoding, fake)
			if encoding != "" && literal == fake {
				continue
			}
			literals = append(literals, literal)
			originals = append(originals, encodeKnownValue(encoding, original))
			bounded = append(bounded, ambiguousFake(fake))
			maxFakeLen = max(maxFakeLen, len(literal))
		}
	}
	m.restore = &restorationSnapshot{
		matcher:   newLiteralMatcher(literals, func(i int) bool { return bounded[i] }),
		originals: originals, numbers: numbers, maxFakeLen: maxFakeLen,
	}
	return m.restore
}

// ambiguousFake reports whether a fake could also be part of other text: a
// short alias such as host-k3x9q2, or a number or address, which is a
// different value inside a longer one. Those are restored only as whole
// words; longer fakes are restored wherever they appear.
func ambiguousFake(fake string) bool {
	if len(fake) < 12 || net.ParseIP(fake) != nil {
		return true
	}
	for i := 0; i < len(fake); i++ {
		if c := fake[i]; (c < '0' || c > '9') && c != '.' && c != '-' {
			return false
		}
	}
	return true
}

func (s *Store) SessionStats() (sessions, entries int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupLocked(s.opts.Now())
	for _, m := range s.sessions {
		entries += len(m.forward)
	}
	return len(s.sessions), entries
}

// HasSession reports whether session currently holds mappings.
func (s *Store) HasSession(session string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupLocked(s.opts.Now())
	return s.sessions[normalizeSession(session)] != nil
}

func (s *Store) DeleteSession(session string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, normalizeSession(session))
}

func (s *Store) hashValue(value string, attempt int) string {
	sum := keyedDigest(s.key[:], "placeholder", value, attempt)
	return hex.EncodeToString(sum[:])[:placeholderHashLen]
}

func sortedFakeKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return len(keys[i]) > len(keys[j]) })
	return keys
}
