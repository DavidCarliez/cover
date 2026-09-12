package redact

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
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
}

type sessionMappings struct {
	forward map[string]string
	reverse map[string]string
	updated time.Time
	restore *restorationSnapshot
}

// restorationSnapshot is immutable after construction, so callers can use it
// without holding Store.mu. A session invalidates its snapshot whenever a new
// mapping is added.
type restorationSnapshot struct {
	replacer     *strings.Replacer
	jsonReplacer *strings.Replacer
	fakes        [][]byte
	maxFakeLen   int
}

func (s *restorationSnapshot) restoreBytes(data []byte) ([]byte, bool) {
	input := string(data)
	restored := s.replacer.Replace(input)
	if restored == input {
		return data, false
	}
	return []byte(restored), true
}

func (s *restorationSnapshot) restoreString(value string) (string, bool) {
	restored := s.replacer.Replace(value)
	return restored, restored != value
}

// Store owns bounded, in-memory-only, bijective mappings separated by session.
type Store struct {
	mu       sync.RWMutex
	sessions map[string]*sessionMappings
	opts     StoreOptions
	key      [32]byte
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
	return &Store{sessions: make(map[string]*sessionMappings), opts: opts, key: opts.PseudonymKey}
}

func normalizeSession(session string) string {
	if session == "" {
		return defaultSessionID
	}
	return session
}

func (s *Store) cleanupLocked(now time.Time) {
	for id, m := range s.sessions {
		if now.Sub(m.updated) > s.opts.SessionTTL {
			delete(s.sessions, id)
		}
	}
}

func (s *Store) sessionLocked(id string, create bool) (*sessionMappings, error) {
	id = normalizeSession(id)
	now := s.opts.Now()
	s.cleanupLocked(now)
	if m, ok := s.sessions[id]; ok {
		m.updated = now
		return m, nil
	}
	if !create {
		return nil, nil
	}
	if len(s.sessions) >= s.opts.MaxSessions {
		return nil, fmt.Errorf("mapping session capacity reached")
	}
	m := &sessionMappings{forward: map[string]string{}, reverse: map[string]string{}, updated: now}
	s.sessions[id] = m
	return m, nil
}

// Map returns a stable reversible fake. generate receives a collision retry number.
func (s *Store) Map(session, original string, occupied map[string]struct{}, generate func(int) (string, error)) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := s.sessionLocked(session, true)
	if err != nil {
		return "", err
	}
	if fake, ok := m.forward[original]; ok {
		if collidesWithOccupied(fake, occupied) {
			return "", fmt.Errorf("existing replacement collides with request context")
		}
		return fake, nil
	}
	if len(m.forward) >= s.opts.MaxEntriesPerSession {
		return "", fmt.Errorf("mapping entry capacity reached")
	}
	for attempt := 0; attempt < 256; attempt++ {
		fake, err := generate(attempt)
		if err != nil {
			return "", fmt.Errorf("replacement generation failed")
		}
		if fake == "" || fake == original {
			continue
		}
		if collidesWithOccupied(fake, occupied) {
			continue
		}
		if _, isOriginal := m.forward[fake]; isOriginal {
			continue
		}
		if other, exists := m.reverse[fake]; exists && other != original {
			continue
		}
		m.forward[original] = fake
		m.reverse[fake] = original
		m.restore = nil
		return fake, nil
	}
	return "", fmt.Errorf("could not allocate collision-free replacement")
}

func collidesWithOccupied(candidate string, occupied map[string]struct{}) bool {
	for value := range occupied {
		if value == candidate || strings.Contains(value, candidate) {
			return true
		}
	}
	return false
}

func (s *Store) PlaceholderFor(value string) string {
	fake, err := s.PlaceholderForSession(defaultSessionID, value, nil)
	if err != nil {
		return placeholderOpen + s.hashValue(value, 0) + placeholderClose
	}
	return fake
}

func (s *Store) PlaceholderForSession(session, value string, occupied map[string]struct{}) (string, error) {
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
	pairs := make([]string, 0, len(keys)*2)
	jsonPairs := make([]string, 0, len(keys)*2)
	fakes := make([][]byte, 0, len(keys))
	maxFakeLen := 0
	for _, fake := range keys {
		pairs = append(pairs, fake, m.reverse[fake])
		encoded, _ := json.Marshal(m.reverse[fake])
		jsonPairs = append(jsonPairs, fake, string(encoded[1:len(encoded)-1]))
		fakes = append(fakes, []byte(fake))
		if len(fake) > maxFakeLen {
			maxFakeLen = len(fake)
		}
	}
	m.restore = &restorationSnapshot{
		replacer: strings.NewReplacer(pairs...), fakes: fakes, maxFakeLen: maxFakeLen,
		jsonReplacer: strings.NewReplacer(jsonPairs...),
	}
	return m.restore
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
