// Package secretsfile reads secrets from an env-style file that an external
// agent (for example the Infisical agent) keeps up to date, and follows
// changes of that file without a restart.
//
// Nothing in this package logs or returns a secret value: errors name the
// line, logs name the keys.
package secretsfile

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// maxFileBytes bounds how much of the file is read. A file of bearer tokens
// is a few kilobytes; anything far beyond that is a mistake.
const maxFileBytes = 1 << 20

// Parse reads the agent format: KEY='value', KEY="value" or KEY=value, one
// per line. Empty lines and lines starting with '#' are skipped, CRLF line
// ends are accepted, an optional leading "export " is ignored and of a key
// that occurs twice the last one wins. Quoted values are taken literally,
// without escape sequences. An error names the line number, never its
// content.
func Parse(data []byte) (map[string]string, error) {
	values := map[string]string{}
	data = bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF})
	for index, raw := range strings.Split(string(data), "\n") {
		number := index + 1
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
		key, value, found := strings.Cut(line, "=")
		if !found {
			return nil, fmt.Errorf("line %d: no '=' found", number)
		}
		key = strings.TrimSpace(key)
		if !validKey(key) {
			return nil, fmt.Errorf("line %d: the name before '=' may only contain letters, digits and '_' and must not start with a digit", number)
		}
		value = strings.TrimSpace(value)
		if len(value) > 0 && (value[0] == '\'' || value[0] == '"') {
			quote := value[0]
			if len(value) < 2 || value[len(value)-1] != quote {
				return nil, fmt.Errorf("line %d: quoted value is not closed", number)
			}
			value = value[1 : len(value)-1]
		}
		values[key] = value
	}
	return values, nil
}

func validKey(key string) bool {
	if key == "" {
		return false
	}
	for i := 0; i < len(key); i++ {
		c := key[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c == '_':
		case c >= '0' && c <= '9':
			if i == 0 {
				return false
			}
		default:
			return false
		}
	}
	return true
}

type state struct {
	values   map[string]string
	loadedAt time.Time
}

// Store holds the parsed content of one secrets file. Lookups never block
// on a reload.
type Store struct {
	path string

	current atomic.Pointer[state]

	// mu serialises reloads; everything below is only used under it.
	mu        sync.Mutex
	applied   [sha256.Size]byte
	hasData   bool
	candidate [sha256.Size]byte
	pending   bool
	lastError string
}

// Open reads the file once and returns the store. A file that is missing or
// broken at this point is not fatal: the store starts empty, logs the cause
// and picks the file up as soon as Poll sees a valid one, so the gateway
// does not depend on the agent having written the file first.
func Open(path string) *Store {
	s := &Store{path: path}
	s.current.Store(&state{values: map[string]string{}})
	s.reload(true)
	return s
}

// Path returns the file the store reads.
func (s *Store) Path() string { return s.path }

// Lookup returns the value of key. A key with an empty value counts as
// missing.
func (s *Store) Lookup(key string) (string, bool) {
	if s == nil || key == "" {
		return "", false
	}
	value := s.current.Load().values[key]
	return value, value != ""
}

// Len returns the number of keys currently loaded.
func (s *Store) Len() int {
	if s == nil {
		return 0
	}
	return len(s.current.Load().values)
}

// LoadedAt returns when the current content was taken over, the zero time
// if no valid file has been read yet.
func (s *Store) LoadedAt() time.Time {
	if s == nil {
		return time.Time{}
	}
	return s.current.Load().loadedAt
}

// Poll checks the file for changes right now. Changes are compared by
// content hash, so a rewrite within the same second or with the same size
// is noticed.
//
// A changed content is only taken over once two polls in a row read the
// same bytes. The agent rewrites the file in place, and a poll can fall
// into the middle of that; without the second look a half written file
// would be taken over as a file from which keys were removed.
func (s *Store) Poll() { s.reload(false) }

// Reload takes the current file content over immediately, without waiting
// for a second identical read.
func (s *Store) Reload() { s.reload(true) }

// Watch polls the file every interval until ctx is done.
func (s *Store) Watch(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.Poll()
		}
	}
}

func (s *Store) reload(immediate bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := readLimited(s.path)
	if err != nil {
		s.pending = false
		s.fail(describeReadError(err))
		return
	}
	sum := sha256.Sum256(data)
	if s.hasData && sum == s.applied {
		s.pending = false
		s.lastError = ""
		return
	}
	if !immediate && !(s.pending && sum == s.candidate) {
		s.candidate = sum
		s.pending = true
		return
	}
	s.pending = false

	values, err := Parse(data)
	if err != nil {
		s.fail("cannot parse: " + err.Error())
		return
	}
	previous := s.current.Load().values
	s.current.Store(&state{values: values, loadedAt: time.Now()})
	s.applied = sum
	s.hasData = true
	s.lastError = ""
	log.Printf("secrets file loaded path=%s keys=%d changed=%s", s.path, len(values), strings.Join(changedKeys(previous, values), ","))
}

// fail keeps the current values and logs each kind of failure once, until
// the file is fine again or fails differently.
func (s *Store) fail(message string) {
	if message == s.lastError {
		return
	}
	s.lastError = message
	log.Printf("secrets file not loaded, keeping the last good state path=%s keys=%d reason=%s", s.path, len(s.current.Load().values), message)
}

func describeReadError(err error) string {
	switch {
	case errors.Is(err, os.ErrNotExist):
		return "file does not exist"
	case errors.Is(err, os.ErrPermission):
		return "permission denied"
	case errors.Is(err, errTooLarge):
		return errTooLarge.Error()
	}
	return "cannot read file"
}

var errTooLarge = errors.New("file is larger than 1 MiB")

func readLimited(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxFileBytes {
		return nil, errTooLarge
	}
	return data, nil
}

// changedKeys lists the names of keys that were added, removed or got
// another value.
func changedKeys(previous, next map[string]string) []string {
	changed := []string{}
	for key, value := range next {
		if old, ok := previous[key]; !ok || old != value {
			changed = append(changed, key)
		}
	}
	for key := range previous {
		if _, ok := next[key]; !ok {
			changed = append(changed, key)
		}
	}
	sort.Strings(changed)
	return changed
}
