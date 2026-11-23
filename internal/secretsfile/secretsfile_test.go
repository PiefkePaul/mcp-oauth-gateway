package secretsfile

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestParseAgentFormat(t *testing.T) {
	input := "\n# written by the agent\r\n" +
		"WHATSAPP='abc=def=='\r\n" +
		"GERMAN_LEGAL_MCP=\"with space\"\n" +
		"PLAIN=value#not-a-comment\n" +
		"export EXPORTED=x\n" +
		"  SPACED = y  \n" +
		"EMPTY=\n" +
		"QUOTE_INSIDE='it's'\n" +
		"DOUBLE=first\nDOUBLE=second\n"
	values, err := Parse([]byte(input))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	want := map[string]string{
		"WHATSAPP":         "abc=def==",
		"GERMAN_LEGAL_MCP": "with space",
		"PLAIN":            "value#not-a-comment",
		"EXPORTED":         "x",
		"SPACED":           "y",
		"EMPTY":            "",
		"QUOTE_INSIDE":     "it's",
		"DOUBLE":           "second",
	}
	if len(values) != len(want) {
		t.Fatalf("got %d keys, want %d", len(values), len(want))
	}
	for key, value := range want {
		if values[key] != value {
			t.Errorf("%s: got %q, want %q", key, values[key], value)
		}
	}
}

func TestParseEmptyAndBOM(t *testing.T) {
	if values, err := Parse(nil); err != nil || len(values) != 0 {
		t.Fatalf("empty file: %v %v", values, err)
	}
	values, err := Parse([]byte("\xEF\xBB\xBFA=1\n"))
	if err != nil || values["A"] != "1" {
		t.Fatalf("BOM: %v %v", values, err)
	}
}

func TestParseErrorsNameTheLineNotTheContent(t *testing.T) {
	const secret = "s3cr3t-value-0123456789"
	cases := []string{
		"OK=1\n" + secret + "\n",
		"OK=1\nBAD-KEY=" + secret + "\n",
		"OK=1\n1BAD=" + secret + "\n",
		"OK=1\nOPEN='" + secret + "\n",
		"OK=1\n=" + secret + "\n",
	}
	for _, input := range cases {
		_, err := Parse([]byte(input))
		if err == nil {
			t.Errorf("%q: expected an error", strings.ReplaceAll(input, secret, "…"))
			continue
		}
		if !strings.Contains(err.Error(), "line 2") {
			t.Errorf("error should name line 2: %v", err)
		}
		if strings.Contains(err.Error(), secret) {
			t.Errorf("error contains the value: %v", err)
		}
	}
}

// captureLog collects everything the package logs during the test.
func captureLog(t *testing.T) *lockedBuffer {
	t.Helper()
	buffer := &lockedBuffer{}
	previous := log.Writer()
	log.SetOutput(buffer)
	t.Cleanup(func() { log.SetOutput(previous) })
	return buffer
}

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func TestStoreNoticesChangeWithSameSizeAndTime(t *testing.T) {
	logs := captureLog(t)
	path := filepath.Join(t.TempDir(), "routes.env")
	writeFile(t, path, "A='value-one'\n")
	store := Open(path)
	if value, ok := store.Lookup("A"); !ok || value != "value-one" {
		t.Fatalf("initial load: %q %v", value, ok)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	// Same length, and the modification time is put back.
	writeFile(t, path, "A='value-two'\n")
	if err := os.Chtimes(path, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}

	store.Poll()
	if value, _ := store.Lookup("A"); value != "value-one" {
		t.Fatalf("a change must not be taken over on the first look, got %q", value)
	}
	store.Poll()
	if value, _ := store.Lookup("A"); value != "value-two" {
		t.Fatalf("expected the new value after the second identical read, got %q", value)
	}
	if out := logs.String(); strings.Contains(out, "value-one") || strings.Contains(out, "value-two") {
		t.Fatalf("log contains a value: %s", out)
	}
	if out := logs.String(); !strings.Contains(out, "changed=A") {
		t.Fatalf("log should name the changed key: %s", out)
	}
}

func TestStoreDoesNotTakeOverAFileCaughtMidWrite(t *testing.T) {
	captureLog(t)
	path := filepath.Join(t.TempDir(), "routes.env")
	writeFile(t, path, "A='1'\nB='2'\n")
	store := Open(path)

	// The agent truncates and rewrites in place; one poll sees half of it.
	writeFile(t, path, "A='1'\n")
	store.Poll()
	writeFile(t, path, "A='1'\nB='3'\n")
	store.Poll()
	if value, ok := store.Lookup("B"); !ok || value != "2" {
		t.Fatalf("B must survive the half written file, got %q %v", value, ok)
	}
	store.Poll()
	if value, _ := store.Lookup("B"); value != "3" {
		t.Fatalf("expected the finished file to be taken over, got %q", value)
	}
}

func TestStoreKeepsLastGoodStateOnBrokenOrMissingFile(t *testing.T) {
	logs := captureLog(t)
	path := filepath.Join(t.TempDir(), "routes.env")
	writeFile(t, path, "A='good'\n")
	store := Open(path)

	writeFile(t, path, "A='good'\nthis line is broken\n")
	store.Poll()
	store.Poll()
	store.Poll()
	if value, _ := store.Lookup("A"); value != "good" {
		t.Fatalf("broken file must keep the old state, got %q", value)
	}

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	store.Poll()
	store.Poll()
	if value, _ := store.Lookup("A"); value != "good" {
		t.Fatalf("missing file must keep the old state, got %q", value)
	}
	out := logs.String()
	if strings.Count(out, "file does not exist") != 1 {
		t.Fatalf("a missing file should be logged once: %s", out)
	}
	if strings.Contains(out, "this line is broken") || strings.Contains(out, "good") && strings.Contains(out, "A='good'") {
		t.Fatalf("log contains file content: %s", out)
	}

	writeFile(t, path, "A='back'\n")
	store.Poll()
	store.Poll()
	if value, _ := store.Lookup("A"); value != "back" {
		t.Fatalf("expected recovery, got %q", value)
	}
}

func TestStoreStartsEmptyWithoutFileAndPicksItUp(t *testing.T) {
	captureLog(t)
	path := filepath.Join(t.TempDir(), "routes.env")
	store := Open(path)
	if store.Len() != 0 || !store.LoadedAt().IsZero() {
		t.Fatalf("expected an empty store")
	}
	writeFile(t, path, "A='1'\nEMPTY=''\n")
	store.Reload()
	if value, ok := store.Lookup("A"); !ok || value != "1" {
		t.Fatalf("got %q %v", value, ok)
	}
	if _, ok := store.Lookup("EMPTY"); ok {
		t.Fatalf("an empty value counts as missing")
	}
	if store.LoadedAt().IsZero() {
		t.Fatalf("expected a load time")
	}
}

func TestStoreConcurrentLookupsDuringReload(t *testing.T) {
	captureLog(t)
	path := filepath.Join(t.TempDir(), "routes.env")
	writeFile(t, path, "A='1'\n")
	store := Open(path)

	done := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-done:
					return
				default:
					if _, ok := store.Lookup("A"); !ok {
						t.Error("A must always be there")
						return
					}
				}
			}
		}()
	}
	for i := 0; i < 200; i++ {
		writeFile(t, path, "A='"+strings.Repeat("x", i%7+1)+"'\n")
		store.Reload()
	}
	close(done)
	wg.Wait()
}
