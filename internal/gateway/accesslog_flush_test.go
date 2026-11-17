package gateway

import (
	"bufio"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestAccessLogResponseWriterIsFlusher(t *testing.T) {
	var w http.ResponseWriter = &accessLogResponseWriter{ResponseWriter: httptest.NewRecorder()}
	if _, ok := w.(http.Flusher); !ok {
		t.Fatal("accessLogResponseWriter must implement http.Flusher")
	}
	if err := http.NewResponseController(w).Flush(); err != nil {
		t.Fatalf("ResponseController flush: %v", err)
	}
}

// An SSE stream that stays open must deliver headers and the first event
// through the access log middleware and the reverse proxy right away.
func TestAccessLogMiddlewareStreamsSSEThroughReverseProxy(t *testing.T) {
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "event: message\ndata: hello\n\n")
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer upstream.Close()
	defer close(release)

	target, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	gateway := httptest.NewServer(accessLogMiddleware(httputil.NewSingleHostReverseProxy(target)))
	defer gateway.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(gateway.URL + "/mcp")
	if err != nil {
		t.Fatalf("headers did not arrive while the stream was open: %v", err)
	}
	defer resp.Body.Close()

	line, err := bufio.NewReader(resp.Body).ReadString('\n')
	if err != nil {
		t.Fatalf("first event did not arrive: %v", err)
	}
	if !strings.HasPrefix(line, "event: message") {
		t.Fatalf("unexpected first line %q", line)
	}
}
