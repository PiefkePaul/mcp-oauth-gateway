package gateway

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"strings"

	"github.com/PiefkePaul/mcp-oauth-gateway/internal/auth"
)

const (
	sessionBindingKeyLabel = "mcp-session-binding/v1"
	// 16 bytes of HMAC, base64url without padding.
	sessionBindingTagLength = 22
)

// sessionBinding binds every MCP session ID to the route and the agent
// (auth.Identity.OwnerKey) that created it. Clients only ever see
// "<upstream id>.<tag>"; a request whose tag does not match its own route
// and agent is answered with 404 and never reaches the upstream. This keeps
// sessions of different users and of different agents of the same user
// apart for every transport, including upstreams that cannot tell callers
// apart because they all share one upstream credential.
type sessionBinding struct {
	routeID string
	key     []byte
	next    http.Handler
}

func newSessionBinding(routeID string, key []byte, next http.Handler) *sessionBinding {
	return &sessionBinding{routeID: routeID, key: key, next: next}
}

func (b *sessionBinding) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	owner := auth.IdentityFromContext(r.Context()).OwnerKey()

	if external := strings.TrimSpace(r.Header.Get(stdioSessionHeader)); external != "" {
		inner, ok := b.unseal(owner, external)
		if !ok {
			writeSessionNotFound(w)
			return
		}
		r = r.Clone(r.Context())
		r.Header.Set(stdioSessionHeader, inner)
	}

	b.next.ServeHTTP(&sessionBindingResponseWriter{ResponseWriter: w, binding: b, owner: owner}, r)
}

func (b *sessionBinding) tag(owner, inner string) string {
	mac := hmac.New(sha256.New, b.key)
	mac.Write([]byte(b.routeID))
	mac.Write([]byte{0})
	mac.Write([]byte(owner))
	mac.Write([]byte{0})
	mac.Write([]byte(inner))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))[:sessionBindingTagLength]
}

func (b *sessionBinding) seal(owner, inner string) string {
	return inner + "." + b.tag(owner, inner)
}

func (b *sessionBinding) unseal(owner, external string) (string, bool) {
	dot := strings.LastIndexByte(external, '.')
	if dot <= 0 {
		return "", false
	}
	inner, tag := external[:dot], external[dot+1:]
	if !hmac.Equal([]byte(tag), []byte(b.tag(owner, inner))) {
		return "", false
	}
	return inner, true
}

// writeSessionNotFound answers like an MCP server that does not know the
// session: 404 tells spec-compliant clients to start a new session.
func writeSessionNotFound(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte(`{"jsonrpc":"2.0","error":{"code":-32001,"message":"Session not found"},"id":null}` + "\n"))
}

// sessionBindingResponseWriter seals the session ID the upstream assigns
// before the headers are sent.
type sessionBindingResponseWriter struct {
	http.ResponseWriter
	binding     *sessionBinding
	owner       string
	wroteHeader bool
}

func (w *sessionBindingResponseWriter) sealHeader() {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	header := w.ResponseWriter.Header()
	if inner := strings.TrimSpace(header.Get(stdioSessionHeader)); inner != "" {
		header.Set(stdioSessionHeader, w.binding.seal(w.owner, inner))
	}
}

func (w *sessionBindingResponseWriter) WriteHeader(status int) {
	// Informational responses do not carry the final headers.
	if status >= 200 {
		w.sealHeader()
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *sessionBindingResponseWriter) Write(p []byte) (int, error) {
	w.sealHeader()
	return w.ResponseWriter.Write(p)
}

func (w *sessionBindingResponseWriter) Flush() {
	w.sealHeader()
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (w *sessionBindingResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}
