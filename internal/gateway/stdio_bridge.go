package gateway

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/PiefkePaul/mcp-oauth-gateway/internal/auth"
	"github.com/PiefkePaul/mcp-oauth-gateway/internal/config"
)

const (
	stdioSessionHeader       = "Mcp-Session-Id"
	stdioRequestTimeout      = 5 * time.Minute
	maxStdioBridgeBodyBytes  = 16 << 20
	stdioSSEHeartbeat        = 25 * time.Second
	stdioWaitDelay           = 5 * time.Second
	jsonrpcInternalErrorCode = -32603
	jsonrpcInvalidErrorCode  = -32600
	jsonrpcMethodNotFound    = -32601
	stdioBridgeErrorPrefix   = "stdio bridge error: "
)

type stdioBridge struct {
	route          config.Route
	secretResolver stdioSecretResolver
	opts           stdioBridgeOptions

	mu       sync.Mutex
	sessions map[string]*stdioSession

	stop     chan struct{}
	stopOnce sync.Once
}

type stdioSecretResolver func(route config.Route) (map[string]string, error)

type stdioSession struct {
	id       string
	owner    string
	identity *auth.Identity
	route    config.Route

	// Guarded by stdioBridge.mu.
	active       int
	lastActivity time.Time

	cancel context.CancelFunc
	cmd    *exec.Cmd
	stdin  io.WriteCloser

	writeMu sync.Mutex
	mu      sync.Mutex
	pending map[string]chan stdioResponse
	done    chan struct{}

	stdoutWriter *io.PipeWriter
	stdoutDone   chan struct{}
}

type stdioResponse struct {
	payload []byte
	err     error
}

type rpcEnvelope struct {
	ID     json.RawMessage `json:"id,omitempty"`
	Method string          `json:"method,omitempty"`
}

func newStdioBridge(route config.Route, resolver stdioSecretResolver) (http.Handler, func() error, error) {
	bridge, err := newStdioBridgeWithOptions(route, resolver, stdioBridgeOptions{})
	if err != nil {
		return nil, nil, err
	}
	return bridge, bridge.Close, nil
}

func newStdioBridgeWithOptions(route config.Route, resolver stdioSecretResolver, opts stdioBridgeOptions) (*stdioBridge, error) {
	if route.Stdio == nil {
		return nil, fmt.Errorf("route %q stdio config is required", route.ID)
	}
	bridge := &stdioBridge{
		route:          route,
		secretResolver: resolver,
		opts:           opts.withDefaults(),
		sessions:       make(map[string]*stdioSession),
		stop:           make(chan struct{}),
	}
	go bridge.sweepLoop()
	return bridge, nil
}

func (b *stdioBridge) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != b.route.PublicMCPPath() {
		http.NotFound(w, r)
		return
	}

	switch r.Method {
	case http.MethodPost:
		b.handlePost(w, r)
	case http.MethodGet:
		b.handleSSE(w, r)
	case http.MethodDelete:
		b.handleDelete(w, r)
	default:
		w.Header().Set("Allow", "GET, POST, DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (b *stdioBridge) handlePost(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxStdioBridgeBodyBytes))
	if err != nil {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]any{
			"error":             "request_too_large",
			"error_description": err.Error(),
		})
		return
	}

	messages, batch, err := parseJSONRPCMessages(raw)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error":             "invalid_jsonrpc",
			"error_description": err.Error(),
		})
		return
	}

	hasInitialize := false
	for _, message := range messages {
		method, _ := jsonRPCMethod(message)
		if method == "initialize" {
			hasInitialize = true
			break
		}
	}

	session, err := b.acquireSession(r.Header.Get(stdioSessionHeader), auth.IdentityFromContext(r.Context()), hasInitialize)
	if err != nil {
		writeStdioSessionError(w, err)
		return
	}
	defer b.releaseSession(session)
	w.Header().Set(stdioSessionHeader, session.id)

	responses := make([]json.RawMessage, 0, len(messages))
	for _, message := range messages {
		id, hasID := jsonRPCID(message)
		if !hasID {
			if err := session.SendNotification(message); err != nil {
				log.Printf("stdio bridge notification failed route=%s session=%s err=%v", b.route.ID, session.id, err)
			}
			continue
		}

		ctx, cancel := context.WithTimeout(r.Context(), stdioRequestTimeout)
		payload, err := session.SendRequest(ctx, id, message)
		cancel()
		if err != nil {
			payload = buildJSONRPCError(id, jsonrpcInternalErrorCode, stdioBridgeErrorPrefix+err.Error())
		}
		responses = append(responses, payload)
	}

	if len(responses) == 0 {
		w.WriteHeader(http.StatusAccepted)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	if batch {
		_, _ = w.Write(mustMarshalRawArray(responses))
		return
	}
	_, _ = w.Write(responses[0])
}

func (b *stdioBridge) handleDelete(w http.ResponseWriter, r *http.Request) {
	sessionID := strings.TrimSpace(r.Header.Get(stdioSessionHeader))
	if sessionID == "" {
		w.WriteHeader(http.StatusAccepted)
		return
	}

	owner := stdioSessionOwner(r)
	b.mu.Lock()
	session := b.sessions[sessionID]
	if session != nil && session.owner == owner {
		delete(b.sessions, sessionID)
	} else {
		// Unknown or foreign session: answer identically so the response does
		// not reveal whether the session exists.
		session = nil
	}
	b.mu.Unlock()

	if session != nil {
		_ = session.Close()
	}
	w.WriteHeader(http.StatusAccepted)
}

func (b *stdioBridge) handleSSE(w http.ResponseWriter, r *http.Request) {
	// A stream for a session keeps that session alive and ends with it.
	var sessionDone <-chan struct{}
	if requestedID := strings.TrimSpace(r.Header.Get(stdioSessionHeader)); requestedID != "" {
		session, err := b.acquireSession(requestedID, auth.IdentityFromContext(r.Context()), false)
		if err != nil {
			writeStdioSessionError(w, err)
			return
		}
		defer b.releaseSession(session)
		sessionDone = session.done
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache, no-transform")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	flusher, _ := w.(http.Flusher)
	if flusher != nil {
		flusher.Flush()
	}

	ticker := time.NewTicker(stdioSSEHeartbeat)
	defer ticker.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-sessionDone:
			return
		case <-ticker.C:
			_, _ = io.WriteString(w, ": keepalive\n\n")
			if flusher != nil {
				flusher.Flush()
			}
		}
	}
}

// stdioSessionOwner returns the agent a session is bound to (user plus
// credential, see auth.Identity.OwnerKey). Requests without an identity map
// to "" and can only reach sessions created without one.
func stdioSessionOwner(r *http.Request) string {
	return auth.IdentityFromContext(r.Context()).OwnerKey()
}

// acquireSession returns the caller's session (or a new one for
// initialize) and marks it active until releaseSession. New sessions are
// subject to the per-agent and per-route limits.
func (b *stdioBridge) acquireSession(requestedID string, identity *auth.Identity, forceNew bool) (*stdioSession, error) {
	requestedID = strings.TrimSpace(requestedID)
	owner := identity.OwnerKey()

	b.mu.Lock()
	defer b.mu.Unlock()

	if requestedID != "" && !forceNew {
		session := b.sessions[requestedID]
		if session != nil && session.exited() {
			// Forget sessions whose process died so clients get a clean
			// "unknown session" and can re-initialize.
			delete(b.sessions, requestedID)
			session = nil
		}
		// A session owned by someone else is reported exactly like a missing
		// one so callers cannot probe for other users' session IDs.
		if session == nil || session.owner != owner {
			return nil, fmt.Errorf("%w %q", errStdioSessionUnknown, requestedID)
		}
		session.active++
		session.lastActivity = time.Now()
		return session, nil
	}

	// Only initialize may open a session. Anything else without a session ID
	// would otherwise start an uninitialized child process that is never
	// cleaned up.
	if requestedID == "" && !forceNew {
		return nil, fmt.Errorf("missing %s header; send initialize first", stdioSessionHeader)
	}

	if err := b.makeRoomLocked(owner); err != nil {
		return nil, err
	}

	sessionID, err := randomSessionID()
	if err != nil {
		return nil, err
	}
	session, err := newStdioSession(sessionID, b.route, b.secretResolver)
	if err != nil {
		return nil, err
	}
	session.owner = owner
	session.identity = identity
	session.active = 1
	session.lastActivity = time.Now()
	b.sessions[sessionID] = session
	return session, nil
}

func (b *stdioBridge) releaseSession(session *stdioSession) {
	b.mu.Lock()
	defer b.mu.Unlock()
	session.active--
	session.lastActivity = time.Now()
}

func (b *stdioBridge) Close() error {
	b.stopOnce.Do(func() { close(b.stop) })
	b.mu.Lock()
	sessions := make([]*stdioSession, 0, len(b.sessions))
	for _, session := range b.sessions {
		sessions = append(sessions, session)
	}
	b.sessions = make(map[string]*stdioSession)
	b.mu.Unlock()

	var closeErr error
	for _, session := range sessions {
		if err := session.Close(); err != nil && closeErr == nil {
			closeErr = err
		}
	}
	return closeErr
}

func newStdioSession(sessionID string, route config.Route, resolver stdioSecretResolver) (*stdioSession, error) {
	if route.Stdio == nil {
		return nil, fmt.Errorf("stdio config is required")
	}
	env := make(map[string]string, len(route.Stdio.Env)+len(route.Stdio.EnvSecretRefs))
	for key, value := range route.Stdio.Env {
		env[key] = value
	}
	if len(route.Stdio.EnvSecretRefs) != 0 {
		if resolver == nil {
			return nil, fmt.Errorf("stdio route has secret refs but no secret resolver")
		}
		secrets, err := resolver(route)
		if err != nil {
			return nil, err
		}
		for key, value := range secrets {
			env[key] = value
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, route.Stdio.Command, route.Stdio.Args...)
	if route.Stdio.WorkingDir != "" {
		cmd.Dir = route.Stdio.WorkingDir
	}
	cmd.Env = append(os.Environ(), envMapToList(env)...)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("create stdin pipe: %w", err)
	}
	// Stdout goes through an io.Pipe instead of cmd.StdoutPipe: Wait then
	// waits until everything the child wrote has been copied, so a response
	// written right before the child exits is not lost. WaitDelay bounds
	// that wait if a grandchild keeps the pipe open.
	stdout, stdoutWriter := io.Pipe()
	cmd.Stdout = stdoutWriter
	cmd.WaitDelay = stdioWaitDelay
	stderr, err := cmd.StderrPipe()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("create stderr pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		cancel()
		return nil, fmt.Errorf("start stdio command %q: %w", route.Stdio.Command, err)
	}

	session := &stdioSession{
		id:      sessionID,
		route:   route,
		cancel:  cancel,
		cmd:     cmd,
		stdin:   stdin,
		pending: make(map[string]chan stdioResponse),
		done:    make(chan struct{}),

		stdoutWriter: stdoutWriter,
		stdoutDone:   make(chan struct{}),
	}
	go session.readStdout(stdout)
	go session.readStderr(stderr)
	go session.wait()
	return session, nil
}

func (s *stdioSession) SendRequest(ctx context.Context, id string, payload []byte) ([]byte, error) {
	ch := make(chan stdioResponse, 1)
	s.mu.Lock()
	select {
	case <-s.done:
		s.mu.Unlock()
		return nil, errors.New("stdio process has exited")
	default:
	}
	s.pending[id] = ch
	s.mu.Unlock()

	if err := s.writeMessage(payload); err != nil {
		s.removePending(id)
		return nil, err
	}

	select {
	case response := <-ch:
		if response.err != nil {
			return nil, response.err
		}
		return response.payload, nil
	case <-ctx.Done():
		s.removePending(id)
		return nil, ctx.Err()
	case <-s.done:
		s.removePending(id)
		return nil, errors.New("stdio process has exited")
	}
}

func (s *stdioSession) SendNotification(payload []byte) error {
	select {
	case <-s.done:
		return errors.New("stdio process has exited")
	default:
	}
	return s.writeMessage(payload)
}

func (s *stdioSession) writeMessage(payload []byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	if _, err := s.stdin.Write(bytes.TrimSpace(payload)); err != nil {
		return err
	}
	if _, err := s.stdin.Write([]byte("\n")); err != nil {
		return err
	}
	return nil
}

func (s *stdioSession) readStdout(stdout io.Reader) {
	defer close(s.stdoutDone)
	reader := bufio.NewReader(stdout)
	for {
		line, err := reader.ReadBytes('\n')
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) != 0 {
			s.handleChildMessage(trimmed)
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				log.Printf("stdio bridge stdout failed route=%s session=%s err=%v", s.route.ID, s.id, err)
			}
			return
		}
	}
}

func (s *stdioSession) handleChildMessage(payload []byte) {
	id, hasID := jsonRPCID(payload)
	method, _ := jsonRPCMethod(payload)
	if hasID {
		ch := s.removePending(id)
		if ch != nil {
			ch <- stdioResponse{payload: append([]byte(nil), payload...)}
			return
		}
		if method != "" {
			_ = s.writeMessage(buildJSONRPCError(id, jsonrpcMethodNotFound, "gateway stdio bridge does not support reverse MCP requests"))
		}
		return
	}
	if method != "" {
		log.Printf("stdio bridge notification route=%s session=%s method=%s", s.route.ID, s.id, method)
	}
}

func (s *stdioSession) readStderr(stderr io.Reader) {
	scanner := bufio.NewScanner(stderr)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			log.Printf("stdio bridge stderr route=%s session=%s: %s", s.route.ID, s.id, line)
		}
	}
}

func (s *stdioSession) wait() {
	err := s.cmd.Wait()
	if err != nil {
		log.Printf("stdio bridge process exited route=%s session=%s err=%v", s.route.ID, s.id, err)
	}
	// Deliver every response the child wrote before failing pending calls.
	_ = s.stdoutWriter.Close()
	<-s.stdoutDone

	s.mu.Lock()
	pending := s.pending
	s.pending = make(map[string]chan stdioResponse)
	close(s.done)
	s.mu.Unlock()

	for _, ch := range pending {
		ch <- stdioResponse{err: errors.New("stdio process has exited")}
	}
}

func (s *stdioSession) Close() error {
	s.cancel()
	_ = s.stdin.Close()

	select {
	case <-s.done:
		return nil
	case <-time.After(5 * time.Second):
		if s.cmd.Process != nil {
			_ = s.cmd.Process.Kill()
		}
		<-s.done
		return nil
	}
}

func (s *stdioSession) exited() bool {
	select {
	case <-s.done:
		return true
	default:
		return false
	}
}

func (s *stdioSession) removePending(id string) chan stdioResponse {
	s.mu.Lock()
	defer s.mu.Unlock()
	ch := s.pending[id]
	delete(s.pending, id)
	return ch
}

func parseJSONRPCMessages(raw []byte) (messages []json.RawMessage, batch bool, err error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return nil, false, fmt.Errorf("empty body")
	}

	if raw[0] == '[' {
		var batchMessages []json.RawMessage
		if err := json.Unmarshal(raw, &batchMessages); err != nil {
			return nil, false, err
		}
		if len(batchMessages) == 0 {
			return nil, false, fmt.Errorf("batch must not be empty")
		}
		for _, message := range batchMessages {
			if err := validateJSONRPCMessage(message); err != nil {
				return nil, false, err
			}
		}
		return batchMessages, true, nil
	}

	if err := validateJSONRPCMessage(raw); err != nil {
		return nil, false, err
	}
	return []json.RawMessage{append([]byte(nil), raw...)}, false, nil
}

func validateJSONRPCMessage(raw []byte) error {
	var envelope rpcEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return err
	}
	if envelope.Method == "" && len(envelope.ID) == 0 {
		return fmt.Errorf("message must contain method or id")
	}
	return nil
}

func jsonRPCID(raw []byte) (string, bool) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return "", false
	}
	id, ok := fields["id"]
	if !ok {
		return "", false
	}
	return compactJSON(id), true
}

func jsonRPCMethod(raw []byte) (string, bool) {
	var envelope rpcEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil || envelope.Method == "" {
		return "", false
	}
	return envelope.Method, true
}

func compactJSON(raw []byte) string {
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err != nil {
		return string(bytes.TrimSpace(raw))
	}
	return buf.String()
}

func buildJSONRPCError(id string, code int, message string) []byte {
	idRaw := json.RawMessage(id)
	payload := struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Error   struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}{
		JSONRPC: "2.0",
		ID:      idRaw,
	}
	payload.Error.Code = code
	payload.Error.Message = message
	out, err := json.Marshal(payload)
	if err != nil {
		return []byte(fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"error":{"code":%d,"message":"internal bridge error"}}`, id, jsonrpcInternalErrorCode))
	}
	return out
}

func mustMarshalRawArray(messages []json.RawMessage) []byte {
	out, err := json.Marshal(messages)
	if err != nil {
		return []byte(`[]`)
	}
	return out
}

func envMapToList(values map[string]string) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	for key, value := range values {
		key = strings.TrimSpace(key)
		if key != "" {
			out = append(out, key+"="+value)
		}
	}
	return out
}

func randomSessionID() (string, error) {
	var raw [24]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate stdio session id: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}
