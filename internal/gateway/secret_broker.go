package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/PiefkePaul/mcp-oauth-gateway/internal/config"
)

// secretBroker hands a route's upstream bearer to an external broker that
// writes it into the secret manager. The gateway keeps no copy: the value
// comes back through the route secrets file like every other route's.
type secretBroker struct {
	url    string
	token  string
	client *http.Client
	delay  time.Duration
}

func newSecretBroker(cfg config.SecretBrokerConfig) *secretBroker {
	if !cfg.Enabled() {
		return nil
	}
	return &secretBroker{
		url:   cfg.URL,
		token: cfg.Token,
		delay: cfg.Delay,
		client: &http.Client{
			Timeout: cfg.Timeout,
			// A redirect would carry the value to another address.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

type secretBrokerRequest struct {
	RouteID string `json:"route_id"`
	Key     string `json:"key"`
	Value   string `json:"value"`
}

type secretBrokerResponse struct {
	OK     bool   `json:"ok"`
	Folder string `json:"folder"`
	Key    string `json:"key"`
	Error  string `json:"error"`
}

// errSecretBroker wraps every failure so the admin page can say that the
// value was not stored anywhere.
var errSecretBroker = errors.New("token broker")

// SetRouteSecret sends the value. It returns the secret manager folder the
// broker wrote it to. Error messages never contain the value.
func (b *secretBroker) SetRouteSecret(ctx context.Context, routeID, key, value string) (string, error) {
	body, err := json.Marshal(secretBrokerRequest{RouteID: routeID, Key: key, Value: value})
	if err != nil {
		return "", fmt.Errorf("%w: %v", errSecretBroker, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.url, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("%w: %v", errSecretBroker, err)
	}
	req.Header.Set("Authorization", "Bearer "+b.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := b.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("%w is not reachable: %s", errSecretBroker, redactURLError(err))
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<10))
	var parsed secretBrokerResponse
	_ = json.Unmarshal(raw, &parsed)
	if resp.StatusCode != http.StatusOK || !parsed.OK {
		reason := strings.TrimSpace(parsed.Error)
		if reason == "" {
			reason = http.StatusText(resp.StatusCode)
		}
		if len(reason) > 300 {
			reason = reason[:300]
		}
		return "", fmt.Errorf("%w refused the value (HTTP %d): %s", errSecretBroker, resp.StatusCode, reason)
	}
	return parsed.Folder, nil
}

// redactURLError keeps the reason of a transport error without repeating
// the request, which net/http includes in *url.Error.
func redactURLError(err error) string {
	var unwrapped interface{ Unwrap() error }
	if errors.As(err, &unwrapped) && unwrapped.Unwrap() != nil {
		return unwrapped.Unwrap().Error()
	}
	return err.Error()
}

// handOverUpstreamBearer sends a route's global upstream bearer to the
// token broker. It returns "" without doing anything when no broker is
// configured or the token is empty; the caller then stores the token as
// before. Otherwise the token is not stored by the gateway at all, and the
// notice says where it went. A failed hand-over is an error: falling back to
// the auth store would keep a value the admin expects in the secret manager.
func (s *Server) handOverUpstreamBearer(ctx context.Context, route config.Route, token string) (string, error) {
	if s.secretBroker == nil || token == "" {
		return "", nil
	}
	// Second line of defence next to normalizeUpstreamBearer: a "${...}"
	// value would be resolved by the secret manager to another secret.
	if strings.Contains(token, "${") {
		return "", fmt.Errorf("the Upstream Bearer was not saved anywhere: secret references (\"${\") are not accepted")
	}
	key := route.UpstreamBearerSecretKey()
	folder, err := s.secretBroker.SetRouteSecret(ctx, route.ID, key, token)
	if err != nil {
		log.Printf("secret broker: route=%s key=%s: %v", route.ID, key, err)
		return "", fmt.Errorf("the Upstream Bearer was not saved anywhere: %v", err)
	}
	log.Printf("secret broker: route=%s key=%s handed over (folder %s); the gateway stores no copy", route.ID, key, folder)
	where := "the secret manager"
	if folder != "" {
		where += " (" + folder + ")"
	}
	return fmt.Sprintf("Upstream Bearer handed to the token broker and saved in %s, not in the gateway; it is used once it is in the secrets file as %s (usually within %s)",
		where, key, s.secretBroker.delay.Round(time.Second)), nil
}

// joinErrors joins non-empty error texts for the admin redirect.
func joinErrors(texts ...string) string {
	var parts []string
	for _, text := range texts {
		if text = strings.TrimSpace(text); text != "" {
			parts = append(parts, text)
		}
	}
	return strings.Join(parts, "; ")
}
