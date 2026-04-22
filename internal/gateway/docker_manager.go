package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/PiefkePaul/mcp-oauth-gateway/internal/config"
)

type dockerManager struct {
	cfg    config.DockerManagementConfig
	client *dockerClient
}

type dockerDeploymentSpec struct {
	RouteID       string
	DisplayName   string
	Image         string
	ContainerName string
	InternalPort  int
	Env           map[string]string
	Networks      []string
	RestartPolicy string
}

type dockerContainerState struct {
	Exists    bool
	ID        string
	Name      string
	Image     string
	State     string
	Status    string
	StartedAt string
}

type dockerClient struct {
	httpClient *http.Client
	baseURL    string
}

func newDockerManager(cfg config.DockerManagementConfig) (*dockerManager, error) {
	client, err := newDockerClient(cfg.Host)
	if err != nil {
		return nil, err
	}
	return &dockerManager{
		cfg:    cfg,
		client: client,
	}, nil
}

func newDockerClient(rawHost string) (*dockerClient, error) {
	rawHost = strings.TrimSpace(rawHost)
	if rawHost == "" {
		rawHost = "unix:///var/run/docker.sock"
	}

	parsed, err := url.Parse(rawHost)
	if err != nil {
		return nil, fmt.Errorf("invalid docker host: %w", err)
	}

	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		ResponseHeaderTimeout: 30 * time.Second,
	}
	baseURL := rawHost

	switch parsed.Scheme {
	case "unix":
		socketPath := parsed.Path
		if socketPath == "" {
			socketPath = parsed.Opaque
		}
		if socketPath == "" {
			return nil, fmt.Errorf("docker unix socket path is required")
		}
		transport.Proxy = nil
		transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, "unix", socketPath)
		}
		baseURL = "http://docker"
	case "tcp":
		baseURL = "http://" + parsed.Host
	case "http", "https":
		baseURL = strings.TrimRight(rawHost, "/")
	default:
		return nil, fmt.Errorf("unsupported docker host scheme %q", parsed.Scheme)
	}

	return &dockerClient{
		httpClient: &http.Client{Transport: transport, Timeout: 2 * time.Minute},
		baseURL:    strings.TrimRight(baseURL, "/"),
	}, nil
}

func (m *dockerManager) Ping(ctx context.Context) error {
	return m.client.ping(ctx)
}

func (m *dockerManager) CreateAndStart(ctx context.Context, spec dockerDeploymentSpec) error {
	if err := validateDockerDeploymentSpec(spec); err != nil {
		return err
	}
	if err := m.client.pullImage(ctx, spec.Image); err != nil {
		return err
	}
	if err := m.client.createContainer(ctx, spec); err != nil {
		return err
	}
	for _, network := range spec.Networks[1:] {
		if err := m.client.connectNetwork(ctx, network, spec.ContainerName); err != nil {
			return err
		}
	}
	return m.client.startContainer(ctx, spec.ContainerName)
}

func (m *dockerManager) Start(ctx context.Context, containerName string) error {
	return m.client.startContainer(ctx, containerName)
}

func (m *dockerManager) Stop(ctx context.Context, containerName string) error {
	return m.client.stopContainer(ctx, containerName)
}

func (m *dockerManager) Remove(ctx context.Context, containerName string) error {
	return m.client.removeContainer(ctx, containerName)
}

func (m *dockerManager) Inspect(ctx context.Context, containerName string) (dockerContainerState, error) {
	return m.client.inspectContainer(ctx, containerName)
}

func validateDockerDeploymentSpec(spec dockerDeploymentSpec) error {
	if strings.TrimSpace(spec.Image) == "" {
		return fmt.Errorf("image is required")
	}
	if strings.TrimSpace(spec.ContainerName) == "" {
		return fmt.Errorf("container name is required")
	}
	if spec.InternalPort <= 0 || spec.InternalPort > 65535 {
		return fmt.Errorf("internal port must be between 1 and 65535")
	}
	return nil
}

func (c *dockerClient) ping(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/_ping", nil)
	if err != nil {
		return err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("docker ping failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return dockerHTTPError(resp, "docker ping failed")
	}
	return nil
}

func (c *dockerClient) pullImage(ctx context.Context, image string) error {
	if exists, err := c.imageExists(ctx, image); err != nil {
		return err
	} else if exists {
		return nil
	}

	fromImage, tag := splitDockerImageTag(image)
	query := url.Values{}
	query.Set("fromImage", fromImage)
	if tag != "" {
		query.Set("tag", tag)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/images/create?"+query.Encode(), nil)
	if err != nil {
		return err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("pull image %q failed: %w", image, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return dockerHTTPError(resp, "pull image failed")
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

func (c *dockerClient) imageExists(ctx context.Context, image string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/images/"+url.PathEscape(image)+"/json", nil)
	if err != nil {
		return false, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("inspect image %q failed: %w", image, err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		_, _ = io.Copy(io.Discard, resp.Body)
		return true, nil
	case http.StatusNotFound:
		_, _ = io.Copy(io.Discard, resp.Body)
		return false, nil
	default:
		return false, dockerHTTPError(resp, "inspect image failed")
	}
}

func (c *dockerClient) createContainer(ctx context.Context, spec dockerDeploymentSpec) error {
	env := make([]string, 0, len(spec.Env))
	for key, value := range spec.Env {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		env = append(env, key+"="+value)
	}
	slices.Sort(env)

	exposedPort := strconv.Itoa(spec.InternalPort) + "/tcp"
	networkMode := ""
	if len(spec.Networks) != 0 {
		networkMode = spec.Networks[0]
	}
	restartPolicy := strings.TrimSpace(spec.RestartPolicy)
	if restartPolicy == "" {
		restartPolicy = "unless-stopped"
	}

	payload := map[string]any{
		"Image": spec.Image,
		"Env":   env,
		"Labels": map[string]string{
			"mcp-oauth-gateway.managed":  "true",
			"mcp-oauth-gateway.route_id": spec.RouteID,
		},
		"ExposedPorts": map[string]any{
			exposedPort: map[string]any{},
		},
		"HostConfig": map[string]any{
			"RestartPolicy": map[string]string{"Name": restartPolicy},
		},
	}
	if networkMode != "" {
		payload["HostConfig"].(map[string]any)["NetworkMode"] = networkMode
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	endpoint := c.baseURL + "/containers/create?name=" + url.QueryEscape(spec.ContainerName)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("create container %q failed: %w", spec.ContainerName, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return dockerHTTPError(resp, "create container failed")
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

func (c *dockerClient) connectNetwork(ctx context.Context, networkName, containerName string) error {
	payload := map[string]string{"Container": containerName}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/networks/"+path.Clean(networkName)+"/connect", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("connect container %q to network %q failed: %w", containerName, networkName, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return dockerHTTPError(resp, "connect network failed")
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

func (c *dockerClient) startContainer(ctx context.Context, containerName string) error {
	return c.containerAction(ctx, containerName, "start")
}

func (c *dockerClient) stopContainer(ctx context.Context, containerName string) error {
	return c.containerAction(ctx, containerName, "stop")
}

func (c *dockerClient) removeContainer(ctx context.Context, containerName string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.baseURL+"/containers/"+url.PathEscape(containerName)+"?force=true", nil)
	if err != nil {
		return err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("remove container %q failed: %w", containerName, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return dockerHTTPError(resp, "remove container failed")
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

func (c *dockerClient) containerAction(ctx context.Context, containerName, action string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/containers/"+url.PathEscape(containerName)+"/"+action, nil)
	if err != nil {
		return err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("%s container %q failed: %w", action, containerName, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return dockerHTTPError(resp, action+" container failed")
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

func (c *dockerClient) inspectContainer(ctx context.Context, containerName string) (dockerContainerState, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/containers/"+url.PathEscape(containerName)+"/json", nil)
	if err != nil {
		return dockerContainerState{}, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return dockerContainerState{}, fmt.Errorf("inspect container %q failed: %w", containerName, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return dockerContainerState{Exists: false, Name: containerName}, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return dockerContainerState{}, dockerHTTPError(resp, "inspect container failed")
	}

	var payload struct {
		ID     string `json:"Id"`
		Name   string `json:"Name"`
		Config struct {
			Image string `json:"Image"`
		} `json:"Config"`
		State struct {
			Status    string `json:"Status"`
			Running   bool   `json:"Running"`
			StartedAt string `json:"StartedAt"`
		} `json:"State"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return dockerContainerState{}, fmt.Errorf("decode inspect response: %w", err)
	}
	state := payload.State.Status
	if state == "" && payload.State.Running {
		state = "running"
	}
	return dockerContainerState{
		Exists:    true,
		ID:        payload.ID,
		Name:      strings.TrimPrefix(payload.Name, "/"),
		Image:     payload.Config.Image,
		State:     state,
		Status:    state,
		StartedAt: payload.State.StartedAt,
	}, nil
}

func dockerHTTPError(resp *http.Response, fallback string) error {
	payload, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<10))
	message := strings.TrimSpace(string(payload))
	if message == "" {
		message = fallback
	}
	return fmt.Errorf("%s: docker returned %s", message, resp.Status)
}

func splitDockerImageTag(image string) (string, string) {
	image = strings.TrimSpace(image)
	if strings.Contains(image, "@") {
		return image, ""
	}
	lastSlash := strings.LastIndex(image, "/")
	lastColon := strings.LastIndex(image, ":")
	if lastColon > lastSlash {
		return image[:lastColon], image[lastColon+1:]
	}
	return image, "latest"
}
