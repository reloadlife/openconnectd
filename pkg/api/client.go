package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client talks to openconnectd over HTTP. This is the canonical Go client an
// orchestrator (or the built-in TUI) uses to drive the daemon.
type Client struct {
	baseURL    string
	token      string
	httpClient *http.Client
}

type Option func(*Client)

func WithToken(token string) Option { return func(c *Client) { c.token = token } }

func WithHTTPClient(hc *http.Client) Option { return func(c *Client) { c.httpClient = hc } }

func NewClient(baseURL string, opts ...Option) (*Client, error) {
	c := &Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
	for _, o := range opts {
		o(c)
	}
	if c.baseURL == "" {
		return nil, fmt.Errorf("openconnectd: empty base URL")
	}
	return c, nil
}

func (c *Client) Health(ctx context.Context) error {
	return c.do(ctx, http.MethodGet, "/healthz", nil, nil)
}

func (c *Client) Version(ctx context.Context) (*VersionInfo, error) {
	var out VersionInfo
	if err := c.do(ctx, http.MethodGet, "/v1/version", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// --- Instances ---

func (c *Client) ListInstances(ctx context.Context) ([]Instance, error) {
	var out []Instance
	if err := c.do(ctx, http.MethodGet, "/v1/instances", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Client) CreateInstance(ctx context.Context, req InstanceCreateRequest) (*Instance, error) {
	var out Instance
	if err := c.do(ctx, http.MethodPost, "/v1/instances", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) DeleteInstance(ctx context.Context, name string) error {
	return c.do(ctx, http.MethodDelete, "/v1/instances/"+esc(name), nil, nil)
}

// PatchInstance updates mutable fields (local_bind, public_endpoint, dns,
// routes, camouflage, enabled). ocserv is reloaded (SIGHUP) on success.
func (c *Client) PatchInstance(ctx context.Context, name string, body map[string]any) (*Instance, error) {
	var out Instance
	if err := c.do(ctx, http.MethodPatch, "/v1/instances/"+esc(name), body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// --- Clients (provisioned users) ---

func (c *Client) ListClients(ctx context.Context, instance string) ([]ClientPeer, error) {
	var out []ClientPeer
	if err := c.do(ctx, http.MethodGet, "/v1/instances/"+esc(instance)+"/clients", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Client) CreateClient(ctx context.Context, instance string, req ClientCreateRequest) (*ClientPeer, error) {
	if strings.TrimSpace(req.CommonName) == "" {
		return nil, fmt.Errorf("openconnectd: common_name required")
	}
	var out ClientPeer
	if err := c.do(ctx, http.MethodPost, "/v1/instances/"+esc(instance)+"/clients", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) DeleteClient(ctx context.Context, instance, commonName string) error {
	return c.do(ctx, http.MethodDelete, "/v1/instances/"+esc(instance)+"/clients/"+esc(commonName), nil, nil)
}

// PatchClient updates mutable client fields (static_ip, suspended, password).
func (c *Client) PatchClient(ctx context.Context, instance, commonName string, body map[string]any) (*ClientPeer, error) {
	if strings.TrimSpace(commonName) == "" {
		return nil, fmt.Errorf("openconnectd: common_name required")
	}
	var out ClientPeer
	path := "/v1/instances/" + esc(instance) + "/clients/" + esc(commonName)
	if err := c.do(ctx, http.MethodPatch, path, body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ClientConfig returns a ready-to-import connection profile for the user
// (an AnyConnect/OpenConnect XML profile plus the cert bundle, or a plain
// server+credentials descriptor for password auth).
func (c *Client) ClientConfig(ctx context.Context, instance, commonName string) (string, error) {
	path := "/v1/instances/" + esc(instance) + "/clients/" + esc(commonName) + "/client-config"
	return c.text(ctx, path)
}

// --- Sessions (live, from occtl) ---

// Sessions lists currently-connected users. When instance is "", all instances.
// This is the source of per-user monitoring (rx/tx, remote IP, DTLS state).
func (c *Client) Sessions(ctx context.Context, instance string) ([]Session, error) {
	path := "/v1/sessions"
	if instance != "" {
		path += "?instance=" + url.QueryEscape(instance)
	}
	var out []Session
	if err := c.do(ctx, http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// Disconnect kicks a live session by common name (occtl disconnect user).
func (c *Client) Disconnect(ctx context.Context, instance, commonName string) error {
	path := "/v1/instances/" + esc(instance) + "/sessions/" + esc(commonName)
	return c.do(ctx, http.MethodDelete, path, nil, nil)
}

// --- helpers ---

func esc(s string) string { return url.PathEscape(s) }

func (c *Client) text(ctx context.Context, path string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return "", err
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	res, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	data, _ := io.ReadAll(res.Body)
	if res.StatusCode >= 400 {
		return "", decodeErr(res.StatusCode, data)
	}
	return string(data), nil
}

func (c *Client) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	res, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	data, _ := io.ReadAll(res.Body)
	if res.StatusCode >= 400 {
		return decodeErr(res.StatusCode, data)
	}
	if out == nil || res.StatusCode == http.StatusNoContent || len(data) == 0 {
		return nil
	}
	return json.Unmarshal(data, out)
}

func decodeErr(status int, data []byte) error {
	var eb ErrorBody
	if json.Unmarshal(data, &eb) == nil && eb.Error.Message != "" {
		if eb.Error.Code != "" {
			return fmt.Errorf("openconnectd: %s: %s", eb.Error.Code, eb.Error.Message)
		}
		return fmt.Errorf("openconnectd: %s", eb.Error.Message)
	}
	return fmt.Errorf("openconnectd: HTTP %d: %s", status, strings.TrimSpace(string(data)))
}
