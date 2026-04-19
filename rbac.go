package rbac

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type Role struct {
	Namespaces []string `yaml:"namespaces"`
	Actions    []string `yaml:"actions"`
	Deny       []string `yaml:"deny"`
}

type Config struct {
	Roles map[string]Role `yaml:"roles"`
	Users map[string]string `yaml:"users"` // user -> role
}

type Proxy struct {
	config Config
	logger *slog.Logger
	socket string
}

func New(configPath, socket string, logger *slog.Logger) (*Proxy, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return &Proxy{config: Config{Roles: map[string]Role{"admin": {Actions: []string{"*"}}}, Users: map[string]string{"admin": "admin"}}, logger: logger, socket: socket}, nil
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &Proxy{config: cfg, logger: logger, socket: socket}, nil
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	user := p.extractUser(r)

	roleName, ok := p.config.Users[user]
	if !ok {
		roleName = "anonymous"
	}

	role, ok := p.config.Roles[roleName]
	if !ok {
		http.Error(w, "forbidden: unknown role", http.StatusForbidden)
		p.logger.Warn("access denied", "user", user, "role", roleName, "path", r.URL.Path)
		return
	}

	action := methodToAction(r.Method, r.URL.Path)
	if !isAllowed(role, action) {
		http.Error(w, "forbidden: action not allowed", http.StatusForbidden)
		p.logger.Warn("access denied", "user", user, "role", roleName, "action", action, "path", r.URL.Path)
		return
	}

	p.logger.Info("access granted", "user", user, "role", roleName, "action", action)
	p.proxyToSocket(w, r)
}

func (p *Proxy) proxyToSocket(w http.ResponseWriter, r *http.Request) {
	// Create a new request to the Unix socket
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return net.Dial("unix", p.socket)
		},
	}
	client := &http.Client{Transport: transport}

	url := "http://localhost" + r.URL.RequestURI()
	proxyReq, err := http.NewRequestWithContext(r.Context(), r.Method, url, r.Body)
	if err != nil {
		http.Error(w, "proxy error", http.StatusBadGateway)
		return
	}
	proxyReq.Header = r.Header

	resp, err := client.Do(proxyReq)
	if err != nil {
		http.Error(w, "socket error: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for k, v := range resp.Header {
		w.Header()[k] = v
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func methodToAction(method, path string) string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	// /v1.45/services/xxx -> service.inspect
	if len(parts) >= 2 {
		resource := strings.TrimSuffix(parts[len(parts)-1], "s")
		if len(parts) >= 3 {
			resource = strings.TrimSuffix(parts[1], "s")
		}
		switch method {
		case "GET":
			return resource + ".inspect"
		case "POST":
			return resource + ".create"
		case "PUT", "PATCH":
			return resource + ".update"
		case "DELETE":
			return resource + ".rm"
		}
	}
	return "unknown"
}

func isAllowed(role Role, action string) bool {
	for _, d := range role.Deny {
		if matchAction(d, action) {
			return false
		}
	}
	for _, a := range role.Actions {
		if matchAction(a, action) {
			return true
		}
	}
	return false
}

func matchAction(pattern, action string) bool {
	if pattern == "*" {
		return true
	}
	if strings.HasSuffix(pattern, ".*") {
		return strings.HasPrefix(action, strings.TrimSuffix(pattern, ".*"))
	}
	return pattern == action
}

// extractUser gets username from JWT Bearer token (Authentik) or X-Swarmex-User header.
func (p *Proxy) extractUser(r *http.Request) string {
	// Try JWT from Authorization header
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		token := strings.TrimPrefix(auth, "Bearer ")
		if user := p.parseJWTUser(token); user != "" {
			return user
		}
	}
	// Try Authentik forward-auth headers (set by Traefik)
	if user := r.Header.Get("X-Authentik-Username"); user != "" {
		return user
	}
	// Fallback to manual header
	if user := r.Header.Get("X-Swarmex-User"); user != "" {
		return user
	}
	return "anonymous"
}

// parseJWTUser extracts preferred_username from JWT payload without signature verification.
// In production, verify signature against Authentik JWKS endpoint.
func (p *Proxy) parseJWTUser(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ""
	}
	// Decode payload (base64url)
	payload := parts[1]
	// Add padding
	switch len(payload) % 4 {
	case 2:
		payload += "=="
	case 3:
		payload += "="
	}
	decoded, err := base64Decode(payload)
	if err != nil {
		return ""
	}
	// Extract preferred_username from JSON
	var claims map[string]any
	if err := json.Unmarshal(decoded, &claims); err != nil {
		return ""
	}
	if u, ok := claims["preferred_username"].(string); ok {
		return u
	}
	if u, ok := claims["sub"].(string); ok {
		return u
	}
	return ""
}

func base64Decode(s string) ([]byte, error) {
	s = strings.ReplaceAll(s, "-", "+")
	s = strings.ReplaceAll(s, "_", "/")
	return base64.StdEncoding.DecodeString(s)
}
