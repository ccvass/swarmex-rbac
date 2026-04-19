package rbac

import (
	"os"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	yamlContent := `roles:
  - name: admin
    actions:
      - method: "*"
        path: "*"
  - name: viewer
    actions:
      - method: GET
        path: /services*
      - method: GET
        path: /tasks*
`
	f, err := os.CreateTemp("", "rbac-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.WriteString(yamlContent)
	f.Close()

	cfg, err := LoadConfig(f.Name())
	if err != nil {
		t.Fatalf("LoadConfig() error: %v", err)
	}
	if len(cfg.Roles) != 2 {
		t.Fatalf("expected 2 roles, got %d", len(cfg.Roles))
	}
	if cfg.Roles[0].Name != "admin" {
		t.Errorf("expected admin role, got %s", cfg.Roles[0].Name)
	}
	if len(cfg.Roles[1].Actions) != 2 {
		t.Errorf("expected 2 actions for viewer, got %d", len(cfg.Roles[1].Actions))
	}
}

func TestMatchAction(t *testing.T) {
	tests := []struct {
		action Action
		method string
		path   string
		want   bool
	}{
		{Action{"*", "*"}, "GET", "/anything", true},
		{Action{"GET", "/services*"}, "GET", "/services", true},
		{Action{"GET", "/services*"}, "GET", "/services/abc", true},
		{Action{"GET", "/services*"}, "POST", "/services", false},
		{Action{"GET", "/tasks"}, "GET", "/tasks", true},
		{Action{"GET", "/tasks"}, "GET", "/tasks/123", false},
	}
	for _, tt := range tests {
		got := matchAction(tt.action, tt.method, tt.path)
		if got != tt.want {
			t.Errorf("matchAction(%+v, %s, %s) = %v, want %v",
				tt.action, tt.method, tt.path, got, tt.want)
		}
	}
}
