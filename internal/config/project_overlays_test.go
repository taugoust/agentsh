package config

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func loadProjectOverlayTestConfig(data []byte) (*Config, error) {
	var cfg Config
	cfg.Sandbox.Ptrace = DefaultPtraceConfig()
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	applyDefaults(&cfg)
	if err := validateConfig(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func TestProjectOverlaysDefaults(t *testing.T) {
	cfg, err := loadProjectOverlayTestConfig([]byte("policies:\n  project_overlays:\n    enabled: true\n"))
	if err != nil {
		t.Fatalf("loadFromBytes: %v", err)
	}
	po := cfg.Policies.ProjectOverlays
	if !po.Enabled || !po.RequireApproval || po.OnDenied != "fail" {
		t.Fatalf("unexpected defaults: %+v", po)
	}
	if len(po.Paths) != 1 || po.Paths[0] != ".agentsh/policy-overlays/*.yaml" {
		t.Fatalf("paths = %#v", po.Paths)
	}
}

func TestProjectOverlaysExplicitNoApproval(t *testing.T) {
	cfg, err := loadProjectOverlayTestConfig([]byte("policies:\n  project_overlays:\n    enabled: true\n    require_approval: false\n    on_denied: ignore\n"))
	if err != nil {
		t.Fatalf("loadFromBytes: %v", err)
	}
	po := cfg.Policies.ProjectOverlays
	if po.RequireApproval || po.OnDenied != "ignore" {
		t.Fatalf("unexpected explicit settings: %+v", po)
	}
}

func TestProjectOverlaysConfigValidation(t *testing.T) {
	cases := []string{
		"policies:\n  project_overlays:\n    enabled: true\n    on_denied: skip\n",
		"policies:\n  project_overlays:\n    enabled: true\n    paths: [/tmp/*.yaml]\n",
		"policies:\n  project_overlays:\n    enabled: true\n    paths: [../*.yaml]\n",
	}
	for _, input := range cases {
		_, err := loadProjectOverlayTestConfig([]byte(input))
		if err == nil || !strings.Contains(err.Error(), "project_overlays") {
			t.Fatalf("expected project_overlays validation error for %q, got %v", input, err)
		}
	}
}
