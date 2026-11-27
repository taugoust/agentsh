package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestApprovals_DefaultEnabled(t *testing.T) {
	cases := map[string]string{
		"no approvals section":   "server:\n  http:\n    addr: 127.0.0.1:18080\n",
		"empty approvals":        "approvals: {}\n",
		"approvals without flag": "approvals:\n  timeout: 2m\n",
	}
	for name, yml := range cases {
		t.Run(name, func(t *testing.T) {
			cfg, err := loadFromString(t, yml)
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if !cfg.Approvals.Enabled {
				t.Fatalf("approvals.enabled = false, want true by default")
			}
			if cfg.Approvals.Mode != "local_tty" {
				t.Fatalf("approvals.mode = %q, want local_tty", cfg.Approvals.Mode)
			}
		})
	}
}

func TestApprovals_DefaultTimeoutUnchanged(t *testing.T) {
	cfg, err := loadFromString(t, "approvals: {}\n")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Approvals.Timeout != "5m" {
		t.Fatalf("approvals.timeout = %q, want 5m", cfg.Approvals.Timeout)
	}
}

func TestApprovals_ExplicitFalseDisables(t *testing.T) {
	cfg, err := loadFromString(t, "approvals:\n  enabled: false\n")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Approvals.Enabled {
		t.Fatalf("approvals.enabled = true, want explicit false to be kept")
	}
}

func TestApprovals_ExplicitFalseDisablesWithSource(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte("approvals:\n  enabled: false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, _, err := LoadWithSource(p, ConfigSourceUser)
	if err != nil {
		t.Fatalf("LoadWithSource: %v", err)
	}
	if cfg.Approvals.Enabled {
		t.Fatalf("approvals.enabled = true, want explicit false to be kept")
	}
}

func TestApprovals_ApplyDefaultsKeepsLaterOverride(t *testing.T) {
	var cfg Config
	applyDefaults(&cfg)
	if !cfg.Approvals.Enabled {
		t.Fatalf("approvals.enabled = false after defaults, want true")
	}
	cfg.Approvals.Enabled = false
	applyDefaults(&cfg)
	if cfg.Approvals.Enabled {
		t.Fatalf("second applyDefaults re-enabled approvals")
	}
}
