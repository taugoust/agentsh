package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGetDataDir(t *testing.T) {
	dir := GetDataDir()
	if dir == "" {
		t.Error("GetDataDir() returned empty string")
	}
	if !filepath.IsAbs(dir) {
		t.Errorf("GetDataDir() = %q, expected absolute path", dir)
	}
}

func TestGetConfigDir(t *testing.T) {
	dir := GetConfigDir()
	if dir == "" {
		t.Error("GetConfigDir() returned empty string")
	}
	if !filepath.IsAbs(dir) {
		t.Errorf("GetConfigDir() = %q, expected absolute path", dir)
	}
}

func TestGetPoliciesDir(t *testing.T) {
	dir := GetPoliciesDir()
	if dir == "" {
		t.Error("GetPoliciesDir() returned empty string")
	}
	// Should be a subdirectory of config dir
	configDir := GetConfigDir()
	if !filepath.HasPrefix(dir, configDir) {
		t.Errorf("GetPoliciesDir() = %q, expected to be under %q", dir, configDir)
	}
}

func TestGetUserConfigDir(t *testing.T) {
	dir := GetUserConfigDir()
	if dir == "" {
		t.Error("GetUserConfigDir() returned empty string")
	}
	// Should contain "agentsh"
	if !filepath.IsAbs(dir) {
		t.Errorf("GetUserConfigDir() = %q, expected absolute path", dir)
	}
}

func TestConfigSourceString(t *testing.T) {
	tests := []struct {
		source ConfigSource
		want   string
	}{
		{ConfigSourceEnv, "env"},
		{ConfigSourceUser, "user"},
		{ConfigSourceSystem, "system"},
	}
	for _, tt := range tests {
		if got := tt.source.String(); got != tt.want {
			t.Errorf("ConfigSource(%d).String() = %q, want %q", tt.source, got, tt.want)
		}
	}
}

func TestConfigSourceString_Unknown(t *testing.T) {
	// Test that invalid ConfigSource values return "unknown"
	invalid := ConfigSource(99)
	if got := invalid.String(); got != "unknown" {
		t.Errorf("ConfigSource(99).String() = %q, want %q", got, "unknown")
	}
}

func TestGetUserDataDir(t *testing.T) {
	home, _ := os.UserHomeDir()

	// Test with XDG_DATA_HOME set
	orig := os.Getenv("XDG_DATA_HOME")
	os.Setenv("XDG_DATA_HOME", "/custom/data")
	defer os.Setenv("XDG_DATA_HOME", orig)

	got := GetUserDataDir()
	if got != "/custom/data/agentsh" {
		t.Errorf("GetUserDataDir() with XDG_DATA_HOME = %q, want %q", got, "/custom/data/agentsh")
	}

	// Default without XDG_DATA_HOME
	os.Unsetenv("XDG_DATA_HOME")
	got = GetUserDataDir()
	want := home + "/.local/share/agentsh"
	if got != want {
		t.Errorf("GetUserDataDir() = %q, want %q", got, want)
	}
}

func TestLoad_SandboxLimits(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(cfgPath, []byte(`
sandbox:
  enabled: true
  allow_degraded: true
  limits:
    max_memory_mb: 4096
    max_cpu_percent: 80
    max_processes: 200
    max_disk_io_mbps: 200
    max_network_mbps: 100
`), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	if !cfg.Sandbox.Enabled {
		t.Error("sandbox.enabled should be true")
	}
	if !cfg.Sandbox.AllowDegraded {
		t.Error("sandbox.allow_degraded should be true")
	}
	if cfg.Sandbox.Limits.MaxMemoryMB != 4096 {
		t.Errorf("sandbox.limits.max_memory_mb = %d, want 4096", cfg.Sandbox.Limits.MaxMemoryMB)
	}
	if cfg.Sandbox.Limits.MaxCPUPercent != 80 {
		t.Errorf("sandbox.limits.max_cpu_percent = %d, want 80", cfg.Sandbox.Limits.MaxCPUPercent)
	}
	if cfg.Sandbox.Limits.MaxProcesses != 200 {
		t.Errorf("sandbox.limits.max_processes = %d, want 200", cfg.Sandbox.Limits.MaxProcesses)
	}
	if cfg.Sandbox.Limits.MaxDiskIOMbps != 200 {
		t.Errorf("sandbox.limits.max_disk_io_mbps = %d, want 200", cfg.Sandbox.Limits.MaxDiskIOMbps)
	}
	if cfg.Sandbox.Limits.MaxNetworkMbps != 100 {
		t.Errorf("sandbox.limits.max_network_mbps = %d, want 100", cfg.Sandbox.Limits.MaxNetworkMbps)
	}
}

func TestLoad_SandboxLimitsDefaults(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(cfgPath, []byte(`
sandbox:
  enabled: true
`), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	// Check defaults are applied
	if cfg.Sandbox.Limits.MaxMemoryMB != 2048 {
		t.Errorf("sandbox.limits.max_memory_mb default = %d, want 2048", cfg.Sandbox.Limits.MaxMemoryMB)
	}
	if cfg.Sandbox.Limits.MaxCPUPercent != 50 {
		t.Errorf("sandbox.limits.max_cpu_percent default = %d, want 50", cfg.Sandbox.Limits.MaxCPUPercent)
	}
	if cfg.Sandbox.Limits.MaxProcesses != 100 {
		t.Errorf("sandbox.limits.max_processes default = %d, want 100", cfg.Sandbox.Limits.MaxProcesses)
	}
}

func TestLoad_NetworkInterceptConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(cfgPath, []byte(`
sandbox:
  network:
    enabled: true
    proxy_port: 9090
    dns_port: 9054
    intercept_mode: tcp_only
    tls_inspection:
      enabled: true
      ca_cert: "/path/to/ca.crt"
      ca_key: "/path/to/ca.key"
`), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	if cfg.Sandbox.Network.ProxyPort != 9090 {
		t.Errorf("sandbox.network.proxy_port = %d, want 9090", cfg.Sandbox.Network.ProxyPort)
	}
	if cfg.Sandbox.Network.DNSPort != 9054 {
		t.Errorf("sandbox.network.dns_port = %d, want 9054", cfg.Sandbox.Network.DNSPort)
	}
	if cfg.Sandbox.Network.InterceptMode != "tcp_only" {
		t.Errorf("sandbox.network.intercept_mode = %q, want tcp_only", cfg.Sandbox.Network.InterceptMode)
	}
	if !cfg.Sandbox.Network.TLSInspection.Enabled {
		t.Error("sandbox.network.tls_inspection.enabled should be true")
	}
	if cfg.Sandbox.Network.TLSInspection.CACert != "/path/to/ca.crt" {
		t.Errorf("sandbox.network.tls_inspection.ca_cert = %q", cfg.Sandbox.Network.TLSInspection.CACert)
	}
}

func TestLoad_NetworkInterceptDefaults(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(cfgPath, []byte(`
sandbox:
  network:
    enabled: true
`), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	if cfg.Sandbox.Network.ProxyPort != 9080 {
		t.Errorf("sandbox.network.proxy_port default = %d, want 9080", cfg.Sandbox.Network.ProxyPort)
	}
	if cfg.Sandbox.Network.DNSPort != 9053 {
		t.Errorf("sandbox.network.dns_port default = %d, want 9053", cfg.Sandbox.Network.DNSPort)
	}
	if cfg.Sandbox.Network.InterceptMode != "all" {
		t.Errorf("sandbox.network.intercept_mode default = %q, want all", cfg.Sandbox.Network.InterceptMode)
	}
}

func TestLoad_InvalidInterceptMode(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(cfgPath, []byte(`
sandbox:
  network:
    intercept_mode: invalid_mode
`), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := Load(cfgPath)
	if err == nil {
		t.Error("expected error for invalid intercept_mode")
	}
}

func TestLoad_InvalidPlatformMode(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(cfgPath, []byte(`
platform:
  mode: invalid_platform
`), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := Load(cfgPath)
	if err == nil {
		t.Error("expected error for invalid platform.mode")
	}
}

func TestLoad_PlatformConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(cfgPath, []byte(`
platform:
  mode: linux
  fallback:
    enabled: true
    order:
      - linux
  mount_points:
    linux: /mnt/workspace
`), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	if cfg.Platform.Mode != "linux" {
		t.Errorf("platform.mode = %q, want linux", cfg.Platform.Mode)
	}
	if !cfg.Platform.Fallback.Enabled {
		t.Error("platform.fallback.enabled should be true")
	}
	if len(cfg.Platform.Fallback.Order) != 1 {
		t.Errorf("platform.fallback.order len = %d, want 1", len(cfg.Platform.Fallback.Order))
	}
	if cfg.Platform.MountPoints.Linux != "/mnt/workspace" {
		t.Errorf("platform.mount_points.linux = %q", cfg.Platform.MountPoints.Linux)
	}
}
