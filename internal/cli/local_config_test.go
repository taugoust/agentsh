package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/agentsh/agentsh/internal/config"
)

func TestFindConfigPath_EnvVar(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "custom.yaml")
	os.WriteFile(tmpFile, []byte("platform:\n  mode: auto\n"), 0644)

	orig := os.Getenv("AGENTSH_CONFIG")
	os.Setenv("AGENTSH_CONFIG", tmpFile)
	defer os.Setenv("AGENTSH_CONFIG", orig)

	path, source := findConfigPath()
	if path != tmpFile {
		t.Errorf("findConfigPath() path = %q, want %q", path, tmpFile)
	}
	if source != config.ConfigSourceEnv {
		t.Errorf("findConfigPath() source = %v, want %v", source, config.ConfigSourceEnv)
	}
}

func TestFindConfigPath_UserConfig(t *testing.T) {
	// Clear env var
	orig := os.Getenv("AGENTSH_CONFIG")
	os.Unsetenv("AGENTSH_CONFIG")
	defer os.Setenv("AGENTSH_CONFIG", orig)

	// The test verifies the search order logic works correctly
	path, source := findConfigPath()

	// If user config exists, should return user source
	// If not, should fall back to system
	if source != config.ConfigSourceUser && source != config.ConfigSourceSystem {
		t.Errorf("findConfigPath() source = %v, want ConfigSourceUser or ConfigSourceSystem", source)
	}
	if path == "" {
		t.Error("findConfigPath() returned empty path")
	}
}

func TestFindConfigPath_FallbackToSystem(t *testing.T) {
	// Clear env var
	orig := os.Getenv("AGENTSH_CONFIG")
	os.Unsetenv("AGENTSH_CONFIG")
	defer os.Setenv("AGENTSH_CONFIG", orig)

	// When no user config exists, should fall back to system
	path, source := findConfigPath()

	// Should return some path (either user or system)
	if path == "" {
		t.Error("findConfigPath() returned empty path")
	}

	// Source should be user or system (depending on what exists)
	if source != config.ConfigSourceUser && source != config.ConfigSourceSystem {
		t.Errorf("findConfigPath() source = %v, want user or system", source)
	}
}

func TestFindConfigPath_EnvVarTakesPriority(t *testing.T) {
	// Create a temp config file
	tmpFile := filepath.Join(t.TempDir(), "priority-test.yaml")
	if err := os.WriteFile(tmpFile, []byte("platform:\n  mode: auto\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// Set env var
	orig := os.Getenv("AGENTSH_CONFIG")
	os.Setenv("AGENTSH_CONFIG", tmpFile)
	defer os.Setenv("AGENTSH_CONFIG", orig)

	path, source := findConfigPath()

	// Env var should always win, regardless of what user/system configs exist
	if path != tmpFile {
		t.Errorf("findConfigPath() path = %q, want %q (env var should take priority)", path, tmpFile)
	}
	if source != config.ConfigSourceEnv {
		t.Errorf("findConfigPath() source = %v, want ConfigSourceEnv", source)
	}
}

func TestFindConfigPath_EnvVarNonexistent(t *testing.T) {
	// Set env var to nonexistent path - should still return it (validation happens later)
	orig := os.Getenv("AGENTSH_CONFIG")
	os.Setenv("AGENTSH_CONFIG", "/nonexistent/config.yaml")
	defer os.Setenv("AGENTSH_CONFIG", orig)

	path, source := findConfigPath()

	if path != "/nonexistent/config.yaml" {
		t.Errorf("findConfigPath() path = %q, want %q", path, "/nonexistent/config.yaml")
	}
	if source != config.ConfigSourceEnv {
		t.Errorf("findConfigPath() source = %v, want ConfigSourceEnv", source)
	}
}

func TestFindDetachedSupervisorConfigPath_IgnoresWorkingDirectory(t *testing.T) {
	root := t.TempDir()
	projectDir := filepath.Join(root, "project")
	if err := os.MkdirAll(projectDir, 0o755); err != nil {
		t.Fatal(err)
	}
	projectConfig := filepath.Join(projectDir, "config.yml")
	if err := os.WriteFile(projectConfig, []byte("policies:\n  dir: ./project-policies\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("AGENTSH_CONFIG", "")
	t.Setenv("HOME", filepath.Join(root, "home"))
	t.Setenv("USERPROFILE", filepath.Join(root, "home"))
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "xdg-config"))
	t.Setenv("APPDATA", filepath.Join(root, "appdata"))
	t.Chdir(projectDir)

	path, source := findDetachedSupervisorConfigPath()
	if path == "config.yml" || path == projectConfig {
		t.Fatalf("findDetachedSupervisorConfigPath() selected workspace config %q", path)
	}
	if source == config.ConfigSourceEnv {
		t.Fatalf("findDetachedSupervisorConfigPath() source = %v, want installed config source", source)
	}
}

func TestFindDetachedSupervisorConfigPath_ExplicitEnvOptsIn(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yml")
	t.Setenv("AGENTSH_CONFIG", configPath)

	path, source := findDetachedSupervisorConfigPath()
	if path != configPath {
		t.Fatalf("findDetachedSupervisorConfigPath() path = %q, want %q", path, configPath)
	}
	if source != config.ConfigSourceEnv {
		t.Fatalf("findDetachedSupervisorConfigPath() source = %v, want ConfigSourceEnv", source)
	}
}

func TestLoadLocalConfig_ExplicitPath(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "explicit.yaml")
	if err := os.WriteFile(configPath, []byte("platform:\n  mode: auto\n"), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, source, err := loadLocalConfig(configPath)
	if err != nil {
		t.Fatalf("loadLocalConfig() error = %v", err)
	}

	// Explicit path should be treated as ConfigSourceEnv
	if source != config.ConfigSourceEnv {
		t.Errorf("loadLocalConfig() source = %v, want ConfigSourceEnv for explicit path", source)
	}
	if cfg.Platform.Mode != "auto" {
		t.Errorf("loadLocalConfig() cfg.Platform.Mode = %q, want %q", cfg.Platform.Mode, "auto")
	}
}

func TestLoadLocalConfig_ExplicitPath_NotFound(t *testing.T) {
	_, _, err := loadLocalConfig("/nonexistent/config.yaml")
	if err == nil {
		t.Fatal("loadLocalConfig() expected error for nonexistent file")
	}
}
