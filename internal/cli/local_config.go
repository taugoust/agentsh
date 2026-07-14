package cli

import (
	"os"
	"path/filepath"

	"github.com/agentsh/agentsh/internal/config"
)

// findConfigPath searches for a config file in priority order and returns
// the path and its source. General local commands allow a config in the current
// directory as a convenience for source-tree development.
func findConfigPath() (string, config.ConfigSource) {
	return findConfigPathWithWorkingDirectory(true)
}

// findDetachedSupervisorConfigPath deliberately excludes the current working
// directory. For `session start --detach`, that directory is normally the
// workspace being sandboxed and must not be allowed to replace the operator's
// AgentSH config or policy directory. AGENTSH_CONFIG remains the explicit
// opt-in for source-tree and other custom configurations.
func findDetachedSupervisorConfigPath() (string, config.ConfigSource) {
	return findConfigPathWithWorkingDirectory(false)
}

// findConfigPathWithWorkingDirectory searches in this order:
//  1. AGENTSH_CONFIG
//  2. ./config.yml or ./config.yaml, when includeWorkingDirectory is true
//  3. User-local config (~/.config/agentsh/config.yaml or platform equivalent)
//  4. System-wide config (/etc/agentsh/config.yaml or platform equivalent)
//  5. macOS app bundle Resources (fallback for Homebrew Cask installs)
func findConfigPathWithWorkingDirectory(includeWorkingDirectory bool) (string, config.ConfigSource) {
	if v := os.Getenv("AGENTSH_CONFIG"); v != "" {
		return v, config.ConfigSourceEnv
	}

	if includeWorkingDirectory {
		for _, name := range []string{"config.yml", "config.yaml"} {
			if _, err := os.Stat(name); err == nil {
				return name, config.ConfigSourceEnv
			}
		}
	}

	userConfigDir := config.GetUserConfigDir()
	for _, name := range []string{"config.yaml", "config.yml"} {
		userConfig := filepath.Join(userConfigDir, name)
		if _, err := os.Stat(userConfig); err == nil {
			return userConfig, config.ConfigSourceUser
		}
	}

	systemConfigDir := config.GetConfigDir()
	for _, name := range []string{"config.yaml", "config.yml"} {
		systemConfig := filepath.Join(systemConfigDir, name)
		if _, err := os.Stat(systemConfig); err == nil {
			return systemConfig, config.ConfigSourceSystem
		}
	}

	if bundleDir := config.GetBundleResourcesDir(); bundleDir != "" {
		for _, name := range []string{"config.yaml", "config.yml"} {
			bundleConfig := filepath.Join(bundleDir, name)
			if _, err := os.Stat(bundleConfig); err == nil {
				return bundleConfig, config.ConfigSourceBundle
			}
		}
	}

	return filepath.Join(systemConfigDir, "config.yaml"), config.ConfigSourceSystem
}

// defaultConfigPath returns the config path (for backward compatibility).
// Deprecated: Use findConfigPath() to also get the source.
func defaultConfigPath() string {
	path, _ := findConfigPath()
	return path
}

// loadLocalConfig loads configuration from the given path or auto-discovers it.
// Returns the config, the source where it was loaded from, and any error.
func loadLocalConfig(path string) (*config.Config, config.ConfigSource, error) {
	var source config.ConfigSource
	if path == "" {
		path, source = findConfigPath()
	} else {
		// Explicit path provided - treat as env source
		source = config.ConfigSourceEnv
	}
	cfg, source, err := config.LoadWithSource(path, source)
	return cfg, source, err
}
