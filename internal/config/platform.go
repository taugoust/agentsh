package config

import (
	"os"
)

// ConfigSource indicates where the configuration was loaded from.
type ConfigSource int

const (
	// ConfigSourceEnv means config path was specified via AGENTSH_CONFIG env var.
	ConfigSourceEnv ConfigSource = iota
	// ConfigSourceUser means config was loaded from user-local directory.
	ConfigSourceUser
	// ConfigSourceSystem means config was loaded from system-wide directory.
	ConfigSourceSystem
)

// String returns a human-readable name for the config source.
func (s ConfigSource) String() string {
	switch s {
	case ConfigSourceEnv:
		return "env"
	case ConfigSourceUser:
		return "user"
	case ConfigSourceSystem:
		return "system"
	default:
		return "unknown"
	}
}

// GetDataDir returns the system data directory.
func GetDataDir() string {
	return "/var/lib/agentsh"
}

// GetConfigDir returns the system config directory.
func GetConfigDir() string {
	return "/etc/agentsh"
}

// GetPoliciesDir returns the platform-appropriate policies directory.
func GetPoliciesDir() string {
	return GetConfigDir() + string(os.PathSeparator) + "policies"
}

// GetUserConfigDir returns the user-specific config directory.
func GetUserConfigDir() string {
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return xdg + "/agentsh"
	}
	home, _ := os.UserHomeDir()
	return home + "/.config/agentsh"
}

// GetUserDataDir returns the user-specific data directory.
func GetUserDataDir() string {
	if xdg := os.Getenv("XDG_DATA_HOME"); xdg != "" {
		return xdg + "/agentsh"
	}
	home, _ := os.UserHomeDir()
	return home + "/.local/share/agentsh"
}

// GetUserStateDir returns the user-specific state directory used for ephemeral
// runtime artifacts (e.g., WTP WAL/cursor/replay store). It honors
// XDG_STATE_HOME with a fallback to ~/.local/state, per the XDG Base
// Directory Specification.
func GetUserStateDir() string {
	if xdg := os.Getenv("XDG_STATE_HOME"); xdg != "" {
		return xdg + "/agentsh"
	}
	home, _ := os.UserHomeDir()
	return home + "/.local/state/agentsh"
}
