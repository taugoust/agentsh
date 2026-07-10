//go:build !linux

// Package capabilities provides runtime checks for kernel and system
// capabilities required by agentsh sandbox features.
package capabilities

import "github.com/agentsh/agentsh/internal/config"

// CheckResult represents the result of a single capability check.
type CheckResult struct {
	Feature    string // e.g., "seccomp-user-notify"
	ConfigKey  string // e.g., "sandbox.unix_sockets.enabled"
	Available  bool
	Error      error
	Suggestion string // e.g., "Set sandbox.unix_sockets.enabled: false"
}

type CheckOptions struct {
	ExternalEBPFHelper bool
}

// CheckAll on non-Linux platforms is a no-op since the Linux-specific
// sandbox features are not applicable.
func CheckAll(cfg *config.Config) error {
	return CheckAllWithOptions(cfg, CheckOptions{})
}

func CheckAllWithOptions(_ *config.Config, _ CheckOptions) error {
	return nil
}
