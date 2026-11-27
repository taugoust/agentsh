package server

import (
	"fmt"
	"log/slog"

	"github.com/agentsh/agentsh/internal/capabilities"
	"github.com/agentsh/agentsh/internal/config"
)

// DetectAndValidateSecurityMode detects security capabilities and selects the appropriate mode.
// Returns the selected mode, detected capabilities, and any error.
func DetectAndValidateSecurityMode(cfg *config.Config) (string, *capabilities.SecurityCapabilities, error) {
	// Detect available security capabilities
	caps := capabilities.DetectSecurityCapabilities()

	// Determine effective mode
	var mode string
	if cfg != nil && cfg.Security.Mode != "" && cfg.Security.Mode != "auto" {
		mode = cfg.Security.Mode
	} else {
		mode = caps.SelectMode()
	}

	// Validate strict mode requirements
	if cfg != nil && cfg.Security.Strict {
		if err := capabilities.ValidateStrictMode(mode, caps); err != nil {
			return "", caps, fmt.Errorf("strict mode validation failed: %w", err)
		}
	}

	// Validate minimum mode requirements
	if cfg != nil && cfg.Security.MinimumMode != "" {
		if err := capabilities.ValidateMinimumMode(mode, cfg.Security.MinimumMode); err != nil {
			return "", caps, fmt.Errorf("minimum mode validation failed: %w", err)
		}
	}

	// Log degraded mode warnings
	if cfg != nil && cfg.Security.WarnDegraded && mode != capabilities.ModeFull {
		slog.Warn("running in degraded security mode",
			"mode", mode,
			"description", capabilities.ModeDescriptionWithCaps(mode, caps),
			"seccomp", caps.Seccomp,
			"landlock", caps.Landlock,
			"landlock_abi", caps.LandlockABI,
			"ebpf", caps.EBPF,
			"fuse", caps.FUSE,
			"capabilities_active", caps.CapabilitiesActive,
		)
	}

	return mode, caps, nil
}
