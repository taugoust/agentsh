//go:build linux

package api

import (
	"github.com/agentsh/agentsh/internal/capabilities"
	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/policy"
)

// LandlockHook is a post-fork hook that applies Landlock restrictions.
type LandlockHook struct {
	cfg       *config.LandlockConfig
	secCaps   *capabilities.SecurityCapabilities
	workspace string
	policy    *policy.Policy
}

// CreateLandlockHook creates a hook for applying Landlock restrictions.
// Returns nil if Landlock is disabled or unavailable.
func CreateLandlockHook(
	cfg *config.LandlockConfig,
	secCaps *capabilities.SecurityCapabilities,
	workspace string,
	pol *policy.Policy,
) *LandlockHook {
	if cfg == nil || !cfg.Enabled {
		return nil
	}

	if secCaps == nil || !secCaps.Landlock {
		return nil
	}

	return &LandlockHook{
		cfg:       cfg,
		secCaps:   secCaps,
		workspace: workspace,
		policy:    pol,
	}
}
