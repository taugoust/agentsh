package api

import (
	"fmt"
	"os"
	"strings"

	"github.com/agentsh/agentsh/internal/detached"
	"github.com/agentsh/agentsh/internal/session"
)

// applyTrustedGuestEgressProxy consumes the protected launcher-to-supervisor
// environment contract into session-owned command construction state. The
// control variable itself is reserved and never reaches a user command.
func applyTrustedGuestEgressProxy(s *session.Session) error {
	if s == nil {
		return fmt.Errorf("guest egress proxy session is unavailable")
	}
	proxyURL := strings.TrimSpace(os.Getenv(detached.EnvGuestEgressProxyURL))
	if proxyURL == "" {
		return nil
	}
	if _, err := exactLoopbackProxyAddrPort(proxyURL); err != nil {
		return fmt.Errorf("trusted guest egress proxy URL is invalid: %w", err)
	}
	s.SetExternalProxy(proxyURL)
	return nil
}
