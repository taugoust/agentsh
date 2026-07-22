//go:build !linux || !cgo

package api

import (
	"fmt"
	"os"

	"github.com/agentsh/agentsh/internal/session"
)

func (a *App) configureExecveComposition(_ any, s *session.Session, _ seccompWrapperConfig, _ *os.File, _ int) error {
	if s != nil && s.CurrentSandboxComposition() != "" {
		return fmt.Errorf("E_COMPOSITION_BACKEND_UNAVAILABLE: semantic Bubblewrap composition requires Linux with cgo")
	}
	return nil
}
