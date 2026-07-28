//go:build !linux || !cgo

package api

import (
	"fmt"
	"os"

	"github.com/agentsh/agentsh/internal/session"
)

func (a *App) configureExecveComposition(handler any, s *session.Session, wrapperCfg seccompWrapperConfig, setup *os.File, wrapperPID int) error {
	return a.configureExecveCompositionForState(handler, s, s, wrapperCfg, setup, wrapperPID)
}

func (a *App) configureExecveCompositionForState(_ any, _ *session.Session, runtimeState session.CommandRuntimeState, _ seccompWrapperConfig, _ *os.File, _ int) error {
	if runtimeState != nil && runtimeState.CurrentSandboxComposition() != "" {
		return fmt.Errorf("E_COMPOSITION_BACKEND_UNAVAILABLE: semantic Bubblewrap composition requires Linux with cgo")
	}
	return nil
}
