//go:build !linux

package api

import (
	"fmt"

	"github.com/agentsh/agentsh/internal/nethelper"
)

type CompositionRuntimeEvidence struct {
	Mode        string
	ScratchRoot string
	LeaseID     string
}

func (a *App) compositionScratchRoot() (string, error) {
	return "", fmt.Errorf("composition runtime is available only on Linux")
}

func validateLeaseCompositionScratchRoot(string, string, nethelper.CompositionRuntimeAttestation) error {
	return fmt.Errorf("composition runtime is available only on Linux")
}

func (a *App) CompositionRuntimePreflight() (CompositionRuntimeEvidence, error) {
	return CompositionRuntimeEvidence{}, fmt.Errorf("composition runtime is available only on Linux")
}
