//go:build !linux

package api

import "fmt"

type CompositionRuntimeEvidence struct {
	Mode        string
	ScratchRoot string
	LeaseID     string
}

func (a *App) compositionScratchRoot() (string, error) {
	return "", fmt.Errorf("composition runtime is available only on Linux")
}

func validateLeaseCompositionScratchRoot(string, string) error {
	return fmt.Errorf("composition runtime is available only on Linux")
}

func (a *App) CompositionRuntimePreflight() (CompositionRuntimeEvidence, error) {
	return CompositionRuntimeEvidence{}, fmt.Errorf("composition runtime is available only on Linux")
}
