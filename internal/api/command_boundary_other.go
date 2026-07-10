//go:build !linux

package api

import (
	"fmt"
	"syscall"

	"github.com/agentsh/agentsh/pkg/types"
)

func hardenSupervisorForCommandBoundary() error { return nil }

func configureCommandBoundaryProcess(_ *syscall.SysProcAttr, requirements *types.LinuxCommandJailRequirements) error {
	if requirements != nil {
		return fmt.Errorf("strict command boundary is unavailable on this platform")
	}
	return nil
}
