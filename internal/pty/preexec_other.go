//go:build !linux && !windows

package pty

import (
	"syscall"

	"github.com/agentsh/agentsh/pkg/types"
)

func configureStoppedStart(_ *syscall.SysProcAttr, required bool, boundary *types.LinuxCommandJailRequirements) error {
	if required || boundary != nil {
		return ErrPreExecBarrierUnavailable
	}
	return nil
}

func resumeStoppedProcess(_ int) error {
	return ErrPreExecBarrierUnavailable
}
