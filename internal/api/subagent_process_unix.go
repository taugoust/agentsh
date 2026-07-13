//go:build !windows

package api

import (
	"os/exec"
	"syscall"
)

func subagentProcessSignal(cmd *exec.Cmd) string {
	if cmd == nil || cmd.ProcessState == nil {
		return ""
	}
	status, ok := cmd.ProcessState.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() {
		return ""
	}
	return status.Signal().String()
}
