//go:build windows

package api

import "os/exec"

func subagentProcessSignal(_ *exec.Cmd) string {
	return ""
}
