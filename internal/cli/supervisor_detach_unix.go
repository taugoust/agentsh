//go:build !windows

package cli

import (
	"os/exec"
	"syscall"
)

func setDetachedProcessAttrs(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}
