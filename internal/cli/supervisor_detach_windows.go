//go:build windows

package cli

import "os/exec"

func setDetachedProcessAttrs(cmd *exec.Cmd) {}
