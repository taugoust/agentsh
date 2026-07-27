//go:build linux

package api

import (
	"syscall"
)

func getSubagentSysProcAttr() *syscall.SysProcAttr {
	attr := getSysProcAttr()
	// The direct child must not outlive an abruptly killed supervisor. Its
	// process-group identity is also journaled so recovery can kill descendants,
	// which do not inherit this parent-death signal.
	attr.Pdeathsig = syscall.SIGKILL
	return attr
}
