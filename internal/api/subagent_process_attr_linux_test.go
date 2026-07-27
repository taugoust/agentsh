//go:build linux

package api

import (
	"syscall"
	"testing"
)

func TestSubagentProcessUsesParentDeathSIGKILL(t *testing.T) {
	attr := getSubagentSysProcAttr()
	if attr == nil || attr.Pdeathsig != syscall.SIGKILL || !attr.Setpgid {
		t.Fatalf("subagent process attributes = %+v", attr)
	}
}
