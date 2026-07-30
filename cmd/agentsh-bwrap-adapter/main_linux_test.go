//go:build linux

package main

import (
	"testing"

	"github.com/agentsh/agentsh/internal/composition"
	"golang.org/x/sys/unix"
)

func TestCompositionNamespaceFlagsAbsorbPIDIsolation(t *testing.T) {
	flags := compositionNamespaceFlags(composition.Plan{
		UnsharePID:    true,
		UnshareIPC:    true,
		UnshareUTS:    true,
		UnshareCgroup: true,
	})
	if flags&unix.CLONE_NEWPID != 0 {
		t.Fatal("nested composition created a PID namespace outside the outer Landlock procfs boundary")
	}
	for name, flag := range map[string]uintptr{
		"mount":  unix.CLONE_NEWNS,
		"ipc":    unix.CLONE_NEWIPC,
		"uts":    unix.CLONE_NEWUTS,
		"cgroup": unix.CLONE_NEWCGROUP,
	} {
		if flags&flag == 0 {
			t.Errorf("%s namespace flag was dropped", name)
		}
	}
}
