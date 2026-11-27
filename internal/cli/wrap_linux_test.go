//go:build linux

package cli

import (
	"syscall"
	"testing"

	"github.com/agentsh/agentsh/pkg/types"
	"golang.org/x/sys/unix"
)

func TestConfigureWrapCommandBoundaryAppliesFixedLinuxLaunchAttributes(t *testing.T) {
	attr := &syscall.SysProcAttr{}
	requirements := &types.LinuxCommandJailRequirements{
		Required:             true,
		UserNamespace:        true,
		MountNamespace:       true,
		PIDNamespace:         true,
		CgroupNamespace:      true,
		IPCNamespace:         true,
		MapCurrentUserToRoot: true,
		ParentDeathSignal:    "SIGKILL",
		PrivateProc:          true,
		HideCgroupFS:         true,
		HideControlPaths:     true,
		CloseNonStdioFDs:     true,
		DropCapabilities:     true,
		NoNewPrivileges:      true,
	}
	if err := configureWrapCommandBoundary(attr, requirements); err != nil {
		t.Fatalf("configure wrap command boundary: %v", err)
	}
	wantFlags := uintptr(unix.CLONE_NEWUSER | unix.CLONE_NEWNS | unix.CLONE_NEWPID | unix.CLONE_NEWCGROUP | unix.CLONE_NEWIPC)
	if attr.Cloneflags&wantFlags != wantFlags {
		t.Fatalf("clone flags = %#x, want all %#x", attr.Cloneflags, wantFlags)
	}
	if attr.Pdeathsig != syscall.SIGKILL {
		t.Fatalf("parent-death signal = %v, want SIGKILL", attr.Pdeathsig)
	}
	if len(attr.UidMappings) != 1 || len(attr.GidMappings) != 1 || attr.GidMappingsEnableSetgroups {
		t.Fatalf("uid/gid mappings are incomplete: uid=%+v gid=%+v setgroups=%t", attr.UidMappings, attr.GidMappings, attr.GidMappingsEnableSetgroups)
	}
}

func TestConfigureWrapCommandBoundaryUsesNonRootCompositionIdentity(t *testing.T) {
	attr := &syscall.SysProcAttr{}
	requirements := &types.LinuxCommandJailRequirements{
		Required:                true,
		UserNamespace:           true,
		MountNamespace:          true,
		PIDNamespace:            true,
		CgroupNamespace:         true,
		IPCNamespace:            true,
		MapCurrentUserToNonRoot: true,
		ParentDeathSignal:       "SIGKILL",
		PrivateProc:             true,
		HideCgroupFS:            true,
		HideControlPaths:        true,
		CloseNonStdioFDs:        true,
		DropCapabilities:        true,
		NoNewPrivileges:         true,
	}
	if err := configureWrapCommandBoundary(attr, requirements); err != nil {
		t.Fatal(err)
	}
	if got := attr.UidMappings[0].ContainerID; got != 1 {
		t.Fatalf("uid namespace identity = %d, want 1", got)
	}
	if got := attr.GidMappings[0].ContainerID; got != 1 {
		t.Fatalf("gid namespace identity = %d, want 1", got)
	}
	if len(attr.AmbientCaps) != 2 || attr.AmbientCaps[0] != unix.CAP_SYS_ADMIN || attr.AmbientCaps[1] != unix.CAP_SETPCAP {
		t.Fatalf("ambient setup capabilities = %v", attr.AmbientCaps)
	}
}

func TestStripEnvKey(t *testing.T) {
	in := []string{"A=1", "AGENTSH_WRAPPER_LOG_FD=9", "B=2", "AGENTSH_WRAPPER_LOG_FD=10"}
	out := stripEnvKey(in, "AGENTSH_WRAPPER_LOG_FD")
	want := []string{"A=1", "B=2"}
	if len(out) != len(want) || out[0] != want[0] || out[1] != want[1] {
		t.Fatalf("stripEnvKey = %v, want %v", out, want)
	}
}
