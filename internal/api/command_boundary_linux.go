//go:build linux

package api

import (
	"fmt"
	"os"
	"syscall"

	"github.com/agentsh/agentsh/pkg/types"
	"golang.org/x/sys/unix"
)

func hardenSupervisorForCommandBoundary() error {
	// Do not set the supervisor non-dumpable here. Go must write the child's
	// uid_map/gid_map after clone(CLONE_NEWUSER), and Linux rejects those writes
	// when the mapping parent made itself non-dumpable. Strict tool processes are
	// instead isolated from the supervisor by their private PID/proc and mount
	// namespaces; the command-jail init makes itself non-dumpable before exec.
	return nil
}

func configureCommandBoundaryProcess(attr *syscall.SysProcAttr, requirements *types.LinuxCommandJailRequirements) error {
	if requirements == nil {
		return nil
	}
	if !requirements.Complete() {
		return fmt.Errorf("strict command boundary requirements are incomplete")
	}
	if attr == nil {
		return fmt.Errorf("strict command boundary requires process attributes")
	}
	if len(attr.UidMappings) != 0 || len(attr.GidMappings) != 0 {
		return fmt.Errorf("strict command boundary cannot compose with existing uid/gid mappings")
	}
	if attr.Credential != nil {
		return fmt.Errorf("strict command boundary cannot compose with an alternate process credential")
	}
	if attr.Pdeathsig != 0 && attr.Pdeathsig != syscall.SIGKILL {
		return fmt.Errorf("strict command boundary requires SIGKILL parent-death behavior")
	}
	attr.Cloneflags |= unix.CLONE_NEWUSER | unix.CLONE_NEWNS | unix.CLONE_NEWPID | unix.CLONE_NEWCGROUP | unix.CLONE_NEWIPC
	attr.Pdeathsig = syscall.SIGKILL
	attr.UidMappings = []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Geteuid(), Size: 1}}
	attr.GidMappings = []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getegid(), Size: 1}}
	attr.GidMappingsEnableSetgroups = false
	return nil
}
