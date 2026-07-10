//go:build linux

package pty

import (
	"errors"
	"fmt"
	"os"
	"syscall"

	"github.com/agentsh/agentsh/pkg/types"
	"golang.org/x/sys/unix"
)

func configureStoppedStart(attr *syscall.SysProcAttr, required bool, boundary *types.LinuxCommandJailRequirements) error {
	if boundary != nil {
		if !boundary.Complete() {
			return fmt.Errorf("PTY command-boundary requirements are incomplete")
		}
		if !required {
			return fmt.Errorf("PTY command boundary requires a stopped-child barrier")
		}
		if len(attr.UidMappings) != 0 || len(attr.GidMappings) != 0 || attr.Credential != nil {
			return fmt.Errorf("PTY command boundary cannot compose with existing credentials or mappings")
		}
		if attr.Pdeathsig != 0 && attr.Pdeathsig != syscall.SIGKILL {
			return fmt.Errorf("PTY command boundary requires SIGKILL parent-death behavior")
		}
		attr.Cloneflags |= unix.CLONE_NEWUSER | unix.CLONE_NEWNS | unix.CLONE_NEWPID | unix.CLONE_NEWCGROUP | unix.CLONE_NEWIPC
		attr.Pdeathsig = syscall.SIGKILL
		attr.UidMappings = []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Geteuid(), Size: 1}}
		attr.GidMappings = []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getegid(), Size: 1}}
		attr.GidMappingsEnableSetgroups = false
	}
	if required {
		attr.Ptrace = true
	}
	return nil
}

func resumeStoppedProcess(pid int) error {
	if pid <= 0 {
		return errors.New("invalid stopped process pid")
	}
	var status syscall.WaitStatus
	_, err := syscall.Wait4(pid, &status, syscall.WALL, nil)
	if err != nil {
		if errors.Is(err, syscall.ECHILD) {
			return fmt.Errorf("stopped PTY process was reaped before enforcement release: %w", err)
		}
		return fmt.Errorf("wait for stopped PTY process: %w", err)
	}
	if status.Exited() || status.Signaled() {
		return fmt.Errorf("PTY process exited before enforcement release")
	}
	if !status.Stopped() {
		return fmt.Errorf("PTY process did not enter stopped state")
	}
	if err := syscall.PtraceDetach(pid); err != nil {
		if errors.Is(err, syscall.ESRCH) {
			return fmt.Errorf("PTY process vanished before enforcement release: %w", err)
		}
		return fmt.Errorf("resume stopped PTY process: %w", err)
	}
	return nil
}
