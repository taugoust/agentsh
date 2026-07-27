//go:build !windows

package api

import (
	"errors"
	"fmt"
	"syscall"
	"time"

	"github.com/agentsh/agentsh/internal/detached"
)

// terminateDetachedInterruptedProcesses removes every durably identified
// external process group from the dead supervisor incarnation before its
// retained workspace is reopened. Process groups are created with PGID=PID;
// accepting another value would turn a corrupted journal into an arbitrary
// signal capability.
func terminateDetachedInterruptedProcesses(commands []detached.InflightCommand) error {
	for _, command := range commands {
		if !command.ExternalProcess {
			continue
		}
		if command.PID <= 0 || command.ProcessGroupID != command.PID {
			return fmt.Errorf("interrupted command %s has incomplete process-group identity", command.CommandID)
		}
		if command.ProcessStartIdentity != "" || command.BootID != "" {
			if !detached.ProcessIdentityMatches(command.PID, command.ProcessStartIdentity, command.BootID) {
				// A missing leader is expected after parent-death SIGKILL; its
				// descendants can still retain the original process group. A live,
				// reused PID is not safe to signal through stale evidence.
				if err := syscall.Kill(command.PID, 0); err == nil || !errors.Is(err, syscall.ESRCH) {
					return fmt.Errorf("interrupted command %s process identity was reused", command.CommandID)
				}
			}
		}
		if err := syscall.Kill(-command.ProcessGroupID, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
			return fmt.Errorf("terminate interrupted command %s process group: %w", command.CommandID, err)
		}
		deadline := time.Now().Add(2 * time.Second)
		for {
			err := syscall.Kill(-command.ProcessGroupID, 0)
			if errors.Is(err, syscall.ESRCH) {
				break
			}
			if err != nil {
				return fmt.Errorf("verify interrupted command %s process-group termination: %w", command.CommandID, err)
			}
			if time.Now().After(deadline) {
				return fmt.Errorf("interrupted command %s process group survived termination", command.CommandID)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	return nil
}
