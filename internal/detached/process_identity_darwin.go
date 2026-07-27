//go:build darwin

package detached

import (
	"fmt"
	"strings"

	"golang.org/x/sys/unix"
)

// CurrentProcessIdentity binds a Darwin PID to its kernel-reported process
// start time and the current kernel boot time. The tuple detects both PID reuse
// and reboot before recovery signals a retained process group.
func CurrentProcessIdentity(pid int) (startIdentity, bootID string, err error) {
	if pid <= 0 {
		return "", "", fmt.Errorf("invalid process id %d", pid)
	}
	process, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		return "", "", fmt.Errorf("read Darwin process identity: %w", err)
	}
	if process == nil || process.Proc.P_pid != int32(pid) {
		return "", "", fmt.Errorf("Darwin process identity does not match pid %d", pid)
	}
	started := process.Proc.P_starttime
	if started.Sec <= 0 {
		return "", "", fmt.Errorf("Darwin process start time is empty")
	}
	booted, err := unix.SysctlTimeval("kern.boottime")
	if err != nil {
		return "", "", fmt.Errorf("read Darwin boot time: %w", err)
	}
	if booted == nil || booted.Sec <= 0 {
		return "", "", fmt.Errorf("Darwin boot time is empty")
	}
	return fmt.Sprintf("%d:%d", started.Sec, started.Usec), fmt.Sprintf("%d:%d", booted.Sec, booted.Usec), nil
}

func ProcessIdentityMatches(pid int, startIdentity, bootID string) bool {
	if strings.TrimSpace(startIdentity) == "" || strings.TrimSpace(bootID) == "" {
		return false
	}
	start, boot, err := CurrentProcessIdentity(pid)
	return err == nil && start == startIdentity && boot == bootID
}
