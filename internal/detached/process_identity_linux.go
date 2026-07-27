//go:build linux

package detached

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// CurrentProcessIdentity returns the kernel boot ID and /proc start-time ticks.
// PID plus both values is stable across PID reuse and host reboot.
func CurrentProcessIdentity(pid int) (startIdentity, bootID string, err error) {
	if pid <= 0 {
		return "", "", fmt.Errorf("invalid process id %d", pid)
	}
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return "", "", fmt.Errorf("read process stat: %w", err)
	}
	end := strings.LastIndexByte(string(data), ')')
	if end < 0 || end+2 >= len(data) {
		return "", "", fmt.Errorf("malformed process stat")
	}
	// The suffix begins at field 3. starttime is field 22, therefore index 19.
	fields := strings.Fields(string(data[end+2:]))
	if len(fields) <= 19 {
		return "", "", fmt.Errorf("process stat has %d suffix fields", len(fields))
	}
	if _, err := strconv.ParseUint(fields[19], 10, 64); err != nil {
		return "", "", fmt.Errorf("parse process start time: %w", err)
	}
	startIdentity = fields[19]
	bootData, bootErr := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if bootErr != nil {
		return "", "", fmt.Errorf("read kernel boot id: %w", bootErr)
	}
	bootID = strings.TrimSpace(string(bootData))
	if bootID == "" {
		return "", "", fmt.Errorf("kernel boot id is empty")
	}
	return startIdentity, bootID, nil
}

func ProcessIdentityMatches(pid int, startIdentity, bootID string) bool {
	if strings.TrimSpace(startIdentity) == "" || strings.TrimSpace(bootID) == "" {
		return false
	}
	start, boot, err := CurrentProcessIdentity(pid)
	return err == nil && start == startIdentity && boot == bootID
}
