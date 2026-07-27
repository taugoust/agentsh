//go:build !linux

package detached

import "fmt"

func CurrentProcessIdentity(pid int) (startIdentity, bootID string, err error) {
	if pid <= 0 {
		return "", "", fmt.Errorf("invalid process id %d", pid)
	}
	// IncarnationID plus the protected socket/metadata topology remains the
	// cross-platform identity. Linux additionally supplies kernel start ticks.
	return "", "", nil
}

func ProcessIdentityMatches(pid int, startIdentity, bootID string) bool {
	return false
}
