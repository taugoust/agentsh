//go:build linux || darwin

package api

import "syscall"

func childPeerInProcessGroup(pid, processGroupID int) bool {
	if pid <= 0 || processGroupID <= 0 {
		return false
	}
	group, err := syscall.Getpgid(pid)
	return err == nil && group == processGroupID
}
