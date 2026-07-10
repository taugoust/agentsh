//go:build linux

package nethelper

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// protectedUnmappedRootOwner handles filesystem ownership as observed from an
// unprivileged systemd service with PrivateTmp. systemd creates its mount
// namespace through a narrow user namespace; host uid 0 is then reported by
// stat(2) as kernel.overflowuid rather than 0. The installed helper directory
// is root-provisioned, and this fallback additionally requires that the current
// supervisor cannot write it. It never treats the overflow uid as root while
// host uid 0 is mapped in the current namespace.
func protectedUnmappedRootOwner(path string, ownerUID uint32) bool {
	overflowData, err := os.ReadFile(filepath.Join(string(filepath.Separator), "proc", "sys", "kernel", "overflowuid"))
	if err != nil {
		return false
	}
	overflow, err := strconv.ParseUint(strings.TrimSpace(string(overflowData)), 10, 32)
	if err != nil || ownerUID != uint32(overflow) {
		return false
	}
	uidMap, err := os.ReadFile(filepath.Join(string(filepath.Separator), "proc", "self", "uid_map"))
	if err != nil || !uidMapLeavesHostRootUnmapped(uidMap) {
		return false
	}
	accessErr := unix.Access(path, unix.W_OK)
	return errors.Is(accessErr, unix.EACCES) || errors.Is(accessErr, unix.EPERM)
}

func uidMapLeavesHostRootUnmapped(data []byte) bool {
	fields := strings.Fields(string(data))
	if len(fields) == 0 || len(fields)%3 != 0 {
		return false
	}
	for i := 0; i < len(fields); i += 3 {
		_, namespaceErr := strconv.ParseUint(fields[i], 10, 32)
		hostStart, hostErr := strconv.ParseUint(fields[i+1], 10, 32)
		size, sizeErr := strconv.ParseUint(fields[i+2], 10, 32)
		if namespaceErr != nil || hostErr != nil || sizeErr != nil || size == 0 {
			return false
		}
		if hostStart == 0 {
			return false
		}
	}
	return true
}
