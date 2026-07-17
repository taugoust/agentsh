//go:build darwin

package api

import (
	"os"
	"syscall"
)

func helperCurrentUIDGID() (uint32, uint32, bool) {
	return uint32(os.Getuid()), uint32(os.Getgid()), true
}

func helperPathOwnedByUID(info os.FileInfo, uid uint32) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat != nil && stat.Uid == uid
}

func helperPathOwnedByCurrentUser(info os.FileInfo) bool {
	return helperPathOwnedByUID(info, uint32(os.Getuid()))
}
