//go:build linux

package externalrunner

import (
	"os"
	"syscall"
)

func operatorPolicyOwnerTrusted(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && trustedCIDOwner(stat.Uid)
}
