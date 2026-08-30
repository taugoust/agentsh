//go:build linux

package externalrunner

import (
	"os"
	"strings"
	"syscall"
)

const linuxOverflowUID = 65534

func operatorPolicyOwnerTrusted(path string, info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	if trustedCIDOwner(stat.Uid) {
		return true
	}
	// Root-owned Nix store files appear as the overflow UID inside the
	// unprivileged mount/user namespace used by supervised parent sessions.
	// The immutable profile still pins the exact store path and content digest.
	return stat.Uid == linuxOverflowUID && strings.HasPrefix(path, "/nix/store/")
}
