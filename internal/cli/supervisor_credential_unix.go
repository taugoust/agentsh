//go:build !windows

package cli

import (
	"fmt"
	"os"
	"syscall"
)

func validateSupervisorCredentialFileOwner(info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil {
		return fmt.Errorf("credential file ownership is unavailable")
	}
	if stat.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("credential file must be owned by supervisor uid %d, got uid %d", os.Geteuid(), stat.Uid)
	}
	return nil
}
