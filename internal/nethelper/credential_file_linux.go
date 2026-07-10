//go:build linux

package nethelper

import (
	"fmt"
	"os"
	"syscall"
)

// ValidateCredentialFileOwnership requires helper credential material consumed
// by the root service to remain root-owned and private.
func ValidateCredentialFileOwnership(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil {
		return fmt.Errorf("credential file ownership is unavailable")
	}
	if stat.Uid != 0 {
		return fmt.Errorf("credential file must be owned by root, got uid %d", stat.Uid)
	}
	return nil
}
