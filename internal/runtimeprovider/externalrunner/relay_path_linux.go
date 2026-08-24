//go:build linux

package externalrunner

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

func hostMonitorRelayPath(stateDir, _ string) string {
	digest := sha256.Sum256([]byte(stateDir))
	return filepath.Join(fmt.Sprintf("/tmp/agentsh-relay-%d", os.Getuid()), hex.EncodeToString(digest[:16])+".sock")
}

func prepareHostMonitorRelayPath(path string) error {
	parent := filepath.Dir(path)
	if err := os.Mkdir(parent, 0o700); err != nil && !os.IsExist(err) {
		return fmt.Errorf("create host relay directory: %w", err)
	}
	info, err := os.Lstat(parent)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return fmt.Errorf("host relay directory is not a private directory")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Getuid()) {
		return fmt.Errorf("host relay directory has the wrong owner")
	}
	return nil
}
