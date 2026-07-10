//go:build !windows

package nethelper

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
)

func validateListenSocketPath(socketPath string) error {
	if !filepath.IsAbs(socketPath) {
		return fmt.Errorf("helper socket path must be absolute")
	}
	if filepath.Clean(socketPath) != socketPath {
		return fmt.Errorf("helper socket path must be canonical")
	}
	return nil
}

func validateSocketParent(dir string) error {
	if dir == "" {
		return fmt.Errorf("helper socket directory is empty")
	}
	dir = filepath.Clean(dir)
	info, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("stat helper socket directory %s: %w", dir, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("helper socket parent %s is not a directory", dir)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("helper socket directory %s must not be group/world writable", dir)
	}
	if err := validateOwnerCurrentOrRoot(info, dir, "helper socket directory "+dir); err != nil {
		return err
	}
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return fmt.Errorf("resolve helper socket directory %s: %w", dir, err)
	}
	if runtime.GOOS == "linux" && filepath.Clean(resolved) != dir {
		return fmt.Errorf("helper socket directory %s must not contain symlink components", dir)
	}
	return nil
}

func validateSocketFileSecurity(socketPath string) error {
	return validateSocketFileOwner(socketPath, uint32(os.Getuid()), false)
}

func validateSocketFileOwner(socketPath string, expectedUID uint32, allowRoot bool) error {
	info, err := os.Lstat(socketPath)
	if err != nil {
		return fmt.Errorf("stat helper socket %s: %w", socketPath, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("helper socket %s must not be a symlink", socketPath)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("helper socket %s is not a Unix socket", socketPath)
	}
	if info.Mode().Perm() != 0o600 {
		return fmt.Errorf("helper socket %s must be mode 0600", socketPath)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return fmt.Errorf("helper socket %s ownership is unavailable", socketPath)
	}
	if st.Uid != expectedUID && !(allowRoot && st.Uid == 0) {
		return fmt.Errorf("helper socket %s must be owned by uid %d, got uid %d", socketPath, expectedUID, st.Uid)
	}
	resolved, err := filepath.EvalSymlinks(socketPath)
	if err != nil {
		return fmt.Errorf("resolve helper socket %s: %w", socketPath, err)
	}
	if runtime.GOOS == "linux" && filepath.Clean(resolved) != filepath.Clean(socketPath) {
		return fmt.Errorf("helper socket %s must not contain symlink components", socketPath)
	}
	return nil
}

func validateClientSocketPath(socketPath string) error {
	if err := validateListenSocketPath(socketPath); err != nil {
		return err
	}
	if err := validateSocketParent(filepath.Dir(socketPath)); err != nil {
		return err
	}
	return validateSocketFileSecurity(socketPath)
}

func validateOwnerCurrentOrRoot(info os.FileInfo, path, what string) error {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return fmt.Errorf("%s ownership is unavailable", what)
	}
	uid := uint32(os.Getuid())
	if st.Uid != uid && st.Uid != 0 && !protectedUnmappedRootOwner(path, st.Uid) {
		return fmt.Errorf("%s must be owned by uid %d or root, got uid %d", what, uid, st.Uid)
	}
	return nil
}
