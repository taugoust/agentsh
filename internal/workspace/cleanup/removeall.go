package cleanup

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// RemoveAllWritable removes path like os.RemoveAll, but first makes every
// non-symlink directory below path user-readable/writable/executable and every
// non-symlink file user-readable/writable. This is intended only for AgentSH-
// owned disposable session/runtime directories: tools such as Go deliberately
// make module-cache directories read-only, which can otherwise cause cleanup to
// fail after accept/reject.
//
// Symlinks are never followed or chmodded.
func RemoveAllWritable(path string) error {
	prepErr := makeTreeWritable(path)
	removeErr := os.RemoveAll(path)
	if removeErr == nil {
		return nil
	}
	if prepErr != nil {
		return fmt.Errorf("prepare writable: %v; remove: %w", prepErr, removeErr)
	}
	return removeErr
}

func makeTreeWritable(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	mode := info.Mode()
	if mode&os.ModeSymlink != 0 {
		return nil
	}
	if !mode.IsDir() {
		return chmodUser(path, mode, 0o600)
	}

	// Directories must be writable by their owner before their children can be
	// unlinked. Chmod before ReadDir so unreadable directories can still be
	// traversed when owned by the current user.
	if err := chmodUser(path, mode, 0o700); err != nil {
		return err
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return err
	}
	var firstErr error
	for _, entry := range entries {
		child := filepath.Join(path, entry.Name())
		if err := makeTreeWritable(child); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func chmodUser(path string, mode fs.FileMode, bits fs.FileMode) error {
	perm := mode.Perm()
	want := perm | bits
	if want == perm {
		return nil
	}
	return os.Chmod(path, want)
}
