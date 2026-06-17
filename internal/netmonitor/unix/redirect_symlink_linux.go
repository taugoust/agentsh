//go:build linux && cgo

package unix

import (
	"fmt"
	"os"
	"path/filepath"
)

// CreateStubSymlink creates a short-path symlink pointing to the agentsh-stub binary.
// The symlink is placed in a non-listable but traversable temp directory.
// Returns (symlink path, cleanup function, error).
// The symlink path is kept short to fit within most execve filename buffers.
func CreateStubSymlink(stubBinaryPath string) (string, func(), error) {
	// Create a temp directory with a short prefix. MkdirTemp starts at 0700, but
	// redirected tracees run as an unprivileged user and must be able to traverse
	// this directory when the rewritten execve reaches the kernel. The path is
	// not a secret and the target is the public agentsh-stub binary, so use 0711:
	// searchable/executable by everyone, listable only by the owner.
	dir, err := os.MkdirTemp("", "as-")
	if err != nil {
		return "", nil, fmt.Errorf("create stub symlink dir: %w", err)
	}
	if err := os.Chmod(dir, 0711); err != nil {
		os.RemoveAll(dir)
		return "", nil, fmt.Errorf("chmod stub symlink dir: %w", err)
	}

	// Use single-char name "s" to keep the total path short.
	symlinkPath := filepath.Join(dir, "s")
	if err := os.Symlink(stubBinaryPath, symlinkPath); err != nil {
		os.RemoveAll(dir)
		return "", nil, fmt.Errorf("create stub symlink: %w", err)
	}

	cleanup := func() {
		os.RemoveAll(dir)
	}

	return symlinkPath, cleanup, nil
}
