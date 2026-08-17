//go:build !windows

package runtimeprovider

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

type lifecycleLock struct {
	file *os.File
}

func acquireNamedLock(stateDir, name string) (*lifecycleLock, error) {
	if !filepath.IsAbs(stateDir) || filepath.Clean(stateDir) != stateDir {
		return nil, fmt.Errorf("runtime lifecycle state directory must be clean and absolute")
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, fmt.Errorf("create runtime lifecycle state directory: %w", err)
	}
	file, err := os.OpenFile(filepath.Join(stateDir, name), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open runtime lifecycle lock: %w", err)
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("lock runtime lifecycle: %w", err)
	}
	return &lifecycleLock{file: file}, nil
}

func acquireLifecycleLock(stateDir string) (*lifecycleLock, error) {
	return acquireNamedLock(stateDir, "runtime-provider.lock")
}

func acquireOperationLock(stateDir string) (*lifecycleLock, error) {
	return acquireNamedLock(stateDir, "runtime-provider.operation.lock")
}

func (l *lifecycleLock) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	file := l.file
	l.file = nil
	return errors.Join(syscall.Flock(int(file.Fd()), syscall.LOCK_UN), file.Close())
}
