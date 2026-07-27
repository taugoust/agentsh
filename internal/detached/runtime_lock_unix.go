//go:build !windows

package detached

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

type SupervisorLock struct {
	file *os.File
}

func AcquireSupervisorLock(stateDir string) (*SupervisorLock, error) {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, fmt.Errorf("create detached state directory: %w", err)
	}
	path := filepath.Join(stateDir, "supervisor.lock")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open detached supervisor lock: %w", err)
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, ErrSupervisorAlreadyRunning
		}
		return nil, fmt.Errorf("lock detached supervisor: %w", err)
	}
	return &SupervisorLock{file: file}, nil
}

func (l *SupervisorLock) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	file := l.file
	l.file = nil
	unlockErr := syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	closeErr := file.Close()
	return errors.Join(unlockErr, closeErr)
}
