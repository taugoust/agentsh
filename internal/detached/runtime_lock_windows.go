//go:build windows

package detached

import "fmt"

type SupervisorLock struct{}

func AcquireSupervisorLock(stateDir string) (*SupervisorLock, error) {
	return nil, fmt.Errorf("detached supervisor recovery locks are unavailable on Windows")
}

func (l *SupervisorLock) Close() error { return nil }
