//go:build windows

package runtimeprovider

// The detached native runtime is not available on Windows. Keep the contract
// package buildable there; Windows providers must supply equivalent lifecycle
// serialization before being registered.
type lifecycleLock struct{}

func acquireLifecycleLock(string) (*lifecycleLock, error) { return &lifecycleLock{}, nil }
func acquireOperationLock(string) (*lifecycleLock, error) { return &lifecycleLock{}, nil }

func (l *lifecycleLock) Close() error { return nil }
