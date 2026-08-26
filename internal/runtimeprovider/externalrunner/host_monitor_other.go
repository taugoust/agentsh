//go:build !linux

package externalrunner

import (
	"context"
	"fmt"
	"io"
	"os"
)

func validateHostMonitorDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return fmt.Errorf("unsafe directory identity or permissions")
	}
	return nil
}

func startHostRunner(Profile, HostMonitorLayout, uint32, *WorkspaceVolume, io.Writer) (hostRunner, error) {
	return nil, fmt.Errorf("external MicroVM host monitors are supported only on Linux")
}

func acquireHostMonitorLock(context.Context, string) (io.Closer, error) {
	return nil, fmt.Errorf("external MicroVM host monitors are supported only on Linux")
}
