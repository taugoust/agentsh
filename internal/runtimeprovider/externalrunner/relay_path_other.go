//go:build !linux

package externalrunner

import (
	"fmt"
	"path/filepath"
)

func hostMonitorRelayPath(_ string, hostDir string) string {
	return filepath.Join(hostDir, HostMonitorSocketName)
}

func prepareHostMonitorRelayPath(string) error {
	return fmt.Errorf("external MicroVM runners are supported only on Linux")
}
