//go:build !linux

package externalrunner

import (
	"context"
	"fmt"
)

func launchDetachedHostMonitor(string, string) (HostProcessIdentity, error) {
	return HostProcessIdentity{}, fmt.Errorf("external MicroVM runners are supported only on Linux")
}

func stopExactHostMonitor(context.Context, HostProcessIdentity) error {
	return fmt.Errorf("external MicroVM runners are supported only on Linux")
}
