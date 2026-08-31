//go:build windows

package permissiongate

import (
	"context"
	"errors"
	"testing"
)

func TestPermissionGateRunUnsupportedOnWindows(t *testing.T) {
	_, err := Run(context.Background(), RunOptions{Command: []string{"pi"}})
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Run() error = %v, want ErrUnsupported", err)
	}
}
