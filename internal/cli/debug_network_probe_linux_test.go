//go:build linux

package cli

import (
	"errors"
	"syscall"
	"testing"
)

func TestGatePermissionDeniedRequiresKernelDenial(t *testing.T) {
	if !gatePermissionDenied(syscall.EPERM) || !gatePermissionDenied(syscall.EACCES) {
		t.Fatal("EPERM/EACCES must count as gate denial evidence")
	}
	for _, err := range []error{nil, syscall.ECONNREFUSED, syscall.ETIMEDOUT, errors.New("no UDP reply")} {
		if gatePermissionDenied(err) {
			t.Fatalf("unrelated error %v counted as gate denial evidence", err)
		}
	}
}
