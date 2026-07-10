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

func TestRawSocketCreationDeniedAcceptsFixedSeccompErrno(t *testing.T) {
	for _, err := range []error{syscall.EPERM, syscall.EACCES, syscall.EAFNOSUPPORT} {
		if !rawSocketCreationDenied(err) {
			t.Fatalf("raw socket denial %v was not accepted", err)
		}
	}
	for _, err := range []error{nil, syscall.EPROTONOSUPPORT, syscall.EINVAL, errors.New("unrelated")} {
		if rawSocketCreationDenied(err) {
			t.Fatalf("unrelated error %v counted as raw socket denial evidence", err)
		}
	}
}
