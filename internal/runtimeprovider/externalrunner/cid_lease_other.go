//go:build !linux

package externalrunner

import (
	"context"
	"fmt"
)

func allocateCID(context.Context, string, string, uint32, uint32) (CIDLease, error) {
	return CIDLease{}, fmt.Errorf("external MicroVM runner CID allocation is supported only on Linux")
}

func verifyCID(context.Context, string, CIDLease, uint32, uint32) error {
	return fmt.Errorf("external MicroVM runner CID allocation is supported only on Linux")
}

func releaseCID(context.Context, string, CIDLease, uint32, uint32) error {
	return fmt.Errorf("external MicroVM runner CID allocation is supported only on Linux")
}
