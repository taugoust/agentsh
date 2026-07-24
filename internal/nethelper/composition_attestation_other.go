//go:build !linux

package nethelper

import "fmt"

func attestCompositionRuntimeForLease(uint32, string) (CompositionRuntimeAttestation, error) {
	return CompositionRuntimeAttestation{}, fmt.Errorf("composition runtime attestation is supported only on Linux")
}
