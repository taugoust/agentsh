//go:build !linux

package ebpf

import (
	"fmt"

	"github.com/cilium/ebpf"
)

// EmbeddedMapDefaults is unavailable on non-Linux platforms because BPF objects
// are generated only as part of Linux Nix builds.
func EmbeddedMapDefaults() (MapOverrides, error) {
	return MapOverrides{}, fmt.Errorf("ebpf objects are not built on this platform")
}

// LoadConnectProgram is unavailable on non-Linux platforms.
func LoadConnectProgram() (*ebpf.Collection, error) {
	return nil, fmt.Errorf("ebpf connect program is not supported on this platform")
}
