//go:build !linux

package nethelper

import (
	"fmt"
	"net"
)

type EphemeralLeasePaths struct {
	LeaseID                string `json:"lease_id"`
	UnitName               string `json:"unit_name"`
	RuntimeDir             string `json:"runtime_dir"`
	SocketPath             string `json:"socket_path"`
	CredentialFile         string `json:"credential_file"`
	RootCredential         string `json:"-"`
	ResultFile             string `json:"result_file"`
	CompositionScratchRoot string `json:"composition_scratch_root"`
	PinLeaseDir            string `json:"-"`
	PinRoot                string `json:"pin_root"`
}

func ValidateEphemeralLeaseID(string) error {
	return fmt.Errorf("ephemeral nethelper leases are supported only on Linux")
}

func EphemeralPathsForUID(uint32, string) (EphemeralLeasePaths, error) {
	return EphemeralLeasePaths{}, fmt.Errorf("ephemeral nethelper leases are supported only on Linux")
}

func ValidateEphemeralServiceInvocation(uint32, string) (EphemeralLeasePaths, error) {
	return EphemeralLeasePaths{}, fmt.Errorf("ephemeral nethelper leases are supported only on Linux")
}

func ValidateHelperSocketForUID(string, uint32) error {
	return fmt.Errorf("ephemeral nethelper leases are supported only on Linux")
}

func ListenEphemeralUnixForUID(string, uint32, uint32) (net.Listener, error) {
	return nil, fmt.Errorf("ephemeral nethelper leases are supported only on Linux")
}

func DropEphemeralSetupCapabilities() error {
	return fmt.Errorf("ephemeral nethelper leases are supported only on Linux")
}
