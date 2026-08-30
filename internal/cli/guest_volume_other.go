//go:build !linux

package cli

import (
	"fmt"

	"github.com/agentsh/agentsh/internal/guestcontrol"
)

func verifyGuestControlWorkspaceVolume(manifest guestcontrol.Manifest, _, _ string) error {
	if manifest.ProtocolVersion == guestcontrol.ProtocolVersionV2 {
		return nil
	}
	if manifest.ProtocolVersion == guestcontrol.ProtocolVersionV3 {
		return fmt.Errorf("guest control protocol version 3 workspace-volume proof is supported only on Linux")
	}
	if manifest.ProtocolVersion == guestcontrol.ProtocolVersionV4 {
		return fmt.Errorf("guest control protocol version 4 workspace-volume proof is supported only on Linux")
	}
	return fmt.Errorf("guest control protocol version %d is unsupported", manifest.ProtocolVersion)
}
