//go:build !linux

package cli

import (
	"strings"
	"testing"

	"github.com/agentsh/agentsh/internal/guestcontrol"
)

func TestGuestControlProtocol3VolumeProofIsUnsupportedOffLinux(t *testing.T) {
	manifest := guestcontrol.Manifest{ProtocolVersion: guestcontrol.ProtocolVersionV3}
	if err := verifyGuestControlWorkspaceVolume(manifest, "", ""); err == nil || !strings.Contains(err.Error(), "only on Linux") {
		t.Fatalf("non-Linux protocol-v3 error = %v", err)
	}
	manifest.ProtocolVersion = guestcontrol.ProtocolVersionV2
	if err := verifyGuestControlWorkspaceVolume(manifest, "", ""); err != nil {
		t.Fatalf("non-Linux retained protocol-v2 error = %v", err)
	}
}
