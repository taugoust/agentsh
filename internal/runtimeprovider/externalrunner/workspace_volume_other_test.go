//go:build !linux

package externalrunner

import (
	"context"
	"errors"
	"testing"
)

func TestWorkspaceVolumeAPIsAreUnsupportedOffLinux(t *testing.T) {
	if volume, err := CreateWorkspaceVolume(context.Background(), WorkspaceVolumeRequest{}, ""); volume != nil || !errors.Is(err, ErrWorkspaceVolumeUnsupported) {
		t.Fatalf("CreateWorkspaceVolume = %#v, %v", volume, err)
	}
	if volume, err := OpenWorkspaceVolume(context.Background(), WorkspaceVolumeRequest{}, ""); volume != nil || !errors.Is(err, ErrWorkspaceVolumeUnsupported) {
		t.Fatalf("OpenWorkspaceVolume = %#v, %v", volume, err)
	}
	if err := DeleteWorkspaceVolume(context.Background(), WorkspaceVolumeRequest{}, ""); !errors.Is(err, ErrWorkspaceVolumeUnsupported) {
		t.Fatalf("DeleteWorkspaceVolume = %v", err)
	}
}
