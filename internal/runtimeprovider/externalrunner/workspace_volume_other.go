//go:build !linux

package externalrunner

import "context"

func createWorkspaceVolume(context.Context, WorkspaceVolumeRequest, string) (*WorkspaceVolume, error) {
	return nil, ErrWorkspaceVolumeUnsupported
}

func openWorkspaceVolume(context.Context, WorkspaceVolumeRequest, string) (*WorkspaceVolume, error) {
	return nil, ErrWorkspaceVolumeUnsupported
}

func deleteWorkspaceVolume(context.Context, WorkspaceVolumeRequest, string) error {
	return ErrWorkspaceVolumeUnsupported
}
