//go:build linux

package nethelper

import (
	"fmt"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func attestCompositionRuntimeForLease(uid uint32, leaseID string) (CompositionRuntimeAttestation, error) {
	paths, err := EphemeralPathsForUID(uid, leaseID)
	if err != nil {
		return CompositionRuntimeAttestation{}, err
	}
	if filepath.Dir(paths.CompositionScratchRoot) != paths.RuntimeDir {
		return CompositionRuntimeAttestation{}, fmt.Errorf("composition runtime is not the fixed lease child")
	}
	for _, object := range []struct {
		label string
		path  string
	}{
		{label: "composition runtime", path: paths.CompositionScratchRoot},
		{label: "composition lease directory", path: paths.RuntimeDir},
	} {
		resolved, err := filepath.EvalSymlinks(object.path)
		if err != nil || filepath.Clean(resolved) != object.path {
			return CompositionRuntimeAttestation{}, fmt.Errorf("%s contains a symlink component", object.label)
		}
	}

	var runtimeStat unix.Stat_t
	if err := unix.Lstat(paths.CompositionScratchRoot, &runtimeStat); err != nil {
		return CompositionRuntimeAttestation{}, fmt.Errorf("stat composition runtime: %w", err)
	}
	if err := ValidateCompositionScratchMetadata(runtimeStat.Mode, runtimeStat.Uid, runtimeStat.Gid); err != nil {
		return CompositionRuntimeAttestation{}, err
	}
	var parentStat unix.Stat_t
	if err := unix.Lstat(paths.RuntimeDir, &parentStat); err != nil {
		return CompositionRuntimeAttestation{}, fmt.Errorf("stat composition lease directory: %w", err)
	}
	if err := ValidateCompositionLeaseDirectoryMetadata(parentStat.Mode, parentStat.Uid, parentStat.Gid); err != nil {
		return CompositionRuntimeAttestation{}, err
	}
	return CompositionRuntimeAttestation{
		Runtime:        compositionRuntimeInode(runtimeStat),
		LeaseDirectory: compositionRuntimeInode(parentStat),
	}, nil
}

func compositionRuntimeInode(stat unix.Stat_t) CompositionRuntimeInode {
	return CompositionRuntimeInode{
		Device: uint64(stat.Dev),
		Inode:  stat.Ino,
		Mode:   stat.Mode,
		UID:    stat.Uid,
		GID:    stat.Gid,
	}
}
