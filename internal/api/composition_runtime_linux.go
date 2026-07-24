//go:build linux

package api

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/nethelper"
	"golang.org/x/sys/unix"
)

type CompositionRuntimeEvidence struct {
	Mode        string
	ScratchRoot string
	LeaseID     string
}

func (a *App) compositionScratchRoot() (string, error) {
	if a == nil || a.cfg == nil {
		return "", fmt.Errorf("composition configuration is unavailable")
	}
	configured := a.cfg.Sandbox.Composition.Bubblewrap.ScratchRoot
	if configured != config.CompositionScratchRootAuto {
		if configured == "" || !filepath.IsAbs(configured) || filepath.Clean(configured) != configured {
			return "", fmt.Errorf("static composition scratch root is invalid")
		}
		return configured, nil
	}
	binding := a.nethelperBindingSnapshot()
	if binding.Kind != "ephemeral" || binding.LeaseID == "" || binding.CompositionScratchRoot == "" {
		return "", fmt.Errorf("automatic composition runtime requires an active ephemeral helper lease")
	}
	if binding.BootstrapSchemaVersion < nethelper.BootstrapSchemaVersion {
		return "", fmt.Errorf("helper bootstrap schema %d does not provide a composition runtime", binding.BootstrapSchemaVersion)
	}
	uid, gid, supported := helperCurrentUIDGID()
	if !supported || binding.UID != uid || binding.GID != gid {
		return "", fmt.Errorf("composition runtime lease identity does not match the supervisor")
	}
	if !binding.HardExpiresAt.IsZero() && !time.Now().UTC().Before(binding.HardExpiresAt) {
		return "", fmt.Errorf("composition runtime helper lease has expired")
	}
	expected, err := nethelper.EphemeralPathsForUID(binding.UID, binding.LeaseID)
	if err != nil || expected.CompositionScratchRoot != binding.CompositionScratchRoot {
		return "", fmt.Errorf("composition runtime path does not match the helper-selected lease topology")
	}
	attestation, err := a.authenticatedCompositionRuntimeAttestation(context.Background(), binding)
	if err != nil {
		return "", fmt.Errorf("authenticate composition runtime inode: %w", err)
	}
	if err := validateLeaseCompositionScratchRoot(binding.CompositionScratchRoot, expected.RuntimeDir, attestation.Attestation); err != nil {
		return "", err
	}
	return binding.CompositionScratchRoot, nil
}

func validateLeaseCompositionScratchRoot(path, runtimeDir string, attestation nethelper.CompositionRuntimeAttestation) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Dir(path) != runtimeDir {
		return fmt.Errorf("composition runtime path is not the fixed lease child")
	}
	for _, object := range []struct {
		label string
		path  string
	}{
		{label: "composition runtime", path: path},
		{label: "composition lease directory", path: runtimeDir},
	} {
		resolved, err := filepath.EvalSymlinks(object.path)
		if err != nil || filepath.Clean(resolved) != object.path {
			return fmt.Errorf("%s contains a symlink component", object.label)
		}
	}
	var runtimeStat unix.Stat_t
	if err := unix.Lstat(path, &runtimeStat); err != nil {
		return fmt.Errorf("stat composition runtime: %w", err)
	}
	if err := nethelper.ValidateCompositionScratchMetadata(attestation.Runtime.Mode, attestation.Runtime.UID, attestation.Runtime.GID); err != nil {
		return fmt.Errorf("helper attestation: %w", err)
	}
	if err := compareCompositionRuntimeInode("composition runtime", runtimeStat, attestation.Runtime); err != nil {
		return err
	}
	var parentStat unix.Stat_t
	if err := unix.Lstat(runtimeDir, &parentStat); err != nil {
		return fmt.Errorf("stat composition lease directory: %w", err)
	}
	if err := nethelper.ValidateCompositionLeaseDirectoryMetadata(attestation.LeaseDirectory.Mode, attestation.LeaseDirectory.UID, attestation.LeaseDirectory.GID); err != nil {
		return fmt.Errorf("helper attestation: %w", err)
	}
	return compareCompositionRuntimeInode("composition lease directory", parentStat, attestation.LeaseDirectory)
}

func compareCompositionRuntimeInode(label string, observed unix.Stat_t, attested nethelper.CompositionRuntimeInode) error {
	if uint64(observed.Dev) != attested.Device || observed.Ino != attested.Inode || observed.Mode != attested.Mode {
		return fmt.Errorf(
			"%s does not match authenticated helper inode (observed dev=%d ino=%d mode=%#o uid=%d gid=%d; attested dev=%d ino=%d mode=%#o host_uid=%d host_gid=%d)",
			label,
			uint64(observed.Dev),
			observed.Ino,
			observed.Mode,
			observed.Uid,
			observed.Gid,
			attested.Device,
			attested.Inode,
			attested.Mode,
			attested.UID,
			attested.GID,
		)
	}
	return nil
}

func (a *App) CompositionRuntimePreflight() (CompositionRuntimeEvidence, error) {
	root, err := a.compositionScratchRoot()
	if err != nil {
		return CompositionRuntimeEvidence{}, err
	}
	mode := "static"
	leaseID := ""
	if a.cfg.Sandbox.Composition.Bubblewrap.ScratchRoot == config.CompositionScratchRootAuto {
		mode = "lease"
		leaseID = a.nethelperBindingSnapshot().LeaseID
	} else {
		resolved, resolveErr := filepath.EvalSymlinks(root)
		info, statErr := os.Stat(root)
		if resolveErr != nil || filepath.Clean(resolved) != root || statErr != nil || !info.IsDir() {
			return CompositionRuntimeEvidence{}, fmt.Errorf("static composition runtime must be an existing non-symlink directory")
		}
	}
	return CompositionRuntimeEvidence{Mode: mode, ScratchRoot: root, LeaseID: leaseID}, nil
}
