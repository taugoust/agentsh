//go:build linux

package api

import (
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
	if err := validateLeaseCompositionScratchRoot(binding.CompositionScratchRoot, expected.RuntimeDir); err != nil {
		return "", err
	}
	return binding.CompositionScratchRoot, nil
}

func validateLeaseCompositionScratchRoot(path, runtimeDir string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Dir(path) != runtimeDir {
		return fmt.Errorf("composition runtime path is not the fixed lease child")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || filepath.Clean(resolved) != path {
		return fmt.Errorf("composition runtime contains a symlink component")
	}
	var runtimeStat unix.Stat_t
	if err := unix.Lstat(path, &runtimeStat); err != nil {
		return fmt.Errorf("stat composition runtime: %w", err)
	}
	if err := nethelper.ValidateCompositionScratchMetadata(runtimeStat.Mode, runtimeStat.Uid, runtimeStat.Gid); err != nil {
		return err
	}
	var parentStat unix.Stat_t
	if err := unix.Lstat(runtimeDir, &parentStat); err != nil {
		return fmt.Errorf("stat composition lease directory: %w", err)
	}
	parentType := parentStat.Mode & uint32(unix.S_IFMT)
	parentMode := parentStat.Mode & uint32(unix.S_ISUID|unix.S_ISGID|unix.S_ISVTX|0o777)
	if parentType != uint32(unix.S_IFDIR) || parentMode&0o022 != 0 || parentStat.Uid != 0 || parentStat.Gid != 0 {
		return fmt.Errorf(
			"composition lease directory has unsafe type, mode, or ownership (type=%#o mode=%#o uid=%d gid=%d)",
			parentType,
			parentMode,
			parentStat.Uid,
			parentStat.Gid,
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
