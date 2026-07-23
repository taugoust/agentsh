//go:build linux

package api

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/nethelper"
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
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("stat composition runtime: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0o733 || info.Mode()&os.ModeSticky == 0 || !ok || stat == nil || stat.Uid != 0 || stat.Gid != 0 {
		return fmt.Errorf("composition runtime has unsafe type, mode, or ownership")
	}
	parentInfo, err := os.Lstat(runtimeDir)
	if err != nil {
		return fmt.Errorf("stat composition lease directory: %w", err)
	}
	parentStat, ok := parentInfo.Sys().(*syscall.Stat_t)
	if parentInfo.Mode()&os.ModeSymlink != 0 || !parentInfo.IsDir() || parentInfo.Mode().Perm()&0o022 != 0 || !ok || parentStat == nil || parentStat.Uid != 0 || parentStat.Gid != 0 {
		return fmt.Errorf("composition lease directory has unsafe type, mode, or ownership")
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
