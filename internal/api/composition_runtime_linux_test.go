//go:build linux

package api

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/nethelper"
	"golang.org/x/sys/unix"
)

func TestCompositionRuntimePreflightAcceptsExistingStaticRoot(t *testing.T) {
	root := t.TempDir()
	app := &App{cfg: &config.Config{}}
	app.cfg.Sandbox.Composition.Bubblewrap.ScratchRoot = root
	evidence, err := app.CompositionRuntimePreflight()
	if err != nil {
		t.Fatal(err)
	}
	if evidence.Mode != "static" || evidence.ScratchRoot != root || evidence.LeaseID != "" {
		t.Fatalf("evidence = %+v", evidence)
	}
}

func TestCompositionRuntimeAutoRequiresProtectedLeaseMetadata(t *testing.T) {
	app := &App{cfg: &config.Config{}, nethelperBinding: &nethelperBindingState{}}
	app.cfg.Sandbox.Composition.Bubblewrap.ScratchRoot = config.CompositionScratchRootAuto
	_, err := app.CompositionRuntimePreflight()
	if err == nil || !strings.Contains(err.Error(), "active ephemeral helper lease") {
		t.Fatalf("preflight error = %v", err)
	}
}

func TestValidateLeaseCompositionScratchRootRejectsArbitraryPath(t *testing.T) {
	runtimeDir := t.TempDir()
	path := filepath.Join(t.TempDir(), "composition")
	if err := validateLeaseCompositionScratchRoot(path, runtimeDir, nethelper.CompositionRuntimeAttestation{}); err == nil {
		t.Fatal("arbitrary composition path accepted")
	}
}

func TestValidateLeaseCompositionScratchRootAcceptsAuthenticatedHostRootInode(t *testing.T) {
	runtimeDir := t.TempDir()
	path := filepath.Join(runtimeDir, "composition")
	if err := os.Mkdir(path, os.ModeSticky|0o733); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, os.ModeSticky|0o733); err != nil {
		t.Fatal(err)
	}
	attestation := compositionRuntimeTestAttestation(t, path, runtimeDir)
	if err := validateLeaseCompositionScratchRoot(path, runtimeDir, attestation); err != nil {
		t.Fatalf("authenticated host-root inode rejected: %v", err)
	}

	mismatch := attestation
	mismatch.Runtime.Inode++
	if err := validateLeaseCompositionScratchRoot(path, runtimeDir, mismatch); err == nil || !strings.Contains(err.Error(), "does not match authenticated helper inode") {
		t.Fatalf("mismatched helper inode error = %v", err)
	}

	unsafeOwner := attestation
	unsafeOwner.Runtime.UID = 1000
	if err := validateLeaseCompositionScratchRoot(path, runtimeDir, unsafeOwner); err == nil || !strings.Contains(err.Error(), "helper attestation") {
		t.Fatalf("unsafe attested owner error = %v", err)
	}
}

func compositionRuntimeTestAttestation(t *testing.T, path, runtimeDir string) nethelper.CompositionRuntimeAttestation {
	t.Helper()
	var runtimeStat, parentStat unix.Stat_t
	if err := unix.Lstat(path, &runtimeStat); err != nil {
		t.Fatal(err)
	}
	if err := unix.Lstat(runtimeDir, &parentStat); err != nil {
		t.Fatal(err)
	}
	return nethelper.CompositionRuntimeAttestation{
		Runtime: nethelper.CompositionRuntimeInode{
			Device: uint64(runtimeStat.Dev), Inode: runtimeStat.Ino, Mode: runtimeStat.Mode, UID: 0, GID: 0,
		},
		LeaseDirectory: nethelper.CompositionRuntimeInode{
			Device: uint64(parentStat.Dev), Inode: parentStat.Ino, Mode: parentStat.Mode, UID: 0, GID: 0,
		},
	}
}
