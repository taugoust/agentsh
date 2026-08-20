//go:build linux && cgo

package main

import (
	"errors"
	"path/filepath"
	"reflect"
	"testing"
)

func TestCompleteCommandJailSetupPublishesCompositionAfterVerifiedBoundary(t *testing.T) {
	var got []string
	step := func(name string) func() error {
		return func() error {
			got = append(got, name)
			return nil
		}
	}

	err := completeCommandJailSetup(commandJailSetupOps{
		makeMountsPrivate:      step("mount-propagation-private"),
		installPrivateProc:     step("install-private-proc"),
		refreshLandlock:        step("refresh-landlock"),
		prepareComposition:     step("prepare-composition"),
		installRemainingMounts: step("install-remaining-mounts"),
		publishComposition:     step("publish-composition"),
		enforceLandlock:        func() { got = append(got, "enforce-landlock") },
		dropPrivileges:         step("drop-privileges"),
		installSeccomp:         step("install-final-seccomp"),
		protectDescriptors:     step("protect-descriptors"),
		verifyPrivileges:       step("verify-privileges"),
	})
	if err != nil {
		t.Fatalf("completeCommandJailSetup: %v", err)
	}

	want := []string{
		"mount-propagation-private",
		"install-private-proc",
		"refresh-landlock",
		"prepare-composition",
		"install-remaining-mounts",
		"enforce-landlock",
		"drop-privileges",
		"install-final-seccomp",
		"protect-descriptors",
		"verify-privileges",
		"publish-composition",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("setup order = %v, want %v", got, want)
	}
}

func TestPathHiddenByDirectoryTreesPreservesOnlyExplicitRuntimeSubtrees(t *testing.T) {
	root := filepath.Join(string(filepath.Separator), "state", "session")
	workspace := filepath.Join(root, "workspace")
	trees := []HiddenDirectoryTree{{Path: root, PreserveDirectories: []string{workspace}}}

	for _, path := range []string{
		filepath.Join(root, "recovery.json"),
		filepath.Join(root, "logs", "supervisor.log"),
		filepath.Join(root, "future-control-file"),
	} {
		if !pathHiddenByDirectoryTrees(path, trees) {
			t.Fatalf("control path %q is not hidden", path)
		}
	}
	for _, path := range []string{workspace, filepath.Join(workspace, "project", "file")} {
		if pathHiddenByDirectoryTrees(path, trees) {
			t.Fatalf("preserved path %q is hidden", path)
		}
	}
	if pathHiddenByDirectoryTrees(filepath.Join(string(filepath.Separator), "unrelated"), trees) {
		t.Fatal("unrelated path is hidden by detached state tree")
	}
}

func TestScrubCommandJailEnvRemovesHelperRuntimeControls(t *testing.T) {
	got := scrubCommandJailEnv([]string{
		"PATH=/bin",
		"AGENTSH_NETHELPER_BOOTSTRAP_RESULT=/run/agentsh/nethelper/bootstrap.json",
		"agentsh_nethelper_recovery_token_file=/run/agentsh-wrapper-control/token",
	})
	want := []string{"PATH=/bin"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("scrubbed environment = %v, want %v", got, want)
	}
}

func TestCompleteCommandJailSetupDoesNotRefreshOrApplyLandlockAfterMountFailure(t *testing.T) {
	mountErr := errors.New("injected mount failure")
	landlockRefreshed := false
	landlockApplied := false
	err := completeCommandJailSetup(commandJailSetupOps{
		makeMountsPrivate: func() error { return mountErr },
		refreshLandlock:   func() error { landlockRefreshed = true; return nil },
		enforceLandlock:   func() { landlockApplied = true },
	})
	if !errors.Is(err, mountErr) {
		t.Fatalf("error = %v, want %v", err, mountErr)
	}
	if landlockRefreshed || landlockApplied {
		t.Fatal("Landlock was refreshed or applied after an incomplete mount boundary")
	}
}
