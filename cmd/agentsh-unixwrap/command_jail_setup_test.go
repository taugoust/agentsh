//go:build linux && cgo

package main

import (
	"errors"
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
		makeMountsPrivate:  step("mount-propagation-private"),
		prepareComposition: step("prepare-composition"),
		installMounts:      step("install-command-jail-mounts"),
		publishComposition: step("publish-composition"),
		enforceLandlock:    func() { got = append(got, "enforce-landlock") },
		dropPrivileges:     step("drop-privileges"),
		installSeccomp:     step("install-final-seccomp"),
		protectDescriptors: step("protect-descriptors"),
		verifyPrivileges:   step("verify-privileges"),
	})
	if err != nil {
		t.Fatalf("completeCommandJailSetup: %v", err)
	}

	want := []string{
		"mount-propagation-private",
		"prepare-composition",
		"install-command-jail-mounts",
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

func TestCompleteCommandJailSetupDoesNotApplyLandlockAfterMountFailure(t *testing.T) {
	mountErr := errors.New("injected mount failure")
	landlockApplied := false
	err := completeCommandJailSetup(commandJailSetupOps{
		makeMountsPrivate: func() error { return mountErr },
		enforceLandlock:   func() { landlockApplied = true },
	})
	if !errors.Is(err, mountErr) {
		t.Fatalf("error = %v, want %v", err, mountErr)
	}
	if landlockApplied {
		t.Fatal("Landlock was applied after an incomplete mount boundary")
	}
}
