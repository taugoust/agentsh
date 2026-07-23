//go:build linux

package nethelper

import (
	"strings"
	"testing"
)

func TestEphemeralPathsForUIDAreFixed(t *testing.T) {
	const lease = "lease-11111111-1111-4111-8111-111111111111"
	paths, err := EphemeralPathsForUID(1234, lease)
	if err != nil {
		t.Fatalf("EphemeralPathsForUID: %v", err)
	}
	for name, value := range map[string]string{
		"runtime":     paths.RuntimeDir,
		"socket":      paths.SocketPath,
		"credential":  paths.CredentialFile,
		"result":      paths.ResultFile,
		"composition": paths.CompositionScratchRoot,
		"pin":         paths.PinRoot,
		"unit":        paths.UnitName,
	} {
		if !strings.Contains(value, "1234") || !strings.Contains(value, "11111111-1111-4111-8111-111111111111") {
			t.Fatalf("%s path is not bound to uid and lease: %q", name, value)
		}
	}
	if !strings.HasPrefix(paths.RuntimeDir, "/run/agentsh/nethelper/1234/") {
		t.Fatalf("unexpected runtime dir: %s", paths.RuntimeDir)
	}
	if paths.CompositionScratchRoot != paths.RuntimeDir+"/composition" {
		t.Fatalf("unexpected composition scratch root: %s", paths.CompositionScratchRoot)
	}
	if !strings.HasPrefix(paths.PinRoot, "/sys/fs/bpf/agentsh/nethelper-ephemeral/1234/") || !strings.HasSuffix(paths.PinRoot, "/pins") {
		t.Fatalf("unexpected pin root: %s", paths.PinRoot)
	}
}

func TestValidateEphemeralLeaseID(t *testing.T) {
	if err := ValidateEphemeralLeaseID("lease-11111111-1111-4111-8111-111111111111"); err != nil {
		t.Fatalf("valid lease rejected: %v", err)
	}
	for _, lease := range []string{
		"",
		"session-11111111-1111-4111-8111-111111111111",
		"lease-1",
		"lease-00000000-0000-0000-0000-000000000000",
		"lease-11111111-1111-4111-8111-111111111111/../../root",
	} {
		if err := ValidateEphemeralLeaseID(lease); err == nil {
			t.Fatalf("invalid lease accepted: %q", lease)
		}
	}
}
