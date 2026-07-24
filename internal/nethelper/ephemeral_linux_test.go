//go:build linux

package nethelper

import (
	"strings"
	"testing"

	"golang.org/x/sys/unix"
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

func TestValidateCompositionScratchMetadata(t *testing.T) {
	const validMode = uint32(unix.S_IFDIR | unix.S_ISVTX | 0o733)
	if err := ValidateCompositionScratchMetadata(validMode, 0, 0); err != nil {
		t.Fatalf("valid metadata rejected: %v", err)
	}
	for _, test := range []struct {
		name string
		mode uint32
		uid  uint32
		gid  uint32
	}{
		{name: "regular file", mode: uint32(unix.S_IFREG | unix.S_ISVTX | 0o733)},
		{name: "missing sticky", mode: uint32(unix.S_IFDIR | 0o733)},
		{name: "missing owner write", mode: uint32(unix.S_IFDIR | unix.S_ISVTX | 0o533)},
		{name: "unexpected setuid", mode: validMode | uint32(unix.S_ISUID)},
		{name: "unexpected setgid", mode: validMode | uint32(unix.S_ISGID)},
		{name: "wrong uid", mode: validMode, uid: 2016},
		{name: "wrong gid", mode: validMode, gid: 100},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateCompositionScratchMetadata(test.mode, test.uid, test.gid)
			if err == nil {
				t.Fatal("unsafe metadata accepted")
			}
			for _, detail := range []string{"type=", "mode=", "uid=", "gid="} {
				if !strings.Contains(err.Error(), detail) {
					t.Fatalf("error %q does not contain %q", err, detail)
				}
			}
		})
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
