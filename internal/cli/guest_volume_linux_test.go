//go:build linux

package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agentsh/agentsh/internal/guestcontrol"
)

const testGuestVolumeID = "22222222-2222-4222-8222-222222222222"

type guestVolumeProofFixture struct {
	manifest   guestcontrol.Manifest
	volumeRoot string
	workspace  string
	mountInfo  []byte
}

func newGuestVolumeProofFixture(t *testing.T) guestVolumeProofFixture {
	t.Helper()
	volumeRoot := t.TempDir()
	if err := os.Mkdir(filepath.Join(volumeRoot, guestVolumeWorkspaceDirectory), 0o700); err != nil {
		t.Fatal(err)
	}
	workspace := filepath.Join(volumeRoot, guestVolumeWorkspaceDirectory)
	manifest := guestcontrol.Manifest{
		ProtocolVersion: guestcontrol.ProtocolVersionV3,
		SessionID:       "session-11111111-1111-4111-8111-111111111111",
		VolumeID:        testGuestVolumeID,
	}
	writeGuestVolumeIdentityFixture(t, volumeRoot, guestVolumeIdentity{
		SchemaVersion: guestVolumeIdentitySchemaVersion,
		SessionID:     manifest.SessionID,
		VolumeID:      manifest.VolumeID,
	})
	info, err := os.Lstat(volumeRoot)
	if err != nil {
		t.Fatal(err)
	}
	major, minor, err := guestFileDevice(info)
	if err != nil {
		t.Fatal(err)
	}
	mountInfo := fmt.Sprintf(
		"31 20 %d:%d / %s rw,relatime - ext4 /dev/vda rw\n32 20 %d:%d /workspace %s rw,relatime - ext4 /dev/vda rw\n",
		major, minor, volumeRoot, major, minor, workspace,
	)
	return guestVolumeProofFixture{manifest: manifest, volumeRoot: volumeRoot, workspace: workspace, mountInfo: []byte(mountInfo)}
}

func writeGuestVolumeIdentityFixture(t *testing.T, volumeRoot string, identity any) {
	t.Helper()
	data, err := json.Marshal(identity)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(volumeRoot, guestVolumeIdentityName), append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestGuestControlVolumeRootRequirementTracksProtocol(t *testing.T) {
	legacy := guestcontrol.Manifest{ProtocolVersion: guestcontrol.ProtocolVersionV2}
	if err := verifyGuestControlWorkspaceVolume(legacy, t.TempDir(), ""); err != nil {
		t.Fatalf("legacy protocol unexpectedly required a volume root: %v", err)
	}
	current := guestcontrol.Manifest{ProtocolVersion: guestcontrol.ProtocolVersionV3}
	if err := verifyGuestControlWorkspaceVolume(current, filepath.Join(string(filepath.Separator), guestVolumeWorkspaceDirectory), ""); err == nil || !strings.Contains(err.Error(), "--volume-root") {
		t.Fatalf("protocol v3 missing-volume-root error = %v", err)
	}
	if err := verifyGuestControlWorkspaceVolume(current, t.TempDir(), t.TempDir()); err == nil || !strings.Contains(err.Error(), "exact") {
		t.Fatalf("protocol v3 non-/workspace error = %v", err)
	}
}

func TestGuestControlAcceptsExactExt4VolumeAndWorkspaceSubmountProof(t *testing.T) {
	fixture := newGuestVolumeProofFixture(t)
	if err := verifyGuestControlWorkspaceVolumeSnapshot(fixture.manifest, fixture.workspace, fixture.volumeRoot, fixture.mountInfo); err != nil {
		t.Fatal(err)
	}
}

func TestGuestControlVolumeProofRejectsAdversarialMountInfo(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(guestVolumeProofFixture) []byte
	}{
		{
			name: "volume filesystem",
			mutate: func(f guestVolumeProofFixture) []byte {
				return []byte(strings.Replace(string(f.mountInfo), "- ext4 /dev/vda", "- xfs /dev/vda", 1))
			},
		},
		{
			name: "workspace filesystem",
			mutate: func(f guestVolumeProofFixture) []byte {
				index := strings.LastIndex(string(f.mountInfo), "- ext4 /dev/vda")
				data := string(f.mountInfo)
				return []byte(data[:index] + "- xfs /dev/vda" + data[index+len("- ext4 /dev/vda"):])
			},
		},
		{
			name: "volume root",
			mutate: func(f guestVolumeProofFixture) []byte {
				return []byte(strings.Replace(string(f.mountInfo), " / "+f.volumeRoot, " /other "+f.volumeRoot, 1))
			},
		},
		{
			name: "workspace root",
			mutate: func(f guestVolumeProofFixture) []byte {
				return []byte(strings.Replace(string(f.mountInfo), " /workspace "+f.workspace, " /other "+f.workspace, 1))
			},
		},
		{
			name: "workspace device",
			mutate: func(f guestVolumeProofFixture) []byte {
				lines := strings.Split(string(f.mountInfo), "\n")
				fields := strings.Fields(lines[1])
				fields[2] = "4095:1048575"
				lines[1] = strings.Join(fields, " ")
				return []byte(strings.Join(lines, "\n"))
			},
		},
		{
			name: "mountinfo device differs from stat",
			mutate: func(f guestVolumeProofFixture) []byte {
				lines := strings.Split(string(f.mountInfo), "\n")
				for index := 0; index < 2; index++ {
					fields := strings.Fields(lines[index])
					fields[2] = "4095:1048575"
					lines[index] = strings.Join(fields, " ")
				}
				return []byte(strings.Join(lines, "\n"))
			},
		},
		{
			name: "identity file overmount",
			mutate: func(f guestVolumeProofFixture) []byte {
				line := strings.Fields(strings.Split(string(f.mountInfo), "\n")[0])
				line[0] = "33"
				line[3] = "/identity"
				line[4] = filepath.Join(f.volumeRoot, guestVolumeIdentityName)
				return append(append([]byte(nil), f.mountInfo...), []byte(strings.Join(line, " ")+"\n")...)
			},
		},
		{
			name: "duplicate exact mount",
			mutate: func(f guestVolumeProofFixture) []byte {
				return append(append([]byte(nil), f.mountInfo...), f.mountInfo...)
			},
		},
		{
			name: "escaped mountpoint substitution",
			mutate: func(f guestVolumeProofFixture) []byte {
				return []byte(strings.Replace(string(f.mountInfo), f.workspace+" rw", f.workspace+"\\057substituted rw", 1))
			},
		},
		{
			name: "unclean escaped root",
			mutate: func(f guestVolumeProofFixture) []byte {
				return []byte(strings.Replace(string(f.mountInfo), " /workspace ", " /workspace/..\\040/other ", 1))
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newGuestVolumeProofFixture(t)
			if err := verifyGuestControlWorkspaceVolumeSnapshot(fixture.manifest, fixture.workspace, fixture.volumeRoot, test.mutate(fixture)); err == nil {
				t.Fatal("adversarial mountinfo was accepted")
			}
		})
	}
}

func TestGuestControlVolumeProofRejectsSymlinkedPaths(t *testing.T) {
	t.Run("volume root", func(t *testing.T) {
		fixture := newGuestVolumeProofFixture(t)
		link := filepath.Join(t.TempDir(), "volume-link")
		if err := os.Symlink(fixture.volumeRoot, link); err != nil {
			t.Fatal(err)
		}
		if err := verifyGuestControlWorkspaceVolumeSnapshot(fixture.manifest, fixture.workspace, link, fixture.mountInfo); err == nil || !strings.Contains(err.Error(), "symlink") {
			t.Fatalf("symlinked volume root error = %v", err)
		}
	})
	t.Run("workspace subdirectory", func(t *testing.T) {
		fixture := newGuestVolumeProofFixture(t)
		subdirectory := filepath.Join(fixture.volumeRoot, guestVolumeWorkspaceDirectory)
		if err := os.Remove(subdirectory); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(t.TempDir(), subdirectory); err != nil {
			t.Fatal(err)
		}
		if err := verifyGuestControlWorkspaceVolumeSnapshot(fixture.manifest, fixture.workspace, fixture.volumeRoot, fixture.mountInfo); err == nil || !strings.Contains(err.Error(), "symlink") {
			t.Fatalf("symlinked volume workspace error = %v", err)
		}
	})
	t.Run("identity", func(t *testing.T) {
		fixture := newGuestVolumeProofFixture(t)
		identityPath := filepath.Join(fixture.volumeRoot, guestVolumeIdentityName)
		if err := os.Remove(identityPath); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(t.TempDir(), guestVolumeIdentityName)
		if err := os.WriteFile(target, []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, identityPath); err != nil {
			t.Fatal(err)
		}
		if err := verifyGuestControlWorkspaceVolumeSnapshot(fixture.manifest, fixture.workspace, fixture.volumeRoot, fixture.mountInfo); err == nil {
			t.Fatal("symlinked volume identity was accepted")
		}
	})
	t.Run("hard-linked identity", func(t *testing.T) {
		fixture := newGuestVolumeProofFixture(t)
		identityPath := filepath.Join(fixture.volumeRoot, guestVolumeIdentityName)
		if err := os.Link(identityPath, filepath.Join(fixture.volumeRoot, "identity-alias")); err != nil {
			t.Fatal(err)
		}
		if err := verifyGuestControlWorkspaceVolumeSnapshot(fixture.manifest, fixture.workspace, fixture.volumeRoot, fixture.mountInfo); err == nil {
			t.Fatal("hard-linked volume identity was accepted")
		}
	})
}

func TestGuestControlVolumeProofRejectsMalformedOrMismatchedIdentity(t *testing.T) {
	tests := []struct {
		name     string
		identity any
		raw      string
		mode     os.FileMode
	}{
		{name: "schema", identity: guestVolumeIdentity{SchemaVersion: 2, SessionID: "session-11111111-1111-4111-8111-111111111111", VolumeID: testGuestVolumeID}, mode: 0o600},
		{name: "session", identity: guestVolumeIdentity{SchemaVersion: 1, SessionID: "session-aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", VolumeID: testGuestVolumeID}, mode: 0o600},
		{name: "volume", identity: guestVolumeIdentity{SchemaVersion: 1, SessionID: "session-11111111-1111-4111-8111-111111111111", VolumeID: "33333333-3333-4333-8333-333333333333"}, mode: 0o600},
		{name: "unknown field", raw: `{"schema_version":1,"session_id":"session-11111111-1111-4111-8111-111111111111","volume_id":"22222222-2222-4222-8222-222222222222","unknown":true}`, mode: 0o600},
		{name: "duplicate field", raw: `{"schema_version":1,"session_id":"session-11111111-1111-4111-8111-111111111111","volume_id":"22222222-2222-4222-8222-222222222222","volume_id":"22222222-2222-4222-8222-222222222222"}`, mode: 0o600},
		{name: "trailing JSON", raw: `{"schema_version":1,"session_id":"session-11111111-1111-4111-8111-111111111111","volume_id":"22222222-2222-4222-8222-222222222222"} {}`, mode: 0o600},
		{name: "malformed", raw: `{`, mode: 0o600},
		{name: "public permissions", identity: guestVolumeIdentity{SchemaVersion: 1, SessionID: "session-11111111-1111-4111-8111-111111111111", VolumeID: testGuestVolumeID}, mode: 0o644},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newGuestVolumeProofFixture(t)
			path := filepath.Join(fixture.volumeRoot, guestVolumeIdentityName)
			var data []byte
			if test.raw != "" {
				data = []byte(test.raw)
			} else {
				var err error
				data, err = json.Marshal(test.identity)
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(path, data, test.mode); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, test.mode); err != nil {
				t.Fatal(err)
			}
			if err := verifyGuestControlWorkspaceVolumeSnapshot(fixture.manifest, fixture.workspace, fixture.volumeRoot, fixture.mountInfo); err == nil {
				t.Fatal("malformed or mismatched volume identity was accepted")
			}
		})
	}
}
