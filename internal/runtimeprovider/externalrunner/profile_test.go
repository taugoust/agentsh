package externalrunner

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agentsh/agentsh/internal/guestcontrol"
)

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func testProfile(t *testing.T) Profile {
	t.Helper()
	runnerData := []byte("#!/bin/sh\nexit 0\n")
	runner := filepath.Join(t.TempDir(), "microvm-run")
	if err := os.WriteFile(runner, runnerData, 0o555); err != nil {
		t.Fatal(err)
	}
	return Profile{
		Schema:        ProfileSchema,
		ProfileDigest: digest([]byte("operator-profile")),
		Name:          "pi-linux-qemu-v1",
		Provider:      ProviderName,
		Status:        "diagnostic",
		System:        "x86_64-linux",
		Runner:        Runner{Path: runner, SHA256: digest(runnerData), ProcessModel: "direct-exec"},
		Guest: Guest{
			ProfileDigest: digest([]byte("guest-profile")),
			Policy:        "pi-autonomous", Workspace: "/workspace",
			Protocol: guestcontrol.ProtocolVersionV2, ControlPort: 18081, SupervisorPort: 18082,
		},
		VSock:    VSock{CIDMin: 41000, CIDMax: 41999},
		Network:  Network{Transport: "qemu-user", Enforcement: "disabled-bringup"},
		Timeouts: Timeouts{ReadinessSeconds: 150, GracefulShutdownSeconds: 30},
	}
}

func writeProfile(t *testing.T, profile Profile) string {
	t.Helper()
	data, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "profile.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestReadProfileAndVerifyRunner(t *testing.T) {
	want := testProfile(t)
	got, err := ReadProfile(writeProfile(t, want))
	if err != nil {
		t.Fatal(err)
	}
	if got.Runner != want.Runner || got.Guest != want.Guest || got.Network != want.Network {
		t.Fatalf("profile = %+v, want %+v", got, want)
	}
	if err := got.VerifyRunner(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(got.Runner.Path, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(got.Runner.Path, []byte("replaced"), 0o555); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(got.Runner.Path, 0o555); err != nil {
		t.Fatal(err)
	}
	if err := got.VerifyRunner(); err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("replaced runner error = %v", err)
	}
}

func TestProfileV2RequiresExactWorkspaceVolumeContract(t *testing.T) {
	base := testProfile(t)
	base.Schema = ProfileSchemaV2
	base.Guest.Protocol = guestcontrol.ProtocolVersionV3
	base.WorkspaceVolume = &WorkspaceVolumeSpec{
		Model: WorkspaceVolumeModel, Format: WorkspaceVolumeFormat, Filesystem: WorkspaceVolumeFilesystem,
		RunnerFD: WorkspaceVolumeRunnerFD, VirtualSizeBytes: 8 << 30,
	}
	got, err := ReadProfile(writeProfile(t, base))
	if err != nil {
		t.Fatal(err)
	}
	if got.WorkspaceVolume == nil || *got.WorkspaceVolume != *base.WorkspaceVolume {
		t.Fatalf("workspace volume = %#v, want %#v", got.WorkspaceVolume, base.WorkspaceVolume)
	}

	tests := []struct {
		name   string
		mutate func(*Profile)
	}{
		{"missing", func(p *Profile) { p.WorkspaceVolume = nil }},
		{"model", func(p *Profile) { p.WorkspaceVolume.Model = "host-directory" }},
		{"format", func(p *Profile) { p.WorkspaceVolume.Format = "raw" }},
		{"filesystem", func(p *Profile) { p.WorkspaceVolume.Filesystem = "xfs" }},
		{"runner fd", func(p *Profile) { p.WorkspaceVolume.RunnerFD++ }},
		{"virtual size below minimum", func(p *Profile) { p.WorkspaceVolume.VirtualSizeBytes = WorkspaceVolumeMinVirtualSizeBytes - 1 }},
		{"virtual size above maximum", func(p *Profile) { p.WorkspaceVolume.VirtualSizeBytes = WorkspaceVolumeMaxVirtualSizeBytes + 1 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			profile := base
			spec := *base.WorkspaceVolume
			profile.WorkspaceVolume = &spec
			test.mutate(&profile)
			if err := profile.Validate(); err == nil {
				t.Fatal("invalid v2 workspace volume was accepted")
			}
		})
	}
}

func TestProfileSchemaRequiresBoundGuestProtocol(t *testing.T) {
	legacy := testProfile(t)
	if legacy.Guest.Protocol != guestcontrol.ProtocolVersionV2 || legacy.Validate() != nil {
		t.Fatalf("legacy profile protocol = %d", legacy.Guest.Protocol)
	}
	legacy.Guest.Protocol = guestcontrol.ProtocolVersionV3
	if err := legacy.Validate(); err == nil {
		t.Fatal("external profile v1 accepted guest protocol v3")
	}

	current := testProfile(t)
	current.Schema = ProfileSchemaV2
	current.Name = "pi-linux-qemu-v2"
	current.Guest.Protocol = guestcontrol.ProtocolVersionV3
	current.WorkspaceVolume = &WorkspaceVolumeSpec{
		Model: WorkspaceVolumeModel, Format: WorkspaceVolumeFormat, Filesystem: WorkspaceVolumeFilesystem,
		RunnerFD: WorkspaceVolumeRunnerFD, VirtualSizeBytes: 8 << 30,
	}
	if err := current.Validate(); err != nil {
		t.Fatalf("current profile: %v", err)
	}
	current.Guest.Protocol = guestcontrol.ProtocolVersionV2
	if err := current.Validate(); err == nil {
		t.Fatal("external profile v2 accepted guest protocol v2")
	}
}

func TestProfileV1StillRejectsWorkspaceVolume(t *testing.T) {
	profile := testProfile(t)
	profile.WorkspaceVolume = &WorkspaceVolumeSpec{
		Model: WorkspaceVolumeModel, Format: WorkspaceVolumeFormat, Filesystem: WorkspaceVolumeFilesystem,
		RunnerFD: WorkspaceVolumeRunnerFD, VirtualSizeBytes: 8 << 30,
	}
	if err := profile.Validate(); err == nil {
		t.Fatal("v1 profile with workspace volume was accepted")
	}

	for _, field := range []string{"workspace_volume", "WORKSPACE_VOLUME", "Workspace_Volume"} {
		t.Run(field, func(t *testing.T) {
			data, err := json.Marshal(testProfile(t))
			if err != nil {
				t.Fatal(err)
			}
			data[len(data)-1] = ','
			data = append(data, []byte(fmt.Sprintf("%q:null}", field))...)
			path := filepath.Join(t.TempDir(), "profile.json")
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := ReadProfile(path); err == nil || !strings.Contains(err.Error(), "unknown field") {
				t.Fatalf("v1 %s:null error = %v", field, err)
			}
		})
	}
}

func TestProfileRejectsUntrustedSelections(t *testing.T) {
	base := testProfile(t)
	tests := []struct {
		name   string
		mutate func(*Profile)
	}{
		{"schema", func(p *Profile) { p.Schema = "untrusted/v1" }},
		{"provider", func(p *Profile) { p.Provider = "native" }},
		{"profile digest", func(p *Profile) { p.ProfileDigest = "sha256:bad" }},
		{"runner path", func(p *Profile) { p.Runner.Path = "relative" }},
		{"runner process model", func(p *Profile) { p.Runner.ProcessModel = "sidecars" }},
		{"guest protocol", func(p *Profile) { p.Guest.Protocol-- }},
		{"ports reused", func(p *Profile) { p.Guest.SupervisorPort = p.Guest.ControlPort }},
		{"cid range", func(p *Profile) { p.VSock.CIDMin = p.VSock.CIDMax + 1 }},
		{"diagnostic admission", func(p *Profile) { p.Network.RequireReadyBeforePublish = true }},
		{"strict admission", func(p *Profile) { p.Status = "strict"; p.Network.Enforcement = "strict" }},
		{"timeout", func(p *Profile) { p.Timeouts.ReadinessSeconds = 0 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			profile := base
			test.mutate(&profile)
			if err := profile.Validate(); err == nil {
				t.Fatal("invalid external runner profile was accepted")
			}
		})
	}
}

func TestReadProfileRejectsUnknownAndWritableFiles(t *testing.T) {
	profile := testProfile(t)
	path := writeProfile(t, profile)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)-1] = ','
	data = append(data, []byte(`"unknown":true}`)...)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadProfile(path); err == nil {
		t.Fatal("profile with unknown fields was accepted")
	}
	path = writeProfile(t, profile)
	if err := os.Chmod(path, 0o622); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadProfile(path); err == nil {
		t.Fatal("writable external runner profile was accepted")
	}
}
