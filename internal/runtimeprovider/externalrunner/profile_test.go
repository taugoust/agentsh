package externalrunner

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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
		Runner:        Runner{Path: runner, SHA256: digest(runnerData)},
		Guest: Guest{
			ProfileDigest: digest([]byte("guest-profile")),
			Policy:        "pi-autonomous", Workspace: "/workspace",
			Protocol: guestcontrol.ProtocolVersion, ControlPort: 18081, SupervisorPort: 18082,
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
