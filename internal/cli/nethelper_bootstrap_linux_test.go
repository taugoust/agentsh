//go:build linux

package cli

import (
	"strings"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/nethelper"
)

func TestEphemeralSystemdRunArgsAreFixedAndSecretFree(t *testing.T) {
	paths, err := nethelper.EphemeralPathsForUID(1000, "lease-11111111-1111-4111-8111-111111111111")
	if err != nil {
		t.Fatal(err)
	}
	launcher := "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-agentsh/bin/agentsh"
	startedAt := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	args := ephemeralSystemdRunArgs(paths, launcher, 1000, 100, nethelper.MaximumBootstrapRuntime, startedAt)
	joined := strings.Join(args, "\n")
	for _, required := range []string{
		"--collect",
		"--service-type=exec",
		"--unit=" + paths.UnitName,
		"--property=LoadCredential=" + nethelperSystemdCredentialName + ":" + paths.RootCredential,
		"--property=RuntimeDirectory=" + strings.TrimPrefix(paths.RuntimeDir, "/run/"),
		"--property=RuntimeMaxSec=691200s",
		"--property=ReadWritePaths=" + paths.RuntimeDir + " " + paths.PinLeaseDir,
		"--property=CapabilityBoundingSet=CAP_BPF CAP_NET_ADMIN CAP_PERFMON CAP_CHOWN",
		"--property=AmbientCapabilities=CAP_BPF CAP_NET_ADMIN CAP_PERFMON",
		"--property=NoNewPrivileges=yes",
		"--property=RestrictAddressFamilies=AF_UNIX",
		launcher,
		"--ephemeral-lease",
		paths.LeaseID,
		"--ephemeral-created-at",
		startedAt.Format(time.RFC3339),
		"--ephemeral-hard-expiry",
		startedAt.Add(nethelper.MaximumBootstrapRuntime).Format(time.RFC3339),
	} {
		if !strings.Contains(joined, required) {
			t.Fatalf("systemd-run args missing %q:\n%s", required, joined)
		}
	}
	for _, forbidden := range []string{"sudo", "sh -c", "bash -c", "helper_instance_credential=", "--ephemeral-soft-lease"} {
		if strings.Contains(strings.ToLower(joined), forbidden) {
			t.Fatalf("systemd-run args contain forbidden value %q:\n%s", forbidden, joined)
		}
	}
}

func TestNethelperBootstrapRuntimeDefaultIsBackwardCompatible(t *testing.T) {
	cmd := newNethelperBootstrapCmd()
	flag := cmd.Flags().Lookup("runtime")
	if flag == nil || flag.DefValue != nethelper.DefaultBootstrapRuntime.String() {
		t.Fatalf("runtime flag=%v", flag)
	}
	soft := cmd.Flags().Lookup("soft-lease")
	if soft == nil || soft.DefValue != "0s" {
		t.Fatalf("soft lease flag=%v", soft)
	}
}

func TestEphemeralSystemdRunArgsNegotiatesSoftLease(t *testing.T) {
	paths, err := nethelper.EphemeralPathsForUID(1000, "lease-11111111-1111-4111-8111-111111111111")
	if err != nil {
		t.Fatal(err)
	}
	args := ephemeralSystemdRunArgsWithSoftLease(paths, "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-agentsh/bin/agentsh", 1000, 100, 192*time.Hour, 49*time.Hour, time.Now().UTC().Truncate(time.Second))
	joined := strings.Join(args, "\n")
	if !strings.Contains(joined, "--ephemeral-soft-lease\n49h0m0s") {
		t.Fatalf("soft lease not passed to serve:\n%s", joined)
	}
}

func TestValidateEphemeralNethelperRuntime(t *testing.T) {
	for _, valid := range []time.Duration{nethelper.DefaultBootstrapRuntime, nethelper.MaximumBootstrapRuntime} {
		if err := validateEphemeralNethelperRuntime(valid); err != nil {
			t.Fatalf("runtime %s rejected: %v", valid, err)
		}
	}
	for _, invalid := range []time.Duration{0, -time.Second, nethelper.MaximumBootstrapRuntime + time.Second, time.Second + time.Nanosecond} {
		if err := validateEphemeralNethelperRuntime(invalid); err == nil {
			t.Fatalf("runtime %s accepted", invalid)
		}
	}
}
