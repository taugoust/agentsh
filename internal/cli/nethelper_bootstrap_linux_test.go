//go:build linux

package cli

import (
	"strings"
	"testing"

	"github.com/agentsh/agentsh/internal/nethelper"
)

func TestEphemeralSystemdRunArgsAreFixedAndSecretFree(t *testing.T) {
	paths, err := nethelper.EphemeralPathsForUID(1000, "lease-11111111-1111-4111-8111-111111111111")
	if err != nil {
		t.Fatal(err)
	}
	launcher := "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-agentsh/bin/agentsh"
	args := ephemeralSystemdRunArgs(paths, launcher, 1000, 100)
	joined := strings.Join(args, "\n")
	for _, required := range []string{
		"--collect",
		"--service-type=exec",
		"--unit=" + paths.UnitName,
		"--property=LoadCredential=" + nethelperSystemdCredentialName + ":" + paths.RootCredential,
		"--property=RuntimeDirectory=" + strings.TrimPrefix(paths.RuntimeDir, "/run/"),
		"--property=ReadWritePaths=" + paths.RuntimeDir + " " + paths.PinLeaseDir,
		"--property=CapabilityBoundingSet=CAP_BPF CAP_NET_ADMIN CAP_PERFMON CAP_CHOWN",
		"--property=AmbientCapabilities=CAP_BPF CAP_NET_ADMIN CAP_PERFMON",
		"--property=NoNewPrivileges=yes",
		"--property=RestrictAddressFamilies=AF_UNIX",
		launcher,
		"--ephemeral-lease",
		paths.LeaseID,
	} {
		if !strings.Contains(joined, required) {
			t.Fatalf("systemd-run args missing %q:\n%s", required, joined)
		}
	}
	for _, forbidden := range []string{"sudo", "sh -c", "bash -c", "helper_instance_credential="} {
		if strings.Contains(strings.ToLower(joined), forbidden) {
			t.Fatalf("systemd-run args contain forbidden value %q:\n%s", forbidden, joined)
		}
	}
}
