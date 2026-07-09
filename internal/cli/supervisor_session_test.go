package cli

import (
	"strings"
	"testing"

	"github.com/agentsh/agentsh/internal/config"
)

func TestConfigureSupervisorMVPRejectsConfiguredNetworkEnforcement(t *testing.T) {
	cfg := &config.Config{}
	cfg.Sandbox.Network.Enabled = true
	cfg.Sandbox.Network.Transparent.Enabled = true
	cfg.Sandbox.Network.EBPF.Enforce = true
	cfg.Sandbox.Network.EBPF.Required = true

	err := configureSupervisorMVP(cfg, t.TempDir(), t.TempDir()+"/supervisor.sock")
	if err == nil {
		t.Fatal("expected detached supervisor config to reject unsupported network enforcement")
	}
	msg := err.Error()
	for _, want := range []string{
		"sandbox.network.transparent.enabled",
		"sandbox.network.ebpf.enforce",
		"sandbox.network.ebpf.required",
	} {
		if !strings.Contains(msg, want) {
			t.Fatalf("error %q missing %q", msg, want)
		}
	}
}

func TestConfigureSupervisorMVPStillDisablesBestEffortNetworkPieces(t *testing.T) {
	cfg := &config.Config{}
	cfg.Sandbox.Network.Enabled = true
	cfg.Sandbox.Network.EBPF.Enabled = true
	cfg.Sandbox.Cgroups.Enabled = true

	if err := configureSupervisorMVP(cfg, t.TempDir(), t.TempDir()+"/supervisor.sock"); err != nil {
		t.Fatalf("configureSupervisorMVP: %v", err)
	}
	if cfg.Sandbox.Network.Enabled {
		t.Fatal("network should be disabled for detached MVP")
	}
	if cfg.Sandbox.Network.EBPF.Enabled {
		t.Fatal("best-effort eBPF monitoring should be disabled for detached MVP")
	}
	if cfg.Sandbox.Cgroups.Enabled {
		t.Fatal("cgroups should be disabled for detached MVP")
	}
}
