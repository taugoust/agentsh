package cli

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/detached"
	"github.com/agentsh/agentsh/internal/nethelper"
)

func TestDetachedSupervisorStrictNetworkHasNoMigrationWarning(t *testing.T) {
	cfg := &config.Config{}
	cfg.Sandbox.Network.Enabled = true
	cfg.Sandbox.Network.Transparent.Enabled = true
	cfg.Sandbox.Network.EBPF.Enforce = true
	cfg.Sandbox.Network.EBPF.Required = true

	if msg := detachedSupervisorNetworkEnforcementWarning(cfg); msg != "" {
		t.Fatalf("supported strict configuration produced warning %q", msg)
	}

	stateDir := t.TempDir()
	if err := configureSupervisorMVP(cfg, stateDir, filepath.Join(stateDir, "supervisor.sock")); err != nil {
		t.Fatalf("configureSupervisorMVP should preserve strict network setup: %v", err)
	}
	if !cfg.Sandbox.Network.Enabled || !cfg.Sandbox.Network.EBPF.Enabled || !cfg.Sandbox.Network.EBPF.Enforce || !cfg.Sandbox.Network.EBPF.Required {
		t.Fatalf("strict network configuration was not preserved: %+v", cfg.Sandbox.Network)
	}
}

func TestConfigureSupervisorMVPStillDisablesBestEffortNetworkPieces(t *testing.T) {
	cfg := &config.Config{}
	cfg.Sandbox.Network.Enabled = true
	cfg.Sandbox.Network.EBPF.Enabled = true
	cfg.Sandbox.Cgroups.Enabled = true

	stateDir := t.TempDir()
	if err := configureSupervisorMVP(cfg, stateDir, filepath.Join(stateDir, "supervisor.sock")); err != nil {
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

func TestDetachedSupervisorNetworkEnforcementForDirectLaunch(t *testing.T) {
	cfg := &config.Config{}
	cfg.Sandbox.Network.Enabled = true
	cfg.Sandbox.Network.Transparent.Enabled = true
	cfg.Sandbox.Network.EBPF.Enforce = true
	status := detachedSupervisorPendingNetworkEnforcement(cfg)
	if status == nil {
		t.Fatal("status is nil")
	}
	if status.Status != detached.NetworkEnforcementStatusDegraded {
		t.Fatalf("Status = %q, want degraded", status.Status)
	}
	if status.Tier != detached.NetworkEnforcementTierNone {
		t.Fatalf("Tier = %q, want none", status.Tier)
	}
	if status.NetworkPolicyEnforced {
		t.Fatal("direct detached launch must not claim network policy enforcement")
	}
	if status.CgroupDelegated {
		t.Fatal("direct detached launch should not report cgroup delegation")
	}
	if !strings.Contains(status.Warning, "not proven") {
		t.Fatalf("Warning = %q, want evidence caveat", status.Warning)
	}
}

func TestConfigureSupervisorMVPPreservesStrictEBPFFailClosed(t *testing.T) {
	cfg := &config.Config{}
	cfg.Sandbox.Network.Enabled = true
	cfg.Sandbox.Network.Transparent.Enabled = true
	cfg.Sandbox.Network.EBPF.Required = true
	cfg.Sandbox.Network.EBPF.Enforce = true
	cfg.Sandbox.Cgroups.Enabled = true
	cfg.Sandbox.Cgroups.BasePath = filepath.Join(string(filepath.Separator), "sys", "fs", "cgroup", "system.slice", "agentsh.service")

	stateDir := t.TempDir()
	if err := configureSupervisorMVP(cfg, stateDir, filepath.Join(stateDir, "supervisor.sock")); err != nil {
		t.Fatalf("configureSupervisorMVP: %v", err)
	}
	if !cfg.Sandbox.Network.Enabled {
		t.Fatal("network proxy path should remain enabled for strict detached eBPF")
	}
	if !cfg.Sandbox.Network.EBPF.Enabled || !cfg.Sandbox.Network.EBPF.Required || !cfg.Sandbox.Network.EBPF.Enforce {
		t.Fatalf("strict eBPF flags were not preserved: %+v", cfg.Sandbox.Network.EBPF)
	}
	if cfg.Sandbox.Cgroups.Enabled {
		t.Fatal("detached strict eBPF should use attach-only cgroup probing, not resource-controller mode")
	}
	if cfg.Sandbox.Cgroups.BasePath != "" {
		t.Fatalf("detached supervisor retained unrelated daemon cgroup base path %q", cfg.Sandbox.Cgroups.BasePath)
	}
	if cfg.Sandbox.Network.Transparent.Enabled {
		t.Fatal("transparent netns remains unsupported in detached MVP")
	}
}

func TestDetachedSupervisorNetworkEnforcementForStrictNethelperLaunchDoesNotClaimEnforced(t *testing.T) {
	cfg := &config.Config{}
	cfg.Sandbox.Network.Enabled = true
	cfg.Sandbox.Network.EBPF.Enforce = true
	status := detachedSupervisorPendingNetworkEnforcement(cfg)
	if status == nil {
		t.Fatal("status is nil")
	}
	if status.Tier != detached.NetworkEnforcementTierNone {
		t.Fatalf("Tier = %q, want none before runtime handshake", status.Tier)
	}
	if status.NetworkPolicyEnforced {
		t.Fatal("pending metadata must not claim runtime enforcement")
	}
	if !strings.Contains(status.Detail, "preflight") {
		t.Fatalf("Detail = %q, want preflight pending note", status.Detail)
	}
	if !strings.Contains(status.Warning, "not proven") {
		t.Fatalf("Warning = %q, want evidence caveat", status.Warning)
	}
}

func TestDetachedSupervisorNetworkEnforcementForSystemdDelegatedLaunch(t *testing.T) {
	status := detachedSupervisorPendingNetworkEnforcement(&config.Config{})
	if status == nil {
		t.Fatal("status is nil")
	}
	if status.Status != detached.NetworkEnforcementStatusNone {
		t.Fatalf("Status = %q, want none", status.Status)
	}
	if status.Tier != detached.NetworkEnforcementTierNone {
		t.Fatalf("Tier = %q, want none before runtime probe", status.Tier)
	}
	if status.NetworkPolicyEnforced {
		t.Fatal("launch metadata must not claim network policy enforcement")
	}
	if status.CgroupDelegated {
		t.Fatal("launch intent must not report cgroup delegation before the runtime probe")
	}
	if !strings.Contains(status.Detail, "no runtime network gate") {
		t.Fatalf("Detail = %q, want no gate note", status.Detail)
	}
}

func TestDetachedSessionStartResultJSONIncludesNetworkEnforcement(t *testing.T) {
	res := detachedSessionStartResult{
		supervisorMetadata: supervisorMetadata{
			SessionID:  "session-json",
			EventToken: "must-not-be-returned",
			NetworkEnforcement: &detached.NetworkEnforcement{
				Status:                detached.NetworkEnforcementStatusDegraded,
				Tier:                  detached.NetworkEnforcementTierNone,
				NetworkPolicyEnforced: false,
			},
		},
		StateDir: "state",
	}

	b, err := json.Marshal(res)
	if err != nil {
		t.Fatalf("marshal start result: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("decode start result: %v", err)
	}
	network, ok := doc["network_enforcement"].(map[string]any)
	if !ok {
		t.Fatalf("network_enforcement = %#v, want top-level object", doc["network_enforcement"])
	}
	if network["status"] != string(detached.NetworkEnforcementStatusDegraded) {
		t.Fatalf("status = %#v", network["status"])
	}
	if network["tier"] != string(detached.NetworkEnforcementTierNone) {
		t.Fatalf("tier = %#v", network["tier"])
	}
	if network["network_policy_enforced"] != false {
		t.Fatalf("network_policy_enforced = %#v, want false", network["network_policy_enforced"])
	}
	if _, exposed := doc["event_token"]; exposed {
		t.Fatal("detached event credential must not be returned in session-start JSON")
	}
}

func TestBuildDetachedSupervisorLaunchRecordsNethelperSocket(t *testing.T) {
	req := testDetachedSupervisorLaunchRequest()
	req.GOOS = "linux"
	req.Env = append(req.Env, "AGENTSH_NETHELPER_SOCKET="+filepath.Join("run", "agentsh", "nethelper.sock"))

	launch := buildDetachedSupervisorLaunch(req)
	if launch.NethelperSocket != filepath.Join("run", "agentsh", "nethelper.sock") {
		t.Fatalf("NethelperSocket = %q", launch.NethelperSocket)
	}
}

func TestBuildDetachedSupervisorLaunchDefaultsToDirect(t *testing.T) {
	req := testDetachedSupervisorLaunchRequest()
	req.GOOS = "linux"
	lookPathCalled := false
	req.LookPath = func(string) (string, error) {
		lookPathCalled = true
		return "systemd-run", nil
	}

	launch := buildDetachedSupervisorLaunch(req)
	assertDirectDetachedSupervisorLaunch(t, launch, req)
	if lookPathCalled {
		t.Fatal("systemd-run lookup should not run without opt-in env var")
	}
}

func TestBuildDetachedSupervisorLaunchFallsBackWhenSystemdRunUnavailable(t *testing.T) {
	req := testDetachedSupervisorLaunchRequest()
	req.GOOS = "linux"
	req.Env = append(req.Env,
		detachedSupervisorSystemdRunEnv+"=1",
		"XDG_RUNTIME_DIR=runtime-dir",
	)
	lookPathCalled := false
	req.LookPath = func(name string) (string, error) {
		lookPathCalled = true
		if name != "systemd-run" {
			t.Fatalf("LookPath(%q), want systemd-run", name)
		}
		return "", errors.New("not found")
	}

	launch := buildDetachedSupervisorLaunch(req)
	assertDirectDetachedSupervisorLaunch(t, launch, req)
	if !lookPathCalled {
		t.Fatal("systemd-run lookup should run after opt-in on linux with XDG_RUNTIME_DIR")
	}
}

func TestBuildDetachedSupervisorLaunchFallsBackWithoutUserSystemdRuntime(t *testing.T) {
	req := testDetachedSupervisorLaunchRequest()
	req.GOOS = "linux"
	req.Env = append(req.Env, detachedSupervisorSystemdRunEnv+"=1")
	lookPathCalled := false
	req.LookPath = func(string) (string, error) {
		lookPathCalled = true
		return "systemd-run", nil
	}

	launch := buildDetachedSupervisorLaunch(req)
	assertDirectDetachedSupervisorLaunch(t, launch, req)
	if lookPathCalled {
		t.Fatal("systemd-run lookup should not run without XDG_RUNTIME_DIR")
	}
}

func TestBuildDetachedSupervisorLaunchFallsBackOffLinux(t *testing.T) {
	req := testDetachedSupervisorLaunchRequest()
	req.GOOS = "darwin"
	req.Env = append(req.Env,
		detachedSupervisorSystemdRunEnv+"=1",
		"XDG_RUNTIME_DIR=runtime-dir",
	)
	lookPathCalled := false
	req.LookPath = func(string) (string, error) {
		lookPathCalled = true
		return "systemd-run", nil
	}

	launch := buildDetachedSupervisorLaunch(req)
	assertDirectDetachedSupervisorLaunch(t, launch, req)
	if lookPathCalled {
		t.Fatal("systemd-run lookup should not run off linux")
	}
}

func TestWithoutEnvAssignmentsRemovesExistingSupervisorSecrets(t *testing.T) {
	env := withoutEnvAssignments([]string{"PATH=bin", "AGENTSH_DETACHED_EVENT_TOKEN=old", "agentsh_nethelper_session_nonce=old", "AGENTSH_NETHELPER_SOCKET=sock"}, "AGENTSH_DETACHED_EVENT_TOKEN", "AGENTSH_NETHELPER_SESSION_NONCE")
	want := []string{"PATH=bin", "AGENTSH_NETHELPER_SOCKET=sock"}
	if !reflect.DeepEqual(env, want) {
		t.Fatalf("env = %#v, want %#v", env, want)
	}
}

func TestDetachedSupervisorServiceEnvIncludesNethelperSocket(t *testing.T) {
	credentialFile := filepath.Join("run", "agentsh", "instance-credential")
	env := detachedSupervisorServiceEnv("token", []string{
		"PATH=bin",
		"AGENTSH_NETHELPER_SOCKET=" + filepath.Join("run", "agentsh", "nethelper.sock"),
		"AGENTSH_NETHELPER_INSTANCE_CREDENTIAL=must-not-enter-systemd-properties",
		"AGENTSH_NETHELPER_SESSION_NONCE=must-not-enter-systemd-properties",
		"AGENTSH_NETHELPER_CREDENTIAL_FILE=" + credentialFile,
		detached.EnvNetworkEnforcementRequested + "=strict",
		"AGENTSH_SUBAGENT_COMMAND=/nix/store/pi/bin/pi",
		"AGENTSH_SUBAGENT_ARGS=--mode json -p --no-session",
		"AGENTSH_SUBAGENT_TASK_MODE=arg",
		"AGENTSH_SUBAGENT_PROTOCOL=pi-json",
		"AGENTSH_SUBAGENT_MAX_DEPTH=3",
		"AGENTSH_SUBAGENT_RUNTIME=pi",
	})
	want := []string{
		"AGENTSH_DETACHED_EVENT_TOKEN=token",
		"AGENTSH_NETHELPER_CREDENTIAL_FILE=" + credentialFile,
		"AGENTSH_NETHELPER_SOCKET=" + filepath.Join("run", "agentsh", "nethelper.sock"),
		detached.EnvNetworkEnforcementRequested + "=strict",
		"AGENTSH_SUBAGENT_COMMAND=/nix/store/pi/bin/pi",
		"AGENTSH_SUBAGENT_ARGS=--mode json -p --no-session",
		"AGENTSH_SUBAGENT_TASK_MODE=arg",
		"AGENTSH_SUBAGENT_PROTOCOL=pi-json",
		"AGENTSH_SUBAGENT_MAX_DEPTH=3",
		"AGENTSH_SUBAGENT_RUNTIME=pi",
	}
	if !reflect.DeepEqual(env, want) {
		t.Fatalf("service env = %#v, want %#v", env, want)
	}
}

func TestBuildDetachedSupervisorLaunchBuildsSystemdRunCommand(t *testing.T) {
	req := testDetachedSupervisorLaunchRequest()
	req.GOOS = "linux"
	req.Env = append(req.Env,
		detachedSupervisorSystemdRunEnv+"=auto",
		"XDG_RUNTIME_DIR=runtime-dir",
	)
	req.ServiceEnv = append(req.ServiceEnv, "not-an-env-assignment")
	req.LookPath = func(name string) (string, error) {
		if name != "systemd-run" {
			t.Fatalf("LookPath(%q), want systemd-run", name)
		}
		return "systemd-run", nil
	}

	launch := buildDetachedSupervisorLaunch(req)
	if !launch.UsesSystemd {
		t.Fatal("expected systemd-run launch")
	}
	if launch.Path != "systemd-run" {
		t.Fatalf("Path = %q, want systemd-run", launch.Path)
	}
	if launch.Dir != req.Dir {
		t.Fatalf("Dir = %q, want %q", launch.Dir, req.Dir)
	}
	wantLaunchEnv := withoutEnvAssignments(req.Env, "AGENTSH_DETACHED_EVENT_TOKEN", nethelper.EnvHelperInstanceCredential, nethelper.EnvSessionNonce, detached.EnvSupervisorLaunchMode)
	if !reflect.DeepEqual(launch.Env, wantLaunchEnv) {
		t.Fatalf("Env = %#v, want %#v", launch.Env, wantLaunchEnv)
	}
	if launch.OwnerPIDFromCommand {
		t.Fatal("systemd-run launch should not treat the systemd-run client PID as the supervisor PID")
	}

	unit := detachedSupervisorSystemdUnit(req.SessionID)
	if launch.SystemdUnit != unit {
		t.Fatalf("SystemdUnit = %q, want %q", launch.SystemdUnit, unit)
	}
	wantArgs := []string{
		"--user",
		"--collect",
		"--service-type=exec",
		"--unit=" + unit,
		"-p", "Delegate=yes",
		"-p", "KillMode=mixed",
		"-p", "TimeoutStopSec=10s",
		"-p", "UMask=0077",
		"-p", "NoNewPrivileges=yes",
		"-p", "PrivateTmp=yes",
		"-p", "KeyringMode=private",
		"-p", "LimitCORE=0",
		"-p", "OOMPolicy=stop",
		"-p", "WorkingDirectory=" + req.Dir,
		"-p", "EnvironmentFile=" + req.ServiceEnvFile,
		"--", req.Exe,
	}
	wantArgs = append(wantArgs, req.Args...)
	if !reflect.DeepEqual(launch.Args, wantArgs) {
		t.Fatalf("Args = %#v, want %#v", launch.Args, wantArgs)
	}
}

func TestDetachedSupervisorSystemdUnitSanitizesSessionID(t *testing.T) {
	unit := detachedSupervisorSystemdUnit(" session/with spaces ")
	if unit != "agentsh-supervisor-session-with-spaces.service" {
		t.Fatalf("unit = %q", unit)
	}
}

func testDetachedSupervisorLaunchRequest() detachedSupervisorLaunchRequest {
	return detachedSupervisorLaunchRequest{
		Exe:            "agentsh",
		Args:           detachedSupervisorRunArgs("state", "sock", "config.yml"),
		Env:            []string{"PATH=bin", "AGENTSH_DETACHED_EVENT_TOKEN=token"},
		Dir:            "workspace",
		SessionID:      "session-123",
		ServiceEnv:     []string{"AGENTSH_DETACHED_EVENT_TOKEN=token", "AGENTSH_NETHELPER_CREDENTIAL_FILE=credential-file"},
		ServiceEnvFile: filepath.Join(string(filepath.Separator), "state", "supervisor.env"),
	}
}

func assertDirectDetachedSupervisorLaunch(t *testing.T, launch detachedSupervisorLaunch, req detachedSupervisorLaunchRequest) {
	t.Helper()
	if launch.UsesSystemd {
		t.Fatal("expected direct launch, got systemd-run")
	}
	if launch.Path != req.Exe {
		t.Fatalf("Path = %q, want %q", launch.Path, req.Exe)
	}
	if !reflect.DeepEqual(launch.Args, req.Args) {
		t.Fatalf("Args = %#v, want %#v", launch.Args, req.Args)
	}
	wantEnv := append(append([]string{}, req.Env...), detached.EnvSupervisorLaunchMode+"=direct")
	if !reflect.DeepEqual(launch.Env, wantEnv) {
		t.Fatalf("Env = %#v, want %#v", launch.Env, wantEnv)
	}
	if launch.Dir != req.Dir {
		t.Fatalf("Dir = %q, want %q", launch.Dir, req.Dir)
	}
	if launch.SystemdUnit != "" {
		t.Fatalf("SystemdUnit = %q, want empty", launch.SystemdUnit)
	}
	if !launch.OwnerPIDFromCommand {
		t.Fatal("direct launch should record the child PID as owner PID")
	}
}
