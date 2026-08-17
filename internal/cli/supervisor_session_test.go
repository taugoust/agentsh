package cli

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/client"
	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/detached"
	"github.com/agentsh/agentsh/internal/nethelper"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/google/uuid"
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
	if !cfg.Development.DetachedControlOnly || cfg.Development.AllowUnauthenticatedUnixApprovals {
		t.Fatalf("detached approval auth mode is unsafe: %+v", cfg.Development)
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
	bootstrapResult := filepath.Join("run", "agentsh", "bootstrap.json")
	recoveryToken := filepath.Join("run", "user", "1000", "agentsh-wrapper-control", "nethelper-recovery.token")
	env := detachedSupervisorServiceEnv([]string{
		"PATH=bin",
		"AGENTSH_NETHELPER_SOCKET=" + filepath.Join("run", "agentsh", "nethelper.sock"),
		"AGENTSH_NETHELPER_INSTANCE_CREDENTIAL=must-not-enter-systemd-properties",
		"AGENTSH_NETHELPER_SESSION_NONCE=must-not-enter-systemd-properties",
		"AGENTSH_NETHELPER_CREDENTIAL_FILE=" + credentialFile,
		"AGENTSH_NETHELPER_BOOTSTRAP_RESULT=" + bootstrapResult,
		nethelper.EnvRecoveryTokenFile + "=" + recoveryToken,
		detached.EnvNetworkEnforcementRequested + "=strict",
		"PI_CODING_AGENT_DIR=/run/user/1000/pi-agent",
		"AGENTSH_SUBAGENT_COMMAND=/nix/store/pi/bin/pi",
		"AGENTSH_SUBAGENT_ARGS=--mode json -p --no-session",
		"AGENTSH_SUBAGENT_TASK_MODE=arg",
		"AGENTSH_SUBAGENT_PROTOCOL=pi-json",
		"AGENTSH_SUBAGENT_MAX_DEPTH=3",
		"AGENTSH_SUBAGENT_RUNTIME=pi",
	}, nil)
	want := []string{
		"AGENTSH_NETHELPER_CREDENTIAL_FILE=" + credentialFile,
		"AGENTSH_NETHELPER_SOCKET=" + filepath.Join("run", "agentsh", "nethelper.sock"),
		"AGENTSH_NETHELPER_BOOTSTRAP_RESULT=" + bootstrapResult,
		nethelper.EnvRecoveryTokenFile + "=" + recoveryToken,
		detached.EnvNetworkEnforcementRequested + "=strict",
		"PI_CODING_AGENT_DIR=/run/user/1000/pi-agent",
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

func TestDetachedSupervisorRestartEnvironmentSeparatesVolatileSecrets(t *testing.T) {
	unsafe := restartUnsafeServiceEnvironmentNames([]string{
		"AGENTSH_DETACHED_EVENT_TOKEN=control-token",
		nethelper.EnvCredentialFile + "=/protected/credential",
		"SSH_AUTH_SOCK=/tmp/agent.sock",
		"XDG_CONFIG_HOME=/home/test/.config",
		"OPENAI_API_KEY=secret",
		"CUSTOM_TOKEN=secret",
	})
	want := []string{"CUSTOM_TOKEN", "OPENAI_API_KEY"}
	if !reflect.DeepEqual(unsafe, want) {
		t.Fatalf("volatile restart environment = %#v, want %#v", unsafe, want)
	}
}

func TestDetachedSupervisorServiceEnvIncludesExplicitInheritedValues(t *testing.T) {
	env := detachedSupervisorServiceEnv([]string{
		"PATH=bin",
		"SSH_AUTH_SOCK=/tmp/ssh-example/agent.123",
		"GIT_SSH_COMMAND=ssh -o IdentitiesOnly=no",
		"UNREQUESTED_SECRET=must-not-cross-systemd-boundary",
		"AGENTSH_DETACHED_EVENT_TOKEN=must-not-override-token",
	}, []string{"SSH_AUTH_SOCK", "GIT_*", "AGENTSH_DETACHED_EVENT_TOKEN"})
	want := []string{
		"SSH_AUTH_SOCK=/tmp/ssh-example/agent.123",
		"GIT_SSH_COMMAND=ssh -o IdentitiesOnly=no",
	}
	if !reflect.DeepEqual(env, want) {
		t.Fatalf("service env = %#v, want %#v", env, want)
	}
}

func TestBuildSystemdRunDetachedSupervisorArgsCreatesRestartableUnit(t *testing.T) {
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
		"-p", "Restart=on-failure",
		"-p", "RestartSec=500ms",
		"-p", "StartLimitIntervalSec=30s",
		"-p", "StartLimitBurst=10",
		"-p", "UMask=0077",
		"-p", "NoNewPrivileges=yes",
		"-p", "PrivateTmp=yes",
		"-p", "KeyringMode=private",
		"-p", "LimitCORE=0",
		"-p", "OOMPolicy=continue",
		"-p", "WorkingDirectory=" + req.Dir,
		"-p", "StandardOutput=append:" + req.ServiceLogFile,
		"-p", "StandardError=append:" + req.ServiceLogFile,
		"-p", "EnvironmentFile=" + req.ServiceEnvFile,
		"--", req.Exe,
	}
	wantArgs = append(wantArgs, req.Args...)
	if !reflect.DeepEqual(launch.Args, wantArgs) {
		t.Fatalf("Args = %#v, want %#v", launch.Args, wantArgs)
	}
}

func TestBuildSystemdRunDetachedSupervisorArgsKeepsForwardedAgentSocketVisible(t *testing.T) {
	args := buildSystemdRunDetachedSupervisorArgs(
		"unit",
		"workspace",
		"/state/supervisor.env",
		"/state/supervisor.log",
		[]string{"SSH_AUTH_SOCK=/tmp/ssh-example/agent.123"},
		"agentsh",
		nil,
	)
	if !slices.Contains(args, "PrivateTmp=no") {
		t.Fatalf("args = %#v, want PrivateTmp=no", args)
	}

	args = buildSystemdRunDetachedSupervisorArgs(
		"unit",
		"workspace",
		"/state/supervisor.env",
		"/state/supervisor.log",
		[]string{"SSH_AUTH_SOCK=/run/user/501/agent.sock"},
		"agentsh",
		nil,
	)
	if !slices.Contains(args, "PrivateTmp=yes") {
		t.Fatalf("args = %#v, want PrivateTmp=yes for a socket outside /tmp", args)
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
		ServiceLogFile: filepath.Join(string(filepath.Separator), "state", "logs", "supervisor.log"),
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

func TestDetachedSessionIDRequiresCanonicalCallerIdentity(t *testing.T) {
	canonical := "session-" + uuid.NewString()
	if got, err := detachedSessionID(canonical); err != nil || got != canonical {
		t.Fatalf("detachedSessionID(%q) = %q, %v", canonical, got, err)
	}
	generated, err := detachedSessionID("")
	if err != nil {
		t.Fatalf("generate detached session ID: %v", err)
	}
	if _, err := uuid.Parse(strings.TrimPrefix(generated, "session-")); err != nil || !strings.HasPrefix(generated, "session-") {
		t.Fatalf("generated non-canonical ID %q", generated)
	}
	for _, invalid := range []string{
		" session-" + uuid.NewString(),
		"SESSION-" + uuid.NewString(),
		"session-" + strings.ToUpper(uuid.NewString()),
		"session-00000000-0000-0000-0000-000000000000",
		"session-../escape",
		"arbitrary-id",
	} {
		if _, err := detachedSessionID(invalid); err == nil {
			t.Errorf("detachedSessionID(%q) unexpectedly succeeded", invalid)
		}
	}
	if newSessionStartCmd().Flags().Lookup("session-id") == nil || newSessionStartCmd().Flags().Lookup("control-token-file") == nil {
		t.Fatal("session start does not expose exact identity and private control credential flags")
	}

	stateHome := t.TempDir()
	t.Setenv("XDG_STATE_HOME", stateHome)
	t.Setenv("HOME", stateHome)
	stateDir, err := reserveDetachedSessionState(canonical)
	if err != nil {
		t.Fatalf("reserve caller identity: %v", err)
	}
	if filepath.Base(stateDir) != canonical {
		t.Fatalf("reserved state directory = %q", stateDir)
	}
	if _, err := reserveDetachedSessionState(canonical); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("caller identity collision error = %v", err)
	}
}

func TestWriteDetachedControlTokenFileRequiresPrivateExclusiveDestination(t *testing.T) {
	private := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(private, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(private, "control.token")
	if err := writeDetachedControlTokenFile(path, "control-secret"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "control-secret\n" {
		t.Fatalf("token contents = %q", data)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("token mode = %v", info.Mode().Perm())
	}
	if err := writeDetachedControlTokenFile(path, "replacement"); err == nil {
		t.Fatal("existing token destination was overwritten")
	}
	public := filepath.Join(t.TempDir(), "public")
	if err := os.Mkdir(public, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := writeDetachedControlTokenFile(filepath.Join(public, "control.token"), "secret"); err == nil {
		t.Fatal("public token directory was accepted")
	}
}

func TestValidateDetachedStopAuthorityRequiresExactTopology(t *testing.T) {
	sessionID := "session-11111111-1111-4111-8111-111111111111"
	stateDir := filepath.Join(t.TempDir(), sessionID)
	meta := supervisorMetadata{
		SessionID: sessionID, ID: sessionID, SupervisorSock: filepath.Join(stateDir, "supervisor.sock"),
		ProtocolVersion: detached.ProtocolVersion, Generation: 2, IncarnationID: "incarnation-test",
	}
	manifest := detached.NewRecoveryManifest(sessionID, types.CreateSessionRequest{
		ID: sessionID, Workspace: t.TempDir(),
	}, detached.LaunchSpec{Executable: "/bin/agentsh", WorkingDir: t.TempDir(), EnvironmentFile: filepath.Join(stateDir, "supervisor.env")}, time.Now())
	manifest.Generation = meta.Generation
	manifest.IncarnationID = meta.IncarnationID
	if err := validateDetachedStopAuthority(sessionID, stateDir, meta, manifest, nil); err != nil {
		t.Fatalf("valid stop authority: %v", err)
	}

	wrongSocket := meta
	wrongSocket.SupervisorSock = filepath.Join(t.TempDir(), "supervisor.sock")
	if err := validateDetachedStopAuthority(sessionID, stateDir, wrongSocket, manifest, nil); err == nil {
		t.Fatal("socket outside exact state directory was accepted")
	}
	wrongUnit := meta
	wrongUnit.SystemdUnit = "agentsh-supervisor-session-22222222-2222-4222-8222-222222222222.service"
	if err := validateDetachedStopAuthority(sessionID, stateDir, wrongUnit, manifest, nil); err == nil {
		t.Fatal("wrong exact systemd unit was accepted")
	}
	wrongManifest := manifest
	wrongManifest.IncarnationID = "different-incarnation"
	if err := validateDetachedStopAuthority(sessionID, stateDir, meta, wrongManifest, nil); err == nil {
		t.Fatal("mismatched recovery incarnation was accepted")
	}
}

func TestExactDetachedSessionNotFoundRequiresProtocolV2Typed404(t *testing.T) {
	missing := &client.HTTPError{StatusCode: http.StatusNotFound, Body: `{"error":"session not found"}`}
	meta := supervisorMetadata{ProtocolVersion: detached.ProtocolVersion}
	if !isExactDetachedSessionNotFound(missing, meta) {
		t.Fatal("exact protocol-v2 session-not-found response was not classified as idempotent")
	}
	for _, err := range []error{
		&client.HTTPError{StatusCode: http.StatusNotFound, Body: `{"error":"different resource"}`},
		&client.HTTPError{StatusCode: http.StatusConflict, Body: `{"error":"session not found"}`},
		errors.New("transport failed"),
	} {
		if isExactDetachedSessionNotFound(err, meta) {
			t.Fatalf("ambiguous error was classified as idempotent: %v", err)
		}
	}
	if isExactDetachedSessionNotFound(missing, supervisorMetadata{ProtocolVersion: 1}) {
		t.Fatal("legacy metadata without an incarnation handshake accepted a 404")
	}
}

func TestStopDetachedSessionExact_ContinuesAfterIdentityChecked404(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix sockets are unavailable on Windows")
	}
	stateHome, err := os.MkdirTemp(os.TempDir(), "agsh-e-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(stateHome) })
	t.Setenv("XDG_STATE_HOME", stateHome)
	t.Setenv("HOME", stateHome)

	sessionID := "session-" + uuid.NewString()
	root := detachedSessionsRoot()
	stateDir := filepath.Join(root, sessionID)
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	workspace := t.TempDir()
	sockPath := filepath.Join(stateDir, "supervisor.sock")
	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}

	owner := exec.Command("sleep", "60")
	if err := owner.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = owner.Process.Kill()
		_ = owner.Wait()
	})
	ownerStart, bootID, err := detached.CurrentProcessIdentity(owner.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}

	var destroys atomic.Int32
	var mismatch atomic.Bool
	mismatch.Store(true)
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/detached/status", func(w http.ResponseWriter, _ *http.Request) {
		incarnation := "incarnation-test"
		if mismatch.Load() {
			incarnation = "wrong-incarnation"
		}
		_ = json.NewEncoder(w).Encode(detached.RuntimeStatus{
			ProtocolVersion: detached.ProtocolVersion, SessionID: sessionID,
			LifecycleState: detached.LifecycleReady, Generation: 1,
			IncarnationID: incarnation, OwnerPID: owner.Process.Pid,
			OwnerStartIdentity: ownerStart, BootID: bootID, Recoverable: true,
		})
	})
	mux.HandleFunc("/api/v1/sessions/"+sessionID, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		destroys.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"session not found"}`))
	})
	httpServer := &http.Server{Handler: mux}
	serveDone := make(chan error, 1)
	go func() { serveDone <- httpServer.Serve(listener) }()
	t.Cleanup(func() {
		_ = httpServer.Shutdown(context.Background())
		<-serveDone
	})

	envFile := filepath.Join(stateDir, "supervisor.env")
	if err := os.WriteFile(envFile, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	createdAt := time.Now().UTC().Add(-time.Hour)
	req := types.CreateSessionRequest{
		ID: sessionID, Workspace: workspace, Policy: "default",
		WorkspaceMode: string(types.WorkspaceModeDirect),
	}
	manifest := detached.NewRecoveryManifest(sessionID, req, detached.LaunchSpec{
		Executable: executable, WorkingDir: workspace, EnvironmentFile: envFile,
		LogFile: filepath.Join(stateDir, "supervisor.log"),
	}, createdAt)
	manifest.State = detached.LifecycleReady
	manifest.SessionCreatedAt = createdAt
	manifest.PolicyDigest = "test-policy-digest"
	manifest.Generation = 1
	manifest.IncarnationID = "incarnation-test"
	if err := detached.WriteRecoveryManifest(stateDir, manifest); err != nil {
		t.Fatal(err)
	}
	if err := writeSupervisorMetadata(stateDir, supervisorMetadata{
		SessionID: sessionID, ID: sessionID, CreatedAt: createdAt,
		State: detached.LifecycleReady, Policy: "default",
		RealWorkspace: workspace, WorkspaceMode: string(types.WorkspaceModeDirect),
		SupervisorSock: sockPath, EventToken: "event-token",
		OwnerPID: owner.Process.Pid, OwnerStartIdentity: ownerStart, BootID: bootID,
		Generation: 1, IncarnationID: "incarnation-test",
		ProtocolVersion: detached.ProtocolVersion,
	}); err != nil {
		t.Fatal(err)
	}

	if err := stopDetachedSessionExact(context.Background(), sessionID); err == nil || !strings.Contains(err.Error(), "identity handshake mismatch") {
		t.Fatalf("mismatched live socket stop error = %v", err)
	}
	if destroys.Load() != 0 {
		t.Fatalf("destroy dispatched through mismatched socket")
	}
	if !supervisorPIDAlive(owner.Process.Pid) {
		t.Fatal("mismatched socket stop signaled the recorded owner")
	}
	mismatch.Store(false)
	if err := stopDetachedSessionExact(context.Background(), sessionID); err != nil {
		t.Fatalf("stopDetachedSessionExact: %v", err)
	}
	if destroys.Load() != 1 {
		t.Fatalf("destroy requests = %d, want 1", destroys.Load())
	}
	status, err := detached.ReadTerminalRuntimeStatusFromRoot(root, sessionID)
	if err != nil {
		t.Fatalf("ReadTerminalRuntimeStatusFromRoot: %v", err)
	}
	if status.LifecycleState != detached.LifecycleStopped || status.Recoverable {
		t.Fatalf("terminal status = %+v", status)
	}
	if _, err := os.Lstat(sockPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("supervisor socket still published: %v", err)
	}
}
