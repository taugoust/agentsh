package cli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/agentsh/agentsh/internal/client"
	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/detached"
	"github.com/agentsh/agentsh/internal/detachedreport"
	"github.com/agentsh/agentsh/internal/guestcontrol"
	"github.com/agentsh/agentsh/internal/nethelper"
	"github.com/agentsh/agentsh/internal/runtimeprovider"
	"github.com/agentsh/agentsh/internal/runtimeprovider/artifact"
	"github.com/agentsh/agentsh/internal/runtimeprovider/externalrunner"
	"github.com/agentsh/agentsh/internal/server"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/google/uuid"
	"github.com/spf13/cobra"
)

var errDetachedFinalizationCompleted = errors.New("detached finalization completed during recovery")

const (
	detachedSupervisorHeartbeatInterval = 30 * time.Second
	detachedReviewClientTimeout         = 31 * time.Minute
)

type detachedSessionStartResult struct {
	supervisorMetadata
	Session  types.Session `json:"session"`
	StateDir string        `json:"state_dir"`
}

// MarshalJSON keeps the detached event credential in mode-0600 supervisor
// metadata without returning it to session-start callers. Helper credentials
// are never represented by this response type at all.
func (r detachedSessionStartResult) MarshalJSON() ([]byte, error) {
	meta := r.supervisorMetadata
	meta.EventToken = ""
	type wire struct {
		supervisorMetadata
		Session  types.Session `json:"session"`
		StateDir string        `json:"state_dir"`
	}
	return json.Marshal(wire{supervisorMetadata: meta, Session: r.Session, StateDir: r.StateDir})
}

func newSupervisorCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:    "supervisor",
		Short:  "Run a per-session supervisor",
		Hidden: true,
	}
	cmd.AddCommand(newSupervisorRunCmd())
	return cmd
}

func newSupervisorRunCmd() *cobra.Command {
	var configPath string
	var stateDir string
	var sockPath string
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run one detached supervisor process",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDetachedSupervisor(cmd.Context(), configPath, stateDir, sockPath)
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to server config YAML")
	cmd.Flags().StringVar(&stateDir, "state-dir", "", "Detached session state directory")
	cmd.Flags().StringVar(&sockPath, "socket", "", "Supervisor Unix socket path")
	return cmd
}

func runDetachedSupervisor(ctx context.Context, configPath, stateDir, sockPath string) (runErr error) {
	if strings.TrimSpace(stateDir) == "" {
		return fmt.Errorf("--state-dir is required")
	}
	if strings.TrimSpace(sockPath) == "" {
		return fmt.Errorf("--socket is required")
	}
	stateDir, err := filepath.Abs(stateDir)
	if err != nil {
		return fmt.Errorf("resolve detached state directory: %w", err)
	}
	sockPath, err = filepath.Abs(sockPath)
	if err != nil {
		return fmt.Errorf("resolve detached supervisor socket: %w", err)
	}
	if filepath.Clean(filepath.Dir(sockPath)) != filepath.Clean(stateDir) {
		return fmt.Errorf("detached supervisor socket must be inside the exact state directory")
	}
	lock, err := detached.AcquireSupervisorLock(stateDir)
	if err != nil {
		return err
	}
	defer lock.Close()
	startIdentity, bootID, identityErr := detached.CurrentProcessIdentity(os.Getpid())
	if identityErr != nil {
		return fmt.Errorf("capture detached supervisor process identity: %w", identityErr)
	}
	var runtimeState *detached.Runtime
	if err := runtimeprovider.WithLifecycleLock(stateDir, func() error {
		manifest, readErr := runtimeprovider.ReadManifest(stateDir)
		if readErr == nil && (manifest.State == runtimeprovider.StateStopping || manifest.State == runtimeprovider.StateStopped || manifest.CleanupPending ||
			(!manifest.CleanupIntentKnown && manifest.State == runtimeprovider.StateFailed && !manifest.CleanupComplete)) {
			return fmt.Errorf("detached session %s has committed runtime cleanup state and cannot restart", manifest.SessionID)
		}
		if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
			return readErr
		}
		var beginErr error
		runtimeState, beginErr = detached.BeginRuntime(stateDir, os.Getpid(), startIdentity, bootID, time.Now().UTC())
		if beginErr != nil {
			return beginErr
		}
		protectedMeta, _, metaErr := detached.ReadMetadataFromRoot(filepath.Dir(stateDir), runtimeState.Manifest().SessionID)
		if metaErr != nil {
			return fmt.Errorf("read detached control credential: %w", metaErr)
		}
		if err := runtimeState.SetControlCredential(protectedMeta.EventToken); err != nil {
			return err
		}
		return syncNativeRuntimeProviderManifestLocked(stateDir, runtimeState.Metadata())
	}); err != nil {
		return err
	}
	defer func() {
		if runErr != nil {
			_ = runtimeState.MarkFailed(runErr.Error())
			_ = syncNativeRuntimeProviderManifest(stateDir, runtimeState.Metadata())
		}
	}()

	cfg, _, err := loadLocalConfig(configPath)
	if err != nil {
		return err
	}
	for name, value := range runtimeState.NethelperRecoveryEnvironment() {
		if err := os.Setenv(name, value); err != nil {
			return fmt.Errorf("apply durable nethelper recovery path %s: %w", name, err)
		}
	}
	if err := loadSupervisorNethelperCredential(); err != nil {
		if detachedSupervisorStrictNetworkEnforcement(cfg) && !runtimeState.IsRecovery() {
			return fmt.Errorf("strict detached helper credential unavailable: %w", err)
		}
		fmt.Fprintf(os.Stderr, "agentsh: warning: nethelper credential unavailable; starting fail-closed recovery control plane: %v\n", err)
		if detachedSupervisorStrictNetworkEnforcement(cfg) {
			// Keep capability initialization on the external-helper path while
			// carrying no valid helper authority. The random placeholder can never
			// authenticate; strict command admission remains blocked until the
			// wrapper performs an authorized transactional rebind.
			if strings.TrimSpace(os.Getenv(nethelper.EnvSocket)) == "" {
				_ = os.Setenv(nethelper.EnvSocket, filepath.Join(stateDir, "nethelper-unavailable.sock"))
			}
			_ = os.Setenv(nethelper.EnvHelperInstanceCredential, randomDetachedEventToken())
		} else {
			for _, key := range []string{nethelper.EnvSocket, nethelper.EnvHelperInstanceCredential, nethelper.EnvSessionNonce, nethelper.EnvCredentialFile} {
				_ = os.Unsetenv(key)
			}
		}
	}
	if err := configureSupervisorMVP(cfg, stateDir, sockPath); err != nil {
		return err
	}
	srv, err := server.New(cfg)
	if err != nil {
		return err
	}
	defer srv.Close()
	if _, _, err := srv.BootstrapDetachedSession(ctx, runtimeState); err != nil {
		return err
	}
	if err := syncNativeRuntimeProviderManifest(stateDir, runtimeState.Metadata()); err != nil {
		return fmt.Errorf("persist ready native runtime-provider incarnation: %w", err)
	}

	heartbeatCtx, cancelHeartbeat := context.WithCancel(context.Background())
	defer cancelHeartbeat()
	go func() {
		ticker := time.NewTicker(detachedSupervisorHeartbeatInterval)
		defer ticker.Stop()
		for {
			select {
			case <-heartbeatCtx.Done():
				return
			case now := <-ticker.C:
				if err := runtimeState.Heartbeat(now); err != nil {
					fmt.Fprintf(os.Stderr, "agentsh: detached heartbeat persistence failed: %v\n", err)
				}
			}
		}
	}()
	runErr = srv.Run(ctx)
	status := runtimeState.RuntimeStatus()
	switch status.LifecycleState {
	case detached.LifecycleStopping:
		// The durable stop decision wins over a concurrent listener/shutdown
		// error. Attempt to complete it and exit successfully either way so
		// Restart=on-failure cannot resurrect an expired or explicitly stopped
		// session.
		if err := runtimeState.MarkStopped(); err != nil {
			fmt.Fprintf(os.Stderr, "agentsh: detached stopping state is durable but final stopped persistence failed: %v\n", err)
		}
		runErr = nil
	case detached.LifecycleStopped, detached.LifecycleFinalized:
		runErr = nil
	default:
		if runErr == nil {
			// A clean server return without an already durable stop transition is
			// not a terminal session decision. Exit failed so the service manager
			// recreates this exact incarnation rather than stranding stale state.
			runErr = fmt.Errorf("supervisor exited before a durable stop transition")
		}
	}
	if err := syncNativeRuntimeProviderManifest(stateDir, runtimeState.Metadata()); err != nil {
		runErr = errors.Join(runErr, fmt.Errorf("persist terminal native runtime-provider state: %w", err))
	}
	return runErr
}

func configureSupervisorMVP(cfg *config.Config, stateDir, sockPath string) error {
	if cfg == nil {
		return fmt.Errorf("config is nil")
	}
	if warning := detachedSupervisorNetworkEnforcementWarning(cfg); warning != "" {
		fmt.Fprintf(os.Stderr, "agentsh: warning: %s\n", warning)
	}
	strictNetwork := detachedSupervisorStrictNetworkEnforcement(cfg)

	// Stage 1 is a user-owned, single-session supervisor. Keep the existing
	// seccomp/wrap path, but explicitly disable heavyweight/global pieces unless
	// the source config requires eBPF enforcement. Required/enforced eBPF is now
	// preserved so command setup fails closed instead of silently allowing direct
	// network access.
	cfg.Server.HTTP.Addr = "127.0.0.1:0"
	cfg.Server.GRPC.Enabled = false
	cfg.Server.UnixSocket.Enabled = true
	cfg.Server.UnixSocket.Path = sockPath
	// The socket carries exact-session lifecycle and approval authority. Never
	// inherit a broader configured mode into the detached supervisor.
	cfg.Server.UnixSocket.Permissions = "0600"
	cfg.Auth.Type = "none"
	cfg.Development.DisableAuth = true
	cfg.Development.AllowUnauthenticatedUnixApprovals = false
	cfg.Development.DetachedControlOnly = true
	// Approval authority is available only through the typed control endpoint,
	// which additionally requires the protected per-incarnation credential.
	cfg.Development.PProf.Enabled = false
	cfg.Metrics.Enabled = false

	cfg.Sessions.BaseDir = filepath.Join(stateDir, "runtime")
	cfg.Sessions.MaxSessions = 1
	cfg.Sessions.WorkspaceShadow.Enabled = true
	cfg.Sessions.WorkspaceShadow.BaseDir = filepath.Join(stateDir, "workspace")
	cfg.Sessions.WorkspaceShadow.DestroyAction = "keep"
	cfg.Sessions.WorkspaceOverlay.Enabled = false
	cfg.Sessions.WorkspaceOverlay.BaseDir = filepath.Join(stateDir, "overlay-disabled")

	cfg.Logging.Output = filepath.Join(stateDir, "logs", "supervisor.log")
	cfg.Audit.Output = filepath.Join(stateDir, "events.jsonl")
	cfg.Audit.Storage.SQLitePath = filepath.Join(stateDir, "events.db")
	cfg.Audit.Webhook.URL = ""
	cfg.Audit.OTEL.Enabled = false
	cfg.Audit.Watchtower.Enabled = false
	cfg.Audit.Integrity.Enabled = false

	if strictNetwork {
		// Detached strict-network mode needs a command cgroup for BPF attachment
		// but should not require resource-controller delegation. Leaving
		// sandbox.cgroups.enabled=false lets the cgroup probe use attach-only mode;
		// eBPF flags below still cause the cgroup hook to run. The source daemon's
		// base_path commonly names a root system service cgroup; a delegated user
		// supervisor must discover its own transient-unit cgroup instead of trying
		// to create children under that unrelated, non-writable path.
		cfg.Sandbox.Cgroups.Enabled = false
		cfg.Sandbox.Cgroups.BasePath = ""
		cfg.Sandbox.Network.Enabled = true
		cfg.Sandbox.Network.Transparent.Enabled = false
		cfg.Sandbox.Network.EBPF.Enabled = true
	} else {
		cfg.Sandbox.Cgroups.Enabled = false
		cfg.Sandbox.Network.Enabled = false
		cfg.Sandbox.Network.Transparent.Enabled = false
		cfg.Sandbox.Network.EBPF.Enabled = false
		cfg.Sandbox.Network.EBPF.Enforce = false
		cfg.Sandbox.Network.EBPF.Required = false
	}
	cfg.Sandbox.FUSE.Enabled = false
	cfg.Proxy.Mode = "disabled"
	cfg.PackageChecks.Enabled = false
	cfg.Skillcheck.Enabled = false
	cfg.ThreatFeeds.Enabled = false
	return nil
}

const detachedSupervisorNetworkPolicyRuntimeGap = "network policy checks may report approvals/denies that are not enforced at runtime in detached sessions"

func detachedSupervisorStrictNetworkEnforcement(cfg *config.Config) bool {
	return cfg != nil && (cfg.Sandbox.Network.EBPF.Required || cfg.Sandbox.Network.EBPF.Enforce)
}

func detachedSupervisorNetworkEnforcementWarning(cfg *config.Config) string {
	if cfg == nil {
		return ""
	}
	if detachedSupervisorStrictNetworkEnforcement(cfg) {
		// Preserving strict networking is the supported path. The active preflight
		// is authoritative and reports actionable failures; configured intent by
		// itself is not a warning condition.
		return ""
	}
	if features := detachedSupervisorUnsupportedNetworkFeatures(cfg); len(features) > 0 {
		return fmt.Sprintf("detached supervisor MVP is disabling best-effort network enforcement (%s); %s", strings.Join(features, ", "), detachedSupervisorNetworkPolicyRuntimeGap)
	}
	return ""
}

func detachedSupervisorNetworkRequest(cfg *config.Config) detached.NetworkEnforcementRequest {
	if detachedSupervisorStrictNetworkEnforcement(cfg) {
		return detached.NetworkEnforcementRequestStrict
	}
	if len(detachedSupervisorUnsupportedNetworkFeatures(cfg)) > 0 {
		return detached.NetworkEnforcementRequestBestEffort
	}
	return detached.NetworkEnforcementRequestNone
}

func detachedSupervisorPendingNetworkEnforcement(cfg *config.Config) *detached.NetworkEnforcement {
	requested := detachedSupervisorNetworkRequest(cfg)
	status := detached.NetworkEnforcementStatusNone
	detail := "no runtime network gate was requested"
	warning := "no runtime network gate is active; policy decisions do not imply traffic enforcement"
	if requested != detached.NetworkEnforcementRequestNone {
		status = detached.NetworkEnforcementStatusDegraded
		detail = "runtime preflight has not completed"
		warning = "network policy enforcement is not proven from launch configuration"
	}
	report := &detached.NetworkEnforcement{
		Requested: requested,
		Readiness: status,
		Status:    status,
		Tier:      detached.NetworkEnforcementTierNone,
		CheckedAt: time.Now().UTC(),
		Detail:    detail,
		Warning:   warning,
	}
	report.Normalize()
	return report
}

var detachedSupervisorRuntimeEnvKeys = []string{
	// This is a protected path, not credential material. Child Pi processes need
	// the same lifecycle-local auth/config root as the trusted parent so Pi's
	// auth-file lock can coordinate OAuth refreshes across concurrent children.
	"PI_CODING_AGENT_DIR",
	"AGENTSH_SUBAGENT_COMMAND",
	"AGENTSH_SUBAGENT_ARGS",
	"AGENTSH_SUBAGENT_TASK_MODE",
	"AGENTSH_SUBAGENT_PROTOCOL",
	"AGENTSH_SUBAGENT_MAX_DEPTH",
	"AGENTSH_SUBAGENT_RUNTIME",
	"AGENTSH_DRAFT_SUBAGENT_COMMAND",
	"AGENTSH_DRAFT_SUBAGENT_ARGS",
	"AGENTSH_DRAFT_SUBAGENT_HOME",
	"AGENTSH_DRAFT_SUBAGENT_STATE_DIR",
	// Host-only callback coordinates let a v3 runtime monitor delegate unknown
	// egress decisions to the still-active trusted parent subagent request. They
	// are service environment, never session command environment.
	"AGENTSH_HOST_EGRESS_APPROVAL_CREDENTIAL_FILE",
	"AGENTSH_HOST_EGRESS_APPROVAL_SESSION_ID",
	"AGENTSH_HOST_EGRESS_APPROVAL_SUPERVISOR",
}

func detachedSupervisorServiceEnv(env, inheritPatterns []string) []string {
	var serviceEnv []string
	// Never put the helper credential value in systemd-run argv or transient
	// unit properties. Installed services pass only the protected credential
	// file path; the supervisor reads it before serving requests. The generic
	// subagent runtime configuration is non-secret control-plane data and must
	// cross the systemd-run boundary so spawn_subagent works in detached mode.
	keys := []string{nethelper.EnvCredentialFile, nethelper.EnvSocket, nethelper.EnvBootstrapResult, nethelper.EnvRecoveryTokenFile, detached.EnvNetworkEnforcementRequested, detached.EnvGuestEgressProxyURL}
	keys = append(keys, detachedSupervisorRuntimeEnvKeys...)
	seen := map[string]struct{}{}
	for _, key := range keys {
		if value, ok := lookupEnvAssignment(env, key); ok && strings.TrimSpace(value) != "" {
			serviceEnv = append(serviceEnv, key+"="+strings.TrimSpace(value))
			seen[key] = struct{}{}
		}
	}
	// A systemd-launched detached supervisor does not otherwise inherit the
	// caller's environment. Carry only values explicitly requested through
	// --env-inherit so session creation can both expose them to allowed commands
	// and expand policy variables such as ${SSH_AUTH_SOCK} to the exact path.
	for _, assignment := range env {
		name, value, ok := strings.Cut(assignment, "=")
		if !ok || name == "" || value == "" || !detachedSupervisorEnvRequested(name, inheritPatterns) {
			continue
		}
		if _, ok := seen[name]; ok || isSensitiveSupervisorAssignment(assignment) {
			continue
		}
		serviceEnv = append(serviceEnv, assignment)
		seen[name] = struct{}{}
	}
	return serviceEnv
}

func restartUnsafeServiceEnvironmentNames(assignments []string) []string {
	var unsafe []string
	for _, assignment := range assignments {
		name, _, ok := strings.Cut(assignment, "=")
		name = strings.TrimSpace(name)
		if !ok || name == "" {
			continue
		}
		switch name {
		case "AGENTSH_DETACHED_EVENT_TOKEN", nethelper.EnvCredentialFile, nethelper.EnvSocket,
			nethelper.EnvBootstrapResult, nethelper.EnvRecoveryTokenFile,
			detached.EnvNetworkEnforcementRequested, detached.EnvSupervisorLaunchMode, detached.EnvGuestEgressProxyURL:
			continue
		}
		if !detached.RestartSafeEnvironmentName(name) {
			unsafe = append(unsafe, name)
		}
	}
	slices.Sort(unsafe)
	return slices.Compact(unsafe)
}

func detachedSupervisorEnvRequested(name string, patterns []string) bool {
	for _, pattern := range patterns {
		pattern = strings.TrimSpace(pattern)
		if pattern == name {
			return true
		}
		if matched, err := filepath.Match(pattern, name); err == nil && matched {
			return true
		}
	}
	return false
}

func loadSupervisorNethelperCredential() error {
	credential := strings.TrimSpace(os.Getenv(nethelper.EnvHelperInstanceCredential))
	if credential == "" {
		credential = strings.TrimSpace(os.Getenv(nethelper.EnvSessionNonce))
	}
	if credential == "" {
		credentialFile := strings.TrimSpace(os.Getenv(nethelper.EnvCredentialFile))
		if credentialFile == "" {
			_ = os.Unsetenv(nethelper.EnvSessionNonce)
			return nil
		}
		var err error
		credential, err = readSupervisorNethelperCredentialFile(credentialFile)
		if err != nil {
			return fmt.Errorf("load nethelper instance credential: %w", err)
		}
	}
	if err := validateNethelperInstanceCredential(credential); err != nil {
		return err
	}
	if err := os.Setenv(nethelper.EnvHelperInstanceCredential, credential); err != nil {
		return fmt.Errorf("retain nethelper instance credential until server initialization: %w", err)
	}
	_ = os.Unsetenv(nethelper.EnvSessionNonce)
	// api.NewApp captures the value into the trusted App and unsets both the
	// value and source path before a command can execute.
	return nil
}

func readSupervisorNethelperCredentialFile(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", fmt.Errorf("credential file path is required")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", fmt.Errorf("stat credential file %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("credential file %s must not be a symlink", path)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("credential file %s must be a regular file", path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("credential file %s must not be group/world readable", path)
	}
	if err := validateSupervisorCredentialFileOwner(info); err != nil {
		return "", fmt.Errorf("validate credential file %s: %w", path, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read credential file %s: %w", path, err)
	}
	return strings.TrimSpace(string(data)), nil
}

func detachedSupervisorUnsupportedNetworkFeatures(cfg *config.Config) []string {
	if cfg == nil {
		return nil
	}
	var features []string
	if cfg.Sandbox.Network.Enabled {
		features = append(features, "sandbox.network.enabled")
	}
	if cfg.Sandbox.Network.Enabled && cfg.Sandbox.Network.Transparent.Enabled {
		features = append(features, "sandbox.network.transparent.enabled")
	}
	if cfg.Sandbox.Network.EBPF.Enabled {
		features = append(features, "sandbox.network.ebpf.enabled")
	}
	if cfg.Sandbox.Network.EBPF.Enforce {
		features = append(features, "sandbox.network.ebpf.enforce")
	}
	if cfg.Sandbox.Network.EBPF.Required {
		features = append(features, "sandbox.network.ebpf.required")
	}
	return features
}

func newSessionStartCmd() *cobra.Command {
	var detach bool
	var workspaces []string
	var policy string
	var outputJSON bool
	var workspaceMode string
	var runtimeHomeMode string
	var envBaseMode string
	var envInherit []string
	var sessionID string
	var runtimeProfile string
	var runtimeInputBundle string
	var controlTokenFile string
	cmd := &cobra.Command{
		Use:   "start",
		Short: "Start a session",
		Long: `Start a session.

Experimental Stage 1 detached mode starts a per-session AgentSH supervisor
owned by the current user. The supervisor writes metadata.json and listens on a
session-local supervisor.sock. This MVP disables unsupported best-effort
network/cgroup features, preserves required/enforced eBPF as a fail-closed
setup path, and refuses strict startup unless runtime evidence is ready.
Overlay workspaces, FUSE/COW, trusted-parent Pi, subagents, and credential
broker features remain out of scope.`,
		Example: `  agentsh session start --detach --workspace . --workspace-mode shadow --json
  agentsh wrap --server unix://$SUPERVISOR_SOCK --session $SESSION_ID -- echo hi`,

		RunE: func(cmd *cobra.Command, args []string) error {
			if !detach {
				return fmt.Errorf("session start currently requires --detach (use 'agentsh session create' for daemon-backed sessions)")
			}
			if workspaceMode == "" {
				workspaceMode = string(types.WorkspaceModeShadow)
			}
			if workspaceMode != string(types.WorkspaceModeShadow) && workspaceMode != string(types.WorkspaceModeDirect) {
				return fmt.Errorf("unsupported workspace mode %q for experimental detached supervisor: Stage 1 supports only shadow (recommended) or direct; overlay/COW/FUSE backends are intentionally not implemented in this MVP", workspaceMode)
			}
			if policy == "" {
				policy = "agent-default"
			}
			if len(workspaces) == 0 {
				workspaces = []string{"."}
			}
			res, err := startDetachedSupervisorSessionWithInput(cmd.Context(), sessionID, workspaces, workspaceMode, policy, runtimeHomeMode, envBaseMode, envInherit, runtimeProfile, runtimeInputBundle)
			if err != nil {
				return err
			}
			if controlTokenFile != "" {
				if err := writeDetachedControlTokenFile(controlTokenFile, res.EventToken); err != nil {
					return err
				}
			}
			if outputJSON {
				return printJSON(cmd, res)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Session %s started\n", res.SessionID)
			fmt.Fprintf(cmd.OutOrStdout(), "  Supervisor: unix://%s\n", res.SupervisorSock)
			fmt.Fprintf(cmd.OutOrStdout(), "  Worktree:   %s\n", res.Worktree)
			for _, line := range detachedreport.HumanLines(res.NetworkEnforcement, "  ") {
				fmt.Fprintln(cmd.OutOrStdout(), line)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "\nWrap with:\n  agentsh wrap --server unix://%s --session %s -- <cmd>\n", res.SupervisorSock, res.SessionID)
			return nil
		},
	}
	cmd.Flags().BoolVar(&detach, "detach", false, "Start a detached per-session supervisor")
	cmd.Flags().StringArrayVar(&workspaces, "workspace", nil, "Workspace directory (repeatable for shadow multi-root sessions)")
	cmd.Flags().StringVar(&workspaceMode, "workspace-mode", string(types.WorkspaceModeShadow), "Workspace mode: shadow or direct")
	cmd.Flags().StringVar(&policy, "policy", "agent-default", "Policy name")
	cmd.Flags().StringVar(&runtimeHomeMode, "runtime-home", "", "Process HOME mode: isolated or real")
	cmd.Flags().StringVar(&envBaseMode, "env-base", "", "Child env base: minimal or inherit_allowed")
	cmd.Flags().StringArrayVar(&envInherit, "env-inherit", nil, "Env var name/glob to offer in addition to minimal base (repeatable)")
	cmd.Flags().StringVar(&sessionID, "session-id", "", "Exact caller-preallocated session-UUID identity")
	cmd.Flags().StringVar(&runtimeProfile, "runtime-profile", "", "Operator-configured detached runtime profile (default: sessions.runtime.default_profile)")
	cmd.Flags().StringVar(&runtimeInputBundle, "runtime-input-bundle", "", "Trusted Git input bundle for an isolated external runtime")
	cmd.Flags().StringVar(&controlTokenFile, "control-token-file", "", "Create a private detached-control credential file for a trusted wrapper")
	cmd.Flags().BoolVar(&outputJSON, "json", false, "Output in JSON format")
	return cmd
}

func writeDetachedControlTokenFile(path, token string) error {
	path = filepath.Clean(strings.TrimSpace(path))
	if !filepath.IsAbs(path) || path == string(filepath.Separator) || strings.TrimSpace(token) == "" || strings.ContainsAny(token, " \t\r\n") {
		return fmt.Errorf("detached control token file request is invalid")
	}
	parent := filepath.Dir(path)
	info, err := os.Lstat(parent)
	if err != nil {
		return fmt.Errorf("inspect detached control token directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("detached control token directory must be a private direct directory")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create detached control token file: %w", err)
	}
	ok := false
	defer func() {
		_ = file.Close()
		if !ok {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.WriteString(token + "\n"); err != nil {
		return fmt.Errorf("write detached control token file: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync detached control token file: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close detached control token file: %w", err)
	}
	ok = true
	return nil
}

func randomDetachedEventToken() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return uuid.NewString() + uuid.NewString()
	}
	return hex.EncodeToString(b[:])
}

func validateDetachedSessionID(requested string) error {
	if requested != strings.TrimSpace(requested) || !strings.HasPrefix(requested, "session-") {
		return fmt.Errorf("detached session ID must use canonical session-UUID form")
	}
	raw := strings.TrimPrefix(requested, "session-")
	parsed, err := uuid.Parse(raw)
	if err != nil || parsed == uuid.Nil || requested != "session-"+parsed.String() {
		return fmt.Errorf("detached session ID must use canonical session-UUID form")
	}
	return nil
}

func detachedSessionID(requested string) (string, error) {
	if requested == "" {
		return "session-" + uuid.NewString(), nil
	}
	if err := validateDetachedSessionID(requested); err != nil {
		return "", fmt.Errorf("--session-id: %w", err)
	}
	return requested, nil
}

func reserveDetachedSessionState(sessionID string) (string, error) {
	sessionsRoot := filepath.Join(config.GetUserStateDir(), "sessions")
	if err := os.MkdirAll(sessionsRoot, 0o700); err != nil {
		return "", fmt.Errorf("create detached sessions root: %w", err)
	}
	stateDir := filepath.Join(sessionsRoot, sessionID)
	if err := os.Mkdir(stateDir, 0o700); err != nil {
		if errors.Is(err, os.ErrExist) {
			return "", fmt.Errorf("detached session state already exists for %s", sessionID)
		}
		return "", fmt.Errorf("create detached session state for %s: %w", sessionID, err)
	}
	return stateDir, nil
}

type detachedSupervisorFixedEnvironmentKey struct{}

func withDetachedSupervisorFixedEnvironment(ctx context.Context, assignments []string) (context.Context, error) {
	if len(assignments) == 0 {
		return ctx, nil
	}
	fixed := make([]string, 0, len(assignments))
	seen := make(map[string]struct{}, len(assignments))
	for _, assignment := range assignments {
		name, value, ok := strings.Cut(assignment, "=")
		name = strings.TrimSpace(name)
		if !ok || name == "" || value == "" || strings.ContainsAny(name, "= \t\r\n") || strings.ContainsAny(value, "\x00\r\n") {
			return nil, fmt.Errorf("fixed detached supervisor environment assignment is invalid")
		}
		if _, duplicate := seen[name]; duplicate {
			return nil, fmt.Errorf("fixed detached supervisor environment assignment is duplicated")
		}
		seen[name] = struct{}{}
		fixed = append(fixed, name+"="+value)
	}
	return context.WithValue(ctx, detachedSupervisorFixedEnvironmentKey{}, fixed), nil
}

func detachedSupervisorFixedEnvironment(ctx context.Context) []string {
	if ctx == nil {
		return nil
	}
	assignments, _ := ctx.Value(detachedSupervisorFixedEnvironmentKey{}).([]string)
	return append([]string(nil), assignments...)
}

func startDetachedSupervisorSession(ctx context.Context, requestedSessionID string, workspaces []string, workspaceMode, policyName, runtimeHomeMode, envBaseMode string, envInherit []string, runtimeProfile string) (*detachedSessionStartResult, error) {
	return startDetachedSupervisorSessionAtGeneration(ctx, requestedSessionID, workspaces, workspaceMode, policyName, runtimeHomeMode, envBaseMode, envInherit, runtimeProfile, "", 1)
}

func startDetachedSupervisorSessionWithInput(ctx context.Context, requestedSessionID string, workspaces []string, workspaceMode, policyName, runtimeHomeMode, envBaseMode string, envInherit []string, runtimeProfile, inputBundle string) (*detachedSessionStartResult, error) {
	return startDetachedSupervisorSessionAtGeneration(ctx, requestedSessionID, workspaces, workspaceMode, policyName, runtimeHomeMode, envBaseMode, envInherit, runtimeProfile, inputBundle, 1)
}

func startDetachedSupervisorSessionAtGeneration(ctx context.Context, requestedSessionID string, workspaces []string, workspaceMode, policyName, runtimeHomeMode, envBaseMode string, envInherit []string, runtimeProfile, inputBundle string, expectedGeneration uint64) (*detachedSessionStartResult, error) {
	if expectedGeneration == 0 {
		return nil, fmt.Errorf("detached supervisor expected generation must be positive")
	}
	request, configPath, cfg, err := prepareDetachedRuntimeRequest(
		requestedSessionID, workspaces, workspaceMode, policyName,
		runtimeHomeMode, envBaseMode, envInherit, runtimeProfile,
	)
	if err != nil {
		return nil, err
	}
	request.ExpectedGeneration = expectedGeneration
	_, selected, err := cfg.Sessions.Runtime.ResolveProfile(runtimeProfile)
	if err != nil {
		return nil, err
	}
	if selected.Provider == externalrunner.ProviderName {
		profile, profileErr := externalrunner.ReadProfile(selected.ProfileFile)
		if profileErr != nil {
			return nil, profileErr
		}
		switch profile.Schema {
		case externalrunner.ProfileSchemaV1:
			if strings.TrimSpace(inputBundle) != "" {
				return nil, fmt.Errorf("legacy external runtime does not accept a Git input bundle")
			}
		case externalrunner.ProfileSchemaV2, externalrunner.ProfileSchemaV3:
			descriptor, ingestErr := ingestRuntimeInputBundle(ctx, request.StateDir, request.SessionID, inputBundle)
			if ingestErr != nil {
				return nil, ingestErr
			}
			request.InputArtifact = &descriptor
		}
	} else if strings.TrimSpace(inputBundle) != "" {
		return nil, fmt.Errorf("runtime input bundles require an isolated external runtime profile")
	}
	return startDetachedRuntime(ctx, request, configPath, cfg)
}

func ingestRuntimeInputBundle(ctx context.Context, stateDir, sessionID, path string) (artifact.Descriptor, error) {
	path = filepath.Clean(strings.TrimSpace(path))
	if !filepath.IsAbs(path) || path == string(filepath.Separator) {
		return artifact.Descriptor{}, fmt.Errorf("external runtime Git input bundle path must be clean and absolute")
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 {
		return artifact.Descriptor{}, fmt.Errorf("external runtime Git input bundle is not a direct regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return artifact.Descriptor{}, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return artifact.Descriptor{}, fmt.Errorf("external runtime Git input bundle identity changed while opening")
	}
	store, err := artifact.NewStore(stateDir, sessionID, guestcontrol.MaxArtifactTransferBytes)
	if err != nil {
		return artifact.Descriptor{}, err
	}
	return store.Put(ctx, artifact.KindGitInputBundle, file)
}

func startNativeDetachedSupervisorSession(ctx context.Context, request runtimeprovider.Request, configPath string, preflightCfg *config.Config) (*detachedSessionStartResult, error) {
	sessionID := request.SessionID
	stateDir := request.StateDir
	req := request.Session
	realWorkspace := req.Workspace
	policyName := req.Policy
	workspaceMode := req.WorkspaceMode
	envInherit := req.EnvInherit
	sockPath := filepath.Join(stateDir, "supervisor.sock")
	logsDir := filepath.Join(stateDir, "logs")
	if err := os.Mkdir(logsDir, 0o700); err != nil {
		return nil, fmt.Errorf("create detached supervisor log directory: %w", err)
	}

	logPath := filepath.Join(logsDir, "supervisor.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open supervisor log: %w", err)
	}
	defer logFile.Close()

	exe, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("locate executable: %w", err)
	}
	if preflightCfg == nil {
		return nil, fmt.Errorf("native runtime preflight configuration is unavailable")
	}
	if warning := detachedSupervisorNetworkEnforcementWarning(preflightCfg); warning != "" {
		fmt.Fprintf(os.Stderr, "agentsh: warning: %s\n", warning)
	}
	eventToken := randomDetachedEventToken()
	parentEnv := os.Environ()
	fixedEnvironment := detachedSupervisorFixedEnvironment(ctx)
	if len(fixedEnvironment) > 0 {
		names := make([]string, 0, len(fixedEnvironment))
		for _, assignment := range fixedEnvironment {
			name, _, _ := strings.Cut(assignment, "=")
			names = append(names, name)
		}
		parentEnv = append(withoutEnvAssignments(parentEnv, names...), fixedEnvironment...)
	}
	helperCredential, _ := lookupEnvAssignment(parentEnv, nethelper.EnvHelperInstanceCredential)
	if strings.TrimSpace(helperCredential) == "" {
		helperCredential, _ = lookupEnvAssignment(parentEnv, nethelper.EnvSessionNonce)
	}
	credentialFile, _ := lookupEnvAssignment(parentEnv, nethelper.EnvCredentialFile)
	launcherEnv := withoutEnvAssignments(parentEnv,
		"AGENTSH_DETACHED_EVENT_TOKEN",
		nethelper.EnvHelperInstanceCredential,
		nethelper.EnvSessionNonce,
		nethelper.EnvCredentialFile,
		detached.EnvNetworkEnforcementRequested,
		detached.EnvSupervisorLaunchMode,
	)
	launcherEnv = append(launcherEnv,
		detached.EnvNetworkEnforcementRequested+"="+string(detachedSupervisorNetworkRequest(preflightCfg)),
	)
	if strings.TrimSpace(helperCredential) != "" {
		launcherEnv = append(launcherEnv, nethelper.EnvHelperInstanceCredential+"="+strings.TrimSpace(helperCredential))
	}
	if strings.TrimSpace(credentialFile) != "" {
		launcherEnv = append(launcherEnv, nethelper.EnvCredentialFile+"="+strings.TrimSpace(credentialFile))
	}
	serviceEnv := detachedSupervisorServiceEnv(launcherEnv, envInherit)
	serviceEnvFile := filepath.Join(stateDir, "supervisor.env")
	launch := buildDetachedSupervisorLaunch(detachedSupervisorLaunchRequest{
		Exe:            exe,
		Args:           detachedSupervisorRunArgs(stateDir, sockPath, configPath),
		Env:            launcherEnv,
		Dir:            realWorkspace,
		SessionID:      sessionID,
		ServiceEnv:     serviceEnv,
		ServiceEnvFile: serviceEnvFile,
		ServiceLogFile: logPath,
	})
	if launch.UsesSystemd {
		serviceEnv = withoutEnvAssignments(serviceEnv, detached.EnvSupervisorLaunchMode)
		serviceEnv = append(serviceEnv, detached.EnvSupervisorLaunchMode+"=systemd-user-delegated")
	}
	// Retain the protected, path-oriented bootstrap environment for exact
	// process recreation. The detached control credential remains only in
	// protected metadata and is never placed in a process environment.
	if err := writeDetachedSupervisorEnvironmentFile(serviceEnvFile, serviceEnv); err != nil {
		return nil, err
	}
	createdAt := time.Now().UTC()
	manifest := detached.NewRecoveryManifest(sessionID, req, detached.LaunchSpec{
		Executable: exe, ConfigPath: configPath, WorkingDir: realWorkspace,
		EnvironmentFile: serviceEnvFile, LogFile: logPath,
		SystemdUnit: launch.SystemdUnit, UsesSystemd: launch.UsesSystemd,
		PrivateTmp: !detachedSupervisorNeedsHostTmp(serviceEnv),
	}, createdAt)
	// The child increments the retained recovery generation before publishing.
	// Fresh host sessions start at one; recreated MicroVM guests seed the exact
	// outer generation so stale handshakes cannot satisfy recovery.
	expectedGeneration := request.ExpectedGeneration
	if expectedGeneration == 0 {
		expectedGeneration = 1
	}
	manifest.Generation = expectedGeneration - 1
	manifest.Mutable.VolatileEnvironment = restartUnsafeServiceEnvironmentNames(serviceEnv)
	if len(fixedEnvironment) > 0 {
		fixedNames := make(map[string]struct{}, len(fixedEnvironment))
		for _, assignment := range fixedEnvironment {
			name, _, _ := strings.Cut(assignment, "=")
			fixedNames[strings.ToLower(name)] = struct{}{}
		}
		manifest.Mutable.VolatileEnvironment = slices.DeleteFunc(manifest.Mutable.VolatileEnvironment, func(name string) bool {
			_, fixed := fixedNames[strings.ToLower(name)]
			return fixed
		})
	}
	if err := detached.WriteRecoveryManifest(stateDir, manifest); err != nil {
		return nil, err
	}
	provisioningMeta := supervisorMetadata{
		SessionID: sessionID, ID: sessionID, CreatedAt: createdAt,
		State: detached.LifecycleProvisioning, Policy: policyName,
		RealWorkspace: realWorkspace, WorkspaceMode: workspaceMode,
		SupervisorSock: sockPath, EventToken: eventToken,
		SystemdUnit: launch.SystemdUnit, NetworkEnforcement: detachedSupervisorPendingNetworkEnforcement(preflightCfg),
		ProtocolVersion: supervisorProtocolVersion,
	}
	if err := writeSupervisorMetadata(stateDir, provisioningMeta); err != nil {
		return nil, err
	}
	cmd := exec.Command(launch.Path, launch.Args...)
	cmd.Env = launch.Env
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.Stdin = nil
	cmd.Dir = launch.Dir
	if !launch.UsesSystemd {
		setDetachedProcessAttrs(cmd)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start supervisor: %w", err)
	}
	pid := cmd.Process.Pid
	_ = cmd.Process.Release()
	keepSupervisor := false
	defer func() {
		if keepSupervisor {
			return
		}
		if launch.SystemdUnit != "" {
			_ = stopDetachedSupervisorSystemdUnit(context.Background(), launch.SystemdUnit)
		} else {
			_ = signalProcess(pid, os.Kill)
		}
	}()

	waitClient := client.NewWithTimeout("unix://"+sockPath, "", time.Second)
	if err := waitForSupervisor(ctx, sockPath, waitClient); err != nil {
		if launch.SystemdUnit != "" {
			_ = stopDetachedSupervisorSystemdUnit(ctx, launch.SystemdUnit)
		} else {
			_ = signalProcess(pid, os.Kill)
		}
		return nil, err
	}
	// Bootstrap and retained-shadow reopening happen inside the supervisor before
	// its listeners serve. Fetch the exact identity rather than issuing a second
	// create request from this launcher.
	c := client.NewWithTimeout("unix://"+sockPath, "", 30*time.Second)
	sess, err := c.GetSession(ctx, sessionID)
	if err != nil {
		if launch.SystemdUnit != "" {
			_ = stopDetachedSupervisorSystemdUnit(ctx, launch.SystemdUnit)
		} else {
			_ = signalProcess(pid, os.Kill)
		}
		return nil, fmt.Errorf("read bootstrapped supervised session: %w", err)
	}
	if sess.ID != sessionID {
		return nil, fmt.Errorf("detached supervisor identity mismatch: got %s, want %s", sess.ID, sessionID)
	}
	var networkEnforcement detached.NetworkEnforcement
	networkPath := "/api/v1/sessions/" + url.PathEscape(sessionID) + "/network-enforcement"
	if err := c.DoRawJSON(ctx, http.MethodGet, networkPath, nil, &networkEnforcement); err != nil {
		return nil, fmt.Errorf("read live detached network readiness: %w", err)
	}
	networkEnforcement.Normalize()
	if detachedSupervisorStrictNetworkEnforcement(preflightCfg) && !networkEnforcement.Ready() {
		return nil, fmt.Errorf("strict detached network startup refused: status=%s tier=%s: %s", networkEnforcement.Status, networkEnforcement.Tier, networkEnforcement.Detail)
	}
	meta, _, err := detached.ReadMetadataFromRoot(filepath.Dir(stateDir), sessionID)
	if err != nil {
		return nil, err
	}
	if meta.SessionID != sessionID || meta.State != detached.LifecycleReady || meta.Generation == 0 || strings.TrimSpace(meta.IncarnationID) == "" {
		return nil, fmt.Errorf("detached supervisor did not publish a complete ready identity for %s", sessionID)
	}
	meta.NetworkEnforcement = &networkEnforcement
	worktree := sess.WorkspaceMount
	if sess.Shadow != nil && sess.Shadow.Work != "" {
		worktree = sess.Shadow.Work
	}
	if worktree == "" {
		worktree = sess.Workspace
	}
	meta.Worktree = worktree
	keepSupervisor = true
	return &detachedSessionStartResult{supervisorMetadata: meta, Session: sess, StateDir: stateDir}, nil
}

func detachedSupervisorRuntimeHandshake(ctx context.Context, c *client.Client, sessionID string) (*detached.NetworkEnforcement, error) {
	if c == nil {
		return nil, fmt.Errorf("supervisor client is nil")
	}
	handshakeCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var report detached.NetworkEnforcement
	path := "/api/v1/sessions/" + url.PathEscape(sessionID) + "/network-enforcement/preflight"
	if err := c.DoRawJSON(handshakeCtx, http.MethodPost, path, []byte(`{}`), &report); err != nil {
		return nil, err
	}
	report.Normalize()
	return &report, nil
}

func waitForSupervisor(ctx context.Context, sockPath string, c *client.Client) error {
	return waitForSupervisorAfterGeneration(ctx, sockPath, c, 0)
}

func waitForSupervisorAfterGeneration(ctx context.Context, sockPath string, c *client.Client, priorGeneration uint64) error {
	// Shadow materialization can legitimately take many minutes. The socket is
	// bound during server construction but is not served until exact bootstrap
	// and enforcement preflight commit, so this wait is also the readiness gate.
	deadline := time.Now().Add(30 * time.Minute)
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out waiting for supervisor socket %s", sockPath)
		}
		stateDir := filepath.Dir(sockPath)
		sessionID := filepath.Base(stateDir)
		meta, _, metaErr := detached.ReadMetadataFromRoot(filepath.Dir(stateDir), sessionID)
		if metaErr == nil && (priorGeneration == 0 || meta.Generation > priorGeneration) {
			switch meta.State {
			case detached.LifecycleFailed:
				return fmt.Errorf("detached supervisor %s failed during startup: %s", sessionID, meta.LastError)
			case detached.LifecycleFinalized:
				if priorGeneration > 0 {
					return errDetachedFinalizationCompleted
				}
				return fmt.Errorf("detached supervisor %s became %s during startup", sessionID, meta.State)
			case detached.LifecycleStopped:
				return fmt.Errorf("detached supervisor %s became %s during startup", sessionID, meta.State)
			}
			if _, statErr := os.Stat(sockPath); statErr == nil {
				if _, err := c.ListSessions(ctx); err == nil {
					return nil
				}
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func detachedClientForSession(sessionID string) (*client.Client, supervisorMetadata, error) {
	meta, _, err := readSupervisorMetadata(sessionID)
	if err != nil {
		return nil, supervisorMetadata{}, err
	}
	if err := validateSupervisorMetadataUsable(meta); err != nil {
		return nil, supervisorMetadata{}, err
	}
	// Review/apply can legitimately run rsync across a large project. Keep the
	// transport alive for the server-owned finalization bound; individual
	// identity handshakes still use their explicit short contexts below.
	c := client.NewWithTimeout("unix://"+meta.SupervisorSock, "", detachedReviewClientTimeout)
	handshakeCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := validateDetachedRuntimeHandshake(handshakeCtx, c, meta); err != nil {
		return nil, supervisorMetadata{}, err
	}
	return c.WithDetachedControlToken(meta.EventToken), meta, nil
}

func detachedRuntimeHandshakeStatus(ctx context.Context, c *client.Client, meta supervisorMetadata) (detached.RuntimeStatus, error) {
	if meta.ProtocolVersion < detached.ProtocolVersion {
		// Version-one metadata has no incarnation handshake. Keep read
		// compatibility, but never describe it as crash recoverable.
		return detached.RuntimeStatus{}, nil
	}
	var status detached.RuntimeStatus
	if err := c.DoRawJSON(ctx, http.MethodGet, "/api/v1/detached/status", nil, &status); err != nil {
		return detached.RuntimeStatus{}, fmt.Errorf("detached supervisor identity handshake failed for %s: %w", meta.SessionID, err)
	}
	providerManifest, manifestErr := runtimeprovider.ReadManifest(filepath.Join(detachedSessionsRoot(), meta.SessionID))
	if manifestErr == nil && providerManifest.Provider == externalrunner.ProviderName {
		hostStatus, hostErr := externalrunner.ReadHostMonitorStatus(providerManifest.StateDir)
		if hostErr != nil || status.ProtocolVersion != meta.ProtocolVersion || status.SessionID != meta.SessionID ||
			status.Generation != meta.Generation || status.IncarnationID != meta.IncarnationID ||
			hostStatus.Monitor.PID != meta.OwnerPID || hostStatus.Monitor.StartIdentity != meta.OwnerStartIdentity || hostStatus.Monitor.BootID != meta.BootID {
			return detached.RuntimeStatus{}, fmt.Errorf("external detached runtime identity handshake mismatch for expected session %s", meta.SessionID)
		}
		status.OwnerPID = meta.OwnerPID
		status.OwnerStartIdentity = meta.OwnerStartIdentity
		status.BootID = meta.BootID
		status.Recoverable = false
		return status, nil
	}
	if status.ProtocolVersion != meta.ProtocolVersion || status.SessionID != meta.SessionID ||
		status.Generation != meta.Generation || status.IncarnationID != meta.IncarnationID ||
		status.OwnerPID != meta.OwnerPID || status.OwnerStartIdentity != meta.OwnerStartIdentity || status.BootID != meta.BootID {
		return detached.RuntimeStatus{}, fmt.Errorf("detached supervisor identity handshake mismatch for expected session %s", meta.SessionID)
	}
	return status, nil
}

func validateDetachedRuntimeHandshake(ctx context.Context, c *client.Client, meta supervisorMetadata) error {
	status, err := detachedRuntimeHandshakeStatus(ctx, c, meta)
	if err != nil || meta.ProtocolVersion < detached.ProtocolVersion {
		return err
	}
	if status.LifecycleState != detached.LifecycleReady && status.LifecycleState != detached.LifecycleDegraded && status.LifecycleState != detached.LifecycleRecovering {
		return fmt.Errorf("detached supervisor %s is %s: %s", meta.SessionID, status.LifecycleState, status.LastError)
	}
	return nil
}

func newSessionRecoverCmd() *cobra.Command {
	var outputJSON bool
	cmd := &cobra.Command{
		Use:   "recover SESSION_ID",
		Short: "Recover the exact detached supervisor and retained session",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			status, err := recoverDetachedSession(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			if outputJSON {
				return printJSON(cmd, status)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Session %s recovered (generation %d, state %s)\n", status.SessionID, status.Generation, status.LifecycleState)
			return nil
		},
	}
	cmd.Flags().BoolVar(&outputJSON, "json", false, "Output lifecycle status as JSON")
	return cmd
}

func recoverNativeDetachedSession(ctx context.Context, sessionID string) (detached.RuntimeStatus, error) {
	meta, stateDir, err := readSupervisorMetadata(sessionID)
	if err != nil {
		return detached.RuntimeStatus{}, err
	}
	manifest, err := detached.ReadRecoveryManifest(stateDir)
	if err != nil {
		return detached.RuntimeStatus{}, fmt.Errorf("exact recovery is unavailable for legacy/incomplete detached session %s: %w", sessionID, err)
	}
	if manifest.SessionID != sessionID {
		return detached.RuntimeStatus{}, fmt.Errorf("detached recovery manifest identity mismatch")
	}
	switch manifest.State {
	case detached.LifecycleStopping, detached.LifecycleStopped, detached.LifecycleFinalized:
		return detached.RuntimeStatus{}, fmt.Errorf("detached session %s is %s and cannot be recovered", sessionID, manifest.State)
	case detached.LifecycleFinalizing:
		if manifest.Finalization == nil || manifest.Shadow == nil {
			return detached.RuntimeStatus{}, fmt.Errorf("detached session %s has incomplete finalization recovery state", sessionID)
		}
	}
	if c, _, liveErr := detachedClientForSession(sessionID); liveErr == nil {
		var status detached.RuntimeStatus
		if err := c.DoRawJSON(ctx, http.MethodGet, "/api/v1/detached/status", nil, &status); err == nil {
			return status, nil
		}
	}

	// A failed handshake does not prove that a direct supervisor process died.
	// Never unlink its live socket and race a second process. Systemd restart is
	// an explicit replacement of the exact unit; for direct mode, terminate only
	// a kernel-verified exact owner and wait for it to die first.
	if !manifest.Launch.UsesSystemd && meta.OwnerPID > 0 && supervisorPIDAlive(meta.OwnerPID) {
		if meta.OwnerStartIdentity == "" || meta.BootID == "" {
			return detached.RuntimeStatus{}, fmt.Errorf("refusing direct recovery while unverified owner_pid %d is still alive", meta.OwnerPID)
		}
		if detached.ProcessIdentityMatches(meta.OwnerPID, meta.OwnerStartIdentity, meta.BootID) {
			if err := signalProcess(meta.OwnerPID, os.Kill); err != nil {
				return detached.RuntimeStatus{}, fmt.Errorf("terminate unresponsive exact detached supervisor: %w", err)
			}
			deadline := time.Now().Add(10 * time.Second)
			for supervisorPIDAlive(meta.OwnerPID) && detached.ProcessIdentityMatches(meta.OwnerPID, meta.OwnerStartIdentity, meta.BootID) {
				if time.Now().After(deadline) {
					return detached.RuntimeStatus{}, fmt.Errorf("timed out terminating unresponsive exact detached supervisor %d", meta.OwnerPID)
				}
				time.Sleep(50 * time.Millisecond)
			}
		}
	}
	_ = os.Remove(meta.SupervisorSock)
	serviceEnv, err := detached.ReadServiceEnvironment(manifest.Launch.EnvironmentFile)
	if err != nil {
		return detached.RuntimeStatus{}, fmt.Errorf("load exact supervisor recovery environment: %w", err)
	}
	args := detachedSupervisorRunArgs(stateDir, meta.SupervisorSock, manifest.Launch.ConfigPath)
	if manifest.Launch.UsesSystemd {
		if manifest.Launch.SystemdUnit == "" || manifest.Launch.SystemdUnit != meta.SystemdUnit {
			return detached.RuntimeStatus{}, fmt.Errorf("detached systemd recovery identity is incomplete")
		}
		restartCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		restart := exec.CommandContext(restartCtx, "systemctl", "--user", "restart", manifest.Launch.SystemdUnit)
		restartErr := restart.Run()
		cancel()
		if restartErr != nil {
			systemdRun, lookErr := exec.LookPath("systemd-run")
			if lookErr != nil {
				return detached.RuntimeStatus{}, fmt.Errorf("recreate detached systemd unit: %w", lookErr)
			}
			propertyEnv := serviceEnv
			if !manifest.Launch.PrivateTmp {
				propertyEnv = append(append([]string(nil), serviceEnv...), "SSH_AUTH_SOCK="+filepath.Join(os.TempDir(), "agentsh-recovery-agent.sock"))
			}
			launchArgs := buildSystemdRunDetachedSupervisorArgs(
				manifest.Launch.SystemdUnit, manifest.Launch.WorkingDir,
				manifest.Launch.EnvironmentFile, manifest.Launch.LogFile,
				propertyEnv, manifest.Launch.Executable, args,
			)
			launchCmd := exec.CommandContext(ctx, systemdRun, launchArgs...)
			launchCmd.Env = withoutEnvAssignments(os.Environ(), "AGENTSH_DETACHED_EVENT_TOKEN", nethelper.EnvHelperInstanceCredential, nethelper.EnvSessionNonce)
			launchCmd.Dir = manifest.Launch.WorkingDir
			if output, launchErr := launchCmd.CombinedOutput(); launchErr != nil {
				return detached.RuntimeStatus{}, fmt.Errorf("recreate detached supervisor unit: %w: %s", launchErr, strings.TrimSpace(string(output)))
			}
		}
	} else {
		names := make([]string, 0, len(serviceEnv))
		for _, assignment := range serviceEnv {
			name, _, ok := strings.Cut(assignment, "=")
			if ok {
				names = append(names, name)
			}
		}
		env := withoutEnvAssignments(os.Environ(), names...)
		env = append(env, serviceEnv...)
		env = withoutEnvAssignments(env, detached.EnvSupervisorLaunchMode)
		env = append(env, detached.EnvSupervisorLaunchMode+"=direct")
		logFile, openErr := os.OpenFile(manifest.Launch.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if openErr != nil {
			return detached.RuntimeStatus{}, openErr
		}
		defer logFile.Close()
		launchCmd := exec.Command(manifest.Launch.Executable, args...)
		launchCmd.Env = env
		launchCmd.Dir = manifest.Launch.WorkingDir
		launchCmd.Stdout = logFile
		launchCmd.Stderr = logFile
		setDetachedProcessAttrs(launchCmd)
		if err := launchCmd.Start(); err != nil {
			return detached.RuntimeStatus{}, fmt.Errorf("restart detached supervisor: %w", err)
		}
		_ = launchCmd.Process.Release()
	}

	waitClient := client.NewWithTimeout("unix://"+meta.SupervisorSock, "", time.Second)
	if err := waitForSupervisorAfterGeneration(ctx, meta.SupervisorSock, waitClient, meta.Generation); err != nil {
		if errors.Is(err, errDetachedFinalizationCompleted) {
			return detached.ReadTerminalRuntimeStatusFromRoot(filepath.Dir(stateDir), sessionID)
		}
		return detached.RuntimeStatus{}, err
	}
	fresh, _, err := readSupervisorMetadata(sessionID)
	if err != nil {
		return detached.RuntimeStatus{}, err
	}
	if err := validateSupervisorMetadataUsable(fresh); err != nil {
		return detached.RuntimeStatus{}, err
	}
	var status detached.RuntimeStatus
	statusClient := client.NewWithTimeout("unix://"+fresh.SupervisorSock, "", 3*time.Second)
	if err := statusClient.DoRawJSON(ctx, http.MethodGet, "/api/v1/detached/status", nil, &status); err != nil {
		return detached.RuntimeStatus{}, err
	}
	if status.SessionID != sessionID || status.Generation <= meta.Generation || status.IncarnationID == "" || status.IncarnationID == meta.IncarnationID {
		return detached.RuntimeStatus{}, fmt.Errorf("recovered supervisor did not publish a new valid exact incarnation")
	}
	if err := validateDetachedRuntimeHandshake(ctx, statusClient, fresh); err != nil {
		return detached.RuntimeStatus{}, err
	}
	return status, nil
}

func newSessionStopCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "stop SESSION_ID",
		Short: "Stop a detached session supervisor",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := stopDetachedSessionExact(cmd.Context(), args[0]); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "ok")
			return nil
		},
	}
	return cmd
}

func validateDetachedStopAuthority(sessionID, stateDir string, meta supervisorMetadata, manifest detached.RecoveryManifest, manifestErr error) error {
	if err := validateDetachedSessionID(sessionID); err != nil {
		return err
	}
	if meta.SessionID != sessionID || (meta.ID != "" && meta.ID != sessionID) {
		return fmt.Errorf("detached stop metadata identity mismatch for %s", sessionID)
	}
	if meta.SupervisorSock != filepath.Join(stateDir, "supervisor.sock") {
		return fmt.Errorf("detached stop socket is outside the exact state directory for %s", sessionID)
	}
	expectedUnit := detachedSupervisorSystemdUnit(sessionID)
	if meta.SystemdUnit != "" && meta.SystemdUnit != expectedUnit {
		return fmt.Errorf("detached stop unit identity mismatch for %s", sessionID)
	}
	if meta.ProtocolVersion < detached.ProtocolVersion {
		return nil
	}
	if manifestErr != nil {
		return manifestErr
	}
	if manifest.SessionID != sessionID || manifest.Request.ID != sessionID ||
		manifest.Generation != meta.Generation || manifest.IncarnationID != meta.IncarnationID {
		return fmt.Errorf("detached stop manifest identity mismatch for %s", sessionID)
	}
	if manifest.Launch.SystemdUnit != meta.SystemdUnit || manifest.Launch.UsesSystemd != (meta.SystemdUnit != "") {
		return fmt.Errorf("detached stop launch authority mismatch for %s", sessionID)
	}
	return nil
}

func validateDetachedStopSocket(meta supervisorMetadata, info os.FileInfo) error {
	if info == nil || info.Mode()&os.ModeSocket == 0 || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("detached supervisor path for %s is not a direct Unix socket", meta.SessionID)
	}
	if meta.ProtocolVersion >= detached.ProtocolVersion && (meta.Generation == 0 || strings.TrimSpace(meta.IncarnationID) == "") {
		return fmt.Errorf("detached supervisor %s has incomplete incarnation identity", meta.SessionID)
	}
	if meta.OwnerPID <= 0 || !supervisorPIDAlive(meta.OwnerPID) {
		return fmt.Errorf("detached supervisor %s has no live exact owner process", meta.SessionID)
	}
	if meta.OwnerStartIdentity != "" && meta.BootID != "" && !detached.ProcessIdentityMatches(meta.OwnerPID, meta.OwnerStartIdentity, meta.BootID) {
		return fmt.Errorf("detached supervisor owner identity mismatch for %s", meta.SessionID)
	}
	return nil
}

func stopNativeDetachedSessionExact(ctx context.Context, sessionID string) error {
	if err := validateDetachedSessionID(sessionID); err != nil {
		return err
	}
	meta, stateDir, err := readSupervisorMetadata(sessionID)
	if err != nil {
		return err
	}
	return stopNativeDetachedRuntimeInstanceExact(ctx, stateDir, meta)
}

func stopNativeDetachedRuntimeInstanceExact(ctx context.Context, stateDir string, expected supervisorMetadata) error {
	if err := validateDetachedSessionID(expected.SessionID); err != nil {
		return err
	}
	meta, actualStateDir, err := readSupervisorMetadata(expected.SessionID)
	if err != nil {
		return err
	}
	if filepath.Clean(actualStateDir) != filepath.Clean(stateDir) || !sameSupervisorIncarnation(meta, expected) {
		return fmt.Errorf("detached stop exact incarnation mismatch for %s", expected.SessionID)
	}
	sessionID := expected.SessionID
	manifest, manifestErr := detached.ReadRecoveryManifest(stateDir)
	if err := validateDetachedStopAuthority(sessionID, stateDir, meta, manifest, manifestErr); err != nil {
		return err
	}

	socketInfo, socketErr := os.Lstat(meta.SupervisorSock)
	switch {
	case socketErr == nil:
		if err := validateDetachedStopSocket(meta, socketInfo); err != nil {
			return err
		}
		c := client.NewWithTimeout("unix://"+meta.SupervisorSock, "", 3*time.Second)
		if meta.ProtocolVersion >= detached.ProtocolVersion {
			handshakeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
			status, handshakeErr := detachedRuntimeHandshakeStatus(handshakeCtx, c, meta)
			cancel()
			if handshakeErr != nil {
				return handshakeErr
			}
			switch status.LifecycleState {
			case detached.LifecycleReady, detached.LifecycleDegraded, detached.LifecycleRecovering, detached.LifecycleFailed:
				if err := c.DestroySession(ctx, sessionID); err != nil && !isExactDetachedSessionNotFound(err, meta) {
					return fmt.Errorf("destroy exact detached session %s: %w", sessionID, err)
				}
			case detached.LifecycleStopping, detached.LifecycleStopped, detached.LifecycleFinalized:
				// The exact incarnation has already committed a terminal decision.
				// Continue with its independently bound unit/process teardown.
			case detached.LifecycleProvisioning, detached.LifecycleFinalizing:
				return fmt.Errorf("refusing to stop detached session %s while exact lifecycle is %s", sessionID, status.LifecycleState)
			default:
				return fmt.Errorf("refusing to stop detached session %s with unknown lifecycle %q", sessionID, status.LifecycleState)
			}
		} else {
			if err := c.DestroySession(ctx, sessionID); err != nil {
				return fmt.Errorf("destroy exact legacy detached session %s: %w", sessionID, err)
			}
		}
	case errors.Is(socketErr, os.ErrNotExist):
		// Exact durable state plus a missing exact socket is sufficient to
		// continue unit/process teardown. A present but unqueryable socket is not.
	default:
		return fmt.Errorf("inspect exact detached supervisor socket for %s: %w", sessionID, socketErr)
	}

	if meta.SystemdUnit != "" {
		if err := stopDetachedSupervisorSystemdUnit(ctx, meta.SystemdUnit); err != nil {
			return err
		}
	} else if meta.OwnerPID > 0 && supervisorPIDAlive(meta.OwnerPID) {
		if meta.OwnerStartIdentity != "" && meta.BootID != "" && !detached.ProcessIdentityMatches(meta.OwnerPID, meta.OwnerStartIdentity, meta.BootID) {
			return fmt.Errorf("refusing to signal reused owner_pid %d for detached session %s", meta.OwnerPID, sessionID)
		}
		_ = signalProcess(meta.OwnerPID, os.Kill)
	}
	var lock *detached.SupervisorLock
	for attempt := 0; attempt < 100; attempt++ {
		lock, err = detached.AcquireSupervisorLock(stateDir)
		if err == nil {
			break
		}
		if !errors.Is(err, detached.ErrSupervisorAlreadyRunning) {
			return err
		}
		time.Sleep(50 * time.Millisecond)
	}
	if lock == nil {
		return fmt.Errorf("timed out waiting for exact detached supervisor %s to stop", sessionID)
	}
	defer lock.Close()
	if manifestErr == nil {
		manifest.State = detached.LifecycleStopped
		manifest.LastError = ""
		if err := detached.WriteRecoveryManifest(stateDir, manifest); err != nil {
			return err
		}
	}
	meta.State = detached.LifecycleStopped
	meta.EventToken = ""
	meta.LastError = ""
	meta.HeartbeatAt = time.Now().UTC()
	if err := writeSupervisorMetadata(stateDir, meta); err != nil {
		return err
	}
	_ = os.Remove(meta.SupervisorSock)
	_ = detached.RemoveHeartbeat(stateDir)
	if manifestErr == nil {
		_ = os.Remove(manifest.Launch.EnvironmentFile)
	}
	return nil
}

func sameSupervisorIncarnation(current, expected supervisorMetadata) bool {
	return current.SessionID == expected.SessionID && current.ProtocolVersion == expected.ProtocolVersion &&
		current.Generation == expected.Generation && current.IncarnationID == expected.IncarnationID &&
		current.OwnerPID == expected.OwnerPID && current.OwnerStartIdentity == expected.OwnerStartIdentity &&
		current.BootID == expected.BootID && current.SupervisorSock == expected.SupervisorSock &&
		current.SystemdUnit == expected.SystemdUnit
}

func isExactDetachedSessionNotFound(err error, meta supervisorMetadata) bool {
	if err == nil || meta.ProtocolVersion < detached.ProtocolVersion {
		return false
	}
	var httpErr *client.HTTPError
	if !errors.As(err, &httpErr) || httpErr.StatusCode != http.StatusNotFound {
		return false
	}
	var body struct {
		Error string `json:"error"`
	}
	if json.Unmarshal([]byte(httpErr.Body), &body) != nil {
		return false
	}
	return strings.TrimSpace(body.Error) == "session not found"
}

func signalProcess(pid int, sig os.Signal) error {
	p, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return p.Signal(sig)
}

func isDetachedSupervisorReachable(meta supervisorMetadata) bool {
	if meta.SupervisorSock == "" {
		return false
	}
	conn, err := net.DialTimeout("unix", meta.SupervisorSock, 200*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
