package cli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/agentsh/agentsh/internal/client"
	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/detached"
	"github.com/agentsh/agentsh/internal/detachedreport"
	"github.com/agentsh/agentsh/internal/nethelper"
	"github.com/agentsh/agentsh/internal/server"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/google/uuid"
	"github.com/spf13/cobra"
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
			if stateDir == "" {
				return fmt.Errorf("--state-dir is required")
			}
			if sockPath == "" {
				return fmt.Errorf("--socket is required")
			}
			cfg, _, err := loadLocalConfig(configPath)
			if err != nil {
				return err
			}
			if err := loadSupervisorNethelperCredential(); err != nil {
				if detachedSupervisorStrictNetworkEnforcement(cfg) {
					return fmt.Errorf("strict detached helper credential unavailable: %w", err)
				}
				fmt.Fprintf(os.Stderr, "agentsh: warning: nethelper credential unavailable; continuing without the helper in degraded mode: %v\n", err)
				for _, key := range []string{nethelper.EnvSocket, nethelper.EnvHelperInstanceCredential, nethelper.EnvSessionNonce, nethelper.EnvCredentialFile} {
					_ = os.Unsetenv(key)
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
			return srv.Run(cmd.Context())
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to server config YAML")
	cmd.Flags().StringVar(&stateDir, "state-dir", "", "Detached session state directory")
	cmd.Flags().StringVar(&sockPath, "socket", "", "Supervisor Unix socket path")
	return cmd
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
	if cfg.Server.UnixSocket.Permissions == "" {
		cfg.Server.UnixSocket.Permissions = "0600"
	}
	cfg.Auth.Type = "none"
	cfg.Development.DisableAuth = true
	cfg.Development.AllowUnauthenticatedUnixApprovals = true
	// The supervisor socket is file-permission protected and session-local. Keep
	// api approvals enabled so the trusted parent Pi can poll and resolve pending
	// approvals over this Unix socket. The HTTP/TCP approval routes stay forbidden
	// while auth is disabled.
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
}

func detachedSupervisorServiceEnv(eventToken string, env, inheritPatterns []string) []string {
	serviceEnv := []string{"AGENTSH_DETACHED_EVENT_TOKEN=" + eventToken}
	// Never put the helper credential value in systemd-run argv or transient
	// unit properties. Installed services pass only the protected credential
	// file path; the supervisor reads it before serving requests. The generic
	// subagent runtime configuration is non-secret control-plane data and must
	// cross the systemd-run boundary so spawn_subagent works in detached mode.
	keys := []string{nethelper.EnvCredentialFile, nethelper.EnvSocket, nethelper.EnvBootstrapResult, detached.EnvNetworkEnforcementRequested}
	keys = append(keys, detachedSupervisorRuntimeEnvKeys...)
	seen := map[string]struct{}{"AGENTSH_DETACHED_EVENT_TOKEN": {}}
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
			res, err := startDetachedSupervisorSession(cmd.Context(), workspaces, workspaceMode, policy, runtimeHomeMode, envBaseMode, envInherit)
			if err != nil {
				return err
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
	cmd.Flags().BoolVar(&outputJSON, "json", false, "Output in JSON format")
	return cmd
}

func randomDetachedEventToken() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return uuid.NewString() + uuid.NewString()
	}
	return hex.EncodeToString(b[:])
}

func startDetachedSupervisorSession(ctx context.Context, workspaces []string, workspaceMode, policyName, runtimeHomeMode, envBaseMode string, envInherit []string) (*detachedSessionStartResult, error) {
	if len(workspaces) == 0 {
		workspaces = []string{"."}
	}
	realWorkspaces := make([]string, 0, len(workspaces))
	for _, workspace := range workspaces {
		realWorkspace, err := filepath.Abs(workspace)
		if err != nil {
			return nil, fmt.Errorf("workspace abs: %w", err)
		}
		if resolved, err := filepath.EvalSymlinks(realWorkspace); err == nil {
			realWorkspace = resolved
		}
		if st, err := os.Stat(realWorkspace); err != nil {
			return nil, fmt.Errorf("workspace stat: %w", err)
		} else if !st.IsDir() {
			return nil, fmt.Errorf("workspace must be a directory")
		}
		realWorkspaces = append(realWorkspaces, realWorkspace)
	}
	if len(realWorkspaces) > 1 && workspaceMode != string(types.WorkspaceModeShadow) {
		return nil, fmt.Errorf("multiple workspaces require workspace_mode=shadow")
	}
	realWorkspace := realWorkspaces[0]

	sessionID := "session-" + uuid.NewString()
	stateDir := filepath.Join(config.GetUserStateDir(), "sessions", sessionID)
	sockPath := filepath.Join(stateDir, "supervisor.sock")
	logsDir := filepath.Join(stateDir, "logs")
	if err := os.MkdirAll(logsDir, 0o700); err != nil {
		return nil, fmt.Errorf("create state dir: %w", err)
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
	configPath, _ := findDetachedSupervisorConfigPath()
	if abs, absErr := filepath.Abs(configPath); absErr == nil {
		configPath = abs
	}
	preflightCfg, _, err := loadLocalConfig(configPath)
	if err != nil {
		return nil, err
	}
	if warning := detachedSupervisorNetworkEnforcementWarning(preflightCfg); warning != "" {
		fmt.Fprintf(os.Stderr, "agentsh: warning: %s\n", warning)
	}
	eventToken := randomDetachedEventToken()
	parentEnv := os.Environ()
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
		"AGENTSH_DETACHED_EVENT_TOKEN="+eventToken,
		detached.EnvNetworkEnforcementRequested+"="+string(detachedSupervisorNetworkRequest(preflightCfg)),
	)
	if strings.TrimSpace(helperCredential) != "" {
		launcherEnv = append(launcherEnv, nethelper.EnvHelperInstanceCredential+"="+strings.TrimSpace(helperCredential))
	}
	if strings.TrimSpace(credentialFile) != "" {
		launcherEnv = append(launcherEnv, nethelper.EnvCredentialFile+"="+strings.TrimSpace(credentialFile))
	}
	serviceEnv := detachedSupervisorServiceEnv(eventToken, launcherEnv, envInherit)
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
		if err := writeDetachedSupervisorEnvironmentFile(serviceEnvFile, serviceEnv); err != nil {
			return nil, err
		}
		// The transient unit has no restart policy. Keep the protected file only
		// through launch/session handshake, then remove this extra credential copy.
		defer os.Remove(serviceEnvFile)
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
	ownerPID := pid
	if !launch.OwnerPIDFromCommand {
		ownerPID = 0
	}
	_ = cmd.Process.Release()

	waitClient := client.NewWithTimeout("unix://"+sockPath, "", time.Second)
	if err := waitForSupervisor(ctx, sockPath, waitClient); err != nil {
		if launch.SystemdUnit != "" {
			_ = stopDetachedSupervisorSystemdUnit(ctx, launch.SystemdUnit)
		} else {
			_ = signalProcess(pid, os.Kill)
		}
		return nil, err
	}
	if launch.UsesSystemd {
		// systemd consumed EnvironmentFile before exec. Remove it before any
		// disposable or user command can enter the session.
		_ = os.Remove(serviceEnvFile)
	}
	// Session creation can copy large shadow workspaces with rsync. Keep the
	// supervisor readiness probe short, but use a much longer timeout for the
	// actual create request so multi-root pi-auto sessions do not fail while the
	// shadow workspace is still being materialized.
	c := client.NewWithTimeout("unix://"+sockPath, "", 30*time.Minute)

	req := types.CreateSessionRequest{
		ID:              sessionID,
		Workspace:       realWorkspace,
		Policy:          policyName,
		WorkspaceMode:   workspaceMode,
		Home:            userHomeDir(),
		RuntimeHomeMode: runtimeHomeMode,
		EnvBaseMode:     envBaseMode,
		EnvInherit:      envInherit,
	}
	if len(realWorkspaces) > 1 {
		for _, path := range realWorkspaces {
			req.WorkspaceRoots = append(req.WorkspaceRoots, types.WorkspaceRoot{Path: path})
		}
	}
	if workspaceMode == string(types.WorkspaceModeShadow) {
		req.Shadow = &types.CreateShadowOptions{KeepOnDestroy: true}
	} else if workspaceMode == string(types.WorkspaceModeDirect) {
		realPaths := true
		req.RealPaths = &realPaths
	}
	sess, err := c.CreateSessionWithRequest(ctx, req)
	if err != nil {
		if launch.SystemdUnit != "" {
			_ = stopDetachedSupervisorSystemdUnit(ctx, launch.SystemdUnit)
		} else {
			_ = signalProcess(pid, os.Kill)
		}
		return nil, fmt.Errorf("create supervised session: %w", err)
	}
	worktree := sess.WorkspaceMount
	if sess.Shadow != nil && sess.Shadow.Work != "" {
		worktree = sess.Shadow.Work
	}
	if worktree == "" {
		worktree = sess.Workspace
	}

	networkEnforcement, handshakeErr := detachedSupervisorRuntimeHandshake(ctx, c, sessionID)
	if handshakeErr != nil {
		networkEnforcement = detachedSupervisorPendingNetworkEnforcement(preflightCfg)
		if detachedSupervisorStrictNetworkEnforcement(preflightCfg) {
			networkEnforcement.Status = detached.NetworkEnforcementStatusFailed
		} else {
			networkEnforcement.Status = detached.NetworkEnforcementStatusDegraded
		}
		networkEnforcement.CheckedAt = time.Now().UTC()
		networkEnforcement.Detail = "runtime enforcement handshake failed: " + handshakeErr.Error()
		if detachedSupervisorStrictNetworkEnforcement(preflightCfg) {
			networkEnforcement.Readiness = detached.NetworkEnforcementStatusFailed
			networkEnforcement.Warning = "strict detached startup will be refused because runtime network readiness could not be observed"
		} else {
			networkEnforcement.Warning = "runtime network readiness could not be observed; continuing in degraded mode because strict enforcement was not requested"
		}
		networkEnforcement.Normalize()
	}

	var metaRoots []detached.WorkspaceRoot
	if sess.Shadow != nil {
		for _, root := range sess.Shadow.Roots {
			metaRoots = append(metaRoots, detached.WorkspaceRoot{Name: root.Name, Real: root.Real, Work: root.Work})
		}
	}
	meta := supervisorMetadata{
		SessionID:          sessionID,
		ID:                 sessionID,
		CreatedAt:          time.Now().UTC(),
		State:              "active",
		Policy:             sess.Policy,
		RealWorkspace:      realWorkspace,
		WorkspaceMode:      sess.WorkspaceMode,
		Worktree:           worktree,
		WorkspaceRoots:     metaRoots,
		RuntimeHome:        sess.RuntimeHome,
		RuntimeTmp:         sess.RuntimeTmp,
		ProcessHome:        sess.ProcessHome,
		RuntimeHomeMode:    sess.RuntimeHomeMode,
		EnvBaseMode:        sess.EnvBaseMode,
		EnvInherit:         sess.EnvInherit,
		SupervisorSock:     sockPath,
		EventToken:         eventToken,
		SystemdUnit:        launch.SystemdUnit,
		OwnerPID:           ownerPID,
		NetworkEnforcement: networkEnforcement,
		ProtocolVersion:    supervisorProtocolVersion,
	}
	if detachedSupervisorStrictNetworkEnforcement(preflightCfg) && (networkEnforcement == nil || !networkEnforcement.Ready()) {
		if networkEnforcement == nil {
			networkEnforcement = detachedSupervisorPendingNetworkEnforcement(preflightCfg)
			meta.NetworkEnforcement = networkEnforcement
		}
		networkEnforcement.Status = detached.NetworkEnforcementStatusFailed
		networkEnforcement.Readiness = detached.NetworkEnforcementStatusFailed
		networkEnforcement.CheckedAt = time.Now().UTC()
		networkEnforcement.Warning = "strict detached startup refused because runtime enforcement is not ready"
		networkEnforcement.Normalize()
		meta.State = "failed"
		meta.EventToken = ""
		_ = writeSupervisorMetadata(stateDir, meta)
		_ = c.DestroySession(context.Background(), sessionID)
		if launch.SystemdUnit != "" {
			_ = stopDetachedSupervisorSystemdUnit(ctx, launch.SystemdUnit)
		} else {
			_ = signalProcess(pid, os.Kill)
		}
		return nil, fmt.Errorf("strict detached network startup refused: status=%s tier=%s: %s", networkEnforcement.Status, networkEnforcement.Tier, networkEnforcement.Detail)
	}
	if err := writeSupervisorMetadata(stateDir, meta); err != nil {
		if launch.SystemdUnit != "" {
			_ = stopDetachedSupervisorSystemdUnit(ctx, launch.SystemdUnit)
		} else {
			_ = signalProcess(pid, os.Kill)
		}
		return nil, err
	}
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
	deadline := time.Now().Add(15 * time.Second)
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out waiting for supervisor socket %s", sockPath)
		}
		if _, statErr := os.Stat(sockPath); statErr == nil {
			if _, err := c.ListSessions(ctx); err == nil {
				return nil
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
	return client.New("unix://"+meta.SupervisorSock, ""), meta, nil
}

func newSessionStopCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "stop SESSION_ID",
		Short: "Stop a detached session supervisor",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id := args[0]
			c, meta, err := detachedClientForSession(id)
			if err != nil {
				return err
			}
			_ = c.DestroySession(cmd.Context(), id)
			if meta.SystemdUnit != "" {
				_ = stopDetachedSupervisorSystemdUnit(cmd.Context(), meta.SystemdUnit)
			} else if meta.OwnerPID > 0 {
				_ = signalProcess(meta.OwnerPID, os.Kill)
			}
			meta.State = "stopped"
			meta.EventToken = ""
			if _, stateDir, err := readSupervisorMetadata(id); err == nil {
				_ = writeSupervisorMetadata(stateDir, meta)
			}
			fmt.Fprintln(cmd.OutOrStdout(), "ok")
			return nil
		},
	}
	return cmd
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
