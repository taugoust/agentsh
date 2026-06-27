package cli

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/agentsh/agentsh/internal/client"
	"github.com/agentsh/agentsh/internal/config"
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
			configureSupervisorMVP(cfg, stateDir, sockPath)
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

func configureSupervisorMVP(cfg *config.Config, stateDir, sockPath string) {
	// Stage 1 is a user-owned, single-session supervisor. Keep the existing
	// seccomp/wrap path, but explicitly disable the heavyweight/global pieces
	// called out as MVP non-goals.
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

	cfg.Sandbox.Cgroups.Enabled = false
	cfg.Sandbox.Network.Enabled = false
	cfg.Sandbox.Network.Transparent.Enabled = false
	cfg.Sandbox.Network.EBPF.Enabled = false
	cfg.Sandbox.Network.EBPF.Enforce = false
	cfg.Sandbox.Network.EBPF.Required = false
	cfg.Sandbox.FUSE.Enabled = false
	cfg.Proxy.Mode = "disabled"
	cfg.PackageChecks.Enabled = false
	cfg.Skillcheck.Enabled = false
	cfg.ThreatFeeds.Enabled = false
}

func newSessionStartCmd() *cobra.Command {
	var detach bool
	var workspace string
	var policy string
	var outputJSON bool
	var workspaceMode string
	cmd := &cobra.Command{
		Use:   "start",
		Short: "Start a session",
		Long: `Start a session.

Experimental Stage 1 detached mode starts a per-session AgentSH supervisor
owned by the current user. The supervisor writes metadata.json and listens on a
session-local supervisor.sock. This MVP intentionally disables cgroups, eBPF,
transparent networking, overlay workspaces, FUSE/COW, trusted-parent Pi,
subagents, and credential broker features.`,
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
			res, err := startDetachedSupervisorSession(cmd.Context(), workspace, workspaceMode, policy)
			if err != nil {
				return err
			}
			if outputJSON {
				return printJSON(cmd, res)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Session %s started\n", res.SessionID)
			fmt.Fprintf(cmd.OutOrStdout(), "  Supervisor: unix://%s\n", res.SupervisorSock)
			fmt.Fprintf(cmd.OutOrStdout(), "  Worktree:   %s\n", res.Worktree)
			fmt.Fprintf(cmd.OutOrStdout(), "\nWrap with:\n  agentsh wrap --server unix://%s --session %s -- <cmd>\n", res.SupervisorSock, res.SessionID)
			return nil
		},
	}
	cmd.Flags().BoolVar(&detach, "detach", false, "Start a detached per-session supervisor")
	cmd.Flags().StringVar(&workspace, "workspace", ".", "Workspace directory")
	cmd.Flags().StringVar(&workspaceMode, "workspace-mode", string(types.WorkspaceModeShadow), "Workspace mode: shadow or direct")
	cmd.Flags().StringVar(&policy, "policy", "agent-default", "Policy name")
	cmd.Flags().BoolVar(&outputJSON, "json", false, "Output in JSON format")
	return cmd
}

func startDetachedSupervisorSession(ctx context.Context, workspace, workspaceMode, policyName string) (*detachedSessionStartResult, error) {
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

	sessionID := "session-" + uuid.NewString()
	stateDir := filepath.Join(config.GetUserStateDir(), "sessions", sessionID)
	sockPath := filepath.Join(stateDir, "supervisor.sock")
	logsDir := filepath.Join(stateDir, "logs")
	if err := os.MkdirAll(logsDir, 0o700); err != nil {
		return nil, fmt.Errorf("create state dir: %w", err)
	}

	logFile, err := os.OpenFile(filepath.Join(logsDir, "supervisor.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open supervisor log: %w", err)
	}
	defer logFile.Close()

	exe, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("locate executable: %w", err)
	}
	configPath, _ := findConfigPath()
	if abs, absErr := filepath.Abs(configPath); absErr == nil {
		configPath = abs
	}
	args := []string{"supervisor", "run", "--state-dir", stateDir, "--socket", sockPath, "--config", configPath}
	cmd := exec.Command(exe, args...)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.Stdin = nil
	cmd.Dir = realWorkspace
	setDetachedProcessAttrs(cmd)
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start supervisor: %w", err)
	}
	pid := cmd.Process.Pid
	_ = cmd.Process.Release()

	c := client.NewWithTimeout("unix://"+sockPath, "", time.Second)
	if err := waitForSupervisor(ctx, sockPath, c); err != nil {
		_ = signalProcess(pid, os.Kill)
		return nil, err
	}

	req := types.CreateSessionRequest{
		ID:            sessionID,
		Workspace:     realWorkspace,
		Policy:        policyName,
		WorkspaceMode: workspaceMode,
		Home:          userHomeDir(),
	}
	if workspaceMode == string(types.WorkspaceModeShadow) {
		req.Shadow = &types.CreateShadowOptions{KeepOnDestroy: true}
	} else if workspaceMode == string(types.WorkspaceModeDirect) {
		realPaths := true
		req.RealPaths = &realPaths
	}
	sess, err := c.CreateSessionWithRequest(ctx, req)
	if err != nil {
		_ = signalProcess(pid, os.Kill)
		return nil, fmt.Errorf("create supervised session: %w", err)
	}
	worktree := sess.WorkspaceMount
	if sess.Shadow != nil && sess.Shadow.Work != "" {
		worktree = sess.Shadow.Work
	}
	if worktree == "" {
		worktree = sess.Workspace
	}
	meta := supervisorMetadata{
		SessionID:       sessionID,
		ID:              sessionID,
		CreatedAt:       time.Now().UTC(),
		State:           "active",
		Policy:          sess.Policy,
		RealWorkspace:   realWorkspace,
		WorkspaceMode:   sess.WorkspaceMode,
		Worktree:        worktree,
		SupervisorSock:  sockPath,
		OwnerPID:        pid,
		ProtocolVersion: supervisorProtocolVersion,
	}
	if err := writeSupervisorMetadata(stateDir, meta); err != nil {
		_ = signalProcess(pid, os.Kill)
		return nil, err
	}
	return &detachedSessionStartResult{supervisorMetadata: meta, Session: sess, StateDir: stateDir}, nil
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
			if meta.OwnerPID > 0 {
				_ = signalProcess(meta.OwnerPID, os.Kill)
			}
			meta.State = "stopped"
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
