package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/agentsh/agentsh/internal/client"
	"github.com/agentsh/agentsh/internal/detached"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/spf13/cobra"
)

func newSessionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "session",
		Short: "Manage sessions",
	}

	cmd.AddCommand(newSessionStartCmd())
	cmd.AddCommand(newSessionCreateCmd())
	cmd.AddCommand(newSessionListCmd())
	cmd.AddCommand(newSessionStopCmd())
	cmd.AddCommand(newSessionRecoverCmd())
	cmd.AddCommand(newSessionInfoCmd())
	cmd.AddCommand(newSessionUpdateCmd())
	cmd.AddCommand(newSessionDiffCmd())
	cmd.AddCommand(newSessionAcceptCmd())
	cmd.AddCommand(newSessionRejectCmd())
	cmd.AddCommand(newSessionDestroyCmd())
	cmd.AddCommand(newSessionAttachCmd())
	cmd.AddCommand(newSessionLogsCmd())
	cmd.AddCommand(newSessionNethelperRebindCmd())

	return cmd
}

func newSessionNethelperRebindCmd() *cobra.Command {
	var bootstrapResult string
	var socketPath string
	var credentialFile string
	var expectedLease string
	var expectedGeneration uint64
	var recoveryTokenFile string
	cmd := &cobra.Command{
		Use:   "nethelper-rebind SESSION_ID",
		Short: "Transactionally rebind the exact session to a replacement ephemeral nethelper",
		Long:  "Validate and authenticate replacement helper metadata, run the full strict disposable preflight, and commit only on success. The session ID is never replaced.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := getClientConfig(cmd)
			c, err := client.NewForCLI(client.CLIOptions{HTTPBaseURL: cfg.serverAddr, GRPCAddr: cfg.grpcAddr, APIKey: cfg.apiKey, Transport: cfg.transport, ClientTimeout: cfg.getClientTimeout()})
			if err != nil {
				return err
			}
			rebindClient, ok := c.(interface {
				RebindSessionNethelperAuthorized(context.Context, string, types.NethelperRebindRequest, string) (types.NetworkEnforcement, error)
			})
			if !ok {
				return fmt.Errorf("selected client transport does not support the REST nethelper rebind endpoint")
			}
			tokenBytes, err := os.ReadFile(recoveryTokenFile)
			if err != nil {
				return fmt.Errorf("read wrapper recovery token: %w", err)
			}
			recoveryToken := strings.TrimSpace(string(tokenBytes))
			for i := range tokenBytes {
				tokenBytes[i] = 0
			}
			if len(recoveryToken) < 32 || strings.ContainsAny(recoveryToken, " \t\r\n") {
				return fmt.Errorf("wrapper recovery token is invalid")
			}
			report, err := rebindClient.RebindSessionNethelperAuthorized(cmd.Context(), args[0], types.NethelperRebindRequest{
				BootstrapResultPath:       bootstrapResult,
				SocketPath:                socketPath,
				CredentialFile:            credentialFile,
				ExpectedLeaseID:           expectedLease,
				ExpectedBindingGeneration: expectedGeneration,
			}, recoveryToken)
			if err != nil {
				return err
			}
			return printJSON(cmd, report)
		},
	}
	cmd.Flags().StringVar(&bootstrapResult, "bootstrap-result", "", "Protected candidate bootstrap.json path")
	cmd.Flags().StringVar(&socketPath, "socket", "", "Candidate helper Unix socket path")
	cmd.Flags().StringVar(&credentialFile, "credential-file", "", "Protected candidate credential source path")
	cmd.Flags().StringVar(&expectedLease, "expected-lease", "", "Expected candidate lease ID")
	cmd.Flags().Uint64Var(&expectedGeneration, "expected-generation", 0, "Current binding generation (optimistic concurrency check)")
	cmd.Flags().StringVar(&recoveryTokenFile, "recovery-token-file", "", "Wrapper-owned private recovery token file")
	for _, name := range []string{"bootstrap-result", "socket", "credential-file", "expected-lease", "expected-generation", "recovery-token-file"} {
		_ = cmd.MarkFlagRequired(name)
	}
	return cmd
}

func newSessionCreateCmd() *cobra.Command {
	var workspace string
	var policy string
	var outputJSON bool
	var realPaths bool
	var workspaceMode string
	var runtimeHomeMode string
	var envBaseMode string
	var envInherit []string
	var overlayMode bool
	var shadowMode bool
	var shadowKeepOnDestroy bool
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a new session",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := getClientConfig(cmd)
			c, err := client.NewForCLI(client.CLIOptions{HTTPBaseURL: cfg.serverAddr, GRPCAddr: cfg.grpcAddr, APIKey: cfg.apiKey, Transport: cfg.transport, ClientTimeout: cfg.getClientTimeout()})
			if err != nil {
				return err
			}
			req := types.CreateSessionRequest{Workspace: workspace, Policy: policy, Home: userHomeDir()}
			if overlayMode && shadowMode {
				return fmt.Errorf("--overlay and --shadow are mutually exclusive")
			}
			if shadowMode {
				req.WorkspaceMode = string(types.WorkspaceModeShadow)
			} else if overlayMode {
				req.WorkspaceMode = string(types.WorkspaceModeOverlay)
			} else if workspaceMode != "" {
				req.WorkspaceMode = workspaceMode
			}
			if shadowKeepOnDestroy {
				if req.WorkspaceMode != string(types.WorkspaceModeShadow) {
					return fmt.Errorf("--shadow-keep-on-destroy requires --shadow or --workspace-mode shadow")
				}
				req.Shadow = &types.CreateShadowOptions{KeepOnDestroy: true}
			}
			if runtimeHomeMode != "" {
				req.RuntimeHomeMode = runtimeHomeMode
			}
			if envBaseMode != "" {
				req.EnvBaseMode = envBaseMode
			}
			if len(envInherit) > 0 {
				req.EnvInherit = envInherit
			}
			if cmd.Flags().Changed("real-paths") {
				req.RealPaths = &realPaths
			}
			s, err := c.CreateSessionWithRequest(cmd.Context(), req)
			if err != nil {
				return err
			}

			if outputJSON {
				return printJSON(cmd, s)
			}

			// Human-readable output
			return printSessionCreated(cmd, c, s)
		},
	}
	cmd.Flags().StringVar(&workspace, "workspace", ".", "Workspace directory")
	cmd.Flags().StringVar(&policy, "policy", "default", "Policy name")
	cmd.Flags().BoolVar(&outputJSON, "json", false, "Output in JSON format")
	cmd.Flags().BoolVar(&realPaths, "real-paths", false, "Use real host paths instead of /workspace")
	cmd.Flags().StringVar(&workspaceMode, "workspace-mode", "", "Workspace mode: direct, overlay, or shadow")
	cmd.Flags().StringVar(&runtimeHomeMode, "runtime-home", "", "Process HOME mode: isolated or real")
	cmd.Flags().StringVar(&envBaseMode, "env-base", "", "Child env base: minimal or inherit_allowed")
	cmd.Flags().StringArrayVar(&envInherit, "env-inherit", nil, "Env var name/glob to offer in addition to minimal base (repeatable)")
	cmd.Flags().BoolVar(&overlayMode, "overlay", false, "Use overlay workspace mode")
	cmd.Flags().BoolVar(&shadowMode, "shadow", false, "Use shadow workspace mode")
	cmd.Flags().BoolVar(&shadowKeepOnDestroy, "shadow-keep-on-destroy", false, "Keep shadow workspace on session destroy/expiry for later accept/reject")
	return cmd
}

func newSessionListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List sessions",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := getClientConfig(cmd)
			c, err := client.NewForCLI(client.CLIOptions{HTTPBaseURL: cfg.serverAddr, GRPCAddr: cfg.grpcAddr, APIKey: cfg.apiKey, Transport: cfg.transport})
			if err != nil {
				return err
			}
			sessions, err := c.ListSessions(cmd.Context())
			if err != nil {
				if isConnectionError(err) {
					metas, listErr := listSupervisorMetadata()
					if listErr != nil {
						return listErr
					}
					if len(metas) == 0 {
						return fmt.Errorf("agentsh daemon unavailable at %s and no usable detached supervisors were found under %s (stale metadata, missing supervisor.sock, and dead PIDs are ignored); start one with: agentsh session start --detach --workspace . --workspace-mode shadow --json", cfg.serverAddr, detachedSessionsRoot())
					}
					return printJSON(cmd, metas)
				}
				return err
			}
			return printJSON(cmd, sessions)
		},
	}
	return cmd
}

func newSessionInfoCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "info SESSION_ID",
		Short: "Show session info",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := getClientConfig(cmd)
			c, err := client.NewForCLI(client.CLIOptions{HTTPBaseURL: cfg.serverAddr, GRPCAddr: cfg.grpcAddr, APIKey: cfg.apiKey, Transport: cfg.transport})
			if err != nil {
				return err
			}
			s, err := c.GetSession(cmd.Context(), args[0])
			if err != nil {
				// A successful exact stop removes the supervisor socket, so a live
				// API can no longer return a 404. Protocol-v2 terminal records are
				// protected durable evidence for wrapper cleanup after that point.
				status, terminalErr := detached.ReadTerminalRuntimeStatusFromRoot(detachedSessionsRoot(), args[0])
				if terminalErr == nil {
					return printJSON(cmd, status)
				}
				return err
			}
			return printJSON(cmd, s)
		},
	}
	return cmd
}

func newSessionDestroyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "destroy SESSION_ID",
		Short: "Destroy a session",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := getClientConfig(cmd)
			c, err := client.NewForCLI(client.CLIOptions{HTTPBaseURL: cfg.serverAddr, GRPCAddr: cfg.grpcAddr, APIKey: cfg.apiKey, Transport: cfg.transport})
			if err != nil {
				return err
			}
			if err := c.DestroySession(cmd.Context(), args[0]); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "ok")
			return nil
		},
	}
	return cmd
}

func newSessionDiffCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "diff SESSION_ID",
		Short: "Show review workspace diff",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := getClientConfig(cmd)
			c, err := client.NewForCLI(client.CLIOptions{HTTPBaseURL: cfg.serverAddr, GRPCAddr: cfg.grpcAddr, APIKey: cfg.apiKey, Transport: cfg.transport, ClientTimeout: cfg.getClientTimeout()})
			if err != nil {
				return err
			}
			review, err := c.DiffSessionOverlayReview(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			defer review.Body.Close()
			if _, err = io.Copy(cmd.OutOrStdout(), review.Body); err != nil {
				return err
			}
			if review.Generation != 0 && review.Hash != "" {
				fmt.Fprintf(cmd.ErrOrStderr(), "Review generation: %d\nReview hash: %s\n", review.Generation, review.Hash)
			}
			return nil
		},
	}
	return cmd
}

func newSessionAcceptCmd() *cobra.Command {
	var reviewGeneration uint64
	var reviewHash string
	cmd := &cobra.Command{
		Use:   "accept SESSION_ID",
		Short: "Accept review workspace changes into the real workspace",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := getClientConfig(cmd)
			c, err := client.NewForCLI(client.CLIOptions{HTTPBaseURL: cfg.serverAddr, GRPCAddr: cfg.grpcAddr, APIKey: cfg.apiKey, Transport: cfg.transport, ClientTimeout: cfg.getClientTimeout()})
			if err != nil {
				return err
			}
			s, err := c.AcceptSessionOverlayReviewed(cmd.Context(), args[0], reviewGeneration, reviewHash)
			if err != nil {
				return err
			}
			return printJSON(cmd, s)
		},
	}
	cmd.Flags().Uint64Var(&reviewGeneration, "review-generation", 0, "Fresh shadow review generation returned by session diff")
	cmd.Flags().StringVar(&reviewHash, "review-hash", "", "Fresh shadow review hash returned by session diff")
	return cmd
}

func newSessionRejectCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "reject SESSION_ID",
		Short: "Reject and discard review workspace changes",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := getClientConfig(cmd)
			c, err := client.NewForCLI(client.CLIOptions{HTTPBaseURL: cfg.serverAddr, GRPCAddr: cfg.grpcAddr, APIKey: cfg.apiKey, Transport: cfg.transport})
			if err != nil {
				return err
			}
			s, err := c.RejectSessionOverlay(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			return printJSON(cmd, s)
		},
	}
	return cmd
}

func newSessionUpdateCmd() *cobra.Command {
	var cwd string
	var setEnv []string
	var unsetEnv []string
	cmd := &cobra.Command{
		Use:   "update SESSION_ID",
		Short: "Update session state (cwd/env) without exec",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			patch := types.SessionPatchRequest{
				Cwd:   cwd,
				Env:   map[string]string{},
				Unset: unsetEnv,
			}
			for _, kv := range setEnv {
				k, v, ok := strings.Cut(kv, "=")
				if !ok {
					return fmt.Errorf("invalid --set-env %q (expected KEY=VALUE)", kv)
				}
				patch.Env[k] = v
			}

			cfg := getClientConfig(cmd)
			c, err := client.NewForCLI(client.CLIOptions{HTTPBaseURL: cfg.serverAddr, GRPCAddr: cfg.grpcAddr, APIKey: cfg.apiKey, Transport: cfg.transport})
			if err != nil {
				return err
			}
			s, err := c.PatchSession(cmd.Context(), args[0], patch)
			if err != nil {
				return err
			}
			return printJSON(cmd, s)
		},
	}
	cmd.Flags().StringVar(&cwd, "cwd", "", "Set session cwd (virtual path under /workspace)")
	cmd.Flags().StringArrayVar(&setEnv, "set-env", nil, "Set env var KEY=VALUE (repeatable)")
	cmd.Flags().StringArrayVar(&unsetEnv, "unset-env", nil, "Unset env var KEY (repeatable)")
	return cmd
}

// LogType represents supported log types for session logs command.
type LogType string

const (
	LogTypeAll  LogType = ""     // Show all log types
	LogTypeLLM  LogType = "llm"  // LLM request/response logs
	LogTypeFS   LogType = "fs"   // Filesystem access logs
	LogTypeNet  LogType = "net"  // Network access logs
	LogTypeExec LogType = "exec" // Command execution logs
)

// ValidLogTypes returns the list of valid log type values.
func ValidLogTypes() []string {
	return []string{"llm", "fs", "net", "exec"}
}

func newSessionLogsCmd() *cobra.Command {
	var logType string

	cmd := &cobra.Command{
		Use:   "logs SESSION_ID",
		Short: "View session logs",
		Long: `View session logs with optional filtering by type.

Supported log types:
  llm   - LLM request/response logs (from embedded proxy)
  fs    - Filesystem access logs
  net   - Network access logs
  exec  - Command execution logs

When no type is specified, all log types are shown.`,
		Example: `  # View all logs for a session
  agentsh session logs abc123

  # View only LLM request/response logs
  agentsh session logs abc123 --type=llm

  # View only filesystem logs
  agentsh session logs abc123 --type=fs`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			sessionID := args[0]

			// Validate log type if specified
			if logType != "" {
				valid := false
				for _, t := range ValidLogTypes() {
					if logType == t {
						valid = true
						break
					}
				}
				if !valid {
					return fmt.Errorf("invalid log type %q: must be one of %v", logType, ValidLogTypes())
				}
			}

			cfg := getClientConfig(cmd)
			c, err := client.NewForCLI(client.CLIOptions{HTTPBaseURL: cfg.serverAddr, GRPCAddr: cfg.grpcAddr, APIKey: cfg.apiKey, Transport: cfg.transport})
			if err != nil {
				return err
			}

			// Handle LLM logs specially - they come from llm-requests.jsonl
			if logType == string(LogTypeLLM) {
				return DisplayLLMLogs(cmd.OutOrStdout(), sessionID, false)
			}

			// For other log types (or all), query session events via API
			// Query events from the session
			evs, err := c.QuerySessionEvents(cmd.Context(), sessionID, nil)
			if err != nil {
				return err
			}

			// Filter by type if specified
			if logType != "" {
				var filtered []types.Event
				for _, ev := range evs {
					if ev.Type == logType {
						filtered = append(filtered, ev)
					}
				}
				evs = filtered
			}

			return printJSON(cmd, evs)
		},
	}

	cmd.Flags().StringVar(&logType, "type", "", "Filter logs by type (llm, fs, net, exec)")

	return cmd
}

// printSessionCreated prints human-readable session creation output.
// Format matches the spec:
//
//	Session abc123 started
//	  Proxy: http://127.0.0.1:52341
//	  DLP: redact (email, phone, credit_card, ssn, api_key)
//
//	Export for agent:
//	  export ANTHROPIC_BASE_URL=http://127.0.0.1:52341
//	  export OPENAI_BASE_URL=http://127.0.0.1:52341
func printSessionCreated(cmd *cobra.Command, c client.CLIClient, s types.Session) error {
	w := cmd.OutOrStdout()

	fmt.Fprintf(w, "Session %s started\n", s.ID)

	// Try to get proxy status for DLP info
	proxyStatus, err := c.GetProxyStatus(cmd.Context(), s.ID)
	if err == nil && proxyStatus != nil {
		// Show proxy URL
		if addr, _ := proxyStatus["address"].(string); addr != "" {
			fmt.Fprintf(w, "  Proxy: http://%s\n", addr)
		} else if s.ProxyURL != "" {
			fmt.Fprintf(w, "  Proxy: %s\n", s.ProxyURL)
		}

		// Show DLP info
		dlpMode, _ := proxyStatus["dlp_mode"].(string)
		if dlpMode != "" && dlpMode != "disabled" {
			// Get pattern names
			var patternNames []string
			if pn, ok := proxyStatus["pattern_names"].([]any); ok {
				for _, p := range pn {
					if name, ok := p.(string); ok {
						patternNames = append(patternNames, name)
					}
				}
			}

			if len(patternNames) > 0 {
				fmt.Fprintf(w, "  DLP: %s (%s)\n", dlpMode, strings.Join(patternNames, ", "))
			} else {
				activePatterns := int(getFloatVal(proxyStatus, "active_patterns"))
				if activePatterns > 0 {
					fmt.Fprintf(w, "  DLP: %s (%d patterns active)\n", dlpMode, activePatterns)
				} else {
					fmt.Fprintf(w, "  DLP: %s\n", dlpMode)
				}
			}
		}

		// Show export instructions if proxy is running
		if addr, _ := proxyStatus["address"].(string); addr != "" {
			proxyURL := "http://" + addr
			fmt.Fprintln(w)
			fmt.Fprintln(w, "Export for agent:")
			fmt.Fprintf(w, "  export ANTHROPIC_BASE_URL=%s\n", proxyURL)
			fmt.Fprintf(w, "  export OPENAI_BASE_URL=%s\n", proxyURL)
		}
	} else if s.ProxyURL != "" {
		// Fallback to session info if proxy status unavailable
		fmt.Fprintf(w, "  Proxy: %s\n", s.ProxyURL)
		fmt.Fprintln(w)
		fmt.Fprintln(w, "Export for agent:")
		fmt.Fprintf(w, "  export ANTHROPIC_BASE_URL=%s\n", s.ProxyURL)
		fmt.Fprintf(w, "  export OPENAI_BASE_URL=%s\n", s.ProxyURL)
	}

	if s.Overlay != nil {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "Overlay workspace:")
		fmt.Fprintf(w, "  Merged: %s\n", s.Overlay.Merged)
		fmt.Fprintf(w, "  Diff:   agentsh session diff %s\n", s.ID)
		fmt.Fprintf(w, "  Accept: agentsh session accept %s\n", s.ID)
		fmt.Fprintf(w, "  Reject: agentsh session reject %s\n", s.ID)
	}
	if s.Shadow != nil {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "Shadow workspace:")
		fmt.Fprintf(w, "  Work:   %s\n", s.Shadow.Work)
		fmt.Fprintf(w, "  Home:   %s\n", s.Shadow.Home)
		fmt.Fprintf(w, "  Tmp:    %s\n", s.Shadow.Tmp)
		fmt.Fprintf(w, "  Real:   %s\n", s.Shadow.Real)
		fmt.Fprintf(w, "  Diff:   agentsh session diff %s\n", s.ID)
		fmt.Fprintf(w, "  Accept: agentsh session accept %s\n", s.ID)
		fmt.Fprintf(w, "  Reject: agentsh session reject %s\n", s.ID)
	}

	return nil
}

// getFloatVal extracts a float64 from a map, handling JSON number types.
func getFloatVal(m map[string]any, key string) float64 {
	if m == nil {
		return 0
	}
	if v, ok := m[key].(float64); ok {
		return v
	}
	if v, ok := m[key].(int); ok {
		return float64(v)
	}
	return 0
}

func printJSON(cmd *cobra.Command, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(cmd.OutOrStdout(), string(b))
	return err
}
