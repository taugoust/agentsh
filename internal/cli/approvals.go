package cli

import (
	"context"
	"fmt"
	"time"

	"github.com/agentsh/agentsh/internal/client"
	"github.com/spf13/cobra"
)

func newApprovalsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "approvals",
		Short: "Watch and resolve approvals",
	}
	cmd.AddCommand(newApprovalsWatchCmd())
	cmd.AddCommand(newApprovalsResolveCmd())
	return cmd
}

func newApprovalsWatchCmd() *cobra.Command {
	var sessionID string
	var all bool
	var outputJSON bool
	cmd := &cobra.Command{
		Use:   "watch",
		Short: "Watch pending approvals",
		RunE: func(cmd *cobra.Command, args []string) error {
			seen := map[string]struct{}{}
			for {
				approvals, err := listApprovalsForWatch(cmd, sessionID, all)
				if err != nil {
					return err
				}
				for _, approval := range approvals {
					id, _ := approval["id"].(string)
					if id == "" {
						id = fmt.Sprint(approval["approval_id"])
					}
					if id != "" {
						if _, ok := seen[id]; ok {
							continue
						}
						seen[id] = struct{}{}
					}
					if outputJSON {
						if err := printJSON(cmd, approval); err != nil {
							return err
						}
					} else {
						fmt.Fprintf(cmd.OutOrStdout(), "%v\n", approval)
					}
				}
				select {
				case <-cmd.Context().Done():
					return cmd.Context().Err()
				case <-time.After(time.Second):
				}
			}
		},
	}
	cmd.Flags().StringVar(&sessionID, "session", "", "Detached session ID to watch")
	cmd.Flags().BoolVar(&all, "all", false, "Watch all discovered detached supervisors")
	cmd.Flags().BoolVar(&outputJSON, "json", false, "Output JSON events")
	return cmd
}

func listApprovalsForWatch(cmd *cobra.Command, sessionID string, all bool) ([]map[string]any, error) {
	if sessionID != "" {
		c, _, err := detachedClientForSession(sessionID)
		if err != nil {
			return nil, err
		}
		return c.ListApprovals(cmd.Context())
	}
	if all {
		metas, err := listSupervisorMetadata()
		if err != nil {
			return nil, err
		}
		var out []map[string]any
		for _, meta := range metas {
			if !isDetachedSupervisorReachable(meta) {
				continue
			}
			c := client.New("unix://"+meta.SupervisorSock, "")
			items, err := c.ListApprovals(cmd.Context())
			if err != nil {
				continue
			}
			for _, item := range items {
				item["session_id"] = meta.SessionID
				out = append(out, item)
			}
		}
		return out, nil
	}
	cfg := getClientConfig(cmd)
	c, err := client.NewForCLI(client.CLIOptions{HTTPBaseURL: cfg.serverAddr, GRPCAddr: cfg.grpcAddr, APIKey: cfg.apiKey, Transport: cfg.transport, ClientTimeout: cfg.getClientTimeout()})
	if err != nil {
		return nil, err
	}
	return c.ListApprovals(cmd.Context())
}

func resolveApprovalWithClient(cmd *cobra.Command, c client.CLIClient, id, decision, reason, scope string) error {
	if scoped, ok := c.(interface {
		ResolveApprovalWithScope(ctx context.Context, id string, decision string, reason string, scope string) error
	}); ok {
		return scoped.ResolveApprovalWithScope(cmd.Context(), id, decision, reason, scope)
	}
	return c.ResolveApproval(cmd.Context(), id, decision, reason)
}

func resolveApprovalAcrossDetached(cmd *cobra.Command, id, decision, reason, scope string) error {
	metas, err := listSupervisorMetadata()
	if err != nil {
		return err
	}
	var lastErr error
	for _, meta := range metas {
		if !isDetachedSupervisorReachable(meta) {
			continue
		}
		c := client.New("unix://"+meta.SupervisorSock, "")
		if err := c.ResolveApprovalWithScope(cmd.Context(), id, decision, reason, scope); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}
	if lastErr != nil {
		return lastErr
	}
	return fmt.Errorf("no reachable detached supervisor found")
}

func newApprovalsResolveCmd() *cobra.Command {
	var sessionID string
	var decision string
	var scope string
	var reason string
	cmd := &cobra.Command{
		Use:   "resolve APPROVAL_ID",
		Short: "Resolve a pending approval",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if decision != "approve" && decision != "deny" {
				return fmt.Errorf("--decision must be approve or deny")
			}
			if sessionID != "" {
				c, _, err := detachedClientForSession(sessionID)
				if err != nil {
					return err
				}
				if err := c.ResolveApprovalWithScope(cmd.Context(), args[0], decision, reason, scope); err != nil {
					return err
				}
			} else {
				cfg := getClientConfig(cmd)
				c, err := client.NewForCLI(client.CLIOptions{HTTPBaseURL: cfg.serverAddr, GRPCAddr: cfg.grpcAddr, APIKey: cfg.apiKey, Transport: cfg.transport, ClientTimeout: cfg.getClientTimeout()})
				if err != nil {
					return err
				}
				if err := resolveApprovalWithClient(cmd, c, args[0], decision, reason, scope); err != nil {
					if isConnectionError(err) {
						return resolveApprovalAcrossDetached(cmd, args[0], decision, reason, scope)
					}
					return err
				}
			}
			fmt.Fprintln(cmd.OutOrStdout(), "ok")
			return nil
		},
	}
	cmd.Flags().StringVar(&sessionID, "session", "", "Detached session ID")
	cmd.Flags().StringVar(&decision, "decision", "", "Decision: approve or deny")
	cmd.Flags().StringVar(&scope, "scope", "once", "Approval scope: once or session")
	cmd.Flags().StringVar(&reason, "reason", "", "Reason (optional)")
	return cmd
}
