package cli

import (
	"errors"
	"fmt"

	"github.com/agentsh/agentsh/internal/permissiongate"
	"github.com/spf13/cobra"
)

func newPermissionGateCmd() *cobra.Command {
	command := &cobra.Command{
		Use:   "permission-gate",
		Short: "Run Pi with lightweight dangerous-command authorization",
	}
	command.AddCommand(newPermissionGateRunCmd())
	return command
}

func newPermissionGateRunCmd() *cobra.Command {
	var auditPath string
	command := &cobra.Command{
		Use:   "run [flags] -- COMMAND [ARGS...]",
		Short: "Launch a command with the guard-only Permission Gate",
		Long: `Launch Pi directly with an inherited Permission Gate channel.

This mode only classifies Bash authorization requests. It does not create
namespaces or apply filesystem, network, or other sandbox restrictions.`,
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if cmd.ArgsLenAtDash() < 0 || len(args) == 0 {
				return fmt.Errorf("command required after --\n\nUsage: agentsh permission-gate run [flags] -- COMMAND [ARGS...]")
			}
			result, err := permissiongate.Run(cmd.Context(), permissiongate.RunOptions{
				Command:   append([]string(nil), args...),
				AuditPath: auditPath,
			})
			if err != nil {
				if errors.Is(err, permissiongate.ErrUnsupported) {
					return &ExitError{code: 1, message: err.Error()}
				}
				return err
			}
			if result.ExitCode != 0 {
				return &ExitError{code: result.ExitCode}
			}
			return nil
		},
	}
	command.Flags().StringVar(&auditPath, "audit-log", "", "Private per-run JSONL audit path (default: user state directory)")
	return command
}
