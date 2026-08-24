package cli

import (
	"os/signal"
	"syscall"

	"github.com/agentsh/agentsh/internal/runtimeprovider/externalrunner"
	"github.com/spf13/cobra"
)

func newRuntimeMonitorCmd() *cobra.Command {
	var stateDir string
	cmd := &cobra.Command{
		Use:    "runtime-monitor",
		Short:  "Own one detached external runtime instance",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
			defer cancel()
			return externalrunner.RunHostMonitor(ctx, stateDir)
		},
	}
	cmd.Flags().StringVar(&stateDir, "state-dir", "", "Protected exact session state directory")
	_ = cmd.MarkFlagRequired("state-dir")
	return cmd
}
