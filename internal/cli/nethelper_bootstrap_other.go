//go:build !linux

package cli

import (
	"fmt"

	"github.com/agentsh/agentsh/internal/nethelper"
	"github.com/spf13/cobra"
)

func newNethelperBootstrapCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "bootstrap",
		Short: "Start one temporary privileged nethelper lease",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			return fmt.Errorf("temporary nethelper bootstrap is supported only on Linux")
		},
	}
}

func cleanupReleasedEphemeralLease(nethelper.EphemeralLeasePaths, uint32) error {
	return fmt.Errorf("temporary nethelper bootstrap is supported only on Linux")
}
