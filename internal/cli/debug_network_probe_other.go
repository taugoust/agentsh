//go:build !linux

package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newDebugNetworkRuntimeProbeCmd() *cobra.Command {
	return &cobra.Command{
		Use:    "network-runtime-probe",
		Short:  "Run the internal detached network boundary probe",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("network runtime probe is only available on Linux")
		},
	}
}
