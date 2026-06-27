package cli

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"
)

func newDetachedReviewCmd(op string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   op + " SESSION_ID",
		Short: op + " detached session workspace changes",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id := args[0]
			c, _, err := detachedClientForSession(id)
			if err != nil {
				return err
			}
			switch op {
			case "diff":
				r, err := c.DiffSessionOverlay(cmd.Context(), id)
				if err != nil {
					return err
				}
				defer r.Close()
				_, err = io.Copy(cmd.OutOrStdout(), r)
				return err
			case "accept":
				s, err := c.AcceptSessionOverlay(cmd.Context(), id)
				if err != nil {
					return err
				}
				fmt.Fprintf(cmd.ErrOrStderr(), "WARNING: accept does not yet detect concurrent real-workspace changes.\n")
				return printJSON(cmd, s)
			case "reject":
				s, err := c.RejectSessionOverlay(cmd.Context(), id)
				if err != nil {
					return err
				}
				return printJSON(cmd, s)
			default:
				return fmt.Errorf("unsupported review operation %q", op)
			}
		},
	}
	return cmd
}
