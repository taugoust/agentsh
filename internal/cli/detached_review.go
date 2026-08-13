package cli

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"
)

func newDetachedReviewCmd(op string) *cobra.Command {
	var reviewGeneration uint64
	var reviewHash string
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
				review, err := c.DiffSessionOverlayReview(cmd.Context(), id)
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
			case "accept":
				s, err := c.AcceptSessionOverlayReviewed(cmd.Context(), id, reviewGeneration, reviewHash)
				if err != nil {
					return err
				}
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
	if op == "accept" {
		cmd.Flags().Uint64Var(&reviewGeneration, "review-generation", 0, "Fresh shadow review generation returned by diff")
		cmd.Flags().StringVar(&reviewHash, "review-hash", "", "Fresh shadow review hash returned by diff")
	}
	return cmd
}
