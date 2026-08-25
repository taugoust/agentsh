package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"

	"github.com/agentsh/agentsh/internal/runtimeprovider"
	"github.com/agentsh/agentsh/internal/runtimeprovider/externalrunner"
	"github.com/spf13/cobra"
)

type workspaceBaselineReport struct {
	SchemaVersion int                             `json:"schema_version"`
	SessionID     string                          `json:"session_id"`
	Source        string                          `json:"source"`
	Clean         bool                            `json:"clean"`
	Drift         []externalrunner.WorkspaceDrift `json:"drift"`
}

func newRuntimeWorkspaceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:    "runtime-workspace",
		Short:  "Inspect protected runtime workspace state",
		Hidden: true,
	}
	cmd.AddCommand(newRuntimeWorkspaceVerifyBaselineCmd())
	return cmd
}

func newRuntimeWorkspaceVerifyBaselineCmd() *cobra.Command {
	var stateDir string
	var source string
	cmd := &cobra.Command{
		Use:   "verify-baseline SESSION_ID",
		Short: "Verify that a MicroVM Draft source still matches its staging baseline",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			report, err := verifyRuntimeWorkspaceBaseline(cmd.Context(), args[0], stateDir, source)
			if err != nil {
				return err
			}
			encoder := json.NewEncoder(cmd.OutOrStdout())
			encoder.SetEscapeHTML(false)
			return encoder.Encode(report)
		},
	}
	cmd.Flags().StringVar(&stateDir, "state-dir", "", "exact protected AgentSH session state directory")
	cmd.Flags().StringVar(&source, "source", "", "expected real workspace root")
	_ = cmd.MarkFlagRequired("state-dir")
	_ = cmd.MarkFlagRequired("source")
	return cmd
}

func verifyRuntimeWorkspaceBaseline(ctx context.Context, sessionID, stateDir, source string) (workspaceBaselineReport, error) {
	if err := runtimeprovider.ValidateName(sessionID); err != nil || filepath.Base(stateDir) != sessionID || !filepath.IsAbs(stateDir) || filepath.Clean(stateDir) != stateDir {
		return workspaceBaselineReport{}, fmt.Errorf("runtime workspace identity is invalid")
	}
	manifest, err := runtimeprovider.ReadManifest(stateDir)
	if err != nil {
		return workspaceBaselineReport{}, err
	}
	if manifest.SessionID != sessionID || manifest.StateDir != stateDir || manifest.Provider != externalrunner.ProviderName {
		return workspaceBaselineReport{}, fmt.Errorf("runtime workspace is not bound to the expected external session")
	}
	resolvedSource, err := filepath.EvalSymlinks(source)
	if err != nil {
		return workspaceBaselineReport{}, fmt.Errorf("resolve expected runtime workspace source: %w", err)
	}
	resolvedSource, err = filepath.Abs(resolvedSource)
	if err != nil {
		return workspaceBaselineReport{}, err
	}
	layout, err := externalrunner.HostMonitorPaths(stateDir)
	if err != nil {
		return workspaceBaselineReport{}, err
	}
	baseline, err := externalrunner.ReadWorkspaceBaseline(layout.BaselinePath)
	if err != nil {
		return workspaceBaselineReport{}, err
	}
	if baseline.Source != resolvedSource {
		return workspaceBaselineReport{}, fmt.Errorf("runtime workspace baseline source identity mismatch")
	}
	drift, err := externalrunner.VerifyWorkspaceBaseline(ctx, baseline)
	if err != nil {
		return workspaceBaselineReport{}, err
	}
	if drift == nil {
		drift = make([]externalrunner.WorkspaceDrift, 0)
	}
	return workspaceBaselineReport{
		SchemaVersion: 1,
		SessionID:     sessionID,
		Source:        resolvedSource,
		Clean:         len(drift) == 0,
		Drift:         drift,
	}, nil
}
