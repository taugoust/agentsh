package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"

	"github.com/agentsh/agentsh/internal/runtimeprovider"
	"github.com/agentsh/agentsh/internal/runtimeprovider/externalrunner"
	"github.com/agentsh/agentsh/internal/runtimeprovider/gitdraft"
	"github.com/agentsh/agentsh/internal/workspace/runtimebin"
	"github.com/agentsh/agentsh/internal/workspace/shadow"
	"github.com/google/uuid"
	"github.com/spf13/cobra"
)

type runtimeWorkspaceApplyReport struct {
	SchemaVersion  int    `json:"schema_version"`
	SessionID      string `json:"session_id"`
	Source         string `json:"source"`
	FinalizationID string `json:"finalization_id"`
	Phase          string `json:"phase"`
	Applied        bool   `json:"applied"`
}

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
	cmd.AddCommand(newRuntimeWorkspaceApplyReviewedCmd())
	cmd.AddCommand(newRuntimeWorkspaceSealGitDraftCmd())
	cmd.AddCommand(newRuntimeWorkspacePrepareGitInputCmd())
	cmd.AddCommand(newRuntimeWorkspaceExportGitResultCmd())
	cmd.AddCommand(newRuntimeWorkspaceFinalizeGitDraftCmd())
	return cmd
}

func newRuntimeWorkspaceFinalizeGitDraftCmd() *cobra.Command {
	var stateDir string
	var intent string
	cmd := &cobra.Command{
		Use:   "finalize-git-draft SESSION_ID",
		Short: "Delete stopped MicroVM Draft storage under an absorbing terminal intent",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			record, err := externalrunner.FinalizeGitDraftStorage(cmd.Context(), args[0], stateDir, intent)
			if err != nil {
				return err
			}
			encoder := json.NewEncoder(cmd.OutOrStdout())
			encoder.SetEscapeHTML(false)
			return encoder.Encode(record)
		},
	}
	cmd.Flags().StringVar(&stateDir, "state-dir", "", "exact protected AgentSH session state directory")
	cmd.Flags().StringVar(&intent, "intent", "", "absorbing terminal intent: applied or discarded")
	_ = cmd.MarkFlagRequired("state-dir")
	_ = cmd.MarkFlagRequired("intent")
	return cmd
}

func newRuntimeWorkspaceExportGitResultCmd() *cobra.Command {
	var stateDir string
	var output string
	cmd := &cobra.Command{
		Use:   "export-git-result SESSION_ID",
		Short: "Export an exact verified MicroVM Git Draft result bundle",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			record, err := externalrunner.ExportGitDraftResult(cmd.Context(), args[0], stateDir, output)
			if err != nil {
				return err
			}
			encoder := json.NewEncoder(cmd.OutOrStdout())
			encoder.SetEscapeHTML(false)
			return encoder.Encode(record)
		},
	}
	cmd.Flags().StringVar(&stateDir, "state-dir", "", "exact protected AgentSH session state directory")
	cmd.Flags().StringVar(&output, "output", "", "new private result bundle output path")
	_ = cmd.MarkFlagRequired("state-dir")
	_ = cmd.MarkFlagRequired("output")
	return cmd
}

func newRuntimeWorkspacePrepareGitInputCmd() *cobra.Command {
	var repository string
	var output string
	cmd := &cobra.Command{
		Use:   "prepare-git-input",
		Short: "Create an immutable clean-repository input bundle for a MicroVM Draft",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			git, err := runtimebin.Resolve("git")
			if err != nil {
				return err
			}
			report, err := gitdraft.PrepareInputBundle(cmd.Context(), git, repository, output)
			if err != nil {
				return err
			}
			encoder := json.NewEncoder(cmd.OutOrStdout())
			encoder.SetEscapeHTML(false)
			return encoder.Encode(report)
		},
	}
	cmd.Flags().StringVar(&repository, "repository", "", "canonical clean Git repository root")
	cmd.Flags().StringVar(&output, "output", "", "new private Git bundle output path")
	_ = cmd.MarkFlagRequired("repository")
	_ = cmd.MarkFlagRequired("output")
	return cmd
}

func newRuntimeWorkspaceSealGitDraftCmd() *cobra.Command {
	var stateDir string
	cmd := &cobra.Command{
		Use:   "seal-git-draft SESSION_ID",
		Short: "Quiesce and persist an immutable MicroVM Git Draft result",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			record, err := externalrunner.SealGitDraft(cmd.Context(), args[0], stateDir)
			if err != nil {
				return err
			}
			encoder := json.NewEncoder(cmd.OutOrStdout())
			encoder.SetEscapeHTML(false)
			return encoder.Encode(record)
		},
	}
	cmd.Flags().StringVar(&stateDir, "state-dir", "", "exact protected AgentSH session state directory")
	_ = cmd.MarkFlagRequired("state-dir")
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

func newRuntimeWorkspaceApplyReviewedCmd() *cobra.Command {
	var stateDir string
	var source string
	cmd := &cobra.Command{
		Use:   "apply-reviewed SESSION_ID",
		Short: "Apply a stopped MicroVM Draft through the journaled host finalizer",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			report, err := applyReviewedRuntimeWorkspace(cmd.Context(), args[0], stateDir, source)
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

func applyReviewedRuntimeWorkspace(ctx context.Context, sessionID, stateDir, source string) (runtimeWorkspaceApplyReport, error) {
	if err := runtimeprovider.ValidateName(sessionID); err != nil || filepath.Base(stateDir) != sessionID || !filepath.IsAbs(stateDir) || filepath.Clean(stateDir) != stateDir {
		return runtimeWorkspaceApplyReport{}, fmt.Errorf("runtime workspace identity is invalid")
	}
	manifest, err := runtimeprovider.ReadManifest(stateDir)
	if err != nil {
		return runtimeWorkspaceApplyReport{}, err
	}
	if manifest.SessionID != sessionID || manifest.StateDir != stateDir || manifest.Provider != externalrunner.ProviderName {
		return runtimeWorkspaceApplyReport{}, fmt.Errorf("runtime workspace is not bound to the expected external session")
	}
	if manifest.State != runtimeprovider.StateStopped || !manifest.CleanupComplete || manifest.CleanupPending {
		return runtimeWorkspaceApplyReport{}, fmt.Errorf("external runtime must have exact terminal cleanup evidence before Apply")
	}
	resolvedSource, err := filepath.EvalSymlinks(source)
	if err != nil {
		return runtimeWorkspaceApplyReport{}, fmt.Errorf("resolve expected runtime workspace source: %w", err)
	}
	resolvedSource, err = filepath.Abs(resolvedSource)
	if err != nil {
		return runtimeWorkspaceApplyReport{}, err
	}
	layout, err := externalrunner.HostMonitorPaths(stateDir)
	if err != nil {
		return runtimeWorkspaceApplyReport{}, err
	}
	baseline, err := externalrunner.ReadWorkspaceBaseline(layout.BaselinePath)
	if err != nil {
		return runtimeWorkspaceApplyReport{}, err
	}
	if baseline.Source != resolvedSource {
		return runtimeWorkspaceApplyReport{}, fmt.Errorf("runtime workspace baseline source identity mismatch")
	}
	workspace, err := shadow.OpenMaterialized(ctx, sessionID, resolvedSource, layout.WorkspaceDir, shadow.Options{
		DiffExcludes:   []string{".git", ".direnv"},
		AcceptExcludes: []string{".git", ".direnv"},
	}, manifest.CreatedAt)
	if err != nil {
		return runtimeWorkspaceApplyReport{}, err
	}
	if pending, ok := workspace.PendingFinalization(); ok {
		if pending.Action != shadow.FinalizationAccept {
			return runtimeWorkspaceApplyReport{}, fmt.Errorf("a different runtime workspace finalization is pending")
		}
		if err := workspace.ResumeFinalization(ctx, pending.ID); err != nil {
			return runtimeWorkspaceApplyReport{}, err
		}
		completed, _ := workspace.PendingFinalization()
		return runtimeWorkspaceApplyReport{SchemaVersion: 1, SessionID: sessionID, Source: resolvedSource, FinalizationID: completed.ID, Phase: completed.Phase, Applied: completed.Phase == shadow.FinalizationApplied}, nil
	}
	baselineReport, err := verifyRuntimeWorkspaceBaseline(ctx, sessionID, stateDir, resolvedSource)
	if err != nil {
		return runtimeWorkspaceApplyReport{}, err
	}
	if !baselineReport.Clean {
		return runtimeWorkspaceApplyReport{}, fmt.Errorf("real workspace changed after staging at %s", baselineReport.Drift[0].Path)
	}
	review, err := workspace.Review(ctx)
	if err != nil {
		return runtimeWorkspaceApplyReport{}, err
	}
	// Bind the dynamically reviewed base back to the original staging baseline.
	// PrepareAccept then rehashes both trees before committing its durable intent.
	baselineReport, err = verifyRuntimeWorkspaceBaseline(ctx, sessionID, stateDir, source)
	if err != nil {
		return runtimeWorkspaceApplyReport{}, err
	}
	if !baselineReport.Clean {
		return runtimeWorkspaceApplyReport{}, fmt.Errorf("real workspace changed while preparing Apply at %s", baselineReport.Drift[0].Path)
	}
	intent, err := workspace.PrepareAccept(ctx, uuid.NewString(), review.Generation, review.Hash)
	if err != nil {
		return runtimeWorkspaceApplyReport{}, err
	}
	if err := workspace.ApplyFinalization(ctx, intent.ID); err != nil {
		return runtimeWorkspaceApplyReport{}, err
	}
	completed, _ := workspace.PendingFinalization()
	return runtimeWorkspaceApplyReport{SchemaVersion: 1, SessionID: sessionID, Source: baselineReport.Source, FinalizationID: completed.ID, Phase: completed.Phase, Applied: completed.Phase == shadow.FinalizationApplied}, nil
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
