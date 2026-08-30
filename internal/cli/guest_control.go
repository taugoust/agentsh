package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/agentsh/agentsh/internal/client"
	"github.com/agentsh/agentsh/internal/detached"
	"github.com/agentsh/agentsh/internal/guestcontrol"
	"github.com/agentsh/agentsh/internal/runtimeprovider"
	"github.com/agentsh/agentsh/internal/runtimeprovider/gitdraft"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/spf13/cobra"
)

const (
	guestControlCleanupTimeout       = 30 * time.Second
	guestControlSupervisorStopBudget = 2 * time.Second
	guestEgressProbeTimeout          = 5 * time.Second
)

func guestEgressProxyEnvironment(proxyURL string) []string {
	return []string{detached.EnvGuestEgressProxyURL + "=" + proxyURL}
}

func newGuestControlCmd(version string) *cobra.Command {
	cmd := &cobra.Command{
		Use:    "guest-control",
		Short:  "Run the trusted MicroVM guest control service",
		Hidden: true,
	}
	cmd.AddCommand(newGuestControlRunCmd(version))
	return cmd
}

func newGuestControlRunCmd(version string) *cobra.Command {
	var manifestPath string
	var handshakePath string
	var workspace string
	var volumeRoot string
	var profile string
	var profileDigest string
	var allowedPolicies []string
	var probeCommand string
	var probeArgs []string
	var gitCommand string
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Start one exact guest supervisor and authenticated VSOCK control endpoint",
		RunE: func(cmd *cobra.Command, _ []string) error {
			workspace = filepath.Clean(strings.TrimSpace(workspace))
			if !filepath.IsAbs(workspace) || workspace == string(filepath.Separator) {
				return fmt.Errorf("guest control workspace must be a dedicated absolute mount")
			}
			workspaceInfo, err := os.Lstat(workspace)
			if err != nil || !workspaceInfo.IsDir() || workspaceInfo.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("guest control workspace mount is invalid")
			}
			manifest, err := guestcontrol.ReadManifest(manifestPath, workspace, profile, profileDigest, allowedPolicies)
			if err != nil {
				return err
			}
			if err := verifyGuestControlWorkspaceVolume(manifest, workspace, volumeRoot); err != nil {
				return err
			}
			if strings.TrimSpace(probeCommand) == "" || !filepath.IsAbs(probeCommand) || filepath.Clean(probeCommand) != probeCommand {
				return fmt.Errorf("guest control probe command must be a fixed absolute executable")
			}
			if (manifest.ProtocolVersion == guestcontrol.ProtocolVersionV3 || manifest.ProtocolVersion == guestcontrol.ProtocolVersionV4) && (!filepath.IsAbs(gitCommand) || filepath.Clean(gitCommand) != gitCommand) {
				return fmt.Errorf("guest control protocol version %d requires a fixed absolute Git executable", manifest.ProtocolVersion)
			}
			if info, err := os.Lstat(probeCommand); err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("guest control probe command is invalid")
			}

			var egressRelay *guestcontrol.EgressRelay
			supervisorCtx := cmd.Context()
			if manifest.ProtocolVersion == guestcontrol.ProtocolVersionV4 {
				egressRelay, err = guestcontrol.ListenEgressRelay(manifest.EgressPort, manifest.EgressToken)
				if err != nil {
					return err
				}
				defer egressRelay.Close()
				probeCtx, cancelProbe := context.WithTimeout(cmd.Context(), guestEgressProbeTimeout)
				err = egressRelay.ProbeHost(probeCtx)
				cancelProbe()
				if err != nil {
					return err
				}
				proxyEnvironment := guestEgressProxyEnvironment(egressRelay.ProxyURL())
				supervisorCtx, err = withDetachedSupervisorFixedEnvironment(supervisorCtx, proxyEnvironment)
				if err != nil {
					return err
				}
			}

			result, err := startDetachedSupervisorSessionAtGeneration(
				supervisorCtx, manifest.SessionID, []string{workspace}, string(types.WorkspaceModeDirect),
				manifest.Policy, "isolated", "minimal", nil, runtimeprovider.DefaultProfile, "", manifest.ExpectedGeneration,
			)
			if err != nil {
				return fmt.Errorf("start guest AgentSH supervisor: %w", err)
			}
			handler := &guestControlHandler{
				sessionID: manifest.SessionID,
				client:    client.NewWithTimeout("unix://"+result.SupervisorSock, "", 30*time.Second),
				probe:     types.ExecRequest{Command: probeCommand, Args: append([]string(nil), probeArgs...), WorkingDir: workspace, IncludeEvents: "summary"},
			}
			if manifest.ProtocolVersion == guestcontrol.ProtocolVersionV3 || manifest.ProtocolVersion == guestcontrol.ProtocolVersionV4 {
				handler.draft = &gitdraft.GuestWorkspace{SessionID: manifest.SessionID, Workspace: workspace, VolumeRoot: volumeRoot, Git: gitCommand}
			}
			defer func() {
				cleanupCtx, cancel := context.WithTimeout(context.Background(), guestControlCleanupTimeout)
				defer cancel()
				_ = handler.Shutdown(cleanupCtx)
			}()

			server, err := guestcontrol.ListenVSock(manifest.VSockPort)
			if err != nil {
				return err
			}
			defer server.Close()
			relay, err := guestcontrol.ListenSupervisorRelay(manifest.SupervisorPort)
			if err != nil {
				return err
			}
			defer relay.Close()

			bootIDBytes, err := os.ReadFile(filepath.Join(string(filepath.Separator), "proc", "sys", "kernel", "random", "boot_id"))
			if err != nil {
				return fmt.Errorf("read guest boot identity: %w", err)
			}
			networkReady := result.NetworkEnforcement != nil && result.NetworkEnforcement.Ready()
			capabilities := []string{"exec_probe", "shutdown", "supervisor_proxy"}
			if manifest.ProtocolVersion == guestcontrol.ProtocolVersionV3 || manifest.ProtocolVersion == guestcontrol.ProtocolVersionV4 {
				capabilities = append(capabilities, "artifact_import", "artifact_export")
			}
			egressReady := false
			if manifest.ProtocolVersion == guestcontrol.ProtocolVersionV4 {
				// The v3 transport has no direct guest network to attest. Keep the
				// legacy direct-network readiness bit false and report only the
				// authenticated explicit-proxy readiness below.
				networkReady = false
				egressReady = egressRelay != nil
				capabilities = append(capabilities, "host_egress_proxy")
			}
			handler.handshake = guestcontrol.Handshake{
				ProtocolVersion: manifest.ProtocolVersion,
				SessionID:       manifest.SessionID,
				Generation:      result.Generation,
				IncarnationID:   result.IncarnationID,
				LaunchNonce:     manifest.LaunchNonce,
				GuestBootID:     strings.TrimSpace(string(bootIDBytes)),
				Profile:         manifest.Profile,
				ProfileDigest:   manifest.ProfileDigest,
				AgentSHVersion:  version,
				EventToken:      result.EventToken,
				Policy:          manifest.Policy,
				VSockCID:        manifest.VSockCID,
				VSockPort:       server.Port(),
				SupervisorPort:  relay.Port(),
				NetworkReady:    networkReady,
				Capabilities:    capabilities,
				VolumeID:        manifest.VolumeID,
				EgressPort:      manifest.EgressPort,
				EgressReady:     egressReady,
			}
			if localCID := server.LocalCID(); localCID != 0 && localCID != ^uint32(0) && localCID != manifest.VSockCID {
				return fmt.Errorf("guest kernel reported VSOCK CID %d, expected %d", localCID, manifest.VSockCID)
			}
			if err := handler.handshake.Validate(manifest); err != nil {
				return err
			}
			if manifest.ProtocolVersion == guestcontrol.ProtocolVersionV4 {
				return serveGuestControlV4(cmd.Context(), handshakePath, manifest, handler, server, relay, egressRelay, result.SupervisorSock)
			}
			if err := guestcontrol.WriteHandshake(handshakePath, handler.handshake); err != nil {
				return fmt.Errorf("publish guest control handshake: %w", err)
			}
			serveCtx, cancelServe := context.WithCancel(cmd.Context())
			defer cancelServe()
			type serveResult struct {
				control bool
				err     error
			}
			results := make(chan serveResult, 2)
			go func() { results <- serveResult{control: true, err: server.Serve(serveCtx, manifest, handler)} }()
			go func() { results <- serveResult{err: relay.Serve(serveCtx, manifest, result.SupervisorSock)} }()
			first := <-results
			cancelServe()
			_ = server.Close()
			_ = relay.Close()
			if first.control && first.err == nil {
				// Shutdown has already stopped the exact guest supervisor. Do not
				// let a kernel-blocked VSOCK accept delay terminal evidence and VM
				// poweroff; process exit closes the already-disabled relay.
				return nil
			}
			var second serveResult
			select {
			case second = <-results:
			case <-time.After(time.Second):
			}
			for _, serveErr := range []error{first.err, second.err} {
				if serveErr != nil && !errors.Is(serveErr, context.Canceled) {
					return serveErr
				}
			}
			return cmd.Context().Err()
		},
	}
	cmd.Flags().StringVar(&manifestPath, "manifest", "", "Protected host request manifest")
	cmd.Flags().StringVar(&handshakePath, "handshake", "", "Protected handshake output path")
	cmd.Flags().StringVar(&workspace, "workspace", "", "Operator-owned staged workspace mount")
	cmd.Flags().StringVar(&volumeRoot, "volume-root", "", "Operator-owned workspace volume root (required by protocol v3 and later)")
	cmd.Flags().StringVar(&profile, "profile", "", "Compiled operator-owned guest profile name")
	cmd.Flags().StringVar(&profileDigest, "profile-digest", "", "Compiled operator-owned guest profile digest")
	cmd.Flags().StringArrayVar(&allowedPolicies, "allowed-policy", nil, "Operator-allowed guest policy (repeatable)")
	cmd.Flags().StringVar(&probeCommand, "probe-command", "", "Fixed harmless executable used by the bring-up probe")
	cmd.Flags().StringArrayVar(&probeArgs, "probe-arg", nil, "Fixed bring-up probe argument (repeatable)")
	cmd.Flags().StringVar(&gitCommand, "git-command", "", "Fixed Git executable used for protocol-v3-and-later Draft materialization")
	for _, name := range []string{"manifest", "handshake", "workspace", "profile", "profile-digest", "allowed-policy", "probe-command"} {
		_ = cmd.MarkFlagRequired(name)
	}
	return cmd
}

func serveGuestControlV4(ctx context.Context, handshakePath string, manifest guestcontrol.Manifest, handler *guestControlHandler, control *guestcontrol.Server, supervisor *guestcontrol.SupervisorRelay, egress *guestcontrol.EgressRelay, supervisorSocket string) error {
	if handler == nil || control == nil || supervisor == nil || egress == nil {
		return fmt.Errorf("guest control protocol version 4 relay set is incomplete")
	}
	serveCtx, cancelServe := context.WithCancel(ctx)
	defer cancelServe()
	type serveResult struct {
		kind string
		err  error
	}
	results := make(chan serveResult, 3)
	go func() { results <- serveResult{kind: "egress", err: egress.Serve(serveCtx)} }()
	if err := guestcontrol.WriteHandshake(handshakePath, handler.handshake); err != nil {
		cancelServe()
		_ = egress.Close()
		return fmt.Errorf("publish guest control handshake: %w", err)
	}
	go func() { results <- serveResult{kind: "control", err: control.Serve(serveCtx, manifest, handler)} }()
	go func() {
		results <- serveResult{kind: "supervisor", err: supervisor.Serve(serveCtx, manifest, supervisorSocket)}
	}()

	first := <-results
	cancelServe()
	_ = control.Close()
	_ = supervisor.Close()
	_ = egress.Close()
	if first.kind == "control" && first.err == nil {
		// Authenticated shutdown has already stopped the exact supervisor.
		return nil
	}
	all := []serveResult{first}
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	for len(all) < 3 {
		select {
		case result := <-results:
			all = append(all, result)
		case <-deadline.C:
			all = append(all, serveResult{}, serveResult{})
		}
	}
	for _, result := range all {
		if result.err != nil && !errors.Is(result.err, context.Canceled) {
			return result.err
		}
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return fmt.Errorf("guest control protocol version 4 relay stopped unexpectedly")
}

type guestControlHandler struct {
	sessionID string
	client    *client.Client
	probe     types.ExecRequest
	handshake guestcontrol.Handshake
	draft     *gitdraft.GuestWorkspace

	requestMu sync.Mutex
	requests  map[string]struct{}

	shutdownMu   sync.Mutex
	shutdownDone bool
	stopSession  func(context.Context, string) error
	stopBudget   time.Duration
}

func (h *guestControlHandler) Handshake() guestcontrol.Handshake { return h.handshake }

func (h *guestControlHandler) ClaimRequest(requestID string) bool {
	h.requestMu.Lock()
	defer h.requestMu.Unlock()
	if h.requests == nil {
		h.requests = make(map[string]struct{})
	}
	if _, exists := h.requests[requestID]; exists {
		return false
	}
	if len(h.requests) >= 4096 {
		return false
	}
	h.requests[requestID] = struct{}{}
	return true
}

func (h *guestControlHandler) ImportArtifact(ctx context.Context, transfer guestcontrol.ArtifactTransfer, source io.Reader) error {
	if h == nil || h.draft == nil {
		return fmt.Errorf("guest Git Draft workspace is unavailable")
	}
	if err := h.draft.Import(ctx, transfer, source); err != nil {
		return err
	}
	sealing, err := h.draft.Sealing()
	if err != nil {
		return err
	}
	if sealing {
		return h.client.SealWorkspaceAdmission(ctx, h.sessionID)
	}
	return nil
}

func (h *guestControlHandler) ExportArtifact(ctx context.Context, kind string) (guestcontrol.ArtifactTransfer, io.ReadCloser, error) {
	if h == nil || h.draft == nil || h.client == nil || kind != guestcontrol.ArtifactKindGitResultBundle {
		return guestcontrol.ArtifactTransfer{}, nil, fmt.Errorf("guest Git Draft result export is unavailable")
	}
	if err := h.draft.BeginSeal(); err != nil {
		return guestcontrol.ArtifactTransfer{}, nil, fmt.Errorf("persist guest sealing intent: %w", err)
	}
	if err := h.client.SealWorkspaceAdmission(ctx, h.sessionID); err != nil {
		return guestcontrol.ArtifactTransfer{}, nil, fmt.Errorf("quiesce guest workspace before sealing: %w", err)
	}
	return h.draft.Seal(ctx)
}

func (h *guestControlHandler) ExecProbe(ctx context.Context) (guestcontrol.ExecProbeResult, error) {
	if h == nil || h.client == nil {
		return guestcontrol.ExecProbeResult{}, fmt.Errorf("guest AgentSH client is unavailable")
	}
	response, err := h.client.Exec(ctx, h.sessionID, h.probe)
	if err != nil {
		return guestcontrol.ExecProbeResult{}, err
	}
	return guestcontrol.ExecProbeResult{
		ExitCode: response.Result.ExitCode,
		Stdout:   response.Result.Stdout,
		Stderr:   response.Result.Stderr,
	}, nil
}

func (h *guestControlHandler) Shutdown(ctx context.Context) error {
	if h == nil {
		return nil
	}
	h.shutdownMu.Lock()
	defer h.shutdownMu.Unlock()
	if h.shutdownDone {
		return nil
	}
	stop := h.stopSession
	if stop == nil {
		stop = stopDetachedSessionExact
	}
	// The host monitor owns exact process-tree teardown. Give the inner
	// supervisor a short graceful budget for terminal metadata, but do not make
	// VM poweroff wait for its user-systemd stop timeout. Guest-control exit
	// proceeds to audit sync and reboot, which reaps the isolated guest.
	stopBudget := h.stopBudget
	if stopBudget <= 0 {
		stopBudget = guestControlSupervisorStopBudget
	}
	stopCtx, cancel := context.WithTimeout(ctx, stopBudget)
	err := stop(stopCtx, h.sessionID)
	budgetExpired := errors.Is(stopCtx.Err(), context.DeadlineExceeded)
	cancel()
	if err != nil && !budgetExpired {
		return err
	}
	h.shutdownDone = true
	return nil
}

var _ guestcontrol.Handler = (*guestControlHandler)(nil)
