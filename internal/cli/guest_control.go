package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/agentsh/agentsh/internal/client"
	"github.com/agentsh/agentsh/internal/guestcontrol"
	"github.com/agentsh/agentsh/internal/runtimeprovider"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/spf13/cobra"
)

const guestControlCleanupTimeout = 30 * time.Second

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
	var profile string
	var profileDigest string
	var allowedPolicies []string
	var probeCommand string
	var probeArgs []string
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
			if strings.TrimSpace(probeCommand) == "" || !filepath.IsAbs(probeCommand) || filepath.Clean(probeCommand) != probeCommand {
				return fmt.Errorf("guest control probe command must be a fixed absolute executable")
			}
			if info, err := os.Lstat(probeCommand); err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("guest control probe command is invalid")
			}

			result, err := startDetachedSupervisorSession(
				cmd.Context(), manifest.SessionID, []string{workspace}, string(types.WorkspaceModeDirect),
				manifest.Policy, "isolated", "minimal", nil, runtimeprovider.DefaultProfile,
			)
			if err != nil {
				return fmt.Errorf("start guest AgentSH supervisor: %w", err)
			}
			handler := &guestControlHandler{
				sessionID: manifest.SessionID,
				client:    client.NewWithTimeout("unix://"+result.SupervisorSock, "", 30*time.Second),
				probe:     types.ExecRequest{Command: probeCommand, Args: append([]string(nil), probeArgs...), WorkingDir: workspace, IncludeEvents: "summary"},
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
			handler.handshake = guestcontrol.Handshake{
				ProtocolVersion: guestcontrol.ProtocolVersion,
				SessionID:       manifest.SessionID,
				Generation:      result.Generation,
				IncarnationID:   result.IncarnationID,
				LaunchNonce:     manifest.LaunchNonce,
				GuestBootID:     strings.TrimSpace(string(bootIDBytes)),
				Profile:         manifest.Profile,
				ProfileDigest:   manifest.ProfileDigest,
				AgentSHVersion:  version,
				Policy:          manifest.Policy,
				VSockCID:        manifest.VSockCID,
				VSockPort:       server.Port(),
				SupervisorPort:  relay.Port(),
				NetworkReady:    networkReady,
				Capabilities:    []string{"exec_probe", "shutdown", "supervisor_proxy"},
			}
			if localCID := server.LocalCID(); localCID != 0 && localCID != ^uint32(0) && localCID != manifest.VSockCID {
				return fmt.Errorf("guest kernel reported VSOCK CID %d, expected %d", localCID, manifest.VSockCID)
			}
			if err := handler.handshake.Validate(manifest); err != nil {
				return err
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
	cmd.Flags().StringVar(&profile, "profile", "", "Compiled operator-owned guest profile name")
	cmd.Flags().StringVar(&profileDigest, "profile-digest", "", "Compiled operator-owned guest profile digest")
	cmd.Flags().StringArrayVar(&allowedPolicies, "allowed-policy", nil, "Operator-allowed guest policy (repeatable)")
	cmd.Flags().StringVar(&probeCommand, "probe-command", "", "Fixed harmless executable used by the bring-up probe")
	cmd.Flags().StringArrayVar(&probeArgs, "probe-arg", nil, "Fixed bring-up probe argument (repeatable)")
	for _, name := range []string{"manifest", "handshake", "workspace", "profile", "profile-digest", "allowed-policy", "probe-command"} {
		_ = cmd.MarkFlagRequired(name)
	}
	return cmd
}

type guestControlHandler struct {
	sessionID string
	client    *client.Client
	probe     types.ExecRequest
	handshake guestcontrol.Handshake

	requestMu sync.Mutex
	requests  map[string]struct{}

	shutdownMu   sync.Mutex
	shutdownDone bool
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
	if err := stopDetachedSessionExact(ctx, h.sessionID); err != nil {
		return err
	}
	h.shutdownDone = true
	return nil
}

var _ guestcontrol.Handler = (*guestControlHandler)(nil)
