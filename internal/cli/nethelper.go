package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/agentsh/agentsh/internal/nethelper"
	"github.com/google/uuid"
	"github.com/spf13/cobra"
)

const nethelperSystemdCredentialName = "agentsh-nethelper-instance-credential"

func newNethelperCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:    "nethelper",
		Short:  "Run the privileged network helper",
		Hidden: true,
	}
	cmd.AddCommand(newNethelperServeCmd())
	cmd.AddCommand(newNethelperCapabilitiesCmd())
	cmd.AddCommand(newNethelperLeaseIDCmd())
	cmd.AddCommand(newNethelperBootstrapCmd())
	cmd.AddCommand(newNethelperStatusCmd())
	cmd.AddCommand(newNethelperRenewCmd())
	cmd.AddCommand(newNethelperReleaseCmd())
	cmd.AddCommand(newNethelperCleanupPinsCmd())
	return cmd
}

// resolveNethelperInstanceCredential deliberately accepts only the named
// systemd credential. Secret argv flags, inherited secret environment values,
// and arbitrary credential paths are not part of the installed helper contract.
func resolveNethelperInstanceCredential() (string, error) {
	credentialDir := strings.TrimSpace(os.Getenv("CREDENTIALS_DIRECTORY"))
	if credentialDir == "" {
		return "", fmt.Errorf("nethelper serve requires the systemd credential %s", nethelperSystemdCredentialName)
	}
	if !filepath.IsAbs(credentialDir) || filepath.Clean(credentialDir) != credentialDir {
		return "", fmt.Errorf("systemd credential directory must be an absolute canonical path")
	}
	return readStrictSecretFile(filepath.Join(credentialDir, nethelperSystemdCredentialName))
}

func readStrictSecretFile(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", fmt.Errorf("secret file path must be absolute and canonical")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", fmt.Errorf("stat secret file %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("secret file %s must not be a symlink", path)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("secret file %s must be a regular file", path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("secret file %s must not be group/world accessible", path)
	}
	if err := nethelper.ValidateCredentialFileOwnership(path); err != nil {
		return "", fmt.Errorf("validate secret file %s: %w", path, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read secret file %s: %w", path, err)
	}
	return strings.TrimSpace(string(data)), nil
}

func validateNethelperInstanceCredential(value string) error {
	value = strings.TrimSpace(value)
	if len(value) < 32 || len(value) > 512 {
		return fmt.Errorf("helper instance credential must be between 32 and 512 bytes")
	}
	for _, r := range value {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return fmt.Errorf("helper instance credential must not contain whitespace or control characters")
		}
	}
	return nil
}

func newNethelperCapabilitiesCmd() *cobra.Command {
	var outputJSON bool
	cmd := &cobra.Command{
		Use:   "capabilities",
		Short: "Report local nethelper lifecycle capabilities",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			result := map[string]any{
				"protocol_version":                  nethelper.CurrentProtocolVersion,
				"bootstrap_schema_version":          nethelper.BootstrapSchemaVersion,
				"bootstrap_runtime":                 true,
				"composition_runtime":               "lease-scoped-root-v1",
				"bootstrap_default_runtime_seconds": int64(nethelper.DefaultBootstrapRuntime / time.Second),
				"bootstrap_max_runtime_seconds":     int64(nethelper.MaximumBootstrapRuntime / time.Second),
				"instance_lifecycle":                append([]string(nil), nethelper.LifecycleCapabilities...),
			}
			if outputJSON {
				return printJSON(cmd, result)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "bootstrap-runtime max=%s lifecycle=%s\n", nethelper.MaximumBootstrapRuntime, strings.Join(nethelper.LifecycleCapabilities, ","))
			return nil
		},
	}
	cmd.Flags().BoolVar(&outputJSON, "json", false, "Output JSON")
	return cmd
}

func newNethelperServeCmd() *cobra.Command {
	var socketPath string
	var expectedUID int
	var expectedGID int
	var pinRoot string
	var ephemeralLease string
	var ephemeralUnit string
	var ephemeralCreatedAt string
	var ephemeralHardExpiry string
	var ephemeralSoftLease time.Duration
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Serve an AgentSH privileged network helper socket",
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.TrimSpace(socketPath) == "" {
				return fmt.Errorf("--socket is required")
			}
			if expectedUID < 0 || uint64(expectedUID) > uint64(^uint32(0)) {
				return fmt.Errorf("--uid must be a non-negative 32-bit Unix uid")
			}
			if expectedGID < -1 || (expectedGID >= 0 && uint64(expectedGID) > uint64(^uint32(0))) {
				return fmt.Errorf("--gid must be -1 or a non-negative 32-bit Unix gid")
			}
			pinRoot = strings.TrimSpace(pinRoot)
			if pinRoot == "" {
				return fmt.Errorf("--pin-root is required; the installed helper must preserve gates across crashes")
			}
			if err := nethelper.ValidatePrivilegedServiceUser(); err != nil {
				return err
			}
			ephemeralLease = strings.TrimSpace(ephemeralLease)
			var ephemeralPaths nethelper.EphemeralLeasePaths
			if ephemeralLease != "" {
				if expectedGID < 0 {
					return fmt.Errorf("--gid is required in ephemeral serve mode")
				}
				var err error
				ephemeralPaths, err = nethelper.ValidateEphemeralServiceInvocation(uint32(expectedUID), ephemeralLease)
				if err != nil {
					return err
				}
				if filepath.Clean(socketPath) != ephemeralPaths.SocketPath {
					return fmt.Errorf("ephemeral helper socket path does not match its fixed lease path")
				}
				if filepath.Clean(pinRoot) != ephemeralPaths.PinRoot {
					return fmt.Errorf("ephemeral helper pin root does not match its fixed lease path")
				}
				if strings.TrimSpace(ephemeralUnit) == "" {
					ephemeralUnit = ephemeralPaths.UnitName
				}
				if ephemeralUnit != ephemeralPaths.UnitName {
					return fmt.Errorf("ephemeral helper unit identity does not match its fixed lease unit")
				}
			}
			credential, err := resolveNethelperInstanceCredential()
			if err != nil {
				return err
			}
			if err := validateNethelperInstanceCredential(credential); err != nil {
				return err
			}
			for _, name := range []string{
				"CREDENTIALS_DIRECTORY",
				nethelper.EnvHelperInstanceCredential,
				nethelper.EnvCredentialFile,
				nethelper.EnvSessionNonce,
				"AGENTSH_DETACHED_EVENT_TOKEN",
			} {
				_ = os.Unsetenv(name)
			}
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}

			authOpts := nethelper.SupervisorAuthorizerOptions{
				HelperInstanceCredential:     credential,
				ExpectedUID:                  uint32(expectedUID),
				EnforceUID:                   true,
				RequireKernelCgroupChecks:    true,
				RequireStableProcessIdentity: true,
			}
			if expectedGID >= 0 {
				authOpts.ExpectedGID = uint32(expectedGID)
				authOpts.EnforceGID = true
			}
			backendOpts := nethelper.KernelBackendOptions{
				PinRoot:          pinRoot,
				PinOwnerUID:      0,
				TargetUID:        uint32(expectedUID),
				EnforceTargetUID: true,
			}
			reaped, err := nethelper.CleanupPinnedResources(nethelper.PinCleanupOptions{
				PinRoot:          backendOpts.PinRoot,
				TargetUID:        uint32(expectedUID),
				EnforceTargetUID: true,
				OwnerUID:         0,
			})
			if err != nil {
				return fmt.Errorf("reap stale helper pins at startup: %w", err)
			}
			if len(reaped.Removed) > 0 {
				fmt.Fprintf(cmd.ErrOrStderr(), "agentsh nethelper reaped %d stale pinned resources\n", len(reaped.Removed))
			}
			for _, warning := range reaped.Warnings {
				fmt.Fprintf(cmd.ErrOrStderr(), "agentsh nethelper startup reaper: %s\n", warning)
			}

			authorizer := nethelper.NewSupervisorAuthorizer(authOpts)
			server := nethelper.NewServer(nethelper.NewKernelBackendWithOptions(backendOpts), authorizer)

			if ephemeralLease != "" {
				listener, err := nethelper.ListenEphemeralUnixForUID(ephemeralPaths.SocketPath, uint32(expectedUID), uint32(expectedGID))
				if err != nil {
					return err
				}
				if err := nethelper.DropEphemeralSetupCapabilities(); err != nil {
					_ = listener.Close()
					_ = os.Remove(ephemeralPaths.SocketPath)
					return err
				}
				createdAt, hardExpiry, err := parseEphemeralLifecycleTimes(ephemeralCreatedAt, ephemeralHardExpiry)
				if err != nil {
					_ = listener.Close()
					_ = os.Remove(ephemeralPaths.SocketPath)
					return err
				}
				serveCtx, cancel := context.WithCancel(ctx)
				controller := nethelper.NewEphemeralInstanceController(nethelper.EphemeralInstanceControllerOptions{
					LeaseID:                  ephemeralLease,
					HelperInstanceCredential: credential,
					ExpectedUID:              uint32(expectedUID),
					ExpectedGID:              uint32(expectedGID),
					EnforceGID:               true,
					Registrations:            authorizer,
					Operations:               authorizer.OperationGate(),
					SoftLease:                ephemeralSoftLease,
					UnitName:                 ephemeralUnit,
					CreatedAt:                createdAt,
					HardExpiresAt:            hardExpiry,
					Stop:                     cancel,
				})
				server.InstanceController = controller
				server.Stop = cancel
				fmt.Fprintf(cmd.OutOrStdout(), "agentsh ephemeral nethelper listening on unix://%s\n", socketPath)
				serveErr := server.ServeListener(serveCtx, listener)
				cancel()
				_ = listener.Close()
				_ = os.Remove(ephemeralPaths.SocketPath)
				if controller.Released() {
					if err := cleanupReleasedEphemeralLease(ephemeralPaths, uint32(expectedUID)); err != nil {
						return err
					}
					if errors.Is(serveErr, context.Canceled) {
						return nil
					}
				}
				return serveErr
			}

			activationListener, activated, err := nethelper.ListenSystemdActivationForUID(socketPath, uint32(expectedUID))
			if err != nil {
				return err
			}
			if !activated {
				return fmt.Errorf("nethelper serve requires systemd socket activation")
			}
			fmt.Fprintf(cmd.OutOrStdout(), "agentsh nethelper listening on unix://%s\n", socketPath)
			return server.ServeListener(ctx, activationListener)
		},
	}
	cmd.Flags().StringVar(&socketPath, "socket", "", "Unix socket path supplied by the installed socket unit")
	cmd.Flags().IntVar(&expectedUID, "uid", -1, "Expected supervisor Unix UID (required)")
	cmd.Flags().IntVar(&expectedGID, "gid", -1, "Expected supervisor Unix GID (-1 disables explicit GID check)")
	cmd.Flags().StringVar(&pinRoot, "pin-root", nethelper.DefaultBPFFSPinRoot(), "Root-owned AgentSH bpffs subtree for helper map/link pins")
	cmd.Flags().StringVar(&ephemeralLease, "ephemeral-lease", "", "Fixed lease ID for a transient SSH-bootstrap helper")
	cmd.Flags().StringVar(&ephemeralUnit, "ephemeral-unit", "", "Fixed non-secret transient unit identity")
	cmd.Flags().StringVar(&ephemeralCreatedAt, "ephemeral-created-at", "", "Bootstrap creation timestamp (RFC3339)")
	cmd.Flags().StringVar(&ephemeralHardExpiry, "ephemeral-hard-expiry", "", "Bootstrap hard expiry (RFC3339)")
	cmd.Flags().DurationVar(&ephemeralSoftLease, "ephemeral-soft-lease", 0, "Negotiated renewable soft lease (zero means hard-expiry-only compatibility mode)")
	return cmd
}

func parseEphemeralLifecycleTimes(createdText, hardText string) (time.Time, time.Time, error) {
	createdText = strings.TrimSpace(createdText)
	hardText = strings.TrimSpace(hardText)
	if createdText == "" && hardText == "" {
		created := time.Now().UTC()
		return created, created.Add(nethelper.DefaultBootstrapRuntime), nil
	}
	created, err := time.Parse(time.RFC3339, createdText)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("invalid --ephemeral-created-at: %w", err)
	}
	hard, err := time.Parse(time.RFC3339, hardText)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("invalid --ephemeral-hard-expiry: %w", err)
	}
	if !hard.After(created) || hard.Sub(created) > nethelper.MaximumBootstrapRuntime {
		return time.Time{}, time.Time{}, fmt.Errorf("ephemeral lifecycle hard expiry is outside the finite bootstrap bound")
	}
	return created.UTC(), hard.UTC(), nil
}

func newNethelperLeaseIDCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "lease-id",
		Short: "Generate an ephemeral nethelper lease identifier",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := fmt.Fprintf(cmd.OutOrStdout(), "lease-%s\n", uuid.NewString())
			return err
		},
	}
}

func newNethelperStatusCmd() *cobra.Command {
	return newNethelperLifecycleClientCmd(false)
}

func newNethelperRenewCmd() *cobra.Command {
	return newNethelperLifecycleClientCmd(true)
}

func newNethelperLifecycleClientCmd(renew bool) *cobra.Command {
	var socketPath string
	var credentialFile string
	var leaseID string
	var outputJSON bool
	name, short := "status", "Query authenticated non-secret ephemeral helper status"
	if renew {
		name, short = "renew", "Renew an ephemeral helper soft lease within its hard expiry"
	}
	cmd := &cobra.Command{
		Use:   name,
		Short: short,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			leaseID = strings.TrimSpace(leaseID)
			if err := nethelper.ValidateEphemeralLeaseID(leaseID); err != nil {
				return err
			}
			credential, err := readSupervisorNethelperCredentialFile(credentialFile)
			if err != nil {
				return fmt.Errorf("load ephemeral helper credential: %w", err)
			}
			if err := validateNethelperInstanceCredential(credential); err != nil {
				return err
			}
			client := nethelper.NewClient(strings.TrimSpace(socketPath))
			requestID := name + "-" + uuid.NewString()
			var response nethelper.InstanceStatusResponse
			if renew {
				response, err = client.RenewInstance(cmd.Context(), nethelper.RenewInstanceRequest{
					ProtocolVersion: nethelper.CurrentProtocolVersion, RequestID: requestID,
					LeaseID: leaseID, HelperInstanceCredential: credential,
				})
			} else {
				response, err = client.InstanceStatus(cmd.Context(), nethelper.InstanceStatusRequest{
					ProtocolVersion: nethelper.CurrentProtocolVersion, RequestID: requestID,
					LeaseID: leaseID, HelperInstanceCredential: credential,
				})
			}
			if err != nil {
				if outputJSON && response.ProtocolVersion != 0 {
					if printErr := printJSON(cmd, response); printErr != nil {
						return printErr
					}
				}
				return err
			}
			if outputJSON {
				return printJSON(cmd, response)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s ephemeral nethelper lease %s; soft expiry %s; hard expiry %s; generation %d\n", response.Status, response.LeaseID, response.SoftExpiresAt.Format(time.RFC3339), response.HardExpiresAt.Format(time.RFC3339), response.RenewalGeneration)
			return nil
		},
	}
	cmd.Flags().StringVar(&socketPath, "socket", "", "Ephemeral helper Unix socket path")
	cmd.Flags().StringVar(&credentialFile, "credential-file", "", "UID-owned ephemeral helper credential file")
	cmd.Flags().StringVar(&leaseID, "lease", "", "Ephemeral helper lease ID")
	cmd.Flags().BoolVar(&outputJSON, "json", false, "Output JSON")
	_ = cmd.MarkFlagRequired("socket")
	_ = cmd.MarkFlagRequired("credential-file")
	_ = cmd.MarkFlagRequired("lease")
	return cmd
}

func newNethelperReleaseCmd() *cobra.Command {
	var socketPath string
	var credentialFile string
	var leaseID string
	var outputJSON bool
	cmd := &cobra.Command{
		Use:   "release",
		Short: "Release one ephemeral nethelper lease",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := nethelper.ValidateEphemeralLeaseID(strings.TrimSpace(leaseID)); err != nil {
				return err
			}
			credential, err := readSupervisorNethelperCredentialFile(credentialFile)
			if err != nil {
				return fmt.Errorf("load ephemeral helper credential: %w", err)
			}
			if err := validateNethelperInstanceCredential(credential); err != nil {
				return err
			}
			client := nethelper.NewClient(strings.TrimSpace(socketPath))
			resp, err := client.ReleaseInstance(cmd.Context(), nethelper.ReleaseInstanceRequest{
				ProtocolVersion:          nethelper.CurrentProtocolVersion,
				RequestID:                "release-" + uuid.NewString(),
				LeaseID:                  strings.TrimSpace(leaseID),
				HelperInstanceCredential: credential,
			})
			if err != nil {
				return err
			}
			if outputJSON {
				return printJSON(cmd, resp)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "released ephemeral nethelper lease %s\n", resp.LeaseID)
			return nil
		},
	}
	cmd.Flags().StringVar(&socketPath, "socket", "", "Ephemeral helper Unix socket path")
	cmd.Flags().StringVar(&credentialFile, "credential-file", "", "UID-owned ephemeral helper credential file")
	cmd.Flags().StringVar(&leaseID, "lease", "", "Ephemeral helper lease ID")
	cmd.Flags().BoolVar(&outputJSON, "json", false, "Output JSON")
	_ = cmd.MarkFlagRequired("socket")
	_ = cmd.MarkFlagRequired("credential-file")
	_ = cmd.MarkFlagRequired("lease")
	return cmd
}

func newNethelperCleanupPinsCmd() *cobra.Command {
	var pinRoot string
	var sessionID string
	var targetUID int
	var force bool
	var dryRun bool
	var outputJSON bool
	cmd := &cobra.Command{
		Use:   "cleanup-pins",
		Short: "Remove orphaned AgentSH nethelper bpffs pins",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := nethelper.ValidatePrivilegedServiceUser(); err != nil {
				return err
			}
			if targetUID < -1 || (targetUID >= 0 && uint64(targetUID) > uint64(^uint32(0))) {
				return fmt.Errorf("--uid must be -1 or a non-negative 32-bit Unix uid")
			}
			opts := nethelper.PinCleanupOptions{
				PinRoot:   pinRoot,
				SessionID: sessionID,
				DryRun:    dryRun,
				OwnerUID:  0,
				Force:     force,
			}
			if targetUID >= 0 {
				opts.TargetUID = uint32(targetUID)
				opts.EnforceTargetUID = true
			}
			res, err := nethelper.CleanupPinnedResources(opts)
			if err != nil {
				return err
			}
			if outputJSON {
				return printJSON(cmd, res)
			}
			if dryRun {
				fmt.Fprintf(cmd.OutOrStdout(), "would remove %d pinned resources\n", len(res.Removed))
			} else {
				fmt.Fprintf(cmd.OutOrStdout(), "removed %d pinned resources\n", len(res.Removed))
			}
			for _, warning := range res.Warnings {
				fmt.Fprintf(cmd.OutOrStdout(), "warning: %s\n", warning)
			}
			for _, path := range res.Removed {
				fmt.Fprintln(cmd.OutOrStdout(), path)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&pinRoot, "pin-root", nethelper.DefaultBPFFSPinRoot(), "AgentSH bpffs pin root to clean")
	cmd.Flags().StringVar(&sessionID, "session", "", "Limit cleanup to one session ID")
	cmd.Flags().IntVar(&targetUID, "uid", -1, "Limit cleanup to one helper-instance UID")
	cmd.Flags().BoolVar(&force, "force", false, "Explicitly remove active or malformed pin trees")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "List pins without removing them")
	cmd.Flags().BoolVar(&outputJSON, "json", false, "Output JSON")
	return cmd
}
