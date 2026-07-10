package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/agentsh/agentsh/internal/nethelper"
	"github.com/spf13/cobra"
)

const nethelperSystemdCredentialName = "agentsh-nethelper-instance-credential"

func newNethelperCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:    "nethelper",
		Short:  "Run the installed privileged network helper",
		Hidden: true,
	}
	cmd.AddCommand(newNethelperServeCmd())
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

func newNethelperServeCmd() *cobra.Command {
	var socketPath string
	var expectedUID int
	var expectedGID int
	var pinRoot string
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Serve the installed AgentSH network helper socket",
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

			activationListener, activated, err := nethelper.ListenSystemdActivationForUID(socketPath, uint32(expectedUID))
			if err != nil {
				return err
			}
			if !activated {
				return fmt.Errorf("nethelper serve requires the installed systemd socket unit")
			}
			server := nethelper.NewServer(
				nethelper.NewKernelBackendWithOptions(backendOpts),
				nethelper.NewSupervisorAuthorizer(authOpts),
			)
			fmt.Fprintf(cmd.OutOrStdout(), "agentsh nethelper listening on unix://%s\n", socketPath)
			return server.ServeListener(ctx, activationListener)
		},
	}
	cmd.Flags().StringVar(&socketPath, "socket", "", "Unix socket path supplied by the installed socket unit")
	cmd.Flags().IntVar(&expectedUID, "uid", -1, "Expected supervisor Unix UID (required)")
	cmd.Flags().IntVar(&expectedGID, "gid", -1, "Expected supervisor Unix GID (-1 disables explicit GID check)")
	cmd.Flags().StringVar(&pinRoot, "pin-root", nethelper.DefaultBPFFSPinRoot(), "Root-owned AgentSH bpffs subtree for helper map/link pins")
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
