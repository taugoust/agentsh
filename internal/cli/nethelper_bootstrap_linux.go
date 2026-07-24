//go:build linux

package cli

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/agentsh/agentsh/internal/nethelper"
	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"
)

type nethelperBootstrapResult = nethelper.BootstrapResult

func newNethelperBootstrapCmd() *cobra.Command {
	var targetUID int
	var targetGID int
	var leaseID string
	var runtimeLimit time.Duration
	var softLease time.Duration
	cmd := &cobra.Command{
		Use:   "bootstrap",
		Short: "Start one temporary privileged nethelper lease",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := validateEphemeralNethelperRuntime(runtimeLimit); err != nil {
				return err
			}
			if softLease < 0 || softLease > runtimeLimit {
				return fmt.Errorf("--soft-lease must be zero or no greater than --runtime")
			}
			if targetUID <= 0 || uint64(targetUID) > uint64(^uint32(0)) {
				return fmt.Errorf("--uid must be a positive 32-bit Unix uid")
			}
			if targetGID < 0 || uint64(targetGID) > uint64(^uint32(0)) {
				return fmt.Errorf("--gid must be a non-negative 32-bit Unix gid")
			}
			result, err := bootstrapEphemeralNethelperWithSoftLease(uint32(targetUID), uint32(targetGID), strings.TrimSpace(leaseID), runtimeLimit, softLease)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "agentsh temporary nethelper ready; result: %s\n", result.ResultFile)
			return nil
		},
	}
	cmd.Flags().IntVar(&targetUID, "uid", -1, "Unix UID authorized to use the temporary helper")
	cmd.Flags().IntVar(&targetGID, "gid", -1, "Primary Unix GID authorized to use the temporary helper")
	cmd.Flags().StringVar(&leaseID, "lease", "", "Canonical lease UUID from nethelper lease-id")
	cmd.Flags().DurationVar(&runtimeLimit, "runtime", nethelper.DefaultBootstrapRuntime, "Finite helper hard runtime (default 13h, maximum 192h)")
	cmd.Flags().DurationVar(&softLease, "soft-lease", 0, "Opt into renewable soft expiry (zero keeps legacy hard-expiry-only behavior)")
	_ = cmd.MarkFlagRequired("uid")
	_ = cmd.MarkFlagRequired("gid")
	_ = cmd.MarkFlagRequired("lease")
	return cmd
}

func validateEphemeralNethelperRuntime(runtimeLimit time.Duration) error {
	if runtimeLimit <= 0 {
		return fmt.Errorf("--runtime must be positive")
	}
	if runtimeLimit > nethelper.MaximumBootstrapRuntime {
		return fmt.Errorf("--runtime exceeds maximum %s", nethelper.MaximumBootstrapRuntime)
	}
	if runtimeLimit%time.Second != 0 {
		return fmt.Errorf("--runtime must be an exact number of seconds")
	}
	return nil
}

func bootstrapEphemeralNethelper(uid, gid uint32, leaseID string, runtimeLimit time.Duration) (result nethelperBootstrapResult, retErr error) {
	return bootstrapEphemeralNethelperWithSoftLease(uid, gid, leaseID, runtimeLimit, 0)
}

func bootstrapEphemeralNethelperWithSoftLease(uid, gid uint32, leaseID string, runtimeLimit, softLease time.Duration) (result nethelperBootstrapResult, retErr error) {
	if err := validateEphemeralNethelperRuntime(runtimeLimit); err != nil {
		return result, err
	}
	if softLease < 0 || softLease > runtimeLimit || softLease%time.Second != 0 {
		return result, fmt.Errorf("soft lease must be zero or an exact number of seconds within runtime")
	}
	if err := nethelper.ValidatePrivilegedServiceUser(); err != nil {
		return result, err
	}
	if err := validateSudoBootstrapIdentity(uid, gid); err != nil {
		return result, err
	}
	paths, err := nethelper.EphemeralPathsForUID(uid, leaseID)
	if err != nil {
		return result, err
	}
	if err := validateEphemeralHostPrerequisites(); err != nil {
		return result, err
	}
	launcher, err := immutableAgentSHLauncher()
	if err != nil {
		return result, err
	}
	if _, err := reapStaleEphemeralLeases(uid, leaseID); err != nil {
		return result, fmt.Errorf("reap stale temporary nethelper leases: %w", err)
	}
	started := false
	success := false
	defer func() {
		if success {
			return
		}
		if started {
			stopTransientNethelper(paths.UnitName)
		}
		_ = cleanupAbortedEphemeralLease(paths, uid)
	}()
	if err := createEphemeralLeaseDirectories(paths, uid); err != nil {
		return result, err
	}

	credential, err := newNethelperCredential()
	if err != nil {
		return result, err
	}
	if err := writePrivateFile(paths.RootCredential, []byte(credential+"\n"), 0, 0); err != nil {
		return result, fmt.Errorf("write root helper credential: %w", err)
	}
	if err := writePrivateFile(paths.CredentialFile, []byte(credential+"\n"), uid, gid); err != nil {
		return result, fmt.Errorf("write supervisor helper credential: %w", err)
	}
	credential = ""

	systemdRun, err := trustedRootExecutable("systemd-run")
	if err != nil {
		return result, fmt.Errorf("systemd-run is required for temporary nethelper bootstrap: %w", err)
	}
	// Capture one conservative start instant before systemd-run. Every published
	// and service-side deadline derives from this exact value.
	startedAt := time.Now().UTC().Truncate(time.Second)
	args := ephemeralSystemdRunArgsWithSoftLease(paths, launcher, uid, gid, runtimeLimit, softLease, startedAt)
	output, err := exec.Command(systemdRun, args...).CombinedOutput()
	if err != nil {
		return result, fmt.Errorf("start transient nethelper service: %w: %s", err, strings.TrimSpace(string(output)))
	}
	started = true

	deadline := time.Now().Add(10 * time.Second)
	var socketErr error
	for time.Now().Before(deadline) {
		socketErr = nethelper.ValidateHelperSocketForUID(paths.SocketPath, uid)
		if socketErr == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if socketErr != nil {
		return result, fmt.Errorf("temporary nethelper did not create its protected socket: %w%s", socketErr, transientUnitStatusSuffix(paths.UnitName))
	}

	result = nethelperBootstrapResult{
		ProtocolVersion:        nethelper.CurrentProtocolVersion,
		BootstrapSchemaVersion: nethelper.BootstrapSchemaVersion,
		LeaseID:                paths.LeaseID,
		UID:                    uid,
		GID:                    gid,
		UnitName:               paths.UnitName,
		SocketPath:             paths.SocketPath,
		CredentialFile:         paths.CredentialFile,
		PinRoot:                paths.PinRoot,
		ResultFile:             paths.ResultFile,
		CompositionScratchRoot: paths.CompositionScratchRoot,
		StartedAt:              startedAt,
		ExpiresAt:              startedAt.Add(runtimeLimit),
		RuntimeSeconds:         int64(runtimeLimit / time.Second),
		SoftLeaseSeconds:       int64(softLease / time.Second),
		RenewalRequired:        softLease > 0,
	}
	wire, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return result, err
	}
	wire = append(wire, '\n')
	if err := writePrivateFile(paths.ResultFile, wire, uid, gid); err != nil {
		return result, fmt.Errorf("write temporary nethelper result: %w", err)
	}
	success = true
	return result, nil
}

func validateSudoBootstrapIdentity(uid, gid uint32) error {
	sudoUID, err := strconv.ParseUint(strings.TrimSpace(os.Getenv("SUDO_UID")), 10, 32)
	if err != nil || sudoUID == 0 {
		return fmt.Errorf("temporary nethelper bootstrap must be invoked directly through sudo by a non-root user")
	}
	sudoGID, err := strconv.ParseUint(strings.TrimSpace(os.Getenv("SUDO_GID")), 10, 32)
	if err != nil {
		return fmt.Errorf("temporary nethelper bootstrap requires sudo to supply SUDO_GID")
	}
	if uint32(sudoUID) != uid || uint32(sudoGID) != gid {
		return fmt.Errorf("requested helper uid/gid does not match the sudo caller")
	}
	if strings.TrimSpace(os.Getenv("SUDO_USER")) == "" {
		return fmt.Errorf("temporary nethelper bootstrap requires sudo to supply SUDO_USER")
	}
	return nil
}

func validateEphemeralHostPrerequisites() error {
	for path, fsType := range map[string]int64{
		"/sys/fs/cgroup": unix.CGROUP2_SUPER_MAGIC,
		"/sys/fs/bpf":    unix.BPF_FS_MAGIC,
	} {
		var stat unix.Statfs_t
		if err := unix.Statfs(path, &stat); err != nil {
			return fmt.Errorf("inspect %s: %w", path, err)
		}
		if int64(stat.Type) != fsType {
			return fmt.Errorf("%s is not the required kernel filesystem", path)
		}
	}
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		return fmt.Errorf("systemd system manager is required: %w", err)
	}
	return nil
}

func immutableAgentSHLauncher() (string, error) {
	executable, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("resolve agentsh executable: %w", err)
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		return "", fmt.Errorf("resolve agentsh executable symlinks: %w", err)
	}
	candidate := executable
	if strings.HasPrefix(filepath.Base(executable), ".agentsh-") || filepath.Base(executable) == ".agentsh-wrapped" {
		candidate = filepath.Join(filepath.Dir(executable), "agentsh")
	}
	candidate = filepath.Clean(candidate)
	if !strings.HasPrefix(candidate, "/nix/store/") || !strings.Contains(candidate, "/bin/") {
		return "", fmt.Errorf("temporary root helper requires an immutable Nix store agentsh executable")
	}
	info, err := os.Lstat(candidate)
	if err != nil {
		return "", fmt.Errorf("stat immutable agentsh launcher: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 || info.Mode().Perm()&0o111 == 0 {
		return "", fmt.Errorf("agentsh launcher is not an immutable executable regular file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil || stat.Uid != 0 {
		return "", fmt.Errorf("agentsh launcher must be owned by root")
	}
	return candidate, nil
}

func trustedRootExecutable(name string) (string, error) {
	var path string
	for _, candidate := range []string{
		filepath.Join("/run/current-system/sw/bin", name),
		filepath.Join("/usr/bin", name),
		filepath.Join("/bin", name),
		filepath.Join("/usr/sbin", name),
		filepath.Join("/sbin", name),
	} {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			path = candidate
			break
		}
	}
	if path == "" {
		return "", fmt.Errorf("%s was not found in a trusted system location", name)
	}
	path, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", fmt.Errorf("resolve %s executable: %w", name, err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", fmt.Errorf("stat %s executable: %w", name, err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 || info.Mode().Perm()&0o111 == 0 || !ok || stat == nil || stat.Uid != 0 {
		return "", fmt.Errorf("%s executable has unsafe type, mode, or ownership", name)
	}
	return path, nil
}

func createEphemeralLeaseDirectories(paths nethelper.EphemeralLeasePaths, uid uint32) error {
	for _, item := range []struct {
		path string
		mode os.FileMode
	}{
		{path: "/run/agentsh", mode: 0o711},
		{path: "/run/agentsh/nethelper", mode: 0o711},
		{path: filepath.Dir(paths.RuntimeDir), mode: 0o711},
	} {
		if err := ensureRootDirectory(item.path, item.mode, false); err != nil {
			return err
		}
	}
	if err := ensureRootDirectory(paths.RuntimeDir, 0o711, true); err != nil {
		return err
	}
	if err := ensureCompositionScratchDirectory(paths.CompositionScratchRoot); err != nil {
		return err
	}
	for _, path := range []string{
		"/sys/fs/bpf/agentsh",
		"/sys/fs/bpf/agentsh/nethelper-ephemeral",
		filepath.Dir(paths.PinLeaseDir),
		paths.PinLeaseDir,
		paths.PinRoot,
	} {
		mustCreate := path == paths.PinLeaseDir || path == paths.PinRoot
		if err := ensureRootDirectory(path, 0o700, mustCreate); err != nil {
			return err
		}
	}
	_ = uid // retained in the signature to make the per-UID topology explicit.
	return nil
}

func ensureRootDirectory(path string, mode os.FileMode, mustCreate bool) error {
	path = filepath.Clean(path)
	err := os.Mkdir(path, mode)
	if err != nil {
		if !os.IsExist(err) {
			return fmt.Errorf("create protected directory %s: %w", path, err)
		}
		if mustCreate {
			return fmt.Errorf("refusing to reuse existing ephemeral helper directory %s", path)
		}
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("stat protected directory %s: %w", path, err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0o022 != 0 || !ok || stat == nil || stat.Uid != 0 {
		return fmt.Errorf("protected directory %s has unsafe type, mode, or ownership", path)
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || filepath.Clean(resolved) != path {
		return fmt.Errorf("protected directory %s must not contain symlink components", path)
	}
	return nil
}

func ensureCompositionScratchDirectory(path string) error {
	path = filepath.Clean(path)
	if err := os.Mkdir(path, os.ModeSticky|0o733); err != nil {
		return fmt.Errorf("create protected composition runtime %s: %w", path, err)
	}
	if err := os.Chmod(path, os.ModeSticky|0o733); err != nil {
		return fmt.Errorf("set protected composition runtime mode %s: %w", path, err)
	}
	return validateCompositionScratchDirectory(path)
}

func validateCompositionScratchDirectory(path string) error {
	path = filepath.Clean(path)
	var stat unix.Stat_t
	if err := unix.Lstat(path, &stat); err != nil {
		return fmt.Errorf("stat protected composition runtime %s: %w", path, err)
	}
	if err := nethelper.ValidateCompositionScratchMetadata(stat.Mode, stat.Uid, stat.Gid); err != nil {
		return fmt.Errorf("protected composition runtime %s: %w", path, err)
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || filepath.Clean(resolved) != path {
		return fmt.Errorf("protected composition runtime %s must not contain symlink components", path)
	}
	return nil
}

func writePrivateFile(path string, data []byte, uid, gid uint32) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o400)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = file.Close()
		if !ok {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Chmod(0o400); err != nil {
		return err
	}
	if err := file.Chown(int(uid), int(gid)); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	ok = true
	return nil
}

func newNethelperCredential() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate helper credential: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

func ephemeralSystemdRunArgs(paths nethelper.EphemeralLeasePaths, launcher string, uid, gid uint32, runtimeLimit time.Duration, startedAt time.Time) []string {
	return ephemeralSystemdRunArgsWithSoftLease(paths, launcher, uid, gid, runtimeLimit, 0, startedAt)
}

func ephemeralSystemdRunArgsWithSoftLease(paths nethelper.EphemeralLeasePaths, launcher string, uid, gid uint32, runtimeLimit, softLease time.Duration, startedAt time.Time) []string {
	runtimeCapabilities := "CAP_BPF CAP_NET_ADMIN CAP_PERFMON"
	startupCapabilities := runtimeCapabilities + " CAP_CHOWN"
	runtimeDirectory := strings.TrimPrefix(paths.RuntimeDir, "/run/")
	properties := []string{
		"User=root",
		"Group=root",
		"Restart=no",
		"RuntimeDirectory=" + runtimeDirectory,
		"RuntimeDirectoryMode=0711",
		"RuntimeDirectoryPreserve=no",
		"RuntimeMaxSec=" + strconv.FormatInt(int64(runtimeLimit/time.Second), 10) + "s",
		"TimeoutStopSec=10s",
		"KillMode=mixed",
		"UMask=0077",
		"LoadCredential=" + nethelperSystemdCredentialName + ":" + paths.RootCredential,
		"AmbientCapabilities=" + runtimeCapabilities,
		"CapabilityBoundingSet=" + startupCapabilities,
		"NoNewPrivileges=yes",
		"DevicePolicy=closed",
		"IPAddressDeny=any",
		"PrivateDevices=yes",
		"PrivateIPC=yes",
		"PrivateMounts=yes",
		"PrivateTmp=yes",
		"ProtectClock=yes",
		"ProtectControlGroups=yes",
		"ProtectHome=yes",
		"ProtectHostname=yes",
		"ProtectKernelLogs=yes",
		"ProtectKernelModules=yes",
		"ProtectKernelTunables=yes",
		"ProtectSystem=strict",
		"ReadOnlyPaths=/run /sys/fs/cgroup",
		"ReadWritePaths=" + paths.RuntimeDir + " " + paths.PinLeaseDir,
		"RestrictAddressFamilies=AF_UNIX",
		"RestrictNamespaces=yes",
		"RestrictRealtime=yes",
		"RestrictSUIDSGID=yes",
		"LockPersonality=yes",
		"LimitMEMLOCK=infinity",
		"MemoryDenyWriteExecute=yes",
		"RemoveIPC=yes",
		"SystemCallArchitectures=native",
		"SystemCallFilter=@system-service bpf perf_event_open pidfd_open",
		"SystemCallErrorNumber=EPERM",
		"WorkingDirectory=/",
	}
	args := []string{
		"--collect",
		"--service-type=exec",
		"--unit=" + paths.UnitName,
		"--description=Temporary AgentSH network helper lease " + paths.LeaseID,
	}
	for _, property := range properties {
		args = append(args, "--property="+property)
	}
	args = append(args,
		"--",
		launcher,
		"nethelper", "serve",
		"--socket", paths.SocketPath,
		"--uid", strconv.FormatUint(uint64(uid), 10),
		"--gid", strconv.FormatUint(uint64(gid), 10),
		"--pin-root", paths.PinRoot,
		"--ephemeral-lease", paths.LeaseID,
		"--ephemeral-unit", paths.UnitName,
		"--ephemeral-created-at", startedAt.Format(time.RFC3339),
		"--ephemeral-hard-expiry", startedAt.Add(runtimeLimit).Format(time.RFC3339),
	)
	if softLease > 0 {
		args = append(args, "--ephemeral-soft-lease", softLease.String())
	}
	return args
}

func stopTransientNethelper(unit string) {
	systemctl, err := trustedRootExecutable("systemctl")
	if err != nil {
		return
	}
	_ = exec.Command(systemctl, "stop", unit).Run()
}

func transientUnitStatusSuffix(unit string) string {
	systemctl, err := trustedRootExecutable("systemctl")
	if err != nil {
		return ""
	}
	output, err := exec.Command(systemctl, "status", "--no-pager", "--lines=20", unit).CombinedOutput()
	if err != nil && len(output) == 0 {
		return ""
	}
	text := strings.TrimSpace(string(output))
	if text == "" {
		return ""
	}
	return "; unit status: " + text
}

func reapStaleEphemeralLeases(uid uint32, currentLease string) (int, error) {
	reaped, err := reapStaleEphemeralPinLeases(uid, currentLease)
	if err != nil {
		return reaped, err
	}
	uidRoot := filepath.Join("/run/agentsh/nethelper", strconv.FormatUint(uint64(uid), 10))
	entries, err := os.ReadDir(uidRoot)
	if err != nil {
		if os.IsNotExist(err) {
			return reaped, nil
		}
		return reaped, err
	}
	for _, entry := range entries {
		leaseID := entry.Name()
		if !entry.IsDir() || leaseID == currentLease || nethelper.ValidateEphemeralLeaseID(leaseID) != nil {
			continue
		}
		paths, err := nethelper.EphemeralPathsForUID(uid, leaseID)
		if err != nil || transientNethelperUnitActive(paths.UnitName) {
			continue
		}

		pinCleanupRoot := paths.PinRoot
		if _, err := os.Lstat(pinCleanupRoot); os.IsNotExist(err) {
			// Compatibility with the first ephemeral prototype, which used the
			// lease directory itself as PinRoot.
			pinCleanupRoot = paths.PinLeaseDir
		}
		_, _ = nethelper.CleanupPinnedResources(nethelper.PinCleanupOptions{
			PinRoot:          pinCleanupRoot,
			TargetUID:        uid,
			EnforceTargetUID: true,
			OwnerUID:         0,
		})
		_ = os.Remove(paths.PinRoot)
		_ = os.Remove(paths.PinLeaseDir)
		if _, err := os.Lstat(paths.PinLeaseDir); err == nil {
			// A validated active/malformed pin tree was intentionally retained.
			continue
		} else if !os.IsNotExist(err) {
			continue
		}
		if err := removeEmptyCompositionScratchDirectory(paths.CompositionScratchRoot); err != nil {
			continue
		}

		runtimeEntries, err := os.ReadDir(paths.RuntimeDir)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return reaped, err
		}
		known := map[string]bool{
			filepath.Base(paths.SocketPath):     true,
			filepath.Base(paths.CredentialFile): true,
			filepath.Base(paths.RootCredential): true,
			filepath.Base(paths.ResultFile):     true,
		}
		safe := true
		for _, runtimeEntry := range runtimeEntries {
			if !known[runtimeEntry.Name()] || runtimeEntry.IsDir() {
				safe = false
				break
			}
		}
		if !safe {
			continue
		}
		for name := range known {
			_ = os.Remove(filepath.Join(paths.RuntimeDir, name))
		}
		if err := os.Remove(paths.RuntimeDir); err == nil || os.IsNotExist(err) {
			reaped++
		}
	}
	return reaped, nil
}

func reapStaleEphemeralPinLeases(uid uint32, currentLease string) (int, error) {
	uidRoot := filepath.Join("/sys/fs/bpf/agentsh/nethelper-ephemeral", strconv.FormatUint(uint64(uid), 10))
	entries, err := os.ReadDir(uidRoot)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	reaped := 0
	for _, entry := range entries {
		leaseID := entry.Name()
		if !entry.IsDir() || leaseID == currentLease || nethelper.ValidateEphemeralLeaseID(leaseID) != nil {
			continue
		}
		paths, err := nethelper.EphemeralPathsForUID(uid, leaseID)
		if err != nil || transientNethelperUnitActive(paths.UnitName) {
			continue
		}
		pinCleanupRoot := paths.PinRoot
		if _, err := os.Lstat(pinCleanupRoot); os.IsNotExist(err) {
			pinCleanupRoot = paths.PinLeaseDir
		}
		_, _ = nethelper.CleanupPinnedResources(nethelper.PinCleanupOptions{
			PinRoot:          pinCleanupRoot,
			TargetUID:        uid,
			EnforceTargetUID: true,
			OwnerUID:         0,
		})
		_ = os.Remove(paths.PinRoot)
		if err := os.Remove(paths.PinLeaseDir); err == nil || os.IsNotExist(err) {
			reaped++
		}
	}
	return reaped, nil
}

func transientNethelperUnitActive(unit string) bool {
	systemctl, err := trustedRootExecutable("systemctl")
	if err != nil {
		return false
	}
	return exec.Command(systemctl, "is-active", "--quiet", unit).Run() == nil
}

func removeEmptyCompositionScratchDirectory(path string) error {
	if err := validateCompositionScratchDirectory(path); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return err
	}
	if len(entries) != 0 {
		return fmt.Errorf("composition runtime %s is not empty", path)
	}
	return os.Remove(path)
}

func cleanupAbortedEphemeralLease(paths nethelper.EphemeralLeasePaths, uid uint32) error {
	_, _ = nethelper.CleanupPinnedResources(nethelper.PinCleanupOptions{
		PinRoot:          paths.PinRoot,
		TargetUID:        uid,
		EnforceTargetUID: true,
		OwnerUID:         0,
	})
	for _, path := range []string{paths.ResultFile, paths.CredentialFile, paths.RootCredential, paths.SocketPath} {
		_ = os.Remove(path)
	}
	_ = removeEmptyCompositionScratchDirectory(paths.CompositionScratchRoot)
	_ = os.Remove(paths.PinRoot)
	_ = os.Remove(paths.PinLeaseDir)
	_ = os.Remove(paths.RuntimeDir)
	return nil
}

func cleanupReleasedEphemeralLease(paths nethelper.EphemeralLeasePaths, uid uint32) error {
	result, err := nethelper.CleanupPinnedResources(nethelper.PinCleanupOptions{
		PinRoot:          paths.PinRoot,
		TargetUID:        uid,
		EnforceTargetUID: true,
		OwnerUID:         0,
	})
	if err != nil {
		return fmt.Errorf("clean released helper pins: %w", err)
	}
	if err := os.Remove(paths.PinRoot); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("released helper pin root is not empty; preserving lease state: %w (warnings: %s)", err, strings.Join(result.Warnings, "; "))
	}
	for _, path := range []string{paths.ResultFile, paths.CredentialFile, paths.RootCredential} {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove released helper state %s: %w", path, err)
		}
	}
	// systemd owns RuntimeDirectory removal after the service exits. The empty
	// bpffs lease parent is intentionally left for the next privileged bootstrap
	// (or reboot) because deleting it would require write access to sibling lease
	// parents; all maps/links and the helper-selected PinRoot are gone here.
	return nil
}
