//go:build linux

package nethelper

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"
)

const (
	ephemeralRuntimeBase = "/run/agentsh/nethelper"
	ephemeralPinBase     = "/sys/fs/bpf/agentsh/nethelper-ephemeral"
)

// EphemeralLeasePaths are fixed helper-selected locations for one transient
// SSH bootstrap. Callers may select only the lease ID and target UID.
type EphemeralLeasePaths struct {
	LeaseID        string `json:"lease_id"`
	UnitName       string `json:"unit_name"`
	RuntimeDir     string `json:"runtime_dir"`
	SocketPath     string `json:"socket_path"`
	CredentialFile string `json:"credential_file"`
	RootCredential string `json:"-"`
	ResultFile     string `json:"result_file"`
	PinLeaseDir    string `json:"-"`
	PinRoot        string `json:"pin_root"`
}

func ValidateEphemeralLeaseID(leaseID string) error {
	leaseID = strings.TrimSpace(leaseID)
	if !strings.HasPrefix(leaseID, "lease-") {
		return fmt.Errorf("ephemeral lease id must start with lease-")
	}
	parsed, err := uuid.Parse(strings.TrimPrefix(leaseID, "lease-"))
	if err != nil || parsed == uuid.Nil {
		return fmt.Errorf("ephemeral lease id must contain a non-zero UUID")
	}
	if "lease-"+parsed.String() != leaseID {
		return fmt.Errorf("ephemeral lease id must use canonical lowercase UUID form")
	}
	return nil
}

func EphemeralPathsForUID(uid uint32, leaseID string) (EphemeralLeasePaths, error) {
	if err := ValidateEphemeralLeaseID(leaseID); err != nil {
		return EphemeralLeasePaths{}, err
	}
	uidText := strconv.FormatUint(uint64(uid), 10)
	leaseDir := filepath.Join(ephemeralRuntimeBase, uidText, leaseID)
	pinLeaseDir := filepath.Join(ephemeralPinBase, uidText, leaseID)
	leaseSuffix := strings.TrimPrefix(leaseID, "lease-")
	return EphemeralLeasePaths{
		LeaseID:        leaseID,
		UnitName:       "agentsh-nethelper-ephemeral-" + uidText + "-" + leaseSuffix + ".service",
		RuntimeDir:     leaseDir,
		SocketPath:     filepath.Join(leaseDir, "nethelper.sock"),
		CredentialFile: filepath.Join(leaseDir, "instance-credential"),
		RootCredential: filepath.Join(leaseDir, "root-credential"),
		ResultFile:     filepath.Join(leaseDir, "bootstrap.json"),
		PinLeaseDir:    pinLeaseDir,
		PinRoot:        filepath.Join(pinLeaseDir, "pins"),
	}, nil
}

// ValidateEphemeralServiceInvocation proves that ephemeral serve mode is
// running as the expected transient root systemd service, not as a direct sudo
// process with lookalike flags.
func ValidateEphemeralServiceInvocation(uid uint32, leaseID string) (EphemeralLeasePaths, error) {
	paths, err := EphemeralPathsForUID(uid, leaseID)
	if err != nil {
		return paths, err
	}
	if err := ValidatePrivilegedServiceUser(); err != nil {
		return paths, err
	}
	invocationID := strings.TrimSpace(os.Getenv("INVOCATION_ID"))
	if len(invocationID) != 32 {
		return paths, fmt.Errorf("ephemeral nethelper requires a systemd service invocation id")
	}
	for _, r := range invocationID {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return paths, fmt.Errorf("ephemeral nethelper has an invalid systemd invocation id")
		}
	}
	cgroupPath, err := defaultCgroupResolver().CgroupPathForPID(os.Getpid())
	if err != nil {
		return paths, fmt.Errorf("verify ephemeral helper service cgroup: %w", err)
	}
	expected := filepath.Join(cgroupV2Root(), "system.slice", paths.UnitName)
	if filepath.Clean(cgroupPath) != expected {
		return paths, fmt.Errorf("ephemeral nethelper must run in transient unit %s", paths.UnitName)
	}
	return paths, nil
}

// ListenEphemeralUnixForUID creates the lease socket from the root transient
// service, then gives only the configured supervisor UID access to it.
// ValidateHelperSocketForUID validates a ready helper socket without relying on
// the caller's own UID. Bootstrap uses this before publishing lease metadata.
func ValidateHelperSocketForUID(socketPath string, expectedUID uint32) error {
	if err := validateListenSocketPath(socketPath); err != nil {
		return err
	}
	if err := validateSocketParent(filepath.Dir(socketPath)); err != nil {
		return err
	}
	return validateSocketFileOwner(socketPath, expectedUID, false)
}

func ListenEphemeralUnixForUID(socketPath string, expectedUID, expectedGID uint32) (net.Listener, error) {
	if os.Geteuid() != 0 {
		return nil, fmt.Errorf("ephemeral nethelper listener must run as root")
	}
	if err := validateListenSocketPath(socketPath); err != nil {
		return nil, err
	}
	if err := validateSocketParent(filepath.Dir(socketPath)); err != nil {
		return nil, err
	}
	if info, err := os.Lstat(socketPath); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("refusing to replace invalid ephemeral helper socket %s", socketPath)
		}
		if err := validateSocketFileOwner(socketPath, expectedUID, false); err != nil {
			return nil, err
		}
		if err := os.Remove(socketPath); err != nil {
			return nil, fmt.Errorf("remove stale ephemeral helper socket: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("stat ephemeral helper socket: %w", err)
	}

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("listen on ephemeral helper socket: %w", err)
	}
	cleanup := func() {
		_ = ln.Close()
		_ = os.Remove(socketPath)
	}
	if err := os.Chmod(socketPath, 0o600); err != nil {
		cleanup()
		return nil, fmt.Errorf("chmod ephemeral helper socket: %w", err)
	}
	if err := os.Chown(socketPath, int(expectedUID), int(expectedGID)); err != nil {
		cleanup()
		return nil, fmt.Errorf("chown ephemeral helper socket: %w", err)
	}
	if err := validateSocketFileOwner(socketPath, expectedUID, false); err != nil {
		cleanup()
		return nil, err
	}
	return ln, nil
}

// DropEphemeralSetupCapabilities removes CAP_CHOWN after the transient helper
// has handed socket ownership to the target UID. Clearing it from permitted,
// effective, and inheritable sets prevents regain for this no_new_privs
// process even though the service's startup bounding set had to include it.
func DropEphemeralSetupCapabilities() error {
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3, Pid: 0}
	data := [2]unix.CapUserData{}
	if err := unix.Capget(&header, &data[0]); err != nil {
		return fmt.Errorf("read ephemeral helper capabilities: %w", err)
	}
	capability := uint(unix.CAP_CHOWN)
	word := capability / 32
	mask := ^(uint32(1) << (capability % 32))
	data[word].Effective &= mask
	data[word].Permitted &= mask
	data[word].Inheritable &= mask
	if err := unix.Capset(&header, &data[0]); err != nil {
		return fmt.Errorf("drop ephemeral socket-setup capability: %w", err)
	}
	verify := [2]unix.CapUserData{}
	if err := unix.Capget(&header, &verify[0]); err != nil {
		return fmt.Errorf("verify ephemeral helper capabilities: %w", err)
	}
	if verify[word].Effective&(^(mask)) != 0 || verify[word].Permitted&(^(mask)) != 0 || verify[word].Inheritable&(^(mask)) != 0 {
		return fmt.Errorf("ephemeral socket-setup capability remained active")
	}
	return nil
}
