//go:build linux

package capabilities

import (
	"fmt"
	"strings"
	"syscall"
)

// Landlock syscall numbers
// Note: These are consistent across amd64 and arm64 (verified in Linux 5.13+).
// If golang.org/x/sys/unix exports these constants in a future version,
// prefer those for better portability.
const (
	SYS_LANDLOCK_CREATE_RULESET = 444
	SYS_LANDLOCK_ADD_RULE       = 445
	SYS_LANDLOCK_RESTRICT_SELF  = 446
)

// Landlock access rights for filesystem (ABI v1)
const (
	LANDLOCK_ACCESS_FS_EXECUTE     = 1 << 0
	LANDLOCK_ACCESS_FS_WRITE_FILE  = 1 << 1
	LANDLOCK_ACCESS_FS_READ_FILE   = 1 << 2
	LANDLOCK_ACCESS_FS_READ_DIR    = 1 << 3
	LANDLOCK_ACCESS_FS_REMOVE_DIR  = 1 << 4
	LANDLOCK_ACCESS_FS_REMOVE_FILE = 1 << 5
	LANDLOCK_ACCESS_FS_MAKE_CHAR   = 1 << 6
	LANDLOCK_ACCESS_FS_MAKE_DIR    = 1 << 7
	LANDLOCK_ACCESS_FS_MAKE_REG    = 1 << 8
	LANDLOCK_ACCESS_FS_MAKE_SOCK   = 1 << 9
	LANDLOCK_ACCESS_FS_MAKE_FIFO   = 1 << 10
	LANDLOCK_ACCESS_FS_MAKE_BLOCK  = 1 << 11
	LANDLOCK_ACCESS_FS_MAKE_SYM    = 1 << 12
	// ABI v2
	LANDLOCK_ACCESS_FS_REFER = 1 << 13
	// ABI v3
	LANDLOCK_ACCESS_FS_TRUNCATE = 1 << 14
)

// Landlock access rights for network (ABI v4)
const (
	LANDLOCK_ACCESS_NET_BIND_TCP    = 1 << 0
	LANDLOCK_ACCESS_NET_CONNECT_TCP = 1 << 1
)

// landlockRulesetAttr is the attribute structure for landlock_create_ruleset.
type landlockRulesetAttr struct {
	AccessFS  uint64
	AccessNet uint64
}

// LandlockResult holds the result of Landlock availability detection.
type LandlockResult struct {
	Available               bool
	ABI                     int
	NetworkSupport          bool
	DeviceIOCTLSupport      bool
	AbstractUnixSocketScope bool
	SignalScope             bool
	AuditSupport            bool
	Error                   string
}

func (r LandlockResult) String() string {
	if !r.Available {
		return fmt.Sprintf("Landlock: unavailable (%s)", r.Error)
	}
	features := []string{fmt.Sprintf("ABI v%d", r.ABI)}
	if r.NetworkSupport {
		features = append(features, "network support")
	}
	if r.DeviceIOCTLSupport {
		features = append(features, "device ioctl")
	}
	if r.AbstractUnixSocketScope || r.SignalScope {
		features = append(features, "IPC/signal scopes")
	}
	if r.AuditSupport {
		features = append(features, "audit controls")
	}
	return fmt.Sprintf("Landlock: available (%s)", strings.Join(features, ", "))
}

const LANDLOCK_CREATE_RULESET_VERSION = 1 << 0

// DetectLandlock asks the kernel for its actual highest ABI. Feature handling
// remains explicit; reporting a newer ABI never silently enables new rights.
func DetectLandlock() LandlockResult {
	version, _, errno := syscall.Syscall(
		SYS_LANDLOCK_CREATE_RULESET,
		0,
		0,
		LANDLOCK_CREATE_RULESET_VERSION,
	)
	if errno != 0 || version < 1 {
		return LandlockResult{
			Available: false,
			Error:     fmt.Sprintf("kernel does not support Landlock or it is disabled: %v", errno),
		}
	}
	abi := int(version)
	return LandlockResult{
		Available:               true,
		ABI:                     abi,
		NetworkSupport:          abi >= 4,
		DeviceIOCTLSupport:      abi >= 5,
		AbstractUnixSocketScope: abi >= 6,
		SignalScope:             abi >= 6,
		AuditSupport:            abi >= 7,
	}
}
