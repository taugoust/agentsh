//go:build linux

package landlock

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
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

// Landlock rule types
const (
	LANDLOCK_RULE_PATH_BENEATH = 1
	LANDLOCK_RULE_NET_PORT     = 2
)

// Landlock access rights for filesystem
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
	LANDLOCK_ACCESS_FS_REFER       = 1 << 13 // ABI v2
	LANDLOCK_ACCESS_FS_TRUNCATE    = 1 << 14 // ABI v3
	LANDLOCK_ACCESS_FS_IOCTL_DEV   = 1 << 15 // ABI v5
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

// landlockPathBeneathAttr is the attribute for path rules.
type landlockPathBeneathAttr struct {
	AllowedAccess uint64
	ParentFd      int32
	_             [4]byte // padding
}

// landlockNetPortAttr is the attribute for network port rules.
type landlockNetPortAttr struct {
	AllowedAccess uint64
	Port          uint64
}

// stripGlobPrefix returns the non-glob prefix of a path. If the path contains
// glob characters (*, ?, [), returns everything before the first one with the
// trailing slash trimmed. If no glob characters are present, returns the path
// unchanged. Defense-in-depth: glob patterns should be stripped on the server
// side, but if they leak through, this prevents unix.Open from receiving a
// literal "/bin/**".
func stripGlobPrefix(path string) string {
	for i, c := range path {
		if c == '*' || c == '?' || c == '[' {
			prefix := strings.TrimSuffix(path[:i], "/")
			if prefix == "" {
				return "/"
			}
			return prefix
		}
	}
	return path
}

// RulesetBuilder constructs a Landlock ruleset from paths.
type RulesetBuilder struct {
	abi               int
	workspace         string
	executePaths      []string
	readPaths         []string
	listPaths         []string
	writePaths        []string
	deviceIOCTLPaths  []string
	denyPaths         []string
	handleDeviceIOCTL bool
	allowNetwork      bool
	allowBind         bool
}

// NewRulesetBuilder creates a new ruleset builder for the given ABI version.
func NewRulesetBuilder(abi int) *RulesetBuilder {
	return &RulesetBuilder{
		abi:          abi,
		executePaths: make([]string, 0),
		readPaths:    make([]string, 0),
		listPaths:    make([]string, 0),
		writePaths:   make([]string, 0),
		denyPaths:    make([]string, 0),
	}
}

// SetWorkspace sets the workspace path (gets full read/write/execute access).
func (b *RulesetBuilder) SetWorkspace(path string) {
	b.workspace = path
}

// AddExecutePath adds a path where execution is allowed.
func (b *RulesetBuilder) AddExecutePath(path string) error {
	cleaned := stripGlobPrefix(path)
	if cleaned != path {
		slog.Warn("landlock: glob pattern in execute path, stripped to base dir",
			"original", path, "cleaned", cleaned)
	}
	absPath, err := filepath.Abs(cleaned)
	if err != nil {
		return fmt.Errorf("invalid path %s: %w", path, err)
	}
	b.executePaths = append(b.executePaths, absPath)
	return nil
}

// AddReadPath adds a path where reading is allowed.
func (b *RulesetBuilder) AddReadPath(path string) error {
	cleaned := stripGlobPrefix(path)
	if cleaned != path {
		slog.Warn("landlock: glob pattern in read path, stripped to base dir",
			"original", path, "cleaned", cleaned)
	}
	absPath, err := filepath.Abs(cleaned)
	if err != nil {
		return fmt.Errorf("invalid path %s: %w", path, err)
	}
	b.readPaths = append(b.readPaths, absPath)
	return nil
}

// AddListPath adds a directory prefix with READ_DIR but not READ_FILE. This is
// used for metadata-only directory discovery without making files beneath the
// prefix readable through Landlock.
func (b *RulesetBuilder) AddListPath(path string) error {
	if strings.IndexAny(path, "*?[") >= 0 {
		return fmt.Errorf("list path %q must not contain glob syntax", path)
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("invalid path %s: %w", path, err)
	}
	b.listPaths = append(b.listPaths, absPath)
	return nil
}

// AddWritePath adds a path where writing is allowed.
func (b *RulesetBuilder) AddWritePath(path string) error {
	cleaned := stripGlobPrefix(path)
	if cleaned != path {
		slog.Warn("landlock: glob pattern in write path, stripped to base dir",
			"original", path, "cleaned", cleaned)
	}
	absPath, err := filepath.Abs(cleaned)
	if err != nil {
		return fmt.Errorf("invalid path %s: %w", path, err)
	}
	b.writePaths = append(b.writePaths, absPath)
	return nil
}

// SetDeviceIOCTLPolicy controls whether ABI-5 device ioctls are handled by
// this ruleset. It is opt-in so ordinary command boundaries retain their
// existing behavior; composition-selected commands enable it before exposing
// an identity-bound /dev view.
func (b *RulesetBuilder) SetDeviceIOCTLPolicy(handle bool) {
	b.handleDeviceIOCTL = handle
}

// AddDeviceIOCTLPath grants the ABI-5 IOCTL_DEV right to one exact device
// object. Read/write authority remains independently controlled by the normal
// path rules.
func (b *RulesetBuilder) AddDeviceIOCTLPath(path string) error {
	if strings.IndexAny(path, "*?[") >= 0 {
		return fmt.Errorf("device ioctl path must not contain a glob: %s", path)
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("invalid device ioctl path %s: %w", path, err)
	}
	if filepath.Clean(absPath) != path {
		return fmt.Errorf("device ioctl path must be clean and absolute: %s", path)
	}
	b.deviceIOCTLPaths = append(b.deviceIOCTLPaths, absPath)
	return nil
}

// AddDenyPath marks a path to be denied (by not adding it to the ruleset).
func (b *RulesetBuilder) AddDenyPath(path string) {
	b.denyPaths = append(b.denyPaths, path)
}

// SetNetworkAccess configures network restrictions (ABI v4+ only).
func (b *RulesetBuilder) SetNetworkAccess(allowConnect, allowBind bool) {
	b.allowNetwork = allowConnect
	b.allowBind = allowBind
}

// RuleObject is an exact object used to construct a Landlock path-beneath
// rule. Composition setup retains these O_PATH descriptors so the broker and
// the base ruleset share one object/right model instead of reinterpreting path
// strings independently.
type RuleObject struct {
	Path   string
	Rights uint64
	File   *os.File
}

func (o *RuleObject) Close() error {
	if o == nil || o.File == nil {
		return nil
	}
	err := o.File.Close()
	o.File = nil
	return err
}

// Build creates the Landlock ruleset and closes retained rule descriptors.
func (b *RulesetBuilder) Build() (int, error) {
	fd, objects, err := b.BuildRetained()
	for index := range objects {
		_ = objects[index].Close()
	}
	return fd, err
}

// BuildRetained creates the ruleset and returns the exact O_PATH objects used
// for its filesystem rules. The caller owns both the ruleset fd and objects.
func (b *RulesetBuilder) BuildRetained() (int, []RuleObject, error) {
	// Build access masks based on ABI
	accessFS := b.buildFSAccessMask()

	attr := landlockRulesetAttr{
		AccessFS: accessFS,
	}

	// Add network handling for ABI v4+ ONLY if we want to restrict network access.
	// If both allowNetwork and allowBind are true, we don't add network to HandledAccessNet
	// because that would allow all network access (no restrictions).
	// We only handle network when we want to selectively allow/deny.
	restrictNetwork := b.abi >= 4 && (!b.allowNetwork || !b.allowBind)
	if restrictNetwork {
		attr.AccessNet = LANDLOCK_ACCESS_NET_BIND_TCP |
			LANDLOCK_ACCESS_NET_CONNECT_TCP
	}

	// Calculate size based on ABI version
	var attrSize uintptr
	if b.abi >= 4 && restrictNetwork {
		attrSize = unsafe.Sizeof(attr)
	} else {
		attrSize = unsafe.Sizeof(attr.AccessFS)
	}

	// Create the ruleset
	fd, _, errno := syscall.Syscall(
		SYS_LANDLOCK_CREATE_RULESET,
		uintptr(unsafe.Pointer(&attr)),
		attrSize,
		0,
	)
	if errno != 0 {
		return -1, nil, fmt.Errorf("landlock_create_ruleset: %v", errno)
	}
	rulesetFd := int(fd)
	objects := make([]RuleObject, 0, 1+len(b.executePaths)+len(b.readPaths)+len(b.listPaths)+len(b.writePaths)+len(b.deviceIOCTLPaths))
	closeWithError := func(err error) (int, []RuleObject, error) {
		for index := range objects {
			_ = objects[index].Close()
		}
		_ = unix.Close(rulesetFd)
		return -1, nil, err
	}
	addObject := func(path string, rights uint64) error {
		object, err := AddPathRuleObject(rulesetFd, path, rights)
		if err != nil {
			return err
		}
		objects = append(objects, object)
		return nil
	}

	// Add workspace rule (full filesystem access except device ioctls). Device
	// ioctl authority is always exact-object and independently configured.
	if b.workspace != "" {
		workspaceAccess := accessFS &^ uint64(LANDLOCK_ACCESS_FS_IOCTL_DEV)
		if err := addObject(b.workspace, workspaceAccess); err != nil {
			return closeWithError(fmt.Errorf("add workspace rule: %w", err))
		}
	}

	// Add execute paths
	execAccess := uint64(LANDLOCK_ACCESS_FS_EXECUTE |
		LANDLOCK_ACCESS_FS_READ_FILE |
		LANDLOCK_ACCESS_FS_READ_DIR)
	for _, path := range b.executePaths {
		if b.isDenied(path) {
			continue
		}
		if err := addObject(path, execAccess); err != nil {
			// Non-fatal: path might not exist
			continue
		}
	}

	// Add read paths
	readAccess := uint64(LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR)
	for _, path := range b.readPaths {
		if b.isDenied(path) {
			continue
		}
		if err := addObject(path, readAccess); err != nil {
			continue
		}
	}

	// Add directory-list paths separately. In particular, a rule for `/` grants
	// only READ_DIR: it must never imply READ_FILE for the whole host tree.
	for _, path := range b.listPaths {
		if b.isDenied(path) {
			continue
		}
		if err := addObject(path, LANDLOCK_ACCESS_FS_READ_DIR); err != nil {
			continue
		}
	}

	// Add write paths (includes read access — writable paths must also be readable,
	// e.g., to cat a file you just created, or for tools that read-then-write).
	writeAccess := b.buildWriteAccessMask()
	for _, path := range b.writePaths {
		if b.isDenied(path) {
			continue
		}
		if err := addObject(path, writeAccess); err != nil {
			continue
		}
	}

	if b.abi >= 5 && b.handleDeviceIOCTL {
		for _, path := range b.deviceIOCTLPaths {
			if b.isDenied(path) {
				continue
			}
			if err := addObject(path, LANDLOCK_ACCESS_FS_IOCTL_DEV); err != nil {
				continue
			}
		}
	}

	// Add network rules (ABI v4+) only when restricting network
	// When restrictNetwork is true, we add rules for what we ALLOW
	if restrictNetwork {
		if b.allowNetwork {
			if err := b.addNetRule(rulesetFd, LANDLOCK_ACCESS_NET_CONNECT_TCP); err != nil {
				return closeWithError(fmt.Errorf("add network connect rule: %w", err))
			}
		}
		if b.allowBind {
			if err := b.addNetRule(rulesetFd, LANDLOCK_ACCESS_NET_BIND_TCP); err != nil {
				return closeWithError(fmt.Errorf("add network bind rule: %w", err))
			}
		}
	}

	return rulesetFd, objects, nil
}

func (b *RulesetBuilder) buildFSAccessMask() uint64 {
	access := uint64(
		LANDLOCK_ACCESS_FS_EXECUTE |
			LANDLOCK_ACCESS_FS_READ_FILE |
			LANDLOCK_ACCESS_FS_READ_DIR |
			LANDLOCK_ACCESS_FS_WRITE_FILE |
			LANDLOCK_ACCESS_FS_REMOVE_FILE |
			LANDLOCK_ACCESS_FS_REMOVE_DIR |
			LANDLOCK_ACCESS_FS_MAKE_CHAR |
			LANDLOCK_ACCESS_FS_MAKE_DIR |
			LANDLOCK_ACCESS_FS_MAKE_REG |
			LANDLOCK_ACCESS_FS_MAKE_SOCK |
			LANDLOCK_ACCESS_FS_MAKE_FIFO |
			LANDLOCK_ACCESS_FS_MAKE_BLOCK |
			LANDLOCK_ACCESS_FS_MAKE_SYM)

	if b.abi >= 2 {
		access |= LANDLOCK_ACCESS_FS_REFER
	}
	if b.abi >= 3 {
		access |= LANDLOCK_ACCESS_FS_TRUNCATE
	}
	if b.abi >= 5 && b.handleDeviceIOCTL {
		access |= LANDLOCK_ACCESS_FS_IOCTL_DEV
	}

	return access
}

// buildWriteAccessMask returns the access rights granted to write-allowed paths.
// Includes read (writable paths must be readable), file/dir creation, removal,
// symlink creation (needed by Nix caches), and socket creation (needed for Unix
// domain sockets in /tmp etc.).
func (b *RulesetBuilder) buildWriteAccessMask() uint64 {
	access := uint64(LANDLOCK_ACCESS_FS_WRITE_FILE |
		LANDLOCK_ACCESS_FS_READ_FILE |
		LANDLOCK_ACCESS_FS_READ_DIR |
		LANDLOCK_ACCESS_FS_REMOVE_FILE |
		LANDLOCK_ACCESS_FS_REMOVE_DIR |
		LANDLOCK_ACCESS_FS_MAKE_REG |
		LANDLOCK_ACCESS_FS_MAKE_DIR |
		LANDLOCK_ACCESS_FS_MAKE_SYM |
		LANDLOCK_ACCESS_FS_MAKE_SOCK)
	if b.abi >= 3 {
		access |= LANDLOCK_ACCESS_FS_TRUNCATE
	}
	return access
}

// accessFile is the set of access rights valid for non-directory inodes.
// The kernel returns EINVAL if directory-only rights are passed for a file.
const accessFile = LANDLOCK_ACCESS_FS_EXECUTE |
	LANDLOCK_ACCESS_FS_WRITE_FILE |
	LANDLOCK_ACCESS_FS_READ_FILE |
	LANDLOCK_ACCESS_FS_TRUNCATE |
	LANDLOCK_ACCESS_FS_IOCTL_DEV

// AddPathRuleObject opens one exact object, adds it to an existing ruleset,
// and retains the same O_PATH descriptor for a trusted broker handoff.
func AddPathRuleObject(rulesetFD int, path string, access uint64) (RuleObject, error) {
	fd, err := unix.Open(path, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		slog.Debug("landlock: addPathRule open failed",
			"path", path, "error", err)
		return RuleObject{}, fmt.Errorf("open %s: %w", path, err)
	}
	file := os.NewFile(uintptr(fd), "landlock-rule-object")
	if file == nil {
		_ = unix.Close(fd)
		return RuleObject{}, fmt.Errorf("retain Landlock object %s", path)
	}

	// For non-directory inodes (files, devices, pipes), strip directory-only
	// access rights. The kernel rejects rules with MAKE_REG, REMOVE_DIR, etc.
	// on non-directory paths with EINVAL.
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err == nil && stat.Mode&unix.S_IFDIR == 0 {
		access &= accessFile
	}

	pathBeneath := landlockPathBeneathAttr{
		AllowedAccess: access,
		ParentFd:      int32(fd),
	}

	_, _, errno := syscall.Syscall6(
		SYS_LANDLOCK_ADD_RULE,
		uintptr(rulesetFD),
		LANDLOCK_RULE_PATH_BENEATH,
		uintptr(unsafe.Pointer(&pathBeneath)),
		0, 0, 0,
	)
	if errno != 0 {
		_ = file.Close()
		return RuleObject{}, fmt.Errorf("landlock_add_rule: %v", errno)
	}

	return RuleObject{Path: path, Rights: access, File: file}, nil
}

func (b *RulesetBuilder) addNetRule(rulesetFd int, access uint64) error {
	// IMPORTANT: Landlock network rules are PORT-SPECIFIC.
	// There is no way to allow "all ports" with a single rule.
	// Port 0 only allows binding to ephemeral ports (32768-60999), NOT all ports.
	//
	// For blanket allow-all network access, the solution is to NOT include
	// network access in HandledAccessNet at all (handled in Build()).
	//
	// This function adds a rule for port 0 which allows:
	// - For BIND: binding to ephemeral ports only
	// - For CONNECT: connecting to port 0 (rarely useful)
	//
	// For more granular control, we would need to iterate over specific ports.
	// This is a known limitation documented in security-modes.md.
	netAttr := landlockNetPortAttr{
		AllowedAccess: access,
		Port:          0,
	}

	_, _, errno := syscall.Syscall6(
		SYS_LANDLOCK_ADD_RULE,
		uintptr(rulesetFd),
		LANDLOCK_RULE_NET_PORT,
		uintptr(unsafe.Pointer(&netAttr)),
		0, 0, 0,
	)
	if errno != 0 {
		return fmt.Errorf("landlock_add_rule (net): %v", errno)
	}

	return nil
}

// isDenied checks if a path is in the deny list.
// LIMITATION: This check does not resolve symlinks. A symlink pointing to a
// denied path (e.g., /tmp/link -> /var/run/docker.sock) will not be caught.
// However, Landlock itself operates on the resolved path, so the actual
// protection is still in place - we just might add a rule for a symlink
// that won't be useful.
func (b *RulesetBuilder) isDenied(path string) bool {
	for _, deny := range b.denyPaths {
		if path == deny || strings.HasPrefix(path, deny+string(os.PathSeparator)) {
			return true
		}
	}
	return false
}

// Enforce applies the ruleset to the calling OS thread and its future
// descendants. Callers that will exec must keep their goroutine pinned to this
// thread; Landlock restrictions are not process-wide across an existing thread
// group.
func Enforce(rulesetFd int) error {
	// Set no_new_privs first (required)
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("prctl(PR_SET_NO_NEW_PRIVS): %w", err)
	}

	// Apply the ruleset
	_, _, errno := syscall.Syscall(
		SYS_LANDLOCK_RESTRICT_SELF,
		uintptr(rulesetFd),
		0, 0,
	)
	if errno != 0 {
		return fmt.Errorf("landlock_restrict_self: %v", errno)
	}

	return nil
}
