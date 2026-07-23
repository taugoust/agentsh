//go:build linux && cgo

package unix

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/agentsh/agentsh/pkg/types"
	sysunix "golang.org/x/sys/unix"
)

// FilePolicyChecker evaluates file policy decisions.
type FilePolicyChecker interface {
	CheckFile(ctx context.Context, path, operation string) FilePolicyDecision
}

// FilePolicyDecision represents a file policy check result.
type FilePolicyDecision struct {
	Decision          string
	EffectiveDecision string
	Rule              string
	Message           string
}

// FileRequest holds the parsed context for a file syscall notification.
type FileRequest struct {
	PID         int
	Syscall     int32
	Path        string
	Path2       string // second path for rename/link
	SourcePath  string // composition-attributed original source path
	SourcePath2 string
	Operation   string
	Flags       uint32
	Mode        uint32
	SessionID   string
}

// FileResult holds the outcome of handling a file syscall.
type FileResult struct {
	Action string // ActionContinue or ActionDeny
	Errno  int32
}

// FileHandler processes file syscall notifications against policy.
type FileHandler struct {
	policy              FilePolicyChecker
	registry            *MountRegistry
	emitter             Emitter
	enforce             bool
	emulateOpen         bool // When true, supervisor emulates openat via AddFD
	compositionPaths    *CompositionPathRegistry
	internalControlPID  int
	internalControlRoot string
}

// NewFileHandler creates a new FileHandler.
func NewFileHandler(policy FilePolicyChecker, registry *MountRegistry, emitter Emitter, enforce bool) *FileHandler {
	return &FileHandler{
		policy:   policy,
		registry: registry,
		emitter:  emitter,
		enforce:  enforce,
	}
}

// SetEmulateOpen enables or disables openat AddFD emulation.
func (h *FileHandler) SetEmulateOpen(v bool) {
	h.emulateOpen = v
}

// EmulateOpen returns whether AddFD emulation is active.
func (h *FileHandler) EmulateOpen() bool {
	return h.emulateOpen
}

// Enforce returns whether the file monitor is in enforcement mode.
func (h *FileHandler) Enforce() bool {
	return h != nil && h.enforce
}

// SetCompositionPathRegistry enables source-aware policy attribution for mount
// namespaces committed by the semantic composition broker.
func (h *FileHandler) SetCompositionPathRegistry(registry *CompositionPathRegistry) {
	if h != nil {
		h.compositionPaths = registry
	}
}

// SetInternalControlAccess grants only the pinned trusted wrapper process
// access to AgentSH's private composition runtime. Project policy never sees
// this authority, and the wrapper's payload child has a distinct thread group.
func (h *FileHandler) SetInternalControlAccess(root string, wrapperPID int) {
	if h == nil || wrapperPID <= 0 || !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return
	}
	h.internalControlRoot = root
	h.internalControlPID = wrapperPID
}

func threadGroupID(pid int) int {
	if pid <= 0 {
		return 0
	}
	data, err := os.ReadFile(filepath.Join(string(filepath.Separator), "proc", strconv.Itoa(pid), "status"))
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "Tgid:" {
			value, err := strconv.Atoi(fields[1])
			if err == nil {
				return value
			}
			return 0
		}
	}
	return 0
}

func pathInsideInternalControlRoot(path, root string) bool {
	return path == root || strings.HasPrefix(path, root+string(filepath.Separator))
}

func (h *FileHandler) internalControlAccessAllowed(req FileRequest) bool {
	if h == nil || h.internalControlPID <= 0 || h.internalControlRoot == "" || req.PID <= 0 {
		return false
	}
	if req.PID != h.internalControlPID && threadGroupID(req.PID) != h.internalControlPID {
		return false
	}
	seen := false
	for _, path := range []string{req.Path, req.Path2, req.SourcePath, req.SourcePath2} {
		if path == "" {
			continue
		}
		seen = true
		if !pathInsideInternalControlRoot(filepath.Clean(path), h.internalControlRoot) {
			return false
		}
	}
	return seen
}

// Handle evaluates a file request against policy and returns the enforcement result
// and an optional audit event. The caller is responsible for emitting the event.
//
// Routing logic:
//  1. No policy -> allow with "no_policy" event.
//  2. Path under FUSE mount -> audit-only (FUSE handles enforcement).
//  3. Otherwise -> full enforcement based on policy decision and enforce flag.
func (h *FileHandler) Handle(ctx context.Context, req FileRequest) (FileResult, *types.Event) {
	if ctx == nil {
		ctx = context.Background()
	}

	// 0. Pseudo-paths (pipe:[...], socket:[...], anon_inode:[...]) resolve
	//    from /proc/<pid>/fd/<N> for non-filesystem fds. They are not
	//    filesystem objects and cannot match path-based policy rules —
	//    allow unconditionally to avoid spurious denials.
	if req.Path != "" && !strings.HasPrefix(req.Path, "/") {
		return FileResult{Action: ActionContinue}, nil
	}

	// 1. No policy configured — allow everything.
	if h.policy == nil {
		dec := FilePolicyDecision{
			Decision:          "allow",
			EffectiveDecision: "allow",
			Rule:              "no_policy",
		}
		return FileResult{Action: ActionContinue}, h.buildFileEvent(req, dec, false, false)
	}

	// Resolve /proc/self/fd/N, /proc/<pid>/fd/N, /dev/fd/N to actual target.
	// This prevents policy bypass by re-deriving paths from file descriptors.
	// Normalize both Path and Path2 (for rename/link dual-path syscalls).
	if resolved, wasProcFD := resolveProcFD(req.PID, req.Path); wasProcFD {
		req.Path = resolved
	}
	if req.Path2 != "" {
		if resolved, wasProcFD := resolveProcFD(req.PID, req.Path2); wasProcFD {
			req.Path2 = resolved
		}
	}

	if h.internalControlAccessAllowed(req) {
		dec := FilePolicyDecision{
			Decision:          "allow",
			EffectiveDecision: "allow",
			Rule:              "allow-agentsh-composition-control",
			Message:           "trusted wrapper access to the private composition runtime",
		}
		return FileResult{Action: ActionContinue}, h.buildFileEvent(req, dec, false, false)
	}

	compositionCovered := false
	if h.compositionPaths != nil {
		attributed, covered, err := h.compositionPaths.Resolve(req.PID, req.Path)
		if err != nil {
			dec := FilePolicyDecision{
				Decision: "deny", EffectiveDecision: "deny",
				Rule:    "composition-source-attribution",
				Message: "composition source attribution failed: " + err.Error(),
			}
			return FileResult{Action: ActionDeny, Errno: int32(sysunix.EACCES)}, h.buildFileEvent(req, dec, true, false)
		}
		compositionCovered = covered
		if covered && attributed != "" && attributed != req.Path {
			req.SourcePath = attributed
		}
		if req.Path2 != "" {
			attributed2, covered2, err := h.compositionPaths.Resolve(req.PID, req.Path2)
			if err != nil {
				dec := FilePolicyDecision{
					Decision: "deny", EffectiveDecision: "deny",
					Rule:    "composition-source-attribution",
					Message: "composition source attribution failed: " + err.Error(),
				}
				return FileResult{Action: ActionDeny, Errno: int32(sysunix.EACCES)}, h.buildFileEvent(req, dec, true, false)
			}
			compositionCovered = compositionCovered || covered2
			if covered2 && attributed2 != "" && attributed2 != req.Path2 {
				req.SourcePath2 = attributed2
			}
		}
	}

	// 2. Path under FUSE mount point — audit-only; FUSE handles enforcement.
	//    Only defers when the resolved syscall path is actually under a FUSE
	//    mount point (e.g., sessions/{id}/mount-0), not a source path.
	if !compositionCovered && h.registry != nil && h.registry.IsUnderFUSEMount(req.SessionID, req.Path) {
		dec := h.policy.CheckFile(ctx, req.Path, req.Operation)
		shadowDeny := dec.EffectiveDecision == "deny"
		return FileResult{Action: ActionContinue}, h.buildFileEvent(req, dec, false, shadowDeny)
	}

	// 3. Full enforcement path.
	dec := h.policy.CheckFile(ctx, req.Path, req.Operation)

	// For dual-path syscalls (rename, link), also check the second path.
	if req.Path2 != "" {
		dec2 := h.policy.CheckFile(ctx, req.Path2, req.Operation)
		// If either path is restrictive, the combined decision is restrictive.
		if dec2.EffectiveDecision != "allow" {
			dec = dec2
		}
	}
	// A bind alias must never launder a restrictive source decision through an
	// allowed-looking destination. Evaluate every broker-attributed source and
	// let either visible or source policy deny the operation.
	sourceRestricted := false
	for _, source := range []string{req.SourcePath, req.SourcePath2} {
		if source == "" {
			continue
		}
		sourceDecision := h.policy.CheckFile(ctx, source, req.Operation)
		if sourceDecision.EffectiveDecision != "allow" {
			dec = sourceDecision
			sourceRestricted = true
		}
	}

	if dec.EffectiveDecision != "allow" {
		if !h.enforce {
			// Audit-only mode: log but allow.
			return FileResult{Action: ActionContinue}, h.buildFileEvent(req, dec, false, false)
		}
		// #369 loader-safe + system-dir-node guards: file_monitor must not deny
		// the read-only opens / stats every wrapped program needs to start, or a
		// deny-by-default policy makes every dynamically-linked command fail.
		// The ptrace enforcer effectively allows both classes below; file_monitor
		// matches it. Read-only only — writes/creates/deletes stay enforced.
		if isReadOnlyFileOp(req.Syscall, req.Flags) && !sourceRestricted {
			// (1) Standard system DIRECTORY NODES (/, /dev, /proc/self, /etc, ...).
			// EXACT match — does NOT extend to contents (a deny of /etc/secret
			// still stands). Overrides ANY deny rule (catch-all or explicit) for
			// these specific bare nodes, because they are universally read-safe
			// (every program stats them) and the wrapped shell can't start
			// without them; operator denies on /proc/self etc. are about the
			// CONTENTS (maps, cmdline, environ), which exact-match preserves.
			if isSystemDirNode(req.Path) {
				slog.Debug("file_monitor: system-dir-node read override (#369)",
					"path", req.Path, "operation", req.Operation, "policy_rule", dec.Rule, "session", req.SessionID)
				return FileResult{Action: ActionContinue}, h.buildFileEvent(req, dec, false, true)
			}
			// (2) Loader-essential subtrees (/lib, /usr, ld.so.cache, ...). Subtree
			// match. Scoped to the CATCH-ALL deny only: an operator's explicit
			// deny rule on a system subpath (e.g. `deny read /opt/app/secrets/**`)
			// is still honored, matching ptrace's first-match-explicit-deny.
			if isDefaultDenyRule(dec.Rule) && isLoaderSafeSystemPath(req.Path) {
				slog.Debug("file_monitor: loader-safe read override (#369)",
					"path", req.Path, "operation", req.Operation, "policy_rule", dec.Rule, "session", req.SessionID)
				return FileResult{Action: ActionContinue}, h.buildFileEvent(req, dec, false, true)
			}
		}
		// Enforced deny for any restrictive decision that has not already been
		// resolved to allow by an approval-aware adapter.
		return FileResult{Action: ActionDeny, Errno: int32(sysunix.EACCES)}, h.buildFileEvent(req, dec, true, false)
	}

	// Allowed.
	return FileResult{Action: ActionContinue}, h.buildFileEvent(req, dec, false, false)
}

// buildFileEvent builds a structured event for a file operation without emitting it.
func (h *FileHandler) buildFileEvent(req FileRequest, dec FilePolicyDecision, blocked, shadowDeny bool) *types.Event {
	if h.emitter == nil {
		return nil
	}

	action := "allowed"
	if blocked {
		action = "blocked"
	}

	fields := map[string]any{
		"syscall": fileSyscallName(req.Syscall),
	}
	if shadowDeny {
		fields["shadow_deny"] = true
	}
	if req.Path2 != "" {
		fields["path2"] = req.Path2
	}
	if req.SourcePath != "" {
		fields["composition_source_path"] = req.SourcePath
	}
	if req.SourcePath2 != "" {
		fields["composition_source_path2"] = req.SourcePath2
	}

	ev := &types.Event{
		ID:        fmt.Sprintf("file-%d-%d", req.PID, time.Now().UnixNano()),
		Timestamp: time.Now().UTC(),
		Type:      "file_" + req.Operation,
		SessionID: req.SessionID,
		Source:    "seccomp",
		PID:       req.PID,
		Path:      req.Path,
		Operation: req.Operation,
		Policy: &types.PolicyInfo{
			Decision:          types.Decision(dec.Decision),
			EffectiveDecision: types.Decision(dec.EffectiveDecision),
			Rule:              dec.Rule,
			Message:           dec.Message,
		},
		EffectiveAction: action,
		Fields:          fields,
	}

	return ev
}

// loaderSafeReadPrefixes are system paths whose READ-ONLY access must never be
// denied: the dynamic loader and libc must read these to start any program
// (ld.so.cache/preload/conf, and the standard system library + binary trees the
// loader resolves through). This mirrors the established system-readonly path
// set and the ptrace enforcer's effective behavior (#369). Matching is
// exact-or-subtree, so "/lib" covers both the bare directory open the loader
// performs during search-path resolution and every file beneath it. Note: /opt
// is intentionally excluded — the loader never searches it, and some policies
// (e.g. agent-sandbox) deliberately do not grant it system-read.
var loaderSafeReadPrefixes = []string{
	"/usr", "/lib", "/lib64", "/lib32", "/libx32", "/bin", "/sbin",
	"/etc/ld.so.cache", "/etc/ld.so.preload", "/etc/ld.so.conf", "/etc/ld.so.conf.d",
}

// systemDirNodeReads are the bare KERNEL / PROCESS directory nodes whose
// read-only stat/open every dynamically-linked program performs at startup
// (the shell walking `/`, libc consulting `/proc/self`, programs touching
// `/dev`, `/etc`). In a deny-by-default policy, allow rules typically write
// `"/etc/ssl/**"` style globs that match contents but not the bare node, so
// the node's `openat(O_DIRECTORY)` or `stat` falls to the catch-all (or to a
// broad `deny-proc-sys`-style explicit rule) and is denied — preventing the
// program from starting. The override is EXACT match only, so reads of
// CONTENTS (e.g., `/etc/secret`, `/proc/self/maps`) remain policy-controlled.
//
// Unlike loaderSafeReadPrefixes, this set overrides ANY deny rule for these
// specific bare nodes — they are universally read-safe (the kernel/libc
// invariants every program relies on), the ptrace enforcer already allows
// them, and operator deny rules over these paths are aimed at the CONTENTS
// (which exact-match preserves).
//
// Deliberately NARROW: this list is kernel/process essentials only. Paths
// that are sometimes-but-not-universally needed (`/tmp`, `/var`, `/run`,
// `/etc/ssl`, `/etc/ssl/certs`, `/etc/ca-certificates`) intentionally fall
// to policy — an operator who denies them clearly means it, and a policy
// that needs them should add an explicit allow rule (matching what
// shipped deny-by-default policies will eventually carry).
var systemDirNodeReads = map[string]bool{
	"/":                 true,
	"/dev":              true,
	"/dev/pts":          true,
	"/dev/fd":           true,
	"/proc":             true,
	"/proc/self":        true,
	"/proc/thread-self": true,
	"/sys":              true,
	"/etc":              true,
}

// isSystemDirNode reports whether p is exactly one of the bare system directory
// nodes whose read-only stat/open must always succeed (exact match only).
func isSystemDirNode(p string) bool { return systemDirNodeReads[p] }

// defaultDenyRuleNames are the catch-all "deny everything not explicitly
// allowed" rule names. The loader-safe override fires only when a loader read
// was denied by one of these — never by an operator's explicit deny rule
// targeting a specific path, which must still be honored (matching the ptrace
// enforcer's first-match-explicit-deny semantics). "default-deny-files" is both
// the shipped policies' catch-all rule name and the engine's no-match fallback.
var defaultDenyRuleNames = map[string]bool{
	"default-deny-files": true,
}

// isDefaultDenyRule reports whether a deny decision came from a catch-all
// default rule rather than an explicit, path-specific operator deny.
func isDefaultDenyRule(rule string) bool { return defaultDenyRuleNames[rule] }

// isLoaderSafeSystemPath reports whether p is one of the loader-essential system
// paths (exact match or a subtree element).
func isLoaderSafeSystemPath(p string) bool {
	for _, pre := range loaderSafeReadPrefixes {
		if p == pre || strings.HasPrefix(p, pre+"/") {
			return true
		}
	}
	return false
}
