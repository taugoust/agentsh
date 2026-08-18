//go:build linux && cgo

package unix

import (
	"context"
	"errors"
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

// FilePolicyChecker evaluates raw file policy and any already-cached approval
// scope. CheckFile must not create or wait for an approval.
type FilePolicyChecker interface {
	CheckFile(ctx context.Context, path, operation string) FilePolicyDecision
}

// FileApprovalResolver performs the blocking half of an unresolved file
// approval. Implementations must atomically recheck the prepared scope and
// register a pending request when the cache still misses. Context cancellation
// must be returned so notification-liveness callers can stop the pipeline.
type FileApprovalResolver interface {
	ResolveFileApproval(ctx context.Context, target, operation string, decision FilePolicyDecision) (FilePolicyDecision, error)
}

// FileApprovalCacheOutcome records what the nonblocking scoped-cache check did.
type FileApprovalCacheOutcome string

const (
	FileApprovalCacheNotApplicable FileApprovalCacheOutcome = "not_applicable"
	FileApprovalCacheMiss          FileApprovalCacheOutcome = "miss"
	FileApprovalCacheAllow         FileApprovalCacheOutcome = "allow"
	FileApprovalCacheDeny          FileApprovalCacheOutcome = "deny"
	FileApprovalCacheUnsupported   FileApprovalCacheOutcome = "unsupported"
)

// FilePolicyDecision represents raw policy plus a nonblocking scoped-cache
// outcome. Decision always remains the raw policy decision; only
// EffectiveDecision reflects a cache hit or unsupported approval scope.
type FilePolicyDecision struct {
	Decision          string
	EffectiveDecision string
	Rule              string
	Message           string
	CacheOutcome      FileApprovalCacheOutcome

	// ApprovalScopeKey and ApprovalCommandID bind ResolveFileApproval to the
	// exact cache lookup performed during Prepare.
	ApprovalScopeKey  string
	ApprovalCommandID string
}

// FilePolicyAttribution identifies the independent path obligation represented
// by a policy decision.
type FilePolicyAttribution string

const (
	FilePolicyVisiblePath             FilePolicyAttribution = "visible_path"
	FilePolicySecondPath              FilePolicyAttribution = "second_path"
	FilePolicyCompositionSource       FilePolicyAttribution = "composition_source"
	FilePolicyCompositionSourceSecond FilePolicyAttribution = "composition_source_second_path"
)

// FilePolicyObligation is one independent visible or composition-source policy
// requirement. FilePolicyDecision is embedded so callers can inspect the raw
// decision, rule/message, and cache outcome without losing path attribution.
type FilePolicyObligation struct {
	FilePolicyDecision
	Target             string
	Operation          string
	Attribution        FilePolicyAttribution
	Secondary          bool
	CompositionSource  bool
	LoaderSafeOverride bool
	ResolutionError    string
}

// PreparedFileDecision is the nonblocking result of FileHandler.Prepare.
// Obligations are kept in stable primary, secondary, source, source-secondary
// order. Private terminal state is consumed by Resolve and keeps Handle fully
// backward compatible.
type PreparedFileDecision struct {
	Request     FileRequest
	Obligations []FilePolicyObligation

	terminal      bool
	result        FileResult
	blocked       bool
	shadowDeny    bool
	emitEvent     bool
	eventDecision FilePolicyDecision
}

// HasUnresolvedApprovals reports whether Resolve has blocking approval work.
func (p PreparedFileDecision) HasUnresolvedApprovals() bool {
	if p.terminal {
		return false
	}
	for _, obligation := range p.Obligations {
		if !obligation.LoaderSafeOverride && fileDecisionNeedsApproval(obligation.FilePolicyDecision) {
			return true
		}
	}
	return false
}

// FileRequest holds the parsed context for a file syscall notification.
type FileRequest struct {
	PID                       int
	Syscall                   int32
	Path                      string
	Path2                     string // second path for rename/link
	SourcePath                string // composition-attributed original source path
	SourcePath2               string
	CompositionFreshWritable  bool // path is backed by a broker-created writable tmpfs
	CompositionFreshWritable2 bool
	Operation                 string
	Flags                     uint32
	Mode                      uint32
	Lookup                    *FileLookupRequest // exact raw lookup context; nil for synthetic/test requests
	SessionID                 string
}

// FileResult holds the outcome of handling a file syscall.
type FileResult struct {
	Action string // ActionContinue or ActionDeny
	Errno  int32
}

// FileHandler processes file syscall notifications against policy.
type FileHandler struct {
	policy              FilePolicyChecker
	approvalResolver    FileApprovalResolver
	fileLookupProbe     FileLookupProbe
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
	h := &FileHandler{
		policy:   policy,
		registry: registry,
		emitter:  emitter,
		enforce:  enforce,
	}
	if resolver, ok := policy.(FileApprovalResolver); ok {
		h.approvalResolver = resolver
	}
	return h
}

// SetApprovalResolver overrides the resolver inferred from the policy checker.
// It is primarily useful for adapters and deterministic tests.
func (h *FileHandler) SetApprovalResolver(resolver FileApprovalResolver) {
	if h != nil {
		h.approvalResolver = resolver
	}
}

// SetFileLookupProbe hands the session's tracee-lineage lookup capability to
// the file handler. Phase 4 deliberately does not consult it from Prepare or
// Resolve; phase 5 will add the notification-liveness decision pipeline.
func (h *FileHandler) SetFileLookupProbe(probe FileLookupProbe) {
	if h != nil {
		h.fileLookupProbe = probe
	}
}

// FileLookupProbe returns the currently bound probe capability, if any.
func (h *FileHandler) FileLookupProbe() FileLookupProbe {
	if h == nil {
		return nil
	}
	return h.fileLookupProbe
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

// Handle remains the compatibility entry point. New notification pipelines can
// call Prepare, inspect unresolved obligations, and then call Resolve.
func (h *FileHandler) Handle(ctx context.Context, req FileRequest) (FileResult, *types.Event) {
	prepared := h.Prepare(ctx, req)
	result, event, _ := h.Resolve(ctx, prepared)
	return result, event
}

// Prepare performs all nonblocking file-policy work. It normalizes visible
// paths, resolves composition attribution, applies delegation/loader guards,
// and records cache outcomes without ever creating an approval.
func (h *FileHandler) Prepare(ctx context.Context, req FileRequest) PreparedFileDecision {
	if ctx == nil {
		ctx = context.Background()
	}

	// Pseudo-paths resolve from proc fds for non-filesystem objects and cannot
	// participate in path policy.
	if req.Path != "" && !strings.HasPrefix(req.Path, "/") {
		return terminalPreparedFileDecision(req, nil, FileResult{Action: ActionContinue}, false, false, false)
	}

	if h == nil || h.policy == nil {
		dec := FilePolicyDecision{
			Decision:          "allow",
			EffectiveDecision: "allow",
			Rule:              "no_policy",
			CacheOutcome:      FileApprovalCacheNotApplicable,
		}
		obligations := []FilePolicyObligation{newFilePolicyObligation(req.Path, req.Operation, FilePolicyVisiblePath, dec)}
		return terminalPreparedFileDecision(req, obligations, FileResult{Action: ActionContinue}, false, false, true)
	}

	// Normalize fd aliases before either visible or composition-source policy is
	// evaluated. Both endpoints of dual-path operations remain independent.
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
			CacheOutcome:      FileApprovalCacheNotApplicable,
		}
		obligations := []FilePolicyObligation{newFilePolicyObligation(req.Path, req.Operation, FilePolicyVisiblePath, dec)}
		return terminalPreparedFileDecision(req, obligations, FileResult{Action: ActionContinue}, false, false, true)
	}

	compositionCovered := false
	if h.compositionPaths != nil {
		resolution, err := h.compositionPaths.ResolveDetails(req.PID, req.Path)
		if err != nil {
			return h.compositionAttributionFailure(req, err)
		}
		compositionCovered = resolution.Covered
		req.CompositionFreshWritable = resolution.FreshWritable
		if resolution.Covered && resolution.Path != "" && resolution.Path != req.Path {
			req.SourcePath = resolution.Path
		}
		if req.Path2 != "" {
			resolution2, err := h.compositionPaths.ResolveDetails(req.PID, req.Path2)
			if err != nil {
				return h.compositionAttributionFailure(req, err)
			}
			compositionCovered = compositionCovered || resolution2.Covered
			req.CompositionFreshWritable2 = resolution2.FreshWritable
			if resolution2.Covered && resolution2.Path != "" && resolution2.Path != req.Path2 {
				req.SourcePath2 = resolution2.Path
			}
		}
	}

	// FUSE owns enforcement only for an actual resolved mount path. A raw cache
	// check is safe for audit attribution, but an approval must never be created.
	if !compositionCovered && h.registry != nil && h.registry.IsUnderFUSEMount(req.SessionID, req.Path) {
		obligations := []FilePolicyObligation{
			newFilePolicyObligation(req.Path, req.Operation, FilePolicyVisiblePath, h.preparePolicyDecision(ctx, req.Path, req.Operation)),
		}
		if req.Path2 != "" {
			obligations = append(obligations, newFilePolicyObligation(
				req.Path2, req.Operation, FilePolicySecondPath, h.preparePolicyDecision(ctx, req.Path2, req.Operation),
			))
		}
		if req.SourcePath != "" {
			obligations = append(obligations, newFilePolicyObligation(
				req.SourcePath, req.Operation, FilePolicyCompositionSource, h.preparePolicyDecision(ctx, req.SourcePath, req.Operation),
			))
		}
		if req.SourcePath2 != "" {
			obligations = append(obligations, newFilePolicyObligation(
				req.SourcePath2, req.Operation, FilePolicyCompositionSourceSecond, h.preparePolicyDecision(ctx, req.SourcePath2, req.Operation),
			))
		}
		shadowDeny := false
		for _, obligation := range obligations {
			if strings.EqualFold(obligation.EffectiveDecision, "deny") {
				shadowDeny = true
				break
			}
		}
		return terminalPreparedFileDecision(
			req,
			obligations,
			FileResult{Action: ActionContinue},
			false,
			shadowDeny,
			true,
		)
	}

	freshWritableDecision := FilePolicyDecision{
		Decision:          "allow",
		EffectiveDecision: "allow",
		Rule:              "allow-composition-fresh-writable",
		Message:           "write is confined to a broker-created writable tmpfs",
		CacheOutcome:      FileApprovalCacheNotApplicable,
	}
	obligations := make([]FilePolicyObligation, 0, 4)
	primary := freshWritableDecision
	if !req.CompositionFreshWritable {
		primary = h.preparePolicyDecision(ctx, req.Path, req.Operation)
	}
	obligations = append(obligations, newFilePolicyObligation(req.Path, req.Operation, FilePolicyVisiblePath, primary))

	if req.Path2 != "" {
		secondary := freshWritableDecision
		if !req.CompositionFreshWritable2 {
			secondary = h.preparePolicyDecision(ctx, req.Path2, req.Operation)
		}
		obligations = append(obligations, newFilePolicyObligation(req.Path2, req.Operation, FilePolicySecondPath, secondary))
	}
	if req.SourcePath != "" {
		dec := h.preparePolicyDecision(ctx, req.SourcePath, req.Operation)
		obligations = append(obligations, newFilePolicyObligation(req.SourcePath, req.Operation, FilePolicyCompositionSource, dec))
	}
	if req.SourcePath2 != "" {
		dec := h.preparePolicyDecision(ctx, req.SourcePath2, req.Operation)
		obligations = append(obligations, newFilePolicyObligation(req.SourcePath2, req.Operation, FilePolicyCompositionSourceSecond, dec))
	}

	if h.enforce && isReadOnlyFileOp(req.Syscall, req.Flags) {
		for i := range obligations {
			obligation := &obligations[i]
			if obligation.CompositionSource || strings.EqualFold(obligation.EffectiveDecision, "allow") {
				continue
			}
			systemNode := isSystemDirNode(obligation.Target)
			loaderPath := isDefaultDenyRule(obligation.Rule) && isLoaderSafeSystemPath(obligation.Target)
			if !systemNode && !loaderPath {
				continue
			}
			obligation.LoaderSafeOverride = true
			message := "loader-safe read override (#369)"
			if systemNode {
				message = "system-dir-node read override (#369)"
			}
			slog.Debug("file_monitor: "+message,
				"path", obligation.Target,
				"operation", obligation.Operation,
				"policy_rule", obligation.Rule,
				"session", req.SessionID,
			)
		}
	}

	prepared := PreparedFileDecision{
		Request:     req,
		Obligations: obligations,
		emitEvent:   true,
	}
	activeRestriction := false
	finalRestriction := false
	unresolvedApproval := false
	loaderOverride := false
	for _, obligation := range obligations {
		if obligation.LoaderSafeOverride {
			loaderOverride = true
			continue
		}
		if strings.EqualFold(obligation.EffectiveDecision, "allow") {
			continue
		}
		activeRestriction = true
		if fileDecisionNeedsApproval(obligation.FilePolicyDecision) {
			unresolvedApproval = true
		} else {
			finalRestriction = true
		}
	}
	prepared.eventDecision = dominantFilePolicyDecision(obligations)
	prepared.shadowDeny = loaderOverride

	if !h.enforce && activeRestriction {
		prepared.terminal = true
		prepared.result = FileResult{Action: ActionContinue}
		return prepared
	}
	if finalRestriction {
		// Explicit and cached denials dominate unresolved approvals. Do not
		// create prompts for an operation that cannot proceed.
		prepared.shadowDeny = false
		prepared.terminal = true
		prepared.result = FileResult{Action: ActionDeny, Errno: int32(sysunix.EACCES)}
		prepared.blocked = true
		return prepared
	}
	if unresolvedApproval {
		return prepared
	}

	prepared.terminal = true
	prepared.result = FileResult{Action: ActionContinue}
	prepared.shadowDeny = loaderOverride
	return prepared
}

// Resolve requests every still-unresolved obligation. A denial on any one is
// dominant, but the remaining independent obligations are still resolved while
// the context remains live. Cancellation stops the sequence immediately so no
// later approval can be enqueued after liveness is lost, and the first resolver
// or context error is returned for the notification pipeline to act on.
func (h *FileHandler) Resolve(ctx context.Context, prepared PreparedFileDecision) (FileResult, *types.Event, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if prepared.terminal {
		return prepared.result, h.preparedFileEvent(prepared), nil
	}

	prepared.Obligations = append([]FilePolicyObligation(nil), prepared.Obligations...)
	resolutionFailed := false
	var resolutionErr error
	for i := range prepared.Obligations {
		obligation := &prepared.Obligations[i]
		if obligation.LoaderSafeOverride || !fileDecisionNeedsApproval(obligation.FilePolicyDecision) {
			continue
		}
		if err := ctx.Err(); err != nil {
			obligation.EffectiveDecision = "deny"
			obligation.ResolutionError = err.Error()
			resolutionFailed = true
			resolutionErr = err
			break
		}
		if h == nil || h.approvalResolver == nil {
			obligation.EffectiveDecision = "deny"
			obligation.CacheOutcome = FileApprovalCacheUnsupported
			resolutionFailed = true
			continue
		}

		resolved, err := h.approvalResolver.ResolveFileApproval(ctx, obligation.Target, obligation.Operation, obligation.FilePolicyDecision)
		// Raw policy attribution is immutable across resolution. The resolver is
		// responsible only for the effective result and (optionally) a newer
		// atomic cache outcome.
		obligation.EffectiveDecision = resolved.EffectiveDecision
		if resolved.CacheOutcome != "" {
			obligation.CacheOutcome = resolved.CacheOutcome
		}
		if err != nil {
			obligation.ResolutionError = err.Error()
			if resolutionErr == nil {
				resolutionErr = err
			}
		}
		if !strings.EqualFold(obligation.EffectiveDecision, "allow") || err != nil {
			obligation.EffectiveDecision = "deny"
			resolutionFailed = true
		}
		if err != nil && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
			break
		}
		// A resolver can win just before notification liveness is lost. Recheck
		// the caller's context before any later obligation or successful return;
		// phase 5 will drive this context from notification-ID validation.
		if err := ctx.Err(); err != nil {
			obligation.EffectiveDecision = "deny"
			obligation.ResolutionError = err.Error()
			resolutionFailed = true
			resolutionErr = err
			break
		}
	}

	prepared.eventDecision = dominantFilePolicyDecision(prepared.Obligations)
	if resolutionFailed {
		prepared.result = FileResult{Action: ActionDeny, Errno: int32(sysunix.EACCES)}
		prepared.blocked = true
		prepared.shadowDeny = false
	} else {
		prepared.result = FileResult{Action: ActionContinue}
	}
	prepared.terminal = true
	return prepared.result, h.preparedFileEvent(prepared), resolutionErr
}

func (h *FileHandler) preparePolicyDecision(ctx context.Context, target, operation string) FilePolicyDecision {
	dec := h.policy.CheckFile(ctx, target, operation)
	if dec.CacheOutcome == "" {
		if fileDecisionNeedsApproval(dec) {
			dec.CacheOutcome = FileApprovalCacheMiss
		} else {
			dec.CacheOutcome = FileApprovalCacheNotApplicable
		}
	}
	if fileDecisionNeedsApproval(dec) && h.approvalResolver == nil {
		dec.EffectiveDecision = "deny"
		dec.CacheOutcome = FileApprovalCacheUnsupported
	}
	return dec
}

func (h *FileHandler) compositionAttributionFailure(req FileRequest, err error) PreparedFileDecision {
	dec := FilePolicyDecision{
		Decision:          "deny",
		EffectiveDecision: "deny",
		Rule:              "composition-source-attribution",
		Message:           "composition source attribution failed: " + err.Error(),
		CacheOutcome:      FileApprovalCacheNotApplicable,
	}
	obligations := []FilePolicyObligation{newFilePolicyObligation(req.Path, req.Operation, FilePolicyVisiblePath, dec)}
	return terminalPreparedFileDecision(
		req,
		obligations,
		FileResult{Action: ActionDeny, Errno: int32(sysunix.EACCES)},
		true,
		false,
		true,
	)
}

func terminalPreparedFileDecision(req FileRequest, obligations []FilePolicyObligation, result FileResult, blocked, shadowDeny, emitEvent bool) PreparedFileDecision {
	return PreparedFileDecision{
		Request:       req,
		Obligations:   obligations,
		terminal:      true,
		result:        result,
		blocked:       blocked,
		shadowDeny:    shadowDeny,
		emitEvent:     emitEvent,
		eventDecision: dominantFilePolicyDecision(obligations),
	}
}

func newFilePolicyObligation(target, operation string, attribution FilePolicyAttribution, dec FilePolicyDecision) FilePolicyObligation {
	return FilePolicyObligation{
		FilePolicyDecision: dec,
		Target:             target,
		Operation:          operation,
		Attribution:        attribution,
		Secondary:          attribution == FilePolicySecondPath || attribution == FilePolicyCompositionSourceSecond,
		CompositionSource:  attribution == FilePolicyCompositionSource || attribution == FilePolicyCompositionSourceSecond,
	}
}

func fileDecisionNeedsApproval(dec FilePolicyDecision) bool {
	return strings.EqualFold(dec.Decision, "approve") && strings.EqualFold(dec.EffectiveDecision, "approve")
}

func dominantFilePolicyDecision(obligations []FilePolicyObligation) FilePolicyDecision {
	if len(obligations) == 0 {
		return FilePolicyDecision{}
	}
	selected := obligations[0].FilePolicyDecision
	selectedRank := fileObligationRank(obligations[0])
	for _, obligation := range obligations[1:] {
		if rank := fileObligationRank(obligation); rank > selectedRank {
			selected = obligation.FilePolicyDecision
			selectedRank = rank
		}
	}
	return selected
}

func fileObligationRank(obligation FilePolicyObligation) int {
	if obligation.LoaderSafeOverride && !strings.EqualFold(obligation.EffectiveDecision, "allow") {
		return 2
	}
	if strings.EqualFold(obligation.EffectiveDecision, "deny") {
		return 5
	}
	if fileDecisionNeedsApproval(obligation.FilePolicyDecision) {
		return 4
	}
	if !strings.EqualFold(obligation.EffectiveDecision, "allow") {
		return 3
	}
	return 1
}

func (h *FileHandler) preparedFileEvent(prepared PreparedFileDecision) *types.Event {
	if !prepared.emitEvent || h == nil {
		return nil
	}
	event := h.buildFileEvent(prepared.Request, prepared.eventDecision, prepared.blocked, prepared.shadowDeny)
	if event != nil && len(prepared.Obligations) > 0 {
		event.Fields["policy_obligations"] = filePolicyObligationAuditFields(prepared.Obligations)
	}
	return event
}

func filePolicyObligationAuditFields(obligations []FilePolicyObligation) []map[string]any {
	fields := make([]map[string]any, 0, len(obligations))
	for _, obligation := range obligations {
		entry := map[string]any{
			"target":             obligation.Target,
			"operation":          obligation.Operation,
			"attribution":        string(obligation.Attribution),
			"decision":           obligation.Decision,
			"effective_decision": obligation.EffectiveDecision,
			"rule":               obligation.Rule,
			"message":            obligation.Message,
			"cache_outcome":      string(obligation.CacheOutcome),
			"secondary":          obligation.Secondary,
			"composition_source": obligation.CompositionSource,
		}
		if obligation.LoaderSafeOverride {
			entry["loader_safe_override"] = true
		}
		if obligation.ResolutionError != "" {
			entry["resolution_error"] = obligation.ResolutionError
		}
		if obligation.ApprovalScopeKey != "" {
			entry["approval_scope_key"] = obligation.ApprovalScopeKey
		}
		if obligation.ApprovalCommandID != "" {
			entry["approval_command_id"] = obligation.ApprovalCommandID
		}
		fields = append(fields, entry)
	}
	return fields
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
	if req.CompositionFreshWritable {
		fields["composition_fresh_writable"] = true
	}
	if req.CompositionFreshWritable2 {
		fields["composition_fresh_writable2"] = true
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
