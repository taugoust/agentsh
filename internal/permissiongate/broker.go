package permissiongate

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

const (
	maxRequestsPerRun  = 4096
	maxPendingPrompts  = 64
	promptPreviewBytes = 4 * 1024
)

type readDeadlineSetter interface {
	SetReadDeadline(time.Time) error
}

type pendingPrompt struct {
	request AuthorizeRequest
	matches []Match
}

// Broker serves the inherited, process-local authorization channel. It does
// not execute Bash or apply any namespace, filesystem, or network controls.
type Broker struct {
	transport io.ReadWriter
	audit     AuditAppender
	runID     string
	seen      map[string]struct{}
	pending   map[string]pendingPrompt
	hello     bool
}

// NewBroker constructs a single-connection permission gate broker.
func NewBroker(transport io.ReadWriter, audit AuditAppender, runID string) *Broker {
	return &Broker{
		transport: transport,
		audit:     audit,
		runID:     runID,
		seen:      make(map[string]struct{}),
		pending:   make(map[string]pendingPrompt),
	}
}

// Serve handles frames until the transport closes or a protocol/audit failure
// occurs. Any returned error is fatal to a still-running launched process.
func (b *Broker) Serve() error {
	if b == nil || b.transport == nil || b.audit == nil || strings.TrimSpace(b.runID) == "" {
		return errors.New("permission gate broker is not fully configured")
	}
	reader := newFrameReader(b.transport)
	for {
		frame, err := reader.read()
		if errors.Is(err, io.EOF) {
			return ErrUnexpectedEOF
		}
		if err != nil {
			return err
		}
		request, err := decodeRequest(frame)
		if err != nil {
			return err
		}
		if err := b.handle(request); err != nil {
			return err
		}
	}
}

func (b *Broker) handle(message any) error {
	if !b.hello {
		hello, ok := message.(HelloRequest)
		if !ok {
			return fmt.Errorf("%w: first message must be hello", ErrProtocol)
		}
		return b.handleHello(hello)
	}

	switch request := message.(type) {
	case HelloRequest:
		return fmt.Errorf("%w: duplicate hello", ErrProtocol)
	case AuthorizeRequest:
		return b.handleAuthorize(request)
	case ResolveRequest:
		return b.handleResolve(request)
	case CancelRequest:
		return b.handleCancel(request)
	default:
		return fmt.Errorf("%w: unsupported request", ErrProtocol)
	}
}

func (b *Broker) handleHello(request HelloRequest) error {
	if request.Type != messageHello || request.Client != "pi-permission-gate" {
		return fmt.Errorf("%w: invalid hello client", ErrProtocol)
	}
	response := HelloResponse{
		V:            ProtocolVersion,
		Type:         messageHello,
		Service:      "agentsh-permission-gate",
		Capabilities: []string{"bash", "resolve", "cancel"},
	}
	if err := writeFrame(b.transport, response); err != nil {
		return err
	}
	if transport, ok := b.transport.(readDeadlineSetter); ok {
		if err := transport.SetReadDeadline(time.Time{}); err != nil {
			return fmt.Errorf("clear permission gate handshake deadline: %w", err)
		}
	}
	b.hello = true
	return nil
}

func (b *Broker) handleAuthorize(request AuthorizeRequest) error {
	if err := validateAuthorize(request); err != nil {
		return err
	}
	if len(b.seen) >= maxRequestsPerRun {
		return fmt.Errorf("%w: request limit exceeded", ErrProtocol)
	}
	if _, exists := b.seen[request.ID]; exists {
		return fmt.Errorf("%w: duplicate request ID %q", ErrProtocol, request.ID)
	}
	b.seen[request.ID] = struct{}{}

	matches := MatchDangerous(request.Command)
	if len(matches) == 0 {
		if err := b.audit.Append(newAuditRecord(b.runID, request, nil, "allow", "no dangerous command pattern matched")); err != nil {
			return fmt.Errorf("permission gate audit before allow: %w", err)
		}
		return writeFrame(b.transport, DecisionResponse{
			V: ProtocolVersion, Type: messageDecision, ID: request.ID, Decision: "allow",
		})
	}
	if len(b.pending) >= maxPendingPrompts {
		return fmt.Errorf("%w: too many pending prompts", ErrProtocol)
	}
	b.pending[request.ID] = pendingPrompt{request: request, matches: matches}
	labels := make([]string, 0, len(matches))
	for _, match := range matches {
		labels = append(labels, match.Label)
	}
	preview, truncated := truncateUTF8(request.Command, promptPreviewBytes)
	return writeFrame(b.transport, DecisionResponse{
		V: ProtocolVersion, Type: messageDecision, ID: request.ID, Decision: "prompt",
		Prompt: &PromptMetadata{
			Title:            "Dangerous command requires approval",
			Message:          fmt.Sprintf("Detected: %s", strings.Join(labels, ", ")),
			Labels:           labels,
			CommandPreview:   preview,
			CommandTruncated: truncated,
		},
	})
}

func (b *Broker) handleResolve(request ResolveRequest) error {
	if request.Type != messageResolve || !validID(request.ID) {
		return fmt.Errorf("%w: invalid resolution", ErrProtocol)
	}
	if request.Decision != "allow" && request.Decision != "deny" {
		return fmt.Errorf("%w: resolution decision must be allow or deny", ErrProtocol)
	}
	pending, ok := b.pending[request.ID]
	if !ok {
		return fmt.Errorf("%w: resolution has no pending prompt", ErrProtocol)
	}
	reason := "approved by Pi user interface"
	if request.Decision == "deny" {
		reason = "denied by Pi user interface"
	}
	if err := b.audit.Append(newAuditRecord(b.runID, pending.request, pending.matches, request.Decision, reason)); err != nil {
		return fmt.Errorf("permission gate audit before resolution: %w", err)
	}
	delete(b.pending, request.ID)
	return writeFrame(b.transport, CompleteResponse{
		V: ProtocolVersion, Type: messageComplete, ID: request.ID, Decision: request.Decision,
		Reason: reason,
	})
}

func (b *Broker) handleCancel(request CancelRequest) error {
	if request.Type != messageCancel || !validID(request.ID) {
		return fmt.Errorf("%w: invalid cancellation", ErrProtocol)
	}
	pending, ok := b.pending[request.ID]
	if !ok {
		return fmt.Errorf("%w: cancellation has no pending prompt", ErrProtocol)
	}
	reason := strings.TrimSpace(request.Reason)
	if reason == "" {
		reason = "tool call cancelled"
	}
	if len(reason) > maxAuditReasonBytes {
		return fmt.Errorf("%w: cancellation reason is too long", ErrProtocol)
	}
	if err := b.audit.Append(newAuditRecord(b.runID, pending.request, pending.matches, "deny", reason)); err != nil {
		return fmt.Errorf("permission gate audit before cancellation: %w", err)
	}
	delete(b.pending, request.ID)
	return writeFrame(b.transport, CompleteResponse{
		V: ProtocolVersion, Type: messageComplete, ID: request.ID, Decision: "deny", Reason: reason,
	})
}

func validateAuthorize(request AuthorizeRequest) error {
	if request.Type != messageAuthorize || request.V != ProtocolVersion {
		return fmt.Errorf("%w: invalid authorize envelope", ErrProtocol)
	}
	if !validID(request.ID) {
		return fmt.Errorf("%w: invalid authorize ID", ErrProtocol)
	}
	if request.Kind != "bash" {
		return fmt.Errorf("%w: only bash authorization is supported", ErrProtocol)
	}
	if request.Command == "" || len(request.Command) > MaxCommandBytes {
		return fmt.Errorf("%w: command must contain 1..%d bytes", ErrProtocol, MaxCommandBytes)
	}
	if len(request.CWD) > MaxCWDBytes {
		return fmt.Errorf("%w: cwd exceeds %d bytes", ErrProtocol, MaxCWDBytes)
	}
	if len(request.ToolCallID) > MaxIDBytes {
		return fmt.Errorf("%w: tool_call_id exceeds %d bytes", ErrProtocol, MaxIDBytes)
	}
	if len(request.SessionID) > MaxIDBytes {
		return fmt.Errorf("%w: session_id exceeds %d bytes", ErrProtocol, MaxIDBytes)
	}
	return nil
}

func validID(id string) bool {
	if id == "" || len(id) > MaxIDBytes {
		return false
	}
	for _, r := range id {
		if r < 0x21 || r > 0x7e {
			return false
		}
	}
	return true
}
