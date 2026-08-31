package permissiongate

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	maxAuditBytes          int64 = 8 * 1024 * 1024
	maxAuditRecordBytes          = 16 * 1024
	maxAuditCommandPreview       = 4 * 1024
	maxAuditReasonBytes          = 512
)

// AuditRecord is the bounded local record written for each terminal gate
// decision. ExecutionObserved is always false: guard-only AgentSH authorizes
// intent but does not sandbox or observe the native Bash process.
type AuditRecord struct {
	Timestamp         time.Time `json:"timestamp"`
	Type              string    `json:"type"`
	RunID             string    `json:"run_id"`
	RequestID         string    `json:"request_id"`
	ToolCallID        string    `json:"tool_call_id,omitempty"`
	SessionID         string    `json:"session_id,omitempty"`
	GuardMode         string    `json:"guard_mode"`
	Kind              string    `json:"kind"`
	CWD               string    `json:"cwd,omitempty"`
	CommandSHA256     string    `json:"command_sha256"`
	CommandPreview    string    `json:"command_preview"`
	CommandTruncated  bool      `json:"command_truncated,omitempty"`
	Labels            []string  `json:"labels,omitempty"`
	Decision          string    `json:"decision"`
	Reason            string    `json:"reason,omitempty"`
	ExecutionObserved bool      `json:"execution_observed"`
}

// AuditAppender is the broker's synchronous fail-closed audit dependency.
type AuditAppender interface {
	Append(AuditRecord) error
}

// AuditLog owns one private, bounded JSONL file for a gate run.
type AuditLog struct {
	mu      sync.Mutex
	file    *os.File
	path    string
	written int64
	sticky  error
}

// OpenAuditLog creates a new mode-0600 audit file. An existing file is never
// followed or appended to, which avoids symlink and cross-run confusion.
func OpenAuditLog(path string) (*AuditLog, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("audit path is required")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve audit path: %w", err)
	}
	parent := filepath.Dir(absolute)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return nil, fmt.Errorf("create audit directory: %w", err)
	}
	file, err := os.OpenFile(absolute, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create audit log: %w", err)
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("secure audit log: %w", err)
	}
	return &AuditLog{file: file, path: absolute}, nil
}

// Path returns the absolute audit path.
func (l *AuditLog) Path() string {
	if l == nil {
		return ""
	}
	return l.path
}

// Append writes and synchronizes one bounded JSONL record. Any failure is
// sticky: later calls cannot accidentally permit a command after audit loss.
func (l *AuditLog) Append(record AuditRecord) error {
	if l == nil {
		return errors.New("audit log is unavailable")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.sticky != nil {
		return l.sticky
	}
	if l.file == nil {
		l.sticky = errors.New("audit log is closed")
		return l.sticky
	}

	line, err := json.Marshal(record)
	if err != nil {
		l.sticky = fmt.Errorf("marshal audit record: %w", err)
		return l.sticky
	}
	if len(line) > maxAuditRecordBytes {
		l.sticky = fmt.Errorf("audit record exceeds %d bytes", maxAuditRecordBytes)
		return l.sticky
	}
	line = append(line, '\n')
	if l.written+int64(len(line)) > maxAuditBytes {
		l.sticky = fmt.Errorf("audit log exceeds %d bytes", maxAuditBytes)
		return l.sticky
	}
	if err := writeAll(l.file, line); err != nil {
		l.sticky = fmt.Errorf("append audit record: %w", err)
		return l.sticky
	}
	if err := l.file.Sync(); err != nil {
		l.sticky = fmt.Errorf("sync audit record: %w", err)
		return l.sticky
	}
	l.written += int64(len(line))
	return nil
}

// Close synchronizes and closes the audit file.
func (l *AuditLog) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return l.sticky
	}
	if err := l.file.Sync(); err != nil && l.sticky == nil {
		l.sticky = fmt.Errorf("sync audit log: %w", err)
	}
	if err := l.file.Close(); err != nil && l.sticky == nil {
		l.sticky = fmt.Errorf("close audit log: %w", err)
	}
	l.file = nil
	return l.sticky
}

func newAuditRecord(runID string, request AuthorizeRequest, matches []Match, decision, reason string) AuditRecord {
	labels := make([]string, 0, len(matches))
	for _, match := range matches {
		labels = append(labels, match.Label)
	}
	preview, truncated := truncateUTF8(request.Command, maxAuditCommandPreview)
	digest := sha256.Sum256([]byte(request.Command))
	return AuditRecord{
		Timestamp:         time.Now().UTC(),
		Type:              "permission_gate_authorization",
		RunID:             runID,
		RequestID:         request.ID,
		ToolCallID:        request.ToolCallID,
		SessionID:         request.SessionID,
		GuardMode:         "guard_only",
		Kind:              request.Kind,
		CWD:               request.CWD,
		CommandSHA256:     hex.EncodeToString(digest[:]),
		CommandPreview:    preview,
		CommandTruncated:  truncated,
		Labels:            labels,
		Decision:          decision,
		Reason:            truncateString(reason, maxAuditReasonBytes),
		ExecutionObserved: false,
	}
}

func defaultAuditPath() (path, runID string, err error) {
	runID, err = randomRunID()
	if err != nil {
		return "", "", err
	}
	stateHome := strings.TrimSpace(os.Getenv("XDG_STATE_HOME"))
	if stateHome == "" {
		home, homeErr := os.UserHomeDir()
		if homeErr != nil {
			return "", "", fmt.Errorf("resolve user home for permission gate audit: %w", homeErr)
		}
		stateHome = filepath.Join(home, ".local", "state")
	}
	if !filepath.IsAbs(stateHome) {
		return "", "", errors.New("XDG_STATE_HOME must be absolute")
	}
	runDir := filepath.Join(stateHome, "agentsh", "permission-gate", runID)
	if err := os.MkdirAll(runDir, 0o700); err != nil {
		return "", "", fmt.Errorf("create permission gate state directory: %w", err)
	}
	if err := os.Chmod(runDir, 0o700); err != nil {
		return "", "", fmt.Errorf("secure permission gate state directory: %w", err)
	}
	return filepath.Join(runDir, "audit.jsonl"), runID, nil
}

func randomRunID() (string, error) {
	var value [16]byte
	if _, err := io.ReadFull(rand.Reader, value[:]); err != nil {
		return "", fmt.Errorf("generate permission gate run ID: %w", err)
	}
	return hex.EncodeToString(value[:]), nil
}

func truncateUTF8(value string, maxBytes int) (string, bool) {
	if len(value) <= maxBytes {
		return value, false
	}
	cut := maxBytes
	for cut > 0 && !utf8.ValidString(value[:cut]) {
		cut--
	}
	return value[:cut], true
}

func truncateString(value string, maxBytes int) string {
	truncated, _ := truncateUTF8(value, maxBytes)
	return truncated
}

func writeAll(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := writer.Write(data)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}
