package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

const (
	maxPiProtocolEventTypePrefixBytes = 4 * 1024
	maxPiProtocolRelevantLineBytes    = 4 * 1024 * 1024
	maxPiProtocolDiagnostics          = 8
)

var piProtocolEventTypePattern = regexp.MustCompile(`"type"\s*:\s*"([^"\\]+)"`)

type piProtocolState struct {
	final            string
	sawAssistantEnd  bool
	sawAgentSettled  bool
	stopReason       string
	errorMessage     string
	compactionFailed bool
	compactionError  string
}

// piProtocolReducer incrementally reduces Pi's verbose JSON event stream to
// the small amount of state needed to classify a child result. Aggregate and
// progress events are discarded as soon as their type is known, so a large
// agent_end event cannot evict an earlier final message.
type piProtocolReducer struct {
	state       piProtocolState
	line        []byte
	lineBytes   int64
	eventType   string
	discardLine bool
	finished    bool
	diagnostics []subagentProtocolDiagnostic
}

func newPiProtocolReducer() *piProtocolReducer {
	return &piProtocolReducer{}
}

func (r *piProtocolReducer) Write(p []byte) (int, error) {
	originalLen := len(p)
	if r.finished {
		return originalLen, nil
	}
	for len(p) > 0 {
		newline := bytes.IndexByte(p, '\n')
		if newline < 0 {
			r.appendLinePart(p)
			break
		}
		r.appendLinePart(p[:newline])
		r.finishLine()
		p = p[newline+1:]
	}
	return originalLen, nil
}

func (r *piProtocolReducer) appendLinePart(part []byte) {
	r.lineBytes += int64(len(part))
	if r.discardLine || len(part) == 0 {
		return
	}

	if r.eventType == "" {
		remainingPrefix := maxPiProtocolEventTypePrefixBytes - len(r.line)
		if remainingPrefix > 0 {
			keep := len(part)
			if keep > remainingPrefix {
				keep = remainingPrefix
			}
			r.line = append(r.line, part[:keep]...)
			part = part[keep:]
		}
		r.eventType = piProtocolEventType(r.line)
		if r.eventType != "" && !piProtocolRelevantEvent(r.eventType) {
			r.discardLine = true
			r.line = nil
			return
		}
		if r.eventType == "" && len(r.line) >= maxPiProtocolEventTypePrefixBytes {
			r.recordDiagnostic(subagentProtocolDiagnostic{Kind: "missing_event_type", Bytes: r.lineBytes})
			r.discardLine = true
			r.line = nil
			return
		}
	}

	if len(part) == 0 {
		return
	}
	if len(r.line)+len(part) > maxPiProtocolRelevantLineBytes {
		r.recordDiagnostic(subagentProtocolDiagnostic{Kind: "oversized_line", Event: r.eventType, Bytes: r.lineBytes})
		r.discardLine = true
		r.line = nil
		return
	}
	r.line = append(r.line, part...)
}

func (r *piProtocolReducer) finishLine() {
	defer r.resetLine()
	if r.discardLine || len(bytes.TrimSpace(r.line)) == 0 {
		return
	}

	var event map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(r.line), &event); err != nil {
		r.recordDiagnostic(subagentProtocolDiagnostic{Kind: "malformed_line", Event: r.eventType, Bytes: r.lineBytes})
		return
	}
	eventType, _ := event["type"].(string)
	if !piProtocolRelevantEvent(eventType) {
		return
	}
	r.applyEvent(eventType, event)
}

func (r *piProtocolReducer) resetLine() {
	r.line = nil
	r.lineBytes = 0
	r.eventType = ""
	r.discardLine = false
}

func (r *piProtocolReducer) applyEvent(eventType string, event map[string]any) {
	switch eventType {
	case "agent_settled":
		r.state.sawAgentSettled = true
	case "compaction_end":
		aborted, _ := event["aborted"].(bool)
		willRetry, _ := event["willRetry"].(bool)
		r.state.compactionFailed = aborted && !willRetry
		r.state.compactionError = ""
		if message, _ := event["errorMessage"].(string); message != "" {
			r.state.compactionError = sanitizeSubagentDiagnostic(message)
		}
	case "message_end":
		message, _ := event["message"].(map[string]any)
		if message == nil {
			return
		}
		if role, _ := message["role"].(string); role != "assistant" {
			return
		}
		r.state.sawAssistantEnd = true
		r.state.final = strings.TrimSpace(piMessageContentText(message["content"]))
		r.state.stopReason, _ = message["stopReason"].(string)
		r.state.errorMessage = ""
		if value, _ := message["errorMessage"].(string); value != "" {
			r.state.errorMessage = sanitizeSubagentDiagnostic(value)
		}
		// A successful assistant turn after a failed compaction means Pi
		// recovered and continued the run.
		if !piStopReasonFailed(r.state.stopReason, r.state.errorMessage) {
			r.state.compactionFailed = false
			r.state.compactionError = ""
		}
	}
}

func (r *piProtocolReducer) finish() {
	if r.finished {
		return
	}
	r.finished = true
	if r.lineBytes > 0 || len(r.line) > 0 || r.discardLine {
		r.finishLine()
	}
}

func (r *piProtocolReducer) outcome() subagentProtocolOutcome {
	r.finish()
	return piProtocolOutcome(r.state, r.diagnostics)
}

func (r *piProtocolReducer) recordDiagnostic(diagnostic subagentProtocolDiagnostic) {
	r.diagnostics = append(r.diagnostics, diagnostic)
	if len(r.diagnostics) > maxPiProtocolDiagnostics {
		r.diagnostics = r.diagnostics[len(r.diagnostics)-maxPiProtocolDiagnostics:]
	}
}

func piProtocolEventType(prefix []byte) string {
	match := piProtocolEventTypePattern.FindSubmatch(prefix)
	if len(match) != 2 {
		return ""
	}
	return string(match[1])
}

func piProtocolRelevantEvent(eventType string) bool {
	switch eventType {
	case "message_end", "compaction_end", "agent_settled":
		return true
	default:
		return false
	}
}

func parsePiSubagentProtocol(stdout string) subagentProtocolOutcome {
	reducer := newPiProtocolReducer()
	_, _ = reducer.Write([]byte(stdout))
	return reducer.outcome()
}

func piProtocolOutcome(state piProtocolState, diagnostics []subagentProtocolDiagnostic) subagentProtocolOutcome {
	outcome := subagentProtocolOutcome{
		Final:       state.final,
		StopReason:  state.stopReason,
		Settled:     state.sawAgentSettled,
		Diagnostics: append([]subagentProtocolDiagnostic(nil), diagnostics...),
	}
	if state.compactionFailed {
		outcome.FailureKind = subagentFailureCompaction
		outcome.ErrorMessage = state.compactionError
		if outcome.ErrorMessage == "" {
			outcome.ErrorMessage = "child compaction aborted"
		}
		return outcome
	}
	if state.sawAssistantEnd && piStopReasonFailed(state.stopReason, state.errorMessage) {
		outcome.FailureKind = subagentFailureModel
		outcome.ErrorMessage = state.errorMessage
		if outcome.ErrorMessage == "" {
			outcome.ErrorMessage = fmt.Sprintf("child model stopped: %s", state.stopReason)
		}
		return outcome
	}
	if !state.sawAgentSettled {
		outcome.FailureKind = subagentFailureProtocol
		outcome.ErrorMessage = "child Pi stream ended before agent_settled"
		return outcome
	}
	if !state.sawAssistantEnd {
		outcome.FailureKind = subagentFailureProtocol
		outcome.ErrorMessage = "child Pi settled without a completed assistant message"
		return outcome
	}
	if piStopReasonToolUse(state.stopReason) {
		outcome.FailureKind = subagentFailureProtocol
		outcome.ErrorMessage = "child Pi settled after a tool-use turn without a final assistant response"
		return outcome
	}
	if state.final == "" {
		outcome.FailureKind = subagentFailureProtocol
		outcome.ErrorMessage = "child Pi settled without visible final assistant text"
		return outcome
	}
	outcome.Completed = true
	return outcome
}

func parsePiJSONFinal(stdout string) string {
	return parsePiSubagentProtocol(stdout).Final
}

func piStopReasonFailed(stopReason, errorMessage string) bool {
	if errorMessage != "" {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(stopReason)) {
	case "error", "aborted", "cancelled", "canceled":
		return true
	default:
		return false
	}
}

func piStopReasonToolUse(stopReason string) bool {
	normalized := strings.ToLower(strings.NewReplacer("_", "", "-", "").Replace(strings.TrimSpace(stopReason)))
	return normalized == "tooluse"
}

func piMessageContentText(content any) string {
	switch value := content.(type) {
	case string:
		return value
	case []any:
		parts := make([]string, 0, len(value))
		for _, item := range value {
			if object, ok := item.(map[string]any); ok {
				if blockType, _ := object["type"].(string); blockType == "text" || blockType == "text_delta" || blockType == "markdown" {
					if text, _ := object["text"].(string); text != "" {
						parts = append(parts, text)
					}
				}
			}
		}
		return strings.Join(parts, "")
	default:
		return ""
	}
}
