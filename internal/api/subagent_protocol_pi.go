package api

import (
	"encoding/json"
	"fmt"
	"strings"
)

type piProtocolState struct {
	final            string
	sawAssistantEnd  bool
	stopReason       string
	errorMessage     string
	compactionFailed bool
	compactionError  string
}

func parsePiSubagentProtocol(stdout string) subagentProtocolOutcome {
	state := parsePiProtocolState(stdout)
	outcome := subagentProtocolOutcome{
		Final:      state.final,
		StopReason: state.stopReason,
	}
	if state.sawAssistantEnd {
		if piStopReasonFailed(state.stopReason, state.errorMessage) {
			outcome.FailureKind = subagentFailureModel
			outcome.ErrorMessage = state.errorMessage
			if outcome.ErrorMessage == "" {
				outcome.ErrorMessage = fmt.Sprintf("child model stopped: %s", state.stopReason)
			}
			return outcome
		}
		outcome.Completed = true
		return outcome
	}
	if state.compactionFailed {
		outcome.FailureKind = subagentFailureCompaction
		outcome.ErrorMessage = state.compactionError
		if outcome.ErrorMessage == "" {
			outcome.ErrorMessage = "child compaction aborted"
		}
		return outcome
	}
	outcome.FailureKind = subagentFailureProtocol
	outcome.ErrorMessage = "child Pi stream ended without a completed assistant message"
	return outcome
}

func parsePiJSONFinal(stdout string) string {
	return parsePiSubagentProtocol(stdout).Final
}

func parsePiProtocolState(stdout string) piProtocolState {
	var state piProtocolState
	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var event map[string]any
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			continue
		}
		eventType, _ := event["type"].(string)
		if eventType == "compaction_end" {
			aborted, _ := event["aborted"].(bool)
			willRetry, _ := event["willRetry"].(bool)
			state.compactionFailed = aborted && !willRetry
			state.compactionError = ""
			if message, _ := event["errorMessage"].(string); message != "" {
				state.compactionError = sanitizeSubagentDiagnostic(message)
			}
			continue
		}
		if eventType != "message_end" && eventType != "message_update" && eventType != "message_start" {
			continue
		}
		message, _ := event["message"].(map[string]any)
		if message == nil {
			continue
		}
		if role, _ := message["role"].(string); role != "assistant" {
			continue
		}
		if text := piMessageContentText(message["content"]); text != "" {
			state.final = text
		}
		if eventType == "message_end" {
			state.sawAssistantEnd = true
			state.stopReason, _ = message["stopReason"].(string)
			state.errorMessage = ""
			if value, _ := message["errorMessage"].(string); value != "" {
				state.errorMessage = sanitizeSubagentDiagnostic(value)
			}
		}
	}
	state.final = strings.TrimSpace(state.final)
	return state
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
