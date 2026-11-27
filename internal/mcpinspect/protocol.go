// internal/mcpinspect/protocol.go
package mcpinspect

import (
	"encoding/json"
)

// ToolDefinition represents an MCP tool from tools/list response.
type ToolDefinition struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"inputSchema,omitempty"`
}

// ToolsListResponse is the JSON-RPC response to tools/list.
type ToolsListResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  struct {
		Tools []ToolDefinition `json:"tools"`
	} `json:"result"`
}

// ToolsCallRequest is the JSON-RPC request for tools/call.
type ToolsCallRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"` // "tools/call"
	Params  struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	} `json:"params"`
}

// ContentBlock represents a content block in an MCP tool result.
type ContentBlock struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}

// ToolsCallResponse is the JSON-RPC response to tools/call.
type ToolsCallResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  struct {
		Content []ContentBlock `json:"content"`
	} `json:"result"`
}

// SamplingCreateMessageRequest is the JSON-RPC request for sampling/createMessage.
type SamplingCreateMessageRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"` // "sampling/createMessage"
	Params  struct {
		Messages         []SamplingMessage `json:"messages"`
		ModelPreferences *struct {
			Hints []struct {
				Name string `json:"name"`
			} `json:"hints"`
		} `json:"modelPreferences,omitempty"`
		MaxTokens int `json:"maxTokens"`
	} `json:"params"`
}

// SamplingMessage represents a message in a sampling/createMessage request.
type SamplingMessage struct {
	Role    string `json:"role"`
	Content struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
}

// MessageType identifies the type of MCP message.
type MessageType int

const (
	MessageUnknown MessageType = iota
	MessageToolsList
	MessageToolsListResponse
	MessageToolsCall
	MessageToolsCallResponse
	MessageSamplingRequest
	MessageToolsListChanged
)

// String returns the string representation of MessageType.
func (m MessageType) String() string {
	switch m {
	case MessageToolsList:
		return "tools/list"
	case MessageToolsListResponse:
		return "tools/list_response"
	case MessageToolsCall:
		return "tools/call"
	case MessageToolsCallResponse:
		return "tools/call_response"
	case MessageSamplingRequest:
		return "sampling/createMessage"
	case MessageToolsListChanged:
		return "notifications/tools/list_changed"
	default:
		return "unknown"
	}
}
