package mcpinspect

import (
	"encoding/json"
	"testing"
)

func TestMCPToolCalledEvent_JSON(t *testing.T) {
	event := MCPToolCalledEvent{
		Type:      "mcp_tool_called",
		SessionID: "sess-1",
		ServerID:  "srv-1",
		ToolName:  "test_tool",
		JSONRPCID: json.RawMessage(`42`),
		Input:     json.RawMessage(`{"key":"value"}`),
	}

	data, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("failed to marshal event: %v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal event JSON: %v", err)
	}

	if decoded["type"] != "mcp_tool_called" {
		t.Errorf("type = %v, want mcp_tool_called", decoded["type"])
	}
	if decoded["tool_name"] != "test_tool" {
		t.Errorf("tool_name = %v, want test_tool", decoded["tool_name"])
	}
	if decoded["jsonrpc_id"] != float64(42) {
		t.Errorf("jsonrpc_id = %v, want 42", decoded["jsonrpc_id"])
	}
}

// --- Argument scanning tests ---
