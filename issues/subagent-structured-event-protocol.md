# Define a structured AgentSH subagent event protocol

## Status
Open.

## Problem
AgentSH launches child Pi processes and infers state/final output by parsing child stdout (`text` or `pi-json`). Parent integrations should not need to scrape raw stdout for basic state, tool calls, approvals, or terminal status.

## Evidence / files inspected
- `internal/api/subagent_tool.go`: `Protocol` is only `text` or `pi-json`; final output comes from `parseSubagentFinal` / `parsePiJSONFinal` scanning stdout lines.
- `internal/api/subagent_tool.go`: stream events (`subagent_start`, `subagent_child_start`, raw `stdout`/`stderr`, `subagent_result`, `done`) are AgentSH-local and not a versioned child-runtime protocol.
- `internal/api/subagent_tool.go`: `messageContentText` parses loose `map[string]any` structures instead of typed events.

## Proposed direction
Define a versioned subagent event schema: `child_start`, `tool_start`, `tool_end`, `approval_wait`, `message_delta`, `child_result`, `done`, and `error`. Make runtimes advertise protocol/version and parse typed events before falling back to raw text.

## Rough priority
Medium.
