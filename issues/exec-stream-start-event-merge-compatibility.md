# Restore exec streaming start-event compatibility

## Status
Open.

## Problem
The four-hour timeout merge changed the transport start event from `command_started` to `start`. The merged payload also dropped `session_id` that existed on the feature side. Consumers following the integration branch can therefore lose their expected start event or required correlation metadata.

Persisted audit events remain named `command_started`, further diverging transport and audit schemas.

## Evidence / files inspected
- `internal/api/exec_stream.go`: merged SSE path emits `start`.
- `internal/api/grpc.go`: merged gRPC stream emits `start`.
- Merge commit `3a893852` first parent emitted `command_started`.
- Feature commit `d88a778f` included `session_id` in its start payload.

## Desired behavior
Define and document one versioned canonical stream-start contract while preserving compatibility for existing consumers. Command ID, session ID, and resolved timeout metadata must be consistent across SSE and gRPC.

## Acceptance criteria
- Contract tests cover the pre-merge consumer schema.
- SSE and gRPC expose the same start-event name and fields.
- Existing consumers receive a compatibility event or an explicitly versioned transition.
- Audit and transport naming differences are documented if intentionally retained.

## Rough priority
Medium.
