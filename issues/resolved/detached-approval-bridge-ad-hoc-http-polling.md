# Replace detached approval bridge ad-hoc HTTP polling

## Status
Resolved.

## Problem
Detached approval propagation uses an environment-token HTTP bridge with a localhost default, custom path escaping, and 500ms polling. This creates a second transport/protocol beside supervisor Unix forwarding and makes detached approval behavior dependent on ambient parent API reachability.

## Evidence / files inspected
- `internal/approvals/detached_bridge.go`: defaults to `http://127.0.0.1:18080`, polls every `500ms`, uses `AGENTSH_DETACHED_EVENT_TOKEN`/`AGENTSH_DETACHED_EVENT_URL`, and has a custom `pathEscape`.
- `internal/cli/supervisor_session.go`: supervisor process receives only `AGENTSH_DETACHED_EVENT_TOKEN`; URL is not derived from the parent transport here.
- `internal/api/detached_push.go`: parent stores pushed approvals/resolutions in an in-memory map.
- `internal/api/detached_supervisors.go`: there is also Unix-socket based discovery/forwarding for approvals/session-events.

## Proposed direction
Define one detached supervisor event/approval transport. Prefer the existing authenticated Unix supervisor channel or an explicit parent callback URL passed at launch, with a typed request/response protocol, standard escaping, backoff, and durable/replayable resolution semantics.

## Rough priority
Medium.

## Resolution
Added a versioned transport-neutral detached control exchange, exact-incarnation replay journals, an authenticated native Unix relay, and approval-manager request/terminal observer seams. The per-approval callback and polling bridge was removed; detached approval publication and resolution now use only the typed control path.

Implemented across `48cd054a`, `dec16f7e`, `7c8e2304`, `78d91039`, and the follow-up relay hardening commit.
