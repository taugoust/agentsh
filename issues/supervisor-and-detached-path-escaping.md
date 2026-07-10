# Centralize API path escaping for detached/supervisor calls

## Status
Open.

## Problem
Detached/supervisor code builds API paths and Unix URLs in several places with different escaping rules. This is easy to get wrong for session IDs, approval IDs, and Unix socket paths containing special characters.

## Evidence / files inspected
- `internal/api/detached_supervisors.go`: `escapedAPIPath` uses `url.PathEscape`; `detachedForwardID` manually unescapes path segments.
- `internal/approvals/detached_bridge.go`: `pathEscape` is a custom replacer for `%`, `/`, `?`, `#` rather than `url.PathEscape`.
- `internal/client/client.go`: `unix://` URL parsing reconstructs socket path from host/path.
- `internal/cli/supervisor_session.go`: call sites concatenate `"unix://" + sockPath` directly.

## Proposed direction
Introduce one small transport/path builder package for AgentSH API paths and Unix URLs, with tests for absolute Unix paths, URL-host forms, IDs containing reserved characters, and round-tripping through forwarding.

## Rough priority
Low.
