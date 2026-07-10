# Consolidate detached supervisor transport timeouts

## Status
Open.

## Problem
Detached supervisor Unix transport uses several hard-coded and differently scoped timeouts. Short list/post timeouts, long create timeouts, readiness polling, and unlimited Unix server write timeout are spread across API, CLI, client, and server code, making failures hard to reason about and tune.

## Evidence / files inspected
- `internal/api/detached_supervisors.go`: default detached request timeout is `500ms`; every query/post wraps the caller context with that timeout.
- `internal/cli/supervisor_session.go`: readiness client timeout is `1s`, readiness deadline is `15s`, create-session client timeout is `30m`, reachability dial is `200ms`.
- `internal/client/client.go`: default client timeout is `30s`; Unix transport is special-cased inside generic client construction.
- `internal/server/server.go`: Unix socket server disables `WriteTimeout` entirely for long-lived local calls.

## Proposed direction
Introduce an explicit supervisor transport profile with named deadlines (discovery, health, short RPC, long create/materialize, streaming idle timeout). Keep Unix socket behavior centralized in the client/server transport layer and expose timeout choices in config/metadata instead of scattered literals.

## Rough priority
Medium.
