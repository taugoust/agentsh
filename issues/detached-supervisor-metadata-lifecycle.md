# Harden detached supervisor metadata lifecycle

## Status
Open.

## Problem
Detached supervisor discovery treats `metadata.json` + socket existence + `owner_pid` liveness as authoritative. That is fragile across PID reuse, partial startup, stale sockets, protocol changes, and abrupt supervisor death. The metadata also carries the event token, so stale metadata has both routing and auth implications.

## Evidence / files inspected
- `internal/detached/metadata.go`: `ValidateUsable` checks only non-empty socket, `os.Stat(socket)`, and `pidAlive(owner_pid)`; no start-time, heartbeat, protocol-version, or socket peer validation.
- `internal/cli/supervisor_session.go`: metadata is written only after session creation; stop path best-effort kills PID and writes `state: stopped`.
- `internal/api/detached_supervisors.go`: discovery silently skips invalid entries and de-duplicates by socket.
- `internal/api/detached_push.go`: parent resolves event-token auth by reading local metadata roots.

## Proposed direction
Make metadata a versioned lifecycle record with atomic state transitions (`starting`, `active`, `stopping`, `stopped`, `dead`), PID start-time or process identity, heartbeat/last_seen, protocol-version validation, and a supervisor health handshake over the socket before routing. Store or rotate event tokens so stale records cannot authorize pushes indefinitely.

## Rough priority
High.
