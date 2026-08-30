# MicroVM v3 egress follow-ups

## Status

Resolved.

## Current security contract

The external-runner v3 profile uses `vsock-explicit-proxy`: it does not request QEMU user networking and publishes readiness only after the launch-bound host broker is reachable through the authenticated guest relay. The legacy `network_ready` field remains false because broker reachability is not evidence of direct-network enforcement; v3 reports separate explicit-proxy readiness.

The v3 broker delegates synchronous approval decisions to the active trusted parent subagent request over its exact Unix supervisor socket. A per-Draft bearer is pinned on first use, revoked with the parent request, and transported to the host provider through a private credential file. Parallel Drafts receive distinct delegations, and session-scoped grants are bound to one exact Draft.

Generation recovery recreates the broker with a fresh launch token, derives the endpoint from the recovered CID, and archives the prior generation's network audit with the rest of its host evidence. v1 compatibility and v2 volume recovery remain unchanged.

## Resolution

Implemented by `e34c3407`. Unknown egress remains fail-closed when no active trusted parent approval delegation exists. Approval requests and resolutions are durably audited before any upstream dial.
