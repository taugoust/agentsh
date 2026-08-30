# MicroVM v3 egress follow-ups

## Status

Open.

## Current security contract

The external-runner v3 profile uses `vsock-explicit-proxy`: it does not request QEMU user networking and publishes readiness only after the launch-bound host broker is reachable through the authenticated guest relay. The legacy `network_ready` field remains false because broker reachability is not evidence of direct-network enforcement; v3 reports separate explicit-proxy readiness.

The v3 broker currently has no synchronous approval manager. Policies are compiled with approvals enforced, so every `approve` decision fails closed before DNS or dial. An approval rule is not treated as an allow rule.

Generation recovery recreates the broker with a fresh launch token, derives the endpoint from the recovered CID, and archives the prior generation's network audit with the rest of its host evidence. v1 compatibility and v2 volume recovery remain unchanged.

## Follow-ups

- Bind a host-owned synchronous approval manager to the immutable v3 session identity while preserving the selected-IP pre-dial contract.
