# Pi command cancellation and terminal latency

Resolved.

Pi's Bash tool previously relied only on HTTP disconnect propagation to cancel a dispatched AgentSH command. That normally reached the request context, but it provided no independently addressable cancellation operation when a client, socket, or intermediary failed to propagate the disconnect promptly. In addition, the ordinary `exec_bash` summary path decoded and classified up to 5,000 detailed syscall events after the process had exited. Event-heavy commands such as `nix build` could therefore appear active in Pi while AgentSH was only constructing the terminal response.

AgentSH now accepts a caller-generated canonical request UUID for `exec_bash`, registers the exact active request context, and exposes an idempotent exact-request cancellation endpoint. Cancelling it interrupts both queued admission and running process execution; the existing command runner kills the owned process group. Behavioral tests cover duplicate identities, idempotent cancellation, and cancellation while queued.

Summary and no-event responses now inspect at most 256 events instead of decoding 5,000 after process exit. Full event queries remain available through the event API and `include_events=all`.
