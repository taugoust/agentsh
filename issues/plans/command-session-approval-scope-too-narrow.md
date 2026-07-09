# Implementation plan: command session approval should scope to executable

Parent issue: `issues/command-session-approval-scope-too-narrow.md`

## Goal

Make the default/plain command `Approve for session` behavior cache an approval for the executable/resolved command path, not for the exact `command + argv` hash. Preserve an exact-invocation scope as an explicit narrower target and test both paths.

## Code paths inspected

- Scope construction and scoped cache:
  - `internal/approvals/scope.go`
  - `internal/approvals/manager.go`
- Direct API command approvals:
  - `internal/api/command_approval.go`
  - `internal/api/command_approval_test.go`
- Seccomp execve approval adapter:
  - `internal/api/notify_linux.go`
  - `internal/netmonitor/unix/handler.go`
  - `internal/netmonitor/unix/execve_handler.go`
- Approval resolution payloads:
  - `internal/api/app.go` (`resolveApprovalLocal`)
  - `internal/api/approval_ui.go` (`approvalUIEndpoint.handleRequest`)
  - `internal/api/detached_push.go` (`decodeApprovalResolution`)
- Pi approval UI behavior, for payload compatibility:
  - `~/Workspace/pi-agent-extensions/sandbox/index.ts`

Relevant current behavior: `approvals.NewCommandScope(command, args, rule)` hashes `command + argv`, callers put that scope into `req.Fields`, and `Manager.setScopedFromRequest(... ScopeSession ...)` stores that exact key in the session cache. The Pi UI already supports `fields.scope_options` and relays selected `scope_kind/scope_key/...`, but command approvals currently do not provide broader options.

## Design

### 1. Split command scopes into executable and exact-invocation scopes

In `internal/approvals/scope.go`:

- Add a broad executable scope constructor, e.g.:

  ```go
  func NewCommandExecutableScope(command string, rule string) (Scope, bool)
  ```

  Intended output:
  - `Kind: "command"`
  - `Operation: "exec"`
  - `Path: <normalized command/executable>` when non-empty
  - `Label: <normalized command/executable>`
  - `Rule: strings.TrimSpace(rule)`
  - `Key: "command-executable:" + <stable value>`

- Normalize executable identity conservatively:
  - trim whitespace;
  - if it looks like a path, clean it with `filepath.Clean`;
  - preserve basename-only commands as-is;
  - do not include argv in the broad key;
  - include the rule in the key unless implementation review shows this would break expected behavior. Rule-aware executable scopes are safer because approval for one command policy rule should not silently satisfy a different, more sensitive command rule for the same binary.

- Add/keep an exact-invocation constructor, e.g.:

  ```go
  func NewCommandInvocationScope(command string, args []string, rule string) (Scope, bool)
  ```

  This should contain the current hash-of-`command + argv` behavior. Use a distinct key prefix such as `command-invocation:` so exact and executable scopes cannot collide.

- Update `NewCommandScope` deliberately:
  - Prefer making it an alias of `NewCommandExecutableScope` so existing callers automatically use the corrected session fallback.
  - Update comments so it no longer claims to be an exact invocation scope.
  - Move the old exact comment to `NewCommandInvocationScope`.

### 2. Provide both default scope and explicit options on command approval requests

Create a small helper near command approval code (for example in a new `internal/api/command_approval_scope.go`):

```go
func commandApprovalScopeOptions(command string, args []string, rule string) (defaultScope approvals.Scope, ok bool, options []map[string]any)
```

Behavior:

- `defaultScope` is the executable scope. This is what old/plain approvers get when they resolve `{scope:"session"}` without explicit target fields.
- `options` includes stable de-duplicated `approvals.ScopeFields(...)` for:
  1. executable/session scope;
  2. exact invocation scope.
- Store the exact invocation option even if it is not the default, so UIs can offer a narrow “approve this exact invocation for session” choice.

Use the helper in both command approval entry points:

- `internal/api/command_approval.go` (`App.applyCommandApproval`):
  - check the executable scope first via `a.approvals.CheckScoped(ctx, sessionID, cmdID, defaultScope)`;
  - put default executable scope fields into `apr.Fields`;
  - add `fields["scope_options"] = options` when options are non-empty.

- `internal/api/notify_linux.go` (`approvalRequesterAdapter.RequestExecApproval`):
  - same shape as direct command approvals;
  - because `req.Command` comes from `ExecveContext.Filename`, and `handler.go` canonicalizes it with `filepath.EvalSymlinks`, Nix-store execve prompts will naturally scope by resolved executable path.

Do not broaden policy evaluation itself. This is only an approval-cache target change after policy has already returned `approve`.

### 3. Preserve exact-invocation behavior when explicitly selected

No manager enum change is needed. Existing resolution endpoints already accept explicit target fields:

- HTTP: `scope_kind`, `scope_key`, `scope_label`, `scope_operation`, `scope_path`, `scope_rule`, `scope_prefix`
- legacy approval UI socket: same fields
- detached push resolution: same fields

When Pi or another approver selects the exact option from `scope_options`, it will resolve `scope=session` with the exact invocation `scope_key`; `Manager.setScopedFromRequest` will store that exact scope. Subsequent checks only hit it if callers check that exact invocation scope.

If the first implementation only checks executable scope before prompting, add a second check for exact invocation scope before prompting as well:

```go
if cached, ok := mgr.CheckScoped(ctx, sessionID, cmdID, executableScope); ok { ... }
if cached, ok := mgr.CheckScoped(ctx, sessionID, cmdID, invocationScope); ok { ... }
```

This allows an explicitly selected exact-invocation session approval to suppress the same argv later without broadening to other argv.

### 4. UI/payload compatibility notes

- Keep `Request.Kind == "command"`.
- Keep top-level `fields.scope_kind/scope_key/...` populated with the executable scope for backwards-compatible plain session approval.
- Add `fields.scope_options` for command approvals. The Pi extension already consumes this array and relays the selected target fields.
- Ensure labels are clear:
  - executable option label: the executable path or command name;
  - exact option label: formatted command plus argv.

No change should be required in `internal/api/app.go`, `internal/api/approval_ui.go`, or `internal/api/detached_push.go` unless tests reveal they strip `scope_options` or fail to relay explicit command scopes. They already decode and forward explicit scope target fields.

## Tests

### Unit tests: scope constructors

Update/add tests in `internal/approvals/scope_command_test.go`:

1. `TestNewCommandExecutableScope_IgnoresArgs`
   - build executable scope for `sqlite3` with two different argv slices via the helper or direct constructor;
   - assert same key, same label/path, `Kind == "command"`, `Operation == "exec"`.

2. `TestNewCommandExecutableScope_NixStorePathUsesPathNotArgv`
   - command: `/nix/store/abc-sqlite-3.45/bin/sqlite3`;
   - assert key/label/path are based on that path and do not change when argv changes.

3. `TestNewCommandInvocationScope_RemainsExact`
   - same command + same args => same key;
   - same command + different args => different key;
   - key prefix is `command-invocation:`.

4. If rule is included in executable keys, add `TestNewCommandExecutableScope_IsRuleAware`.

### Manager/cache tests

Add tests in `internal/approvals/scoped_decision_test.go` or a new command-specific test file:

1. Executable session approval matches same executable with different args:
   - `SetScoped(... executableScope(sqlite3), approved=true ...)`;
   - `CheckScoped(... executableScope(sqlite3))` succeeds.

2. Different executable still prompts/misses:
   - cache sqlite executable scope;
   - `CheckScoped(... executableScope(psql))` returns false.

3. Exact session approval remains narrow:
   - cache `NewCommandInvocationScope("sqlite3", []string{"db", "select 1"}, rule)`;
   - same invocation hits;
   - `[]string{"db", "select 2"}` misses.

### Direct API command approval tests

Update `internal/api/command_approval_test.go`:

1. Replace existing exact-scope assumptions with executable-scope assumptions.

2. Add `TestApplyCommandApproval_ApproveExecutableForSessionAllowsDifferentArgs`:
   - create app with `approvals.New("api", time.Minute, nil)`;
   - first call `applyCommandApproval(..., "/nix/store/abc-sqlite/bin/sqlite3", []string{"events.db", "select ... limit 10"}, ...)` in a goroutine;
   - wait for pending approval;
   - assert `req.Fields["scope_key"]` is the executable scope key and not argv-dependent;
   - resolve with `ResolveForSessionWithScope(..., approvals.ScopeSession)` or with the executable target fields;
   - second call same executable with different args returns without creating another pending approval and sets effective decision to `allow`.

3. Add `TestApplyCommandApproval_DifferentExecutableStillPrompts`:
   - after caching sqlite executable session approval, call `applyCommandApproval` for `/nix/store/def-postgresql/bin/psql`;
   - assert a new pending approval appears.

4. Add `TestApplyCommandApproval_ExactInvocationSessionScopeIsNarrow`:
   - start a request;
   - select the exact invocation option from `req.Fields["scope_options"]` and resolve `scope=session` with those target fields;
   - same argv is allowed without prompt;
   - different argv prompts.

### Seccomp execve adapter tests (Linux/cgo)

Add a focused test in `internal/api/notify_linux_test.go` or a new `internal/api/command_execve_approval_linux_test.go` with `//go:build linux && cgo`:

- Instantiate `approvalRequesterAdapter{mgr: approvals.New("api", time.Minute, nil)}`.
- First `RequestExecApproval` with:
  - `Command: "/nix/store/abc-sqlite-3.45/bin/sqlite3"`
  - `Args: []string{"sqlite3", "events.db", "select ... limit 10"}`
  - `Rule: "approve-unknown-nix-store-executables"`
- Wait for pending approval, assert default scope label/path is the resolved executable path and not the full argv.
- Resolve session approval.
- Second `RequestExecApproval` with same command and different args returns approved without a second pending approval.
- A third request for a different Nix-store executable produces a new pending approval.

### API/payload tests

Add/update a small HTTP or local resolver test if not already covered:

- pending command approval JSON includes `fields.scope_options` with both executable and exact invocation options;
- resolving with explicit exact option fields stores that exact key;
- resolving with no explicit target and `scope=session` stores the default executable scope.

The existing Pi extension tests in `~/Workspace/pi-agent-extensions/nix/checks.nix` already exercise `scope_options` for files. If this repository has a cross-project check target for the extension, add/adjust a fixture for command `scope_options`; otherwise document that AgentSH emits the same `scope_options` shape already supported by the extension.

## Validation commands

Run at least:

```sh
go test ./internal/approvals ./internal/api
```

On Linux with cgo/libseccomp available, also run:

```sh
go test ./internal/api -run 'TestApplyCommandApproval|TestApprovalRequesterAdapter|TestCommandApproval' -v
```

Cross-platform compile checks required by project guidelines:

```sh
GOOS=windows go build ./...
go test ./...
```

If the Linux/cgo seccomp-specific test cannot run on the current host, ensure it is build-tagged appropriately and covered in Linux CI.

## Risks and mitigations

- **Over-broad approvals across different command rules:** include `rule` in executable scope keys unless there is a strong compatibility reason not to. This mirrors file directory/tree rule-awareness.
- **Older approvers that ignore `scope_options`:** make top-level scope fields executable-scoped, so `{scope:"session"}` becomes broad executable approval.
- **Exact approvals becoming unreachable:** check both executable and exact invocation scopes before prompting.
- **Direct command names are not always resolved paths:** for the direct API path, use the command string as supplied. Execve/Nix-store prompts already use the canonicalized path from seccomp handling.
- **Audit compatibility:** keep `Request.Kind` and `Scope.Kind` as `"command"`; distinguish scopes through key prefix, label/path, and optional rule.
