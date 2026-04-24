# Code Review — `explicit`

Principal engineer review of the `devenv-nono-llm` codebase. Date: 2026-04-13.

---

## What This Is

`explicit` is a Rust CLI that analyzes projects, generates `devenv.nix` configs, enforces quality gates, and launches sandboxed agent shells (Claude/Codex) with narrowly scoped filesystem capabilities. It's the glue between "this project works on my machine" and a reproducible, observable, agent-safe dev environment.

---

## Critical Issues

### 1. No timeout on `devenv up` / service startup

`run_devenv_up()` spawns services with `devenv up --detach` but never sets a deadline. A broken service definition (bad port, missing env var) hangs the agent indefinitely.

**Fix:** Add a 60-second timeout. Report timeout as a blocking verify failure with an explicit message.

### 2. Rnix mutations are fragile to non-standard formatting

`devenv_file.rs` uses the rnix AST to insert/update nodes. If the user's `devenv.nix` has unusual whitespace or inline comments at insertion points, output can be malformed Nix.

**Fix:** After every write, validate the resulting file by running `nix-instantiate --parse` or `nixfmt --check`. If validation fails, restore the backup and report the error — don't silently write bad Nix.

---

## High Priority

### 3. Verify lanes block on thread join — no per-check timeout

Parallel verification spawns OS threads and `.join()`s on all of them. If one check command hangs (e.g., a test suite that deadlocks), the whole verify invocation hangs.

**Fix:** Give each check command a configurable timeout (default: 5 min). Kill the child process and report a timeout failure. This is especially important because verify is run as a stop-hook by agents.

### 4. SSH wrapper silently skips `ssh-keygen` fingerprinting if binary missing

When `deploy.hosts` is configured, the runtime generates `known_hosts` entries using `ssh-keygen -l`. If `ssh-keygen` is not in `$PATH`, this step fails silently and the agent may connect without host verification.

**Fix:** Emit a warning (or blocking error) at `apply` time if deploy hosts are configured but `ssh-keygen` is absent.

### 5. EOL check blocks agent shell startup on slow network

The `eol.rs` module fetches from `endoflife.date` API with a 3-second timeout. On a flaky connection this adds 3 seconds to every `shell` invocation. If the API is down, the user sees a confusing error.

**Fix:** Do the remote fetch in the background after shell launch. Only block if the embedded DB marks the version as definitively EOL. Log the fetch result asynchronously.

---

## Medium Priority

### 6. `runtime.rs` is ~1800 LOC — split it

Three concerns live in one file: devenv shell env capture, service orchestration, and SSH/deploy setup. This makes it hard to navigate and test in isolation.

**Suggested split:**
- `runtime_shell.rs` — env capture + shell launch
- `runtime_devenv.rs` — `devenv up/down`, service health
- `runtime_ssh.rs` — known_hosts, deploy host setup

### 7. `verify.rs` has the same problem

Policy checks, lint/build/test runners, and output formatting are all in one file. Extract:
- `verify_policy.rs` — README structure, license, explicit.toml validation
- `verify_runner.rs` — command execution + timeout logic
- `verify_output.rs` — formatting for human vs. agent output

### 8. Analysis results are not cached between runs

Every `apply`, `doctor`, and `verify` re-scans all manifests. For large monorepos this is ~1–2 seconds of redundant work. The JSON intermediate (`.nono/analysis.json`) is written but never used as a cache.

**Fix:** Hash the set of manifest files and their mtimes. If unchanged since last `analysis.json` write, skip re-scan. Invalidate on any manifest mtime change.

### 9. Registry rules require recompile to extend

Rules are embedded TOML. Adding support for a new ecosystem (Dart, Zig, Swift) requires a new release.

**Partial fix:** Allow an optional `~/.config/explicit/registry.toml` or `explicit.toml` `[registry]` section to overlay/extend the embedded rules. Keep embedded rules as the default. This unblocks power users without compromising the offline-capable baseline.

---

## Low Priority

### 10. No tests for devenv.nix mutation round-trips

The `devenv_file.rs` logic is tested for generation but not for idempotency: does `apply` → `apply` produce the same file? Does it correctly handle a file with user-added content between managed sections?

**Add:** Property-based tests that generate a `devenv.nix`, run `apply` twice, and assert the output is identical.

### 11. No tests for parallel verify under failure conditions

Integration tests cover happy-path verify. There are no tests for:
- One lane fails, others succeed → correct single-failure reporting
- One lane hangs → timeout fires correctly (once timeout is added)

### 12. `env_trace_lib.rs` only ships on Linux/macOS

The LD_PRELOAD tracer is conditionally compiled, which is correct. But the `observe` subcommand still accepts `--env-trace` on macOS where `DYLD_INSERT_LIBRARIES` is restricted by SIP. The flag silently produces no data.

**Fix:** On macOS, emit a warning that env tracing requires SIP disabled, or document this in `--help`.

### 13. `nono` crate is a direct trust boundary

The entire sandbox posture depends on `nono` crate correctness. There are no tests that verify the sandbox actually blocks writes outside the allowlist.

**Recommendation:** Add at least one integration test that attempts to write to a path outside the sandbox and asserts the attempt is rejected. This would catch regressions if `nono` changes behavior.

---

## Strengths (Keep Doing These)

- **Single-failure verification** — reporting only the first blocking issue is exactly right for agent interaction. Don't change this.
- **Transparent inference** — every generated `devenv.nix` comment explains why a package/service was added. This is excellent for user trust.
- **Narrow sandbox defaults** — only the project root, `.nono/`, language caches, and explicit system paths. The deny-list for protected files (`explicit.toml`, git hooks) is correct.
- **Two-phase design** — analysis → JSON intermediates → generation means every step is inspectable. Keep this.
- **Observability-first** — SQLite event store + live Unix socket is the right architecture for multi-turn agent telemetry.
- **EOL tracking with embedded fallback** — smart design; remote fetch is a nice-to-have, not a hard dependency.

---

## Summary

| Area | Score | Blocker? |
|------|-------|---------|
| Error handling | 8/10 | No |
| Safety (unsafe code) | 8/10 | No |
| Testing | 6/10 | No |
| Module size/structure | 5/10 | No |
| Security posture | 7/10 | No |
| Input validation (Nix AST) | 4/10 | **Yes** |
| Reliability (timeouts) | 4/10 | **Yes** |

Fix the two Critical issues before putting this in front of production agent workloads. The High issues should be addressed in the next sprint. Everything else is quality-of-life.
