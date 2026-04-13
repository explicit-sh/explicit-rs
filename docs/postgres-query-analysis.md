# PostgreSQL Query Analysis Layer For `explicit`

This document specifies a PostgreSQL-focused utility for `explicit` that can:

- capture all SQL issued from processes running inside the `explicit` sandbox
- normalize and fingerprint those queries
- parse the SQL into an AST
- collect planner output for representative queries
- produce Credo-like findings that teach developers which queries are risky or wasteful

Current status:

- not implemented
- intended to become a new `explicit observe postgres` / `explicit postgres lint` capability

## Goal

We want `explicit` to answer questions such as:

- which queries did this app actually run during a sandboxed agent session?
- which queries are likely fine syntactically but structurally weak?
- which query plans show obvious planner or index problems?
- which repeated query patterns look like N+1 or hot-loop waste?
- which findings should block `explicit verify` or a stop hook?

The output should feel closer to Credo than to a raw SQL log:

- categorized rules
- concise explanations
- example query text
- plan excerpts where relevant
- concrete remediation guidance

Credo describes itself as a static analysis tool with a focus on code consistency and teaching. That same bias is the right fit here: actionable findings first, raw telemetry second.

## Recommendation

Build this as two cooperating pieces:

1. a local PostgreSQL protocol proxy that all sandboxed clients talk to
2. a rule engine and report generator that operates on captured SQL plus sampled plan data

Do not start with a server-global log scraper as the primary mechanism.

Reason:

- `explicit` needs session-local visibility for only the processes inside the sandbox
- PostgreSQL protocol capture can see both simple and extended query flows
- global logging is harder to scope cleanly to one `explicit` run
- `pg_stat_statements` is still valuable, but better as enrichment than as the only source of truth

## Why A Proxy First

`explicit` already controls the environment that apps see inside the sandbox. That means it can redirect:

- `PGHOST`
- `PGPORT`
- `DATABASE_URL`
- framework-specific connection strings

to a project-local proxy.

That proxy can then:

- accept PostgreSQL frontend/backend protocol connections
- forward to the real local PostgreSQL server over loopback or Unix socket
- record SQL text from `Query` messages
- record prepared-statement SQL from `Parse` messages
- associate later `Bind` / `Execute` / `Sync` cycles with the prepared SQL
- track timing, row metadata, errors, and cancellations

This is a much better fit than trying to infer one sandbox session from shared server logs.

The PostgreSQL protocol docs matter here because the proxy must explicitly support:

- startup and authentication
- simple query mode
- extended query mode
- cancel requests
- `COPY`

Anything less will break common app stacks.

## Non-Goals For V1

V1 should not try to:

- terminate TLS for remote databases
- analyze databases outside local `explicit` development flows
- persist every bind parameter value by default
- rewrite queries automatically
- become a generic production APM product

This is a development-time advisor for local `explicit` sessions.

## Architecture

### 1. Capture Layer

Working name:

- `explicit-pg-proxy`

Responsibilities:

- listen on a project-local TCP port or Unix socket
- forward traffic to the actual local PostgreSQL service
- record structured query events
- preserve wire compatibility for normal local development tools

Recommended runtime topology:

```text
app inside explicit sandbox
  -> explicit-pg-proxy
  -> local postgres from devenv
```

`explicit shell`, `explicit codex`, and `explicit claude` should export proxy-aware values such as:

- `PGHOST`
- `PGPORT`
- `PGSSLMODE=disable` for the local proxy hop when appropriate
- rewritten `DATABASE_URL`

The proxy should prefer forwarding to the real PostgreSQL Unix socket when available.

### 2. Storage Layer

Use SQLite for local event storage under the project:

- `.nono/postgres-observability/<run-id>/events.sqlite`

Core tables:

- `runs`
- `connections`
- `statements`
- `statement_samples`
- `prepared_statements`
- `bind_samples`
- `plan_samples`
- `findings`

Important fields:

- run id
- session id
- connection id
- database name
- user name
- application name
- query fingerprint
- normalized SQL
- sampled raw SQL
- execution count
- error state
- duration
- rows returned
- plan JSON
- finding rule id
- severity
- explanation

### 3. Analysis Layer

Working name:

- `explicit-pg-lint`

Responsibilities:

- parse SQL into an AST
- normalize and fingerprint queries
- run AST-based rules
- run plan-based rules
- aggregate repeated runtime patterns
- emit findings in a Credo-like format

The parser should be PostgreSQL-specific, not generic SQL.

That means the implementation should use a PostgreSQL grammar or parser binding that understands PostgreSQL syntax and produces a stable AST. The exact library choice can be decided during implementation, but the interface must expose:

- statement type
- tables touched
- joins
- predicates
- sort clauses
- grouping
- subqueries
- CTEs
- function calls
- parameter placeholders

## Query Capture Requirements

The proxy must preserve normal developer behavior for:

- `psql`
- Ecto / Phoenix
- Rails / ActiveRecord
- Django / psycopg
- Rust clients such as `tokio-postgres` and `sqlx`
- plain `libpq`

Minimum protocol support:

- startup message
- authentication pass-through
- simple query flow
- extended query flow
- prepared statements
- portals
- cancel requests
- `COPY IN` / `COPY OUT`

Default data policy:

- store normalized SQL by default
- store a limited sampled raw SQL text for debugging
- redact bind parameter values by default
- allow opt-in capture of bind values for local deep-debug mode only

## Plan Capture Strategy

The analyzer should not rely only on query text. It also needs representative plans.

Recommended approach:

1. capture every executed query through the proxy
2. select representative fingerprints for plan analysis
3. run `EXPLAIN (FORMAT JSON)` on safe replay connections
4. optionally enrich with `auto_explain` and `pg_stat_statements`

Important safety rule:

- do not run `EXPLAIN ANALYZE` automatically for mutating queries

Default behavior:

- `SELECT`: `EXPLAIN (FORMAT JSON)`
- `INSERT` / `UPDATE` / `DELETE` / `MERGE`: plan-only `EXPLAIN (FORMAT JSON)` without execution-side effects
- optional deep mode: sampled `EXPLAIN (ANALYZE, FORMAT JSON, BUFFERS)` for explicitly approved read-only workloads

Useful PostgreSQL enrichments:

- `pg_stat_statements` for aggregated planning and execution stats
- `auto_explain` for slow-query plan samples

These should be optional helpers, not the primary capture mechanism.

## Rule Model

The findings model should be explicitly Credo-like:

- rule id
- category
- severity
- confidence
- subject query fingerprint
- short summary
- detailed explanation
- remediation
- optional plan evidence

Suggested categories:

- `readability`
- `correctness_risk`
- `planner_risk`
- `index_risk`
- `pagination`
- `aggregation`
- `runtime_pattern`

Suggested severities:

- `info`
- `warning`
- `error`

## Initial Rule Set

### AST / SQL Pattern Rules

- `select_star`
  - flag `SELECT *` on non-trivial queries
- `limit_without_order_by`
  - unstable pagination risk
- `deep_offset_pagination`
  - flag large `OFFSET` usage
- `leading_wildcard_like`
  - `LIKE '%foo'` / `ILIKE '%foo'`
- `function_wrapped_predicate`
  - function on filtered column can defeat index usage
- `not_in_subquery`
  - suggest checking `NOT EXISTS` semantics and planner behavior
- `cross_join_without_clear_intent`
  - accidental Cartesian product risk
- `unbounded_update_or_delete`
  - write query without `WHERE`
- `distinct_as_join_fix`
  - `DISTINCT` used to paper over duplicate joins
- `redundant_order_by_in_subquery`
  - sort work with no semantic benefit

### Plan Rules

- `seq_scan_on_large_relation`
  - sequential scan on a large table with selective predicates
- `sort_without_index_support`
  - explicit sort where index-backed order may be expected
- `hash_or_sort_spill_risk`
  - plan indicates memory-heavy operators likely to spill
- `nested_loop_large_outer`
  - nested loop with large outer cardinality
- `join_row_estimate_misestimation`
  - estimated vs actual row mismatch in approved deep mode
- `filter_after_join_blowup`
  - late filter after expensive join expansion

### Runtime Pattern Rules

- `n_plus_one_signature`
  - same fingerprint repeated many times in one request or short window
- `chatty_transaction`
  - too many tiny queries inside one transaction
- `repeated_count_on_hot_path`
  - frequent count queries with identical predicates
- `duplicate_query_burst`
  - identical query repeated back-to-back unnecessarily

## Reporting UX

CLI candidates:

```bash
explicit observe postgres
explicit postgres lint
explicit postgres report --latest
```

Expected output style:

```text
warning planner_risk seq_scan_on_large_relation
  query: SELECT id, email FROM users WHERE lower(email) = $1
  why: function-wrapped predicate on a large relation is likely preventing index usage
  evidence: Seq Scan on users, filter lower(email) = $1
  suggest: use a functional index or normalize the compared value
```

The report should also support:

- grouping by fingerprint
- showing one representative plan
- suppressing low-confidence rules
- machine-readable JSON output

## `explicit` Integration

### Shell and Agent Launch

When PostgreSQL is part of the detected environment and query analysis is enabled:

1. `explicit` starts PostgreSQL
2. `explicit` starts the local proxy
3. `explicit` rewrites PostgreSQL connection env vars toward the proxy
4. `explicit` stores proxy logs and findings under `.nono/`

### Verify and Stop Hooks

This should not block by default on day one.

Recommended rollout:

- phase 1: observability only
- phase 2: `explicit postgres lint` explicit opt-in
- phase 3: `explicit verify` can fail on `error` findings when a project opts in

Possible future `explicit.toml` shape:

```toml
[postgres_analysis]
enable = true
mode = "observe"
fail_on = ["error"]
```

## Security and Privacy

Default posture:

- redact bind values
- avoid storing secrets from SQL literals where possible
- store only normalized SQL unless deep debug is enabled
- keep all artifacts local under `.nono/`

The proxy should assume developers may run queries containing:

- tokens
- emails
- customer ids
- raw JSON payloads

So raw capture must be deliberately limited.

## Rollout Plan

### Phase 1

- basic proxy
- capture simple and extended query text
- fingerprinting
- SQLite event store
- `explicit observe postgres`

### Phase 2

- AST parsing
- initial SQL pattern rules
- JSON report output

### Phase 3

- representative `EXPLAIN (FORMAT JSON)` capture
- plan-based rules
- sampled `auto_explain` integration

### Phase 4

- stop-hook / `verify` integration
- project config
- suppressions

## Risks

- PostgreSQL wire compatibility is the hardest part
- prepared statements and `COPY` need real support, not best-effort parsing
- plan analysis without schema context can produce false positives
- `EXPLAIN ANALYZE` is dangerous if run carelessly
- runtime-pattern rules need request or transaction boundaries to avoid noisy findings

## References

- Credo plugin and design direction: https://rrrene.org/2019/06/10/credo-1-1-0-plugin-support/
- PostgreSQL frontend/backend protocol overview: https://www.postgresql.org/docs/current/protocol.html
- PostgreSQL message flow, including simple and extended query modes: https://www.postgresql.org/docs/current/protocol-flow.html
- PostgreSQL `EXPLAIN` usage and plan structure: https://www.postgresql.org/docs/current/using-explain.html
- PostgreSQL `pg_stat_statements`: https://www.postgresql.org/docs/current/pgstatstatements.html
- PostgreSQL `auto_explain`: https://www.postgresql.org/docs/current/auto-explain.html
