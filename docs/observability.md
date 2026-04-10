# Observability Layer For `explicit`

This document outlines a practical way to add a second layer around `explicit codex` and `explicit claude` so we can observe:

- model input and output
- token usage
- shell tool calls and outputs
- file access patterns
- outbound domains and, when possible, full HTTP and WebSocket requests

Current status in the codebase:

- Codex session JSONL ingestion is implemented
- SQLite run storage and shared live socket reporting are implemented
- Linux environment-variable access tracing via `LD_PRELOAD` is implemented
- macOS environment-variable access tracing is not yet reliable enough to enable by default

## Goal

We want a launch mode that does two jobs at once:

1. keep the existing `devenv` + `nono` sandbox
2. record enough structured telemetry to analyze agent behavior afterwards

That telemetry should be queryable so we can answer questions like:

- which files did the agent read or write?
- which domains did it talk to?
- how many shell commands did it run?
- which commands produced the most output?
- which turns consumed the most tokens?
- which tools appear wasteful relative to successful outcomes?

## Recommendation

Use a layered design instead of trying to solve everything with one mechanism.

### Layer 1: Codex session ingestion

Codex already writes structured JSONL session files under `~/.codex/sessions/`.

From local inspection, those files already contain:

- `user_message`
- `agent_message`
- `token_count`
- `exec_command_end`
- `web_search_end`
- `patch_apply_end`

The `exec_command_end` payload already includes fields such as:

- `command`
- `cwd`
- `parsed_cmd`
- `aggregated_output`
- `exit_code`
- `duration`

This means we can collect model I/O, token usage, and a large part of CLI tool usage without proxying or syscall tracing.

This should be the first thing we ingest.

### Layer 2: Network capture

Codex session files do not tell us which domains or HTTP requests the process made.

For that, the most practical option is a proxy sidecar:

- default metadata mode: capture destination host, port, method, path, status, bytes, timing
- opt-in deep inspection mode: capture headers and bodies

The best candidate is `mitmproxy` or `mitmdump`, because it supports:

- regular proxy mode
- local capture mode
- WebSocket traffic
- addon hooks for exporting flows

Use proxying only for network telemetry. Do not make it responsible for shell or file telemetry.

### Layer 3: File and process tracing

Proxies cannot tell us which files the agent touched.

For that, use OS-native process and file tracing:

- macOS:
  - preferred high-fidelity path: `eslogger` / Endpoint Security
  - fallback path: `fs_usage`
- Linux:
  - `bpftrace` on `open/openat/openat2`, `execve`, and `connect`

This should run as a separate sidecar and attribute events to the launched agent PID tree.

## Why This Split

Each signal has a different reliability boundary:

- model messages and shell tool calls already exist in Codex logs
- network requests are easiest through a proxy
- file touches need kernel or OS tracing

Trying to force one tool to do all three would make the system fragile.

## Storage Choice

Use SQLite as the primary event store.

Why SQLite first:

- append-heavy writes from multiple sidecars are simple
- easy to bundle with Rust
- straightforward WAL mode
- can be queried directly from the CLI
- easy to export later

DuckDB is better for heavy analytics, but it is less ideal as the primary live event sink.

The pragmatic design is:

- primary write path: SQLite
- optional export path: Parquet
- optional analysis path: DuckDB over SQLite or Parquet

If we only want one database, choose SQLite.

## Proposed Launch Flow

Add a new mode such as:

```bash
explicit observe codex
explicit observe claude
explicit codex --observe
```

Launch sequence:

1. create a new `run_id`
2. create `.nono/observability/<run_id>/`
3. create `.nono/observability/<run_id>/events.sqlite`
4. start sidecars
5. launch the agent inside `devenv` + `nono`
6. tail and ingest session artifacts while the agent is running
7. stop sidecars and finalize the run

## Sidecars

### 1. Session ingestor

Responsibilities:

- detect the new Codex session JSONL file created during the run
- tail it live
- normalize events into SQLite

Tables populated:

- `runs`
- `sessions`
- `turns`
- `messages`
- `token_usage`
- `exec_commands`
- `web_searches`
- `patch_events`
- `mcp_events`

This is low-risk and should work immediately.

### 2. Network observer

Responsibilities:

- capture domain and request metadata
- optionally capture full headers and bodies
- tag flows with `run_id` and PID where possible

Recommended modes:

- first choice: `mitmdump --mode regular` and set `HTTP_PROXY` / `HTTPS_PROXY`
- second choice: `mitmdump --mode local:<pid-or-name>` when client proxy env is insufficient

Data to store by default:

- scheme
- host
- port
- method
- path
- query hash or truncated query
- status code
- request bytes
- response bytes
- start time
- duration
- websocket flag

Deep inspection should be opt-in because it will capture sensitive code and tokens.

### 3. File observer

Responsibilities:

- record file reads, writes, creates, deletes, renames, execs
- associate events with the agent process tree

macOS path:

- best fidelity: `eslogger`
- fallback: `fs_usage`

Linux path:

- `bpftrace` one-liners or scripts for:
  - `open/openat/openat2`
  - `execve`
  - `connect`

This data should land in:

- `file_events`
- `process_events`

## Proposed Schema

Minimal schema:

```sql
create table runs (
  run_id text primary key,
  agent text not null,
  root text not null,
  started_at text not null,
  ended_at text,
  sandbox_plan_json text
);

create table sessions (
  session_id text primary key,
  run_id text not null,
  source_path text not null,
  started_at text,
  foreign key (run_id) references runs(run_id)
);

create table turns (
  turn_id text primary key,
  session_id text not null,
  started_at text,
  completed_at text,
  foreign key (session_id) references sessions(session_id)
);

create table messages (
  id integer primary key,
  session_id text not null,
  turn_id text,
  role text not null,
  phase text,
  content text,
  created_at text not null
);

create table token_usage (
  id integer primary key,
  session_id text not null,
  turn_id text,
  input_tokens integer,
  cached_input_tokens integer,
  output_tokens integer,
  reasoning_output_tokens integer,
  total_tokens integer,
  created_at text not null
);

create table exec_commands (
  id integer primary key,
  session_id text not null,
  turn_id text,
  process_id text,
  shell_command text not null,
  cwd text,
  parsed_cmd_json text,
  exit_code integer,
  duration_ms integer,
  aggregated_output text,
  status text,
  created_at text not null
);

create table network_requests (
  id integer primary key,
  run_id text not null,
  pid integer,
  scheme text,
  host text not null,
  port integer,
  method text,
  path text,
  status_code integer,
  request_bytes integer,
  response_bytes integer,
  is_websocket integer not null default 0,
  request_headers_json text,
  response_headers_json text,
  request_body blob,
  response_body blob,
  started_at text not null,
  duration_ms integer
);

create table file_events (
  id integer primary key,
  run_id text not null,
  pid integer,
  op text not null,
  path text not null,
  result text,
  created_at text not null
);
```

## Correlation Strategy

The key problem is correlation.

Use these keys:

- `run_id`: created by `explicit`
- `pid`: agent root PID and descendants
- `session_id`: Codex session id from JSONL
- `turn_id`: per-model turn

Correlations:

- session JSONL gives `session_id` and `turn_id`
- `exec_command_end` already includes `turn_id`
- proxy flows should include `pid` when capture mode exposes it, otherwise attach by time window and process group
- file events should attach by `pid`

## What We Can Capture Immediately

Without extra privileges, we can already capture:

- user prompts
- assistant outputs
- token counts
- shell commands
- shell outputs
- patch apply summaries
- web search events
- sandbox plan and allowed paths

That alone is enough to start measuring:

- command count per turn
- output bytes per command
- failure rate by command
- token usage per turn
- approximate cost of tool-heavy turns

## What Needs Elevated Privileges

### macOS

`fs_usage` and `eslogger` both require elevated permissions.

`eslogger` also requires Full Disk Access for the invoking terminal or parent process, and Apple explicitly notes that it is intended as a command-line utility rather than an app-embedded API.

That means macOS file tracing should be an opt-in helper mode, for example:

```bash
sudo explicit observe codex --trace-files
```

or by launching a privileged helper that writes JSON events into the run directory.

### Linux

`bpftrace` and related eBPF tooling also generally require elevated privileges or the correct capability setup.

This should also be opt-in.

## Network Capture Modes

### Mode A: Metadata only

Store:

- domain
- port
- method
- path
- status
- sizes
- timing

Do not store:

- bodies
- auth headers

This should be the default.

### Mode B: Full capture

Store:

- headers
- bodies
- websocket messages

Only enable this with an explicit flag such as:

```bash
explicit codex --observe-network=full
```

This mode must redact or hash at least:

- `Authorization`
- `Cookie`
- `Set-Cookie`
- API keys in query strings

## Recommended Implementation Order

### Phase 1

Implement the session ingestor only.

This gives immediate value and no extra privileges are required.

### Phase 2

Add SQLite-backed run metadata and a new launcher:

- `explicit observe codex`
- `explicit observe claude`

### Phase 3

Add network metadata capture via `mitmdump`.

Start with metadata only.

### Phase 4

Add file tracing:

- macOS: `eslogger` first, `fs_usage` fallback
- Linux: `bpftrace`

### Phase 5

Add opt-in full body capture and websocket frame capture.

## Risks

### TLS and CA handling

MITM-based inspection can break clients if trust setup is wrong or if the client pins certificates.

This is especially relevant here because Codex on macOS is already sensitive to CA configuration.

Do not make MITM mandatory for normal agent launches.

### Privacy

Raw model prompts, responses, headers, cookies, and source code may all be sensitive.

The database should support:

- redaction
- per-run retention settings
- optional encryption at rest
- an explicit scrub command

### Volume

Raw shell output and network bodies can become large quickly.

Use limits:

- truncate very large outputs in hot tables
- optionally spill bodies to compressed files and store a pointer in SQLite

## Concrete First Step

The best first deliverable is not proxying.

The best first deliverable is:

1. add `explicit observe codex`
2. ingest `~/.codex/sessions/*.jsonl` into SQLite
3. attach the current sandbox plan and run metadata
4. expose a few built-in reports

Example reports:

- top commands by count
- top commands by output bytes
- turns with highest token usage
- failed commands by frequency
- files written under the project root

That gives immediate observability, and then we can add network and file tracing as optional deeper layers.

## Sources

- OpenAI shell tool docs: https://developers.openai.com/api/docs/guides/tools-shell
- OpenAI trace grading docs: https://developers.openai.com/api/docs/guides/trace-grading
- mitmproxy proxy modes: https://docs.mitmproxy.org/stable/concepts/modes/
- mitmproxy protocol support: https://docs.mitmproxy.org/stable/concepts/protocols/
- mitmproxy addon examples: https://docs.mitmproxy.org/stable/addons/examples/
- mitmproxy certificates: https://docs.mitmproxy.org/stable/concepts/certificates/
- Apple `fs_usage`: https://developer.apple.com/library/archive/documentation/Performance/Conceptual/FileSystem/Articles/FileSystemCalls.html
- Apple Endpoint Security / eslogger overview: https://developer.apple.com/videos/play/wwdc2022/110345/
- bpftrace overview: https://bpftrace.org/
- bpftrace one-liner tutorial: https://bpftrace.org/tutorial-one-liners
