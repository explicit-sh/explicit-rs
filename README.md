# explicit

`explicit` analyzes a project, infers what it needs to run locally, writes that into `devenv`, and opens a restricted agent shell with only the required tools and permissions.

The point is to make the normally implicit parts of local development explicit:

- which languages are needed
- which packages are needed
- which local services are needed
- which cache directories agents must access
- which commands must pass before an agent is allowed to stop

## What It Does

Given a project directory, `explicit`:

- scans common project markers such as `package.json`, `Cargo.toml`, `go.mod`, `mix.exs`, `Gemfile`, `composer.json`, `pyproject.toml`, `requirements.txt`, `Makefile`, Gradle files, Maven files, and Compose files
- when started at a repository root, auto-discovers typical leaf projects underneath it and merges their commands, packages, services, and options into one workspace analysis
- detects likely languages, packages, lint commands, build commands, and local services
- detects conventional development web server commands for frameworks such as Phoenix, Rails, Django, Laravel, and common JavaScript app servers
- detects likely test commands and common test frameworks
- detects runtime versions from idiomatic project files such as `.node-version`, `.nvmrc`, `.ruby-version`, `.python-version`, `rust-toolchain.toml`, `go.mod`, `.tool-versions`, `mise.toml`, `.java-version`, and `.php-version`
- ensures [devenv.nix](devenv.nix) imports [explicit.generated.deps.nix](explicit.generated.deps.nix)
- regenerates [explicit.generated.deps.nix](explicit.generated.deps.nix) from the detected requirements, including per-line comments explaining why each language, package, version pin, service, or option was added
- writes analysis output to `.nono/analysis.json` and `.nono/sandbox-plan.json`
- writes a shared stop hook used by Claude and Codex
- installs a managed `pre-push` git hook when the project is a git repo
- blocks shell and agent launch when a detected runtime version is end-of-life according to the embedded `endoflife.date` snapshot, unless you pass `--dangerously-use-end-of-life-versions`
- launches a `devenv` shell, starts detected services, and re-execs into a `nono` sandbox

## Why The Name

Most local development environments rely on hidden assumptions:

- a language runtime happens to already exist
- a service happens to already be running
- a package manager cache happens to be available
- an agent can read broad parts of the machine because nobody defined a narrower boundary

`explicit` turns those assumptions into generated configuration and a concrete sandbox plan.

## Commands

The CLI is:

```bash
explicit scan
explicit apply
explicit doctor
explicit verify
explicit shell
explicit observe
explicit github-app
explicit observe codex
explicit observe list
explicit observe report --latest
explicit codex
explicit claude
```

What each command does:

- `scan`: prints the detected requirements as JSON
- `apply`: updates `devenv.nix` wiring, rewrites `explicit.generated.deps.nix`, and refreshes `.nono/` metadata and hooks
- `doctor`: prints a readable summary of what was detected, including any auto-started dev servers
- `doctor` includes detected runtime versions and where they came from
- `verify`: refreshes local managed devenv inputs when needed, then runs the detected lint, build, test, workspace, and repository policy checks with short failure summaries
- `shell`: realizes the `devenv` environment and launches a sandboxed shell for agents or manual use
- `observe`: attaches to a live agent run in the current project, or falls back to the latest saved report when no live socket exists
- `github-app`: prints GitHub App creation and XDG config instructions for sandboxed GitHub access
- `observe codex`: launches Codex, then ingests the new Codex session JSONL into a run-scoped SQLite database
- `observe list`: lists observed runs under the current project
- `observe report`: prints a readable report for an observed run
- `codex`: shorthand for launching `codex` inside the managed sandbox in the current project
- `claude`: shorthand for launching `claude` inside the managed sandbox in the current project

## Usage

Run directly with Cargo:

```bash
cargo run -- scan
cargo run -- apply
cargo run -- doctor
cargo run -- verify
cargo run -- shell
cargo run -- observe
cargo run -- github-app
cargo run -- observe codex
cargo run -- observe list
cargo run -- observe report --latest
cargo run -- codex
cargo run -- claude
```

Run through the built package:

```bash
nix build .#explicit
./result/bin/explicit doctor
```

Run as a flake app:

```bash
nix run .#explicit -- doctor
nix run .#explicit -- apply
nix run .#explicit -- shell
```

Run inside the repo `devenv` shell:

```bash
devenv shell
explicit apply
explicit doctor
explicit verify
explicit github-app
explicit shell --command codex
explicit observe
explicit observe codex
explicit codex
explicit claude
```

## Agent Shell

The `shell` command does five things in order:

1. runs `apply`
2. prints detected runtime versions and checks them against the embedded end-of-life database
3. captures the environment from `devenv shell`
4. starts detected services with `devenv up --detach` when needed
5. launches a `nono` sandbox with only the required paths allowed

When `explicit codex`, `explicit claude`, or the observed agent variants detect conventional development web servers, they also start those server commands before the sandbox launches. `doctor` shows the exact commands under `Dev servers: ...`, and agent startup logs each started server plus its log file under `.nono/runtime/dev-servers/`.

If PostgreSQL is one of the detected services, `explicit shell`, `explicit codex`, and `explicit claude` also ensure the current `$USER` has a matching login role and database before entering the sandbox. That keeps plain `psql` usable in the local development shell even when the Postgres data directory was initialized earlier without your current user database.

Examples:

```bash
explicit shell --command codex
explicit shell --command claude
explicit shell --dangerously-use-end-of-life-versions --command codex
explicit observe
explicit observe codex exec --skip-git-repo-check "say hello in one word"
explicit observe claude -- --help
explicit observe list
explicit observe report --latest
explicit codex
explicit codex --observe
explicit claude
explicit codex -m gpt-5.4
explicit claude -- --help
cargo run -- shell --command 'pwd; command -v cargo; cargo --version'
```

`explicit codex ...` and `explicit claude ...` pass everything after the subcommand directly to the agent binary. If you need sandbox-specific controls such as `--root`, `--block-network`, or `--no-services`, use `explicit shell --command ...` instead.

`explicit shell`, `explicit codex`, `explicit claude`, and the observed agent variants also accept `--dangerously-use-end-of-life-versions` if you intentionally need to keep working with a runtime that the embedded `endoflife.date` snapshot marks as unsupported.

## GitHub App Auth

`explicit` can mint short-lived GitHub App installation tokens for sandboxed agents automatically.

Run:

```bash
explicit github-app
```

This prints:

- where to create the app in GitHub
- which permissions to start with
- which XDG config path `explicit` reads
- example config

Config lives in the user XDG config path, not in the repository:

- `$XDG_CONFIG_HOME/explicit/config.toml`
- fallback: `~/.config/explicit/config.toml`

If that file contains a `[github_app]` section, `explicit` uses it by default for agent launches. No repo-local `explicit.toml` setting is needed.

Example:

```toml
[github_app]
app_id = 123456
private_key_file = "github-app.pem"

# optional
installation_id = 7890123
base_url = "https://api.github.com"
extra_repositories = ["my-org/shared-submodule"]
```

Notes:

- `private_key_file` may be absolute, `~/...`, or relative to the XDG config directory
- if `installation_id` is omitted, `explicit` looks it up from the current repo GitHub remote
- minted tokens are short-lived
- tokens are injected into sandbox env as `GH_TOKEN` and `GITHUB_TOKEN`
- tokens are not written into project config files or `.nono/runtime/shell-env.json`
- repository restriction is based on current repo plus same-owner GitHub submodules and any `extra_repositories`

Set `enabled = false` under `[github_app]` to keep the config file present but disable minting.

## Observability

`explicit observe codex` and `explicit observe claude` add a run-scoped SQLite event store on top of the existing sandbox.

Plain `explicit codex` and `explicit claude` also publish a live run snapshot over a Unix socket in the project root:

- `.explicit-observe.sock`

That lets another CLI in the same folder attach with:

```bash
explicit observe
```

If a live socket exists, `explicit observe` renders the current run state from that socket. If there is no live run, it falls back to the latest saved observability report.

It currently captures:

- model input and output from Codex session JSONL
- raw terminal transcript bytes and a console preview for observed Claude/Codex runs
- token usage events
- shell tool calls and outputs
- web search events
- patch apply events
- derived file touches from parsed shell commands and patch metadata
- environment variable access events when the observed process runs on Linux with `LD_PRELOAD`

Observed runs are written under:

- `.nono/observability/<run-id>/events.sqlite`
- `.nono/observability/<run-id>/console.typescript` for the raw captured terminal session

You can inspect recorded runs with:

```bash
explicit observe list
explicit observe report --latest
explicit observe report --run <run-id>
```

You can also use the shorthand:

```bash
explicit codex --observe
explicit claude --observe
```

This uses the same sandbox as the normal agent launch, then ingests the run-scoped telemetry after the process exits. Codex gets session JSONL ingestion on top, and both Codex and Claude observed runs now save a raw terminal transcript plus a console preview in the SQLite report. Claude still does not have a Claude-native structured session ingestor yet, so its deepest telemetry is currently the terminal transcript plus runtime and environment data.

The current observability implementation does not yet do full MITM network capture or kernel-level file tracing. Environment access tracing is currently implemented only on Linux; the macOS dyld path still needs a more reliable interposition strategy. The exploration and planned next layers are documented in [docs/observability.md](docs/observability.md).

Planned PostgreSQL query capture and SQL-plan linting for sandboxed local development is specified in [docs/postgres-query-analysis.md](docs/postgres-query-analysis.md).

The sandbox is intentionally narrow. It allows:

- the project root
- `.devenv`, `.nono`, `.codex`, and `.claude` in the project
- user-level agent config directories such as `~/.codex` and `~/.claude`
- detected cache directories such as `~/.cargo`, `~/.mix`, `~/.hex`, npm and pnpm caches, Maven and Gradle caches, and similar language-specific locations
- the minimal executable and system paths needed to run the realized environment and agent binaries

## Stop Hooks

`explicit` writes:

- `.nono/guard-commands.json`
- `.claude/settings.local.json`
- `.codex/hooks.json`
- `.codex/config.toml`

The stop hook blocks agent shutdown if any verification check fails.

Both the shared agent stop hooks and the managed `pre-push` git hook delegate to `explicit verify`, so the check logic lives in one place.

For Claude, `explicit` also installs a `PreToolUse` Bash hook that protects the sandboxed SSH setup. If Claude tries to use the host `~/.ssh/known_hosts` path directly, `explicit` either rewrites the command to the project-scoped `known_hosts` file it prepared for the sandbox or blocks the command with a clear reason when no safe replacement exists.

At a monorepo root, that means one root hook can block exit when any discovered leaf project is broken.

For example, if a project exposes `cargo fmt --check`, `cargo clippy`, `cargo build --release`, `cargo test`, `cargo llvm-cov --fail-under-lines 80`, `mix test --cover`, `pytest`, `pnpm test`, or `make build`, those commands become part of the stop gate.

`explicit verify` also enforces a few repository-level policies:

- git repositories must include a top-level `README.md`
- local file links in `README.md` must be relative, must not escape the git repository, and must point to existing files
- git repositories must end `README.md` with exactly one `## License` section that has at least one word of paragraph content
- package-manager install directories such as `node_modules/`, `deps/`, and `vendor/` must be gitignored and must not be committed
- git repositories must ignore `.DS_Store`
- `mix.exs` projects must include Credo and pass `mix credo --strict`
- `mix.exs` projects with Ecto migrations must not leave pending migrations in the development database; user-facing `verify` suggests `mix ecto.migrate`, and stop hooks will try to run it before other checks
- Rust projects must keep line coverage at or above 80% via `cargo llvm-cov`
- Elixir projects must keep `mix test --cover` coverage enforcement enabled at 80% or higher
- Phoenix projects must replace the generated getting started home page before shipping it
- Rails projects must replace the generated getting started page by defining a real root route
- public GitHub repositories must include a `LICENSE` file
- public GitHub repositories must include GitHub Actions workflows that run automatically and cover the detected lint, build, test, and coverage commands
- existing GitHub Actions workflows are syntax-checked, using `actionlint` when it is available in the environment and a YAML/shape validator as fallback

Verification is intentionally sequential. It reports only the highest-priority failing item on each run, so agents get one concrete thing to fix before the next blocker is revealed.

When `devenv` is available, `explicit verify` prefers the nearest existing ancestor `devenv.nix`. If the current folder has no `devenv.nix`, it walks upward and runs checks from that ancestor shell while still executing the command in the original project directory. If no ancestor exists, it prepares local managed `devenv` files first. If `verify` is already running inside that same `devenv shell`, it reuses the current shell instead of nesting another one.

When verification detects local services such as PostgreSQL, it starts only the matching `devenv` service processes before running checks. Generated PostgreSQL configs prefer loopback TCP so `localhost:5432` works when that port is free, while the `devenv` runtime socket remains available for tools that use standard `PG*` environment variables.

Interactive terminal runs show progress lines, any services started for verification, and workspace discovery notes when the root analysis merged leaf projects. Non-interactive runs collapse to `[PASS]` on success or a single failure report on error.

If no concrete lint, build, or test command is detected, the hook remains advisory and allows exit.

## Workspace Roots

If you run `explicit` at a repository root, or in a directory with an `explicit.toml` workspace section, it treats that directory as a workspace root and tries to discover leaf projects automatically. The goal is that `explicit apply`, `explicit verify`, `explicit codex`, and `explicit claude` all work from the top of a typical monorepo without a hand-written orchestration file. Leaf directories inside a repo do not auto-discover nested workspaces on their own.

Leaf project markers include:

- `package.json`
- `Cargo.toml`
- `go.mod`
- `mix.exs`
- `pyproject.toml`, `requirements.txt`
- `Gemfile`, `Bundlefile`
- `composer.json`
- `pom.xml`, `build.gradle`, `build.gradle.kts`, `gradlew`
- `Makefile` when it exposes `lint`, `build`, `test`, or `check`
- `terragrunt.hcl`
- directories with direct `*.tf` files

Workspace container markers include:

- `package.json#workspaces`
- `pnpm-workspace.yaml`
- `Cargo.toml [workspace]`

Normal leaf projects stop recursive discovery below that subtree. This is intentional so a React Native app leaf does not also turn `android/` into a second independent Gradle leaf unless you explicitly model it that way.

The merged workspace analysis:

- prefixes leaf commands as `cd <member> && ...`
- merges packages, services, Nix options, and language enables across the workspace
- makes the root stop hook and `explicit verify` cover those leaf commands
- emits explicit workspace notes in `doctor`, `verify`, and shell launch output
- prefers OpenTofu for generic `*.tf` infrastructure roots, while keeping `terragrunt.hcl` on Terragrunt. The package stays `opentofu`, but generated commands use the actual CLI name `tofu`.
- ignores common dependency and build trees such as `deps/`, `_build/`, `node_modules/`, `.terraform/`, and `target/`

If multiple leaf projects would force different shared-shell runtime pins, `explicit` fails analysis instead of guessing which version the root `devenv` shell should pin. Soft manifest constraints without a generated shell pin do not fail the workspace by themselves.

If auto-discovery needs help, add an optional `explicit.toml` file at the repo root:

```toml
[workspace]
auto_discover = true
members = ["tools/custom"]
exclude = ["examples", "docs/generated"]
```

`members` lets you force extra leaf roots into the analysis, and `exclude` lets you prune paths that should not participate in root-level verification.

The same `explicit.toml` file can also declare SSH deploy hosts:

```toml
[deploy]
hosts = ["deploy-alias", "prod.example.com", "ssh://git@deploy.example.com:2222/app"]
ssh_agent_hosts = ["deploy-alias", "github.com"]
# or: use_ssh_agent = true
```

Plain SSH aliases from `~/.ssh/config` or `~/.ssh/known_hosts` are valid here too. When deploy hosts are configured, `explicit shell`, `explicit codex`, and `explicit claude` create a project-scoped `.nono/runtime/known_hosts` file from matching entries in your local `~/.ssh/known_hosts`, plus a project-scoped `.nono/runtime/ssh_config` file for opted-in aliases resolved through `ssh -G`. `explicit` also folds in SSH-style Git remote hosts such as `git@github.com:owner/repo.git`, and if a host is still missing locally it attempts `ssh-keyscan` into the project-scoped `known_hosts` file instead of touching the real `~/.ssh/known_hosts`. That runtime `known_hosts` file stays writable inside the sandbox so agents can append safe project-local host keys without widening access to your personal SSH files.

If you set `ssh_agent_hosts`, `explicit` writes `IdentityAgent <host SSH_AUTH_SOCK>` for those hosts into the generated project-scoped `ssh_config`. If you set `use_ssh_agent = true`, it does that for every configured deploy host plus any SSH-style Git remote hosts discovered from the repository. The host agent socket itself is allowed into the sandbox only when one of those options is enabled.

You can also opt into parallel agent routing. When the current project root already has a live `.explicit-observe.sock`, `explicit codex`, `explicit claude`, `explicit observe codex`, and `explicit observe claude` can automatically create or reuse a separate Git worktree and launch the next agent there instead of failing on the shared socket:

```toml
[parallel]
enabled = true
worktree_root = "../.explicit-worktrees/stuffix"
base_branch = "main"
branch_prefix = "agents"

[parallel.env]
DATABASE_URL = "ecto://postgres:postgres@127.0.0.1:5432/stuffix_dev_{slot}"
PGDATABASE = "stuffix_dev_{slot}"
MIX_TEST_PARTITION = "{slot}"
STUFFIX_INSTANCE = "{session}"
```

Parallel routing reads these environment variables when present:

- `EXPLICIT_PARALLEL_SESSION`: preferred session or issue slug, used for the worktree path and branch name
- `EXPLICIT_AGENT_ISSUE`: fallback issue slug if `EXPLICIT_PARALLEL_SESSION` is unset
- `EXPLICIT_PARALLEL_SLOT`: optional numeric slot override used by `{slot}`

If neither session variable is set, `explicit` allocates `slot-02`, `slot-03`, and so on. Each auto-created worktree gets a branch such as `agents/issue-123-fix-login` plus a `.nono/parallel-session.json` file that keeps the assigned slot stable on reuse. The `{slot}`, `{session}`, `{branch}`, and `{worktree}` placeholders in `[parallel.env]` are expanded before the sandbox launches, which makes it practical to isolate development and test databases per concurrent agent while keeping one shared Postgres service process.

`explicit.toml` itself is always treated as read-only inside the sandbox, and on macOS it also gets an explicit deny-write rule so an agent cannot silently expand its own allowlist while it is running.

You can also add explicit sandbox allowances when a project needs a specific host file or directory that the heuristics would not normally grant:

```toml
[sandbox]
read_only_files = ["~/.config/sops/age/secure-enclave-key.txt"]
read_only_dirs = []
read_write_files = []
read_write_dirs = ["tmp/runtime-cache"]
```

`read_only_files`, `read_only_dirs`, `read_write_files`, and `read_write_dirs` accept paths relative to the project root, absolute paths, `~/...`, `$HOME/...`, or `${HOME}/...`. Prefer `~/...` in the config when the path lives under your home directory. This is the right place to allow a single deployment key, token cache, or generated runtime directory without broadening access to the whole parent tree.

When `explicit.toml` exists, the sandbox also protects it from writes on macOS so an LLM cannot silently expand its own allowlist while it is running.

## Generated Files

Files managed by the tool:

- [explicit.generated.deps.nix](explicit.generated.deps.nix): generated language, package, and service settings
- `.explicit-observe.sock`: live per-project run socket while an agent is active
- `.nono/analysis.json`: raw scan result
- `.nono/sandbox-plan.json`: resolved sandbox permissions
- `.nono/guard-commands.json`: generated metadata for detected lint, build, test, and coverage commands
- `.nono/pre-push-verify.sh`: git-hook launcher that delegates to `explicit verify`
- `.git/hooks/pre-push`: managed wrapper that chains any preserved user hook, then runs `.nono/pre-push-verify.sh`
- `.nono/observability/<run-id>/events.sqlite`: observed Codex run data

[devenv.nix](devenv.nix) is treated as the user-owned entrypoint. `explicit` only ensures the generated import exists and leaves the rest of the file under user control.

## Current Heuristics

Today the detector understands common patterns for:

- Rust
- JavaScript and TypeScript
- Python
- Go
- Elixir
- Ruby
- PHP
- Java
- PostgreSQL, Redis, and MySQL from Compose-style service definitions

It also has a built-in native dependency registry for common packaging failures, stored in [registry.toml](registry.toml). The registry is versioned and each rule carries:

- a stable rule id
- an ecosystem and matcher type
- packages, services, and extra toolchains to enable
- a confidence level
- source URLs for the rule

The current rule set covers, for example:

- Ruby and Rails: `nokogiri`, `pg`, `mysql2`, `sqlite3`, `ffi`, `sidekiq`
- Python and Django: `psycopg`, `psycopg2`, `lxml`, `pillow`, `mysqlclient`, `maturin`
- JavaScript and Next.js: `sharp`, `canvas`, `better-sqlite3`, `sqlite3`, `prisma`, `pg`, `mysql2`, `ioredis`
- Elixir and Phoenix: `postgrex`, `myxql`, `exqlite`, `rustler`, `redix`
- Rust: `openssl`, `openssl-sys`, `rusqlite`, `libsqlite3-sys`, `pq-sys`, `sqlx`, `diesel`
- Go: `mattn/go-sqlite3`, `lib/pq`, `pgx`, `go-sql-driver/mysql`, `go-redis`
- PHP and Laravel-style stacks: `ext-pgsql`, `ext-pdo_pgsql`, `ext-redis`, `ext-gd`, `ext-imagick`, `ext-zip`

Those rules add the matching `nixpkgs` system packages, enable local services when the dependency clearly implies one, and can also enable extra toolchains such as Rust for `maturin` or `rustler`.

This is heuristic-driven, not a full project evaluator. When a project is unusual, `explicit` should still give a useful baseline, but you may need to extend `devenv.nix` manually.

## Project Layout

Important files in this repo:

- [src/main.rs](src/main.rs): CLI entrypoint
- [src/analysis.rs](src/analysis.rs): project detection and sandbox planning
- [src/registry.rs](src/registry.rs): TOML-backed cross-language native dependency and service registry loader
- [registry.toml](registry.toml): versioned rule data with confidence levels and source URLs
- [src/devenv_file.rs](src/devenv_file.rs): `rnix`-based `devenv.nix` inspection and generated file rendering
- [src/runtime.rs](src/runtime.rs): `devenv` orchestration and shell launch
- [src/sandbox.rs](src/sandbox.rs): `nono` sandbox application and exec
- [src/hooks.rs](src/hooks.rs): Claude and Codex hook generation
- [flake.nix](flake.nix): Nix packaging and app entrypoints
- [devenv.nix](devenv.nix): repo-level `devenv` entrypoint

## Development

Useful commands while working on the tool itself:

```bash
cargo fmt
cargo test
cargo run -- doctor
nix build .#explicit
```

## Status

The current implementation is aimed at being a strong baseline:

- it makes tool and permission assumptions visible
- it generates a usable `devenv` layer automatically
- it gives Claude and Codex the same stop policy
- it launches agents inside a narrower sandbox than the host machine

It does not yet try to fully infer every project-specific service, package, or permission edge case.

## License

See [LICENSE](LICENSE) for the full license text.
