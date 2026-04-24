use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::hash::{Hash, Hasher};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::thread::JoinHandle;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::analysis::Analysis;
use crate::env_trace;
use crate::runtime;

pub struct ObservedAgentOptions<'a> {
    pub agent: &'a str,
    pub command: String,
    pub agent_args: &'a [String],
    pub block_network: bool,
    pub no_services: bool,
    pub no_sandbox: bool,
    pub dangerously_use_end_of_life_versions: bool,
    pub extra_env: BTreeMap<String, String>,
}

pub fn list_runs(root: &Path) -> Result<()> {
    let mut runs = load_run_rows(root)?;
    runs.sort_by(|left, right| right.started_at_ms.cmp(&left.started_at_ms));

    if runs.is_empty() {
        println!(
            "No observed runs under {}",
            observability_root(root).display()
        );
        return Ok(());
    }

    for run in runs {
        println!(
            "{}  {}  {}  messages={} commands={} env={} console_bytes={} tokens={}  {}",
            run.run_id,
            run.status,
            format_started_at(run.started_at_ms),
            run.message_count,
            run.exec_command_count,
            run.env_access_count,
            run.console_transcript_bytes,
            run.latest_total_tokens
                .map(|value| value.to_string())
                .unwrap_or_else(|| "unknown".to_string()),
            run.db_path.display()
        );
    }

    Ok(())
}

pub fn attach_live_run(root: &Path) -> Result<bool> {
    let socket_path = socket_path(root);
    if !socket_path.exists() {
        return Ok(false);
    }

    loop {
        let snapshot = match fetch_live_snapshot(&socket_path) {
            Ok(snapshot) => snapshot,
            Err(_) => return Ok(false),
        };
        render_live_snapshot(&snapshot);
        if snapshot.is_terminal() {
            return Ok(true);
        }
        thread::sleep(Duration::from_millis(750));
    }
}

pub fn live_socket_active(root: &Path) -> Result<bool> {
    let socket_path = socket_path(root);
    if !socket_path.exists() {
        return Ok(false);
    }
    Ok(fetch_live_snapshot(&socket_path).is_ok())
}

pub fn print_report(root: &Path, run: Option<&str>, latest: bool) -> Result<()> {
    let run = match (run, latest) {
        (Some(run_id), _) => find_run_row(root, run_id)?,
        (None, true) | (None, false) => latest_run_row(root)?,
    };

    let conn = Connection::open(&run.db_path)
        .with_context(|| format!("failed to open {}", run.db_path.display()))?;
    configure_db(&conn)?;
    init_schema(&conn)?;

    let prompt_preview = conn
        .query_row(
            "select content from messages where run_id = ?1 and role = 'user' order by id asc limit 1",
            params![&run.run_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    let answer_preview = conn
        .query_row(
            "select content from messages where run_id = ?1 and role = 'assistant' order by id desc limit 1",
            params![&run.run_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?;

    let top_commands = top_commands(&conn, &run.run_id)?;
    let failed_commands = failed_commands(&conn, &run.run_id)?;
    let top_files = top_files(&conn, &run.run_id)?;
    let top_env_keys = top_env_keys(&conn, &run.run_id)?;
    let transcript_preview = console_transcript_preview(&conn, &run.run_id)?;

    println!("Run: {}", run.run_id);
    println!("Status: {}", run.status);
    println!("Started: {}", format_started_at(run.started_at_ms));
    println!("Database: {}", run.db_path.display());
    println!("Agent: {}", run.agent);
    println!("Messages: {}", run.message_count);
    println!("Token events: {}", run.token_count_events);
    println!("Shell commands: {}", run.exec_command_count);
    println!("Web searches: {}", run.web_search_count);
    println!("Patch events: {}", run.patch_event_count);
    println!("Derived file touches: {}", run.file_touch_count);
    println!("Env accesses: {}", run.env_access_count);
    println!("Console transcript bytes: {}", run.console_transcript_bytes);
    println!(
        "Latest total tokens: {}",
        run.latest_total_tokens
            .map(|value| value.to_string())
            .unwrap_or_else(|| "unknown".to_string())
    );
    println!(
        "Prompt preview: {}",
        prompt_preview
            .as_deref()
            .map(truncate_preview)
            .unwrap_or("none".to_string())
    );
    println!(
        "Answer preview: {}",
        answer_preview
            .as_deref()
            .map(truncate_preview)
            .unwrap_or("none".to_string())
    );
    println!(
        "Console preview: {}",
        transcript_preview
            .as_deref()
            .map(truncate_preview)
            .unwrap_or("none".to_string())
    );

    println!("Top commands:");
    if top_commands.is_empty() {
        println!("  none");
    } else {
        for row in top_commands {
            println!(
                "  {}  count={}  failures={}  output_bytes={}",
                truncate_preview(&row.command),
                row.count,
                row.failures,
                row.output_bytes
            );
        }
    }

    println!("Failed commands:");
    if failed_commands.is_empty() {
        println!("  none");
    } else {
        for row in failed_commands {
            println!(
                "  exit={}  count={}  {}",
                row.exit_code,
                row.count,
                truncate_preview(&row.command)
            );
        }
    }

    println!("Touched files:");
    if top_files.is_empty() {
        println!("  none");
    } else {
        for row in top_files {
            println!(
                "  {}  count={}  ops={}",
                truncate_preview(&row.path),
                row.count,
                row.ops.join(", ")
            );
        }
    }

    println!("Top env keys:");
    if top_env_keys.is_empty() {
        println!("  none");
    } else {
        for row in top_env_keys {
            println!(
                "  {}  count={}  values={}  latest={}",
                row.key,
                row.count,
                row.distinct_values,
                row.latest_value
                    .as_deref()
                    .map(truncate_preview)
                    .unwrap_or_else(|| "missing".to_string())
            );
        }
    }

    Ok(())
}

pub fn launch_live_agent(
    root: &Path,
    analysis: &Analysis,
    agent: &str,
    command: String,
    block_network: bool,
    no_services: bool,
    no_sandbox: bool,
    dangerously_use_end_of_life_versions: bool,
    extra_env: BTreeMap<String, String>,
) -> Result<ExitCode> {
    let server = LiveRunServer::start(
        root,
        LiveRunSnapshot::new(root, agent, &command, false, None, None, None),
    )?;
    server.update(|snapshot| snapshot.state = "running".to_string());
    let status = runtime::launch_shell(
        root,
        analysis,
        runtime::LaunchShellOptions {
            agent: Some(agent),
            command: Some(&command),
            block_network,
            no_services,
            no_sandbox,
            dangerously_use_end_of_life_versions,
            extra_env: (!extra_env.is_empty()).then_some(&extra_env),
            transcript_path: None,
            skip_stop_hooks: false,
        },
    )?;
    server.finish(status);
    Ok(status)
}

pub fn launch_observed_agent(
    root: &Path,
    analysis: &Analysis,
    options: ObservedAgentOptions<'_>,
) -> Result<ExitCode> {
    let run = ObservationRun::create(
        root,
        analysis,
        options.agent,
        &options.command,
        options.agent_args,
    )?;
    let server = LiveRunServer::start(
        root,
        LiveRunSnapshot::new(
            root,
            options.agent,
            &options.command,
            true,
            Some(run.run_id.clone()),
            Some(run.db_path.clone()),
            Some(run.transcript_log_path.clone()),
        ),
    )?;
    let session_snapshot = if options.agent == "codex" {
        snapshot_session_files(&codex_sessions_root()?)?
    } else {
        BTreeMap::new()
    };
    let mut trace_env = env_trace::build_injection_env(&run.trace_log_path)?;
    trace_env.extend(options.extra_env.clone());

    server.update(|snapshot| snapshot.state = "running".to_string());
    let status = runtime::launch_shell(
        root,
        analysis,
        runtime::LaunchShellOptions {
            agent: Some(options.agent),
            command: Some(&options.command),
            block_network: options.block_network,
            no_services: options.no_services,
            no_sandbox: options.no_sandbox,
            dangerously_use_end_of_life_versions: options.dangerously_use_end_of_life_versions,
            extra_env: (!trace_env.is_empty()).then_some(&trace_env),
            transcript_path: Some(&run.transcript_log_path),
            skip_stop_hooks: false,
        },
    )?;
    server.update(|snapshot| snapshot.state = "ingesting".to_string());

    let mut summary = ImportSummary::default();
    if options.agent == "codex" {
        let changed_files = changed_session_files(&codex_sessions_root()?, &session_snapshot)?;
        summary.merge(ingest_codex_sessions(
            &run.db_path,
            &run.run_id,
            &changed_files,
        )?);
    }
    summary.merge(ingest_env_trace_file(
        &run.db_path,
        &run.run_id,
        &run.trace_log_path,
    )?);
    summary.merge(ingest_console_transcript_file(
        &run.db_path,
        &run.run_id,
        &run.transcript_log_path,
    )?);

    server.update(|snapshot| apply_summary_to_snapshot(snapshot, &summary));
    server.finish(status);
    run.finish(&status, &summary)?;
    print_summary(&run, &summary);
    Ok(status)
}

#[derive(Debug)]
struct ObservationRun {
    run_id: String,
    root: PathBuf,
    db_path: PathBuf,
    trace_log_path: PathBuf,
    transcript_log_path: PathBuf,
}

struct LiveRunServer {
    socket_path: PathBuf,
    snapshot: Arc<Mutex<LiveRunSnapshot>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LiveRunSnapshot {
    root: String,
    agent: String,
    command: String,
    observed: bool,
    run_id: Option<String>,
    db_path: Option<String>,
    transcript_path: Option<String>,
    state: String,
    started_at_ms: i64,
    updated_at_ms: i64,
    message_count: usize,
    token_count_events: usize,
    exec_command_count: usize,
    web_search_count: usize,
    patch_event_count: usize,
    file_touch_count: usize,
    env_access_count: usize,
    console_transcript_bytes: usize,
    latest_total_tokens: Option<i64>,
}

#[derive(Debug)]
struct RunRow {
    run_id: String,
    agent: String,
    status: String,
    started_at_ms: i64,
    db_path: PathBuf,
    message_count: i64,
    token_count_events: i64,
    exec_command_count: i64,
    web_search_count: i64,
    patch_event_count: i64,
    file_touch_count: i64,
    env_access_count: i64,
    console_transcript_bytes: i64,
    latest_total_tokens: Option<i64>,
}

#[derive(Debug)]
struct CommandReportRow {
    command: String,
    count: i64,
    failures: i64,
    output_bytes: i64,
}

#[derive(Debug)]
struct FailedCommandRow {
    command: String,
    exit_code: i64,
    count: i64,
}

#[derive(Debug)]
struct FileTouchRow {
    path: String,
    count: i64,
    ops: Vec<String>,
}

#[derive(Debug)]
struct EnvAccessRow {
    key: String,
    count: i64,
    distinct_values: i64,
    latest_value: Option<String>,
}

#[derive(Debug, Default)]
struct ImportSummary {
    session_count: usize,
    message_count: usize,
    token_count_events: usize,
    exec_command_count: usize,
    web_search_count: usize,
    patch_event_count: usize,
    file_touch_count: usize,
    env_access_count: usize,
    console_transcript_bytes: usize,
    latest_total_tokens: Option<i64>,
}

struct MessageInsert<'a> {
    run_id: &'a str,
    session_id: &'a str,
    turn_id: Option<&'a str>,
    role: &'a str,
    phase: Option<&'a str>,
    content: &'a str,
    timestamp: &'a str,
}

struct FileTouchInsert<'a> {
    run_id: &'a str,
    session_id: &'a str,
    turn_id: Option<&'a str>,
    timestamp: &'a str,
    path: &'a str,
    op: &'a str,
    source: &'a str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SessionFileState {
    modified_ms: u128,
    len: u64,
}

impl LiveRunSnapshot {
    fn new(
        root: &Path,
        agent: &str,
        command: &str,
        observed: bool,
        run_id: Option<String>,
        db_path: Option<PathBuf>,
        transcript_path: Option<PathBuf>,
    ) -> Self {
        let now = unix_millis() as i64;
        Self {
            root: root.display().to_string(),
            agent: agent.to_string(),
            command: command.to_string(),
            observed,
            run_id,
            db_path: db_path.map(|value| value.display().to_string()),
            transcript_path: transcript_path.map(|value| value.display().to_string()),
            state: "starting".to_string(),
            started_at_ms: now,
            updated_at_ms: now,
            message_count: 0,
            token_count_events: 0,
            exec_command_count: 0,
            web_search_count: 0,
            patch_event_count: 0,
            file_touch_count: 0,
            env_access_count: 0,
            console_transcript_bytes: 0,
            latest_total_tokens: None,
        }
    }

    fn is_terminal(&self) -> bool {
        matches!(self.state.as_str(), "completed" | "failed")
    }
}

impl ImportSummary {
    fn merge(&mut self, other: Self) {
        self.session_count += other.session_count;
        self.message_count += other.message_count;
        self.token_count_events += other.token_count_events;
        self.exec_command_count += other.exec_command_count;
        self.web_search_count += other.web_search_count;
        self.patch_event_count += other.patch_event_count;
        self.file_touch_count += other.file_touch_count;
        self.env_access_count += other.env_access_count;
        self.console_transcript_bytes += other.console_transcript_bytes;
        if other.latest_total_tokens.is_some() {
            self.latest_total_tokens = other.latest_total_tokens;
        }
    }
}

impl LiveRunServer {
    fn start(root: &Path, snapshot: LiveRunSnapshot) -> Result<Self> {
        let socket_path = socket_path(root);
        prepare_socket_path(&socket_path)?;
        let listener = UnixListener::bind(&socket_path)
            .with_context(|| format!("failed to bind {}", socket_path.display()))?;
        listener
            .set_nonblocking(true)
            .with_context(|| format!("failed to mark {} nonblocking", socket_path.display()))?;

        let snapshot = Arc::new(Mutex::new(snapshot));
        let stop = Arc::new(AtomicBool::new(false));
        let thread_snapshot = Arc::clone(&snapshot);
        let thread_stop = Arc::clone(&stop);
        let thread =
            thread::spawn(move || run_socket_server(listener, thread_snapshot, thread_stop));

        Ok(Self {
            socket_path,
            snapshot,
            stop,
            thread: Some(thread),
        })
    }

    fn update(&self, mutator: impl FnOnce(&mut LiveRunSnapshot)) {
        if let Ok(mut snapshot) = self.snapshot.lock() {
            mutator(&mut snapshot);
            snapshot.updated_at_ms = unix_millis() as i64;
        }
    }

    fn finish(&self, status: ExitCode) {
        self.update(|snapshot| {
            snapshot.state = if status == ExitCode::SUCCESS {
                "completed".to_string()
            } else {
                "failed".to_string()
            };
        });
    }
}

impl Drop for LiveRunServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = UnixStream::connect(&self.socket_path);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        let _ = fs::remove_file(&self.socket_path);
    }
}

impl ObservationRun {
    fn create(
        root: &Path,
        analysis: &Analysis,
        agent: &str,
        command: &str,
        agent_args: &[String],
    ) -> Result<Self> {
        let run_id = unique_run_id(agent);
        let run_dir = root.join(".nono/observability").join(&run_id);
        fs::create_dir_all(&run_dir)
            .with_context(|| format!("failed to create {}", run_dir.display()))?;
        let db_path = run_dir.join("events.sqlite");

        let conn = Connection::open(&db_path)
            .with_context(|| format!("failed to open {}", db_path.display()))?;
        configure_db(&conn)?;
        init_schema(&conn)?;
        conn.execute(
            "insert into runs (
                run_id,
                agent,
                root,
                command,
                agent_args_json,
                started_at_ms,
                status,
                analysis_json,
                sandbox_plan_json
            ) values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                &run_id,
                agent,
                root.display().to_string(),
                command,
                serde_json::to_string(agent_args)?,
                unix_millis() as i64,
                "running",
                serde_json::to_string_pretty(analysis)?,
                serde_json::to_string_pretty(&analysis.sandbox_plan)?,
            ],
        )
        .context("failed to insert observability run row")?;

        Ok(Self {
            run_id,
            root: root.to_path_buf(),
            db_path,
            trace_log_path: run_dir.join("env-access.jsonl"),
            transcript_log_path: run_dir.join("console.typescript"),
        })
    }

    fn finish(&self, status: &ExitCode, summary: &ImportSummary) -> Result<()> {
        let conn = Connection::open(&self.db_path)
            .with_context(|| format!("failed to reopen {}", self.db_path.display()))?;
        configure_db(&conn)?;
        conn.execute(
            "update runs
             set ended_at_ms = ?2,
                 status = ?3,
                 session_count = ?4,
                 message_count = ?5,
                 token_count_events = ?6,
                 exec_command_count = ?7,
                 web_search_count = ?8,
                 patch_event_count = ?9,
                 file_touch_count = ?10,
                 env_access_count = ?11,
                 console_transcript_bytes = ?12,
                 latest_total_tokens = ?13
             where run_id = ?1",
            params![
                &self.run_id,
                unix_millis() as i64,
                if *status == ExitCode::SUCCESS {
                    "completed"
                } else {
                    "failed"
                },
                summary.session_count as i64,
                summary.message_count as i64,
                summary.token_count_events as i64,
                summary.exec_command_count as i64,
                summary.web_search_count as i64,
                summary.patch_event_count as i64,
                summary.file_touch_count as i64,
                summary.env_access_count as i64,
                summary.console_transcript_bytes as i64,
                summary.latest_total_tokens,
            ],
        )
        .context("failed to finalize observability run row")?;
        Ok(())
    }
}

fn print_summary(run: &ObservationRun, summary: &ImportSummary) {
    println!("Observation saved: {}", run.db_path.display());
    println!("Run: {}", run.run_id);
    println!("Root: {}", run.root.display());
    println!("Sessions ingested: {}", summary.session_count);
    println!("Messages: {}", summary.message_count);
    println!("Token events: {}", summary.token_count_events);
    println!("Shell commands: {}", summary.exec_command_count);
    println!("Web searches: {}", summary.web_search_count);
    println!("Patch events: {}", summary.patch_event_count);
    println!("Derived file touches: {}", summary.file_touch_count);
    println!("Env accesses: {}", summary.env_access_count);
    println!(
        "Console transcript bytes: {}",
        summary.console_transcript_bytes
    );
    println!(
        "Latest total tokens: {}",
        summary
            .latest_total_tokens
            .map(|value| value.to_string())
            .unwrap_or_else(|| "unknown".to_string())
    );
}

fn configure_db(conn: &Connection) -> Result<()> {
    conn.pragma_update(None, "journal_mode", "WAL")
        .context("failed to enable WAL mode")?;
    conn.pragma_update(None, "foreign_keys", "ON")
        .context("failed to enable foreign keys")?;
    Ok(())
}

fn socket_path(root: &Path) -> PathBuf {
    let project_socket = root.join(".explicit-observe.sock");
    if project_socket.as_os_str().len() < 96 {
        return project_socket;
    }

    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    root.display().to_string().hash(&mut hasher);
    std::env::temp_dir().join(format!("explicit-observe-{:016x}.sock", hasher.finish()))
}

fn prepare_socket_path(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }

    match fetch_live_snapshot(path) {
        Ok(_) => bail!(
            "an explicit live run socket is already active at {}",
            path.display()
        ),
        Err(_) => {
            fs::remove_file(path)
                .with_context(|| format!("failed to remove stale socket {}", path.display()))?;
        }
    }
    Ok(())
}

fn run_socket_server(
    listener: UnixListener,
    snapshot: Arc<Mutex<LiveRunSnapshot>>,
    stop: Arc<AtomicBool>,
) {
    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((mut stream, _)) => {
                let payload = snapshot
                    .lock()
                    .ok()
                    .and_then(|snapshot| serde_json::to_vec(&*snapshot).ok());
                if let Some(payload) = payload {
                    let _ = stream.write_all(&payload);
                    let _ = stream.write_all(b"\n");
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(100));
            }
            Err(_) => break,
        }
    }
}

fn fetch_live_snapshot(socket_path: &Path) -> Result<LiveRunSnapshot> {
    let stream = UnixStream::connect(socket_path)
        .with_context(|| format!("failed to connect to {}", socket_path.display()))?;
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .with_context(|| format!("failed to read from {}", socket_path.display()))?;
    let snapshot: LiveRunSnapshot =
        serde_json::from_str(line.trim()).context("failed to parse live run snapshot")?;
    Ok(snapshot)
}

fn render_live_snapshot(snapshot: &LiveRunSnapshot) {
    print!("\x1b[2J\x1b[H");
    println!("Project: {}", snapshot.root);
    println!("Agent: {}", snapshot.agent);
    println!("Command: {}", truncate_preview(&snapshot.command));
    println!(
        "Observed: {}",
        if snapshot.observed { "true" } else { "false" }
    );
    println!("State: {}", snapshot.state);
    if let Some(run_id) = &snapshot.run_id {
        println!("Run: {run_id}");
    }
    if let Some(db_path) = &snapshot.db_path {
        println!("Database: {db_path}");
    }
    if let Some(transcript_path) = &snapshot.transcript_path {
        println!("Transcript: {transcript_path}");
        if let Some((byte_count, preview)) =
            live_transcript_status(Path::new(transcript_path)).unwrap_or(None)
        {
            println!("Live console bytes: {byte_count}");
            println!("Live console preview: {}", truncate_preview(&preview));
        }
    }
    println!("Messages: {}", snapshot.message_count);
    println!("Token events: {}", snapshot.token_count_events);
    println!("Shell commands: {}", snapshot.exec_command_count);
    println!("Web searches: {}", snapshot.web_search_count);
    println!("Patch events: {}", snapshot.patch_event_count);
    println!("Derived file touches: {}", snapshot.file_touch_count);
    println!("Env accesses: {}", snapshot.env_access_count);
    println!(
        "Console transcript bytes: {}",
        snapshot.console_transcript_bytes
    );
    println!(
        "Latest total tokens: {}",
        snapshot
            .latest_total_tokens
            .map(|value| value.to_string())
            .unwrap_or_else(|| "unknown".to_string())
    );
    let _ = std::io::stdout().flush();
}

fn apply_summary_to_snapshot(snapshot: &mut LiveRunSnapshot, summary: &ImportSummary) {
    snapshot.message_count = summary.message_count;
    snapshot.token_count_events = summary.token_count_events;
    snapshot.exec_command_count = summary.exec_command_count;
    snapshot.web_search_count = summary.web_search_count;
    snapshot.patch_event_count = summary.patch_event_count;
    snapshot.file_touch_count = summary.file_touch_count;
    snapshot.env_access_count = summary.env_access_count;
    snapshot.console_transcript_bytes = summary.console_transcript_bytes;
    snapshot.latest_total_tokens = summary.latest_total_tokens;
}

fn observability_root(root: &Path) -> PathBuf {
    root.join(".nono/observability")
}

fn load_run_rows(root: &Path) -> Result<Vec<RunRow>> {
    let mut runs = Vec::new();
    let observe_root = observability_root(root);
    if !observe_root.exists() {
        return Ok(runs);
    }

    for entry in fs::read_dir(&observe_root)
        .with_context(|| format!("failed to read {}", observe_root.display()))?
    {
        let entry = entry?;
        let path = entry.path().join("events.sqlite");
        if !path.exists() {
            continue;
        }
        let conn = Connection::open(&path)
            .with_context(|| format!("failed to open {}", path.display()))?;
        init_schema(&conn)?;
        let row = conn
            .query_row(
                "select run_id, agent, status, started_at_ms, message_count, token_count_events, exec_command_count, web_search_count, patch_event_count, file_touch_count, env_access_count, console_transcript_bytes, latest_total_tokens from runs limit 1",
                [],
                |row| {
                    Ok(RunRow {
                        run_id: row.get(0)?,
                        agent: row.get(1)?,
                        status: row.get(2)?,
                        started_at_ms: row.get(3)?,
                        db_path: path.clone(),
                        message_count: row.get(4)?,
                        token_count_events: row.get(5)?,
                        exec_command_count: row.get(6)?,
                        web_search_count: row.get(7)?,
                        patch_event_count: row.get(8)?,
                        file_touch_count: row.get(9)?,
                        env_access_count: row.get(10)?,
                        console_transcript_bytes: row.get(11)?,
                        latest_total_tokens: row.get(12)?,
                    })
                },
            )
            .with_context(|| format!("failed to read run row from {}", path.display()))?;
        runs.push(row);
    }

    Ok(runs)
}

fn latest_run_row(root: &Path) -> Result<RunRow> {
    let mut runs = load_run_rows(root)?;
    runs.sort_by(|left, right| right.started_at_ms.cmp(&left.started_at_ms));
    runs.into_iter().next().with_context(|| {
        format!(
            "no observed runs under {}",
            observability_root(root).display()
        )
    })
}

fn find_run_row(root: &Path, run_id: &str) -> Result<RunRow> {
    load_run_rows(root)?
        .into_iter()
        .find(|row| row.run_id == run_id)
        .with_context(|| format!("observed run not found: {run_id}"))
}

fn top_commands(conn: &Connection, run_id: &str) -> Result<Vec<CommandReportRow>> {
    let mut stmt = conn.prepare(
        "select shell_command,
                count(*) as count,
                sum(case when coalesce(exit_code, 0) != 0 then 1 else 0 end) as failures,
                sum(coalesce(length(aggregated_output), 0)) as output_bytes
         from exec_commands
         where run_id = ?1
         group by shell_command
         order by count desc, output_bytes desc
         limit 5",
    )?;
    let rows = stmt
        .query_map(params![run_id], |row| {
            Ok(CommandReportRow {
                command: row.get(0)?,
                count: row.get(1)?,
                failures: row.get(2)?,
                output_bytes: row.get(3)?,
            })
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(rows)
}

fn failed_commands(conn: &Connection, run_id: &str) -> Result<Vec<FailedCommandRow>> {
    let mut stmt = conn.prepare(
        "select shell_command, exit_code, count(*) as count
         from exec_commands
         where run_id = ?1 and coalesce(exit_code, 0) != 0
         group by shell_command, exit_code
         order by count desc, shell_command asc
         limit 5",
    )?;
    let rows = stmt
        .query_map(params![run_id], |row| {
            Ok(FailedCommandRow {
                command: row.get(0)?,
                exit_code: row.get(1)?,
                count: row.get(2)?,
            })
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(rows)
}

fn top_files(conn: &Connection, run_id: &str) -> Result<Vec<FileTouchRow>> {
    let mut stmt = conn.prepare(
        "select path, count(*) as count, group_concat(distinct op)
         from file_touches
         where run_id = ?1
         group by path
         order by count desc, path asc
         limit 5",
    )?;
    let rows = stmt
        .query_map(params![run_id], |row| {
            let ops = row
                .get::<_, Option<String>>(2)?
                .unwrap_or_default()
                .split(',')
                .filter(|value| !value.is_empty())
                .map(|value| value.to_string())
                .collect::<Vec<_>>();
            Ok(FileTouchRow {
                path: row.get(0)?,
                count: row.get(1)?,
                ops,
            })
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(rows)
}

fn top_env_keys(conn: &Connection, run_id: &str) -> Result<Vec<EnvAccessRow>> {
    let mut stmt = conn.prepare(
        "select key,
                count(*) as count,
                count(distinct coalesce(value, '')) as distinct_values,
                (
                    select value
                    from env_accesses latest
                    where latest.run_id = env_accesses.run_id
                      and latest.key = env_accesses.key
                    order by latest.id desc
                    limit 1
                ) as latest_value
         from env_accesses
         where run_id = ?1
         group by key
         order by count desc, key asc
         limit 10",
    )?;
    let rows = stmt
        .query_map(params![run_id], |row| {
            Ok(EnvAccessRow {
                key: row.get(0)?,
                count: row.get(1)?,
                distinct_values: row.get(2)?,
                latest_value: row.get(3)?,
            })
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(rows)
}

fn console_transcript_preview(conn: &Connection, run_id: &str) -> Result<Option<String>> {
    let content = conn
        .query_row(
            "select content from console_transcripts where run_id = ?1 limit 1",
            params![run_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    Ok(content
        .as_deref()
        .map(sanitize_transcript_preview)
        .filter(|value| !value.trim().is_empty()))
}

fn sanitize_transcript_preview(content: &str) -> String {
    let ansi = regex::Regex::new(r"\x1b\[[0-9;?]*[ -/]*[@-~]").expect("valid ansi regex");
    let without_ansi = ansi.replace_all(content, "");
    let cleaned = without_ansi
        .chars()
        .filter(|ch| !ch.is_control() || matches!(ch, '\n' | '\r' | '\t'))
        .collect::<String>();
    cleaned
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .rev()
        .take(4)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<Vec<_>>()
        .join(" | ")
}

fn live_transcript_status(path: &Path) -> Result<Option<(usize, String)>> {
    if !path.exists() {
        return Ok(None);
    }

    let raw = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    if raw.is_empty() {
        return Ok(None);
    }

    let preview = sanitize_transcript_preview(&String::from_utf8_lossy(&raw));
    Ok(Some((raw.len(), preview)))
}

fn truncate_preview(value: &str) -> String {
    let max_len = 120;
    let char_count = value.chars().count();
    if char_count <= max_len {
        return value.replace('\n', " ");
    }
    let truncated = value
        .chars()
        .take(max_len.saturating_sub(1))
        .collect::<String>();
    format!("{}…", truncated.replace('\n', " "))
}

fn format_started_at(started_at_ms: i64) -> String {
    format!("{started_at_ms}")
}

fn init_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "
        create table if not exists runs (
            run_id text primary key,
            agent text not null,
            root text not null,
            command text not null,
            agent_args_json text not null,
            started_at_ms integer not null,
            ended_at_ms integer,
            status text not null,
            analysis_json text not null,
            sandbox_plan_json text not null,
            session_count integer not null default 0,
            message_count integer not null default 0,
            token_count_events integer not null default 0,
            exec_command_count integer not null default 0,
            web_search_count integer not null default 0,
            patch_event_count integer not null default 0,
            file_touch_count integer not null default 0,
            env_access_count integer not null default 0,
            console_transcript_bytes integer not null default 0,
            latest_total_tokens integer
        );

        create table if not exists sessions (
            session_id text primary key,
            run_id text not null,
            source_path text not null,
            source_modified_ms integer not null,
            imported_at_ms integer not null,
            raw_event_count integer not null default 0,
            foreign key (run_id) references runs(run_id)
        );

        create table if not exists messages (
            id integer primary key,
            run_id text not null,
            session_id text not null,
            turn_id text,
            role text not null,
            phase text,
            content text not null,
            created_at text not null
        );
        create index if not exists idx_messages_run_id on messages(run_id);
        create index if not exists idx_messages_turn_id on messages(turn_id);

        create table if not exists token_usage (
            id integer primary key,
            run_id text not null,
            session_id text not null,
            turn_id text,
            created_at text not null,
            input_tokens integer,
            cached_input_tokens integer,
            output_tokens integer,
            reasoning_output_tokens integer,
            total_tokens integer,
            raw_json text not null
        );
        create index if not exists idx_token_usage_run_id on token_usage(run_id);

        create table if not exists exec_commands (
            id integer primary key,
            run_id text not null,
            session_id text not null,
            turn_id text,
            call_id text,
            process_id text,
            created_at text not null,
            shell_command text not null,
            cwd text,
            parsed_cmd_json text,
            exit_code integer,
            duration_ms integer,
            status text,
            aggregated_output text,
            raw_json text not null
        );
        create index if not exists idx_exec_commands_run_id on exec_commands(run_id);
        create index if not exists idx_exec_commands_turn_id on exec_commands(turn_id);

        create table if not exists web_searches (
            id integer primary key,
            run_id text not null,
            session_id text not null,
            turn_id text,
            call_id text,
            created_at text not null,
            query text not null,
            action_type text,
            queries_json text,
            raw_json text not null
        );
        create index if not exists idx_web_searches_run_id on web_searches(run_id);

        create table if not exists patch_events (
            id integer primary key,
            run_id text not null,
            session_id text not null,
            turn_id text,
            call_id text,
            created_at text not null,
            success integer not null,
            stdout text,
            stderr text,
            changes_json text,
            raw_json text not null
        );
        create index if not exists idx_patch_events_run_id on patch_events(run_id);

        create table if not exists file_touches (
            id integer primary key,
            run_id text not null,
            session_id text not null,
            turn_id text,
            created_at text not null,
            path text not null,
            op text not null,
            source text not null
        );
        create index if not exists idx_file_touches_run_id on file_touches(run_id);
        create index if not exists idx_file_touches_path on file_touches(path);

        create table if not exists env_accesses (
            id integer primary key,
            run_id text not null,
            created_at_ms integer not null,
            process_id integer not null,
            parent_process_id integer not null,
            operation text not null,
            key text not null,
            found integer not null,
            value text,
            executable text,
            raw_json text not null
        );
        create index if not exists idx_env_accesses_run_id on env_accesses(run_id);
        create index if not exists idx_env_accesses_key on env_accesses(key);

        create table if not exists console_transcripts (
            run_id text primary key,
            captured_at_ms integer not null,
            byte_count integer not null,
            content text not null
        );
        ",
    )
    .context("failed to initialize observability schema")?;
    ensure_column(
        conn,
        "runs",
        "env_access_count",
        "integer not null default 0",
    )?;
    ensure_column(
        conn,
        "runs",
        "console_transcript_bytes",
        "integer not null default 0",
    )?;
    Ok(())
}

fn ensure_column(conn: &Connection, table: &str, column: &str, definition: &str) -> Result<()> {
    let mut stmt = conn.prepare(&format!("pragma table_info({table})"))?;
    let exists = stmt
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<std::result::Result<Vec<_>, _>>()?
        .into_iter()
        .any(|name| name == column);
    if exists {
        return Ok(());
    }

    conn.execute(
        &format!("alter table {table} add column {column} {definition}"),
        [],
    )
    .with_context(|| format!("failed to add {column} to {table}"))?;
    Ok(())
}

fn codex_sessions_root() -> Result<PathBuf> {
    let home = dirs::home_dir().context("failed to resolve home directory")?;
    Ok(home.join(".codex/sessions"))
}

fn snapshot_session_files(root: &Path) -> Result<BTreeMap<PathBuf, SessionFileState>> {
    let mut files = BTreeMap::new();
    if !root.exists() {
        return Ok(files);
    }

    for path in walk_jsonl_files(root)? {
        let metadata = fs::metadata(&path)
            .with_context(|| format!("failed to read metadata for {}", path.display()))?;
        files.insert(path, session_file_state(&metadata));
    }
    Ok(files)
}

fn changed_session_files(
    root: &Path,
    before: &BTreeMap<PathBuf, SessionFileState>,
) -> Result<Vec<PathBuf>> {
    let after = snapshot_session_files(root)?;
    let mut created = after
        .into_iter()
        .filter_map(|(path, state)| before.get(&path).is_none().then_some((path, state)))
        .map(|(path, _)| path)
        .collect::<Vec<_>>();
    created.sort();
    Ok(created)
}

fn walk_jsonl_files(root: &Path) -> Result<Vec<PathBuf>> {
    let mut stack = vec![root.to_path_buf()];
    let mut files = Vec::new();

    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir)
            .with_context(|| format!("failed to read directory {}", dir.display()))?
        {
            let entry = entry?;
            let path = entry.path();
            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                stack.push(path);
            } else if path.extension().and_then(|value| value.to_str()) == Some("jsonl") {
                files.push(path);
            }
        }
    }

    Ok(files)
}

fn session_file_state(metadata: &fs::Metadata) -> SessionFileState {
    let modified_ms = metadata
        .modified()
        .ok()
        .and_then(system_time_to_millis)
        .unwrap_or_default();
    SessionFileState {
        modified_ms,
        len: metadata.len(),
    }
}

fn system_time_to_millis(value: SystemTime) -> Option<u128> {
    value
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|value| value.as_millis())
}

fn unix_millis() -> u128 {
    system_time_to_millis(SystemTime::now()).unwrap_or_default()
}

fn unique_run_id(agent: &str) -> String {
    static RUN_COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let counter = RUN_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{agent}-{nanos}-{}-{counter}", std::process::id())
}

#[derive(Debug, Deserialize)]
struct EnvTraceRecord {
    ts_ms: i64,
    pid: i32,
    ppid: i32,
    operation: String,
    key: String,
    found: bool,
    value: Option<String>,
    executable: Option<String>,
}

fn ingest_env_trace_file(db_path: &Path, run_id: &str, trace_path: &Path) -> Result<ImportSummary> {
    let mut summary = ImportSummary::default();
    if !trace_path.exists() {
        return Ok(summary);
    }

    let conn = Connection::open(db_path)
        .with_context(|| format!("failed to open {}", db_path.display()))?;
    configure_db(&conn)?;

    let file = File::open(trace_path)
        .with_context(|| format!("failed to open {}", trace_path.display()))?;
    for line in BufReader::new(file).lines() {
        let line = line.with_context(|| format!("failed to read {}", trace_path.display()))?;
        if line.trim().is_empty() {
            continue;
        }
        let record: EnvTraceRecord = serde_json::from_str(&line)
            .with_context(|| format!("failed to parse {}", trace_path.display()))?;
        insert_env_access(&conn, run_id, &record, &line)?;
        summary.env_access_count += 1;
    }

    Ok(summary)
}

fn ingest_console_transcript_file(
    db_path: &Path,
    run_id: &str,
    transcript_path: &Path,
) -> Result<ImportSummary> {
    let mut summary = ImportSummary::default();
    if !transcript_path.exists() {
        return Ok(summary);
    }

    let raw_bytes = fs::read(transcript_path)
        .with_context(|| format!("failed to read {}", transcript_path.display()))?;
    if raw_bytes.is_empty() {
        return Ok(summary);
    }

    let conn = Connection::open(db_path)
        .with_context(|| format!("failed to open {}", db_path.display()))?;
    configure_db(&conn)?;

    let content = String::from_utf8_lossy(&raw_bytes).into_owned();
    conn.execute(
        "insert into console_transcripts (run_id, captured_at_ms, byte_count, content)
         values (?1, ?2, ?3, ?4)
         on conflict(run_id) do update set
             captured_at_ms = excluded.captured_at_ms,
             byte_count = excluded.byte_count,
             content = excluded.content",
        params![
            run_id,
            unix_millis() as i64,
            raw_bytes.len() as i64,
            content
        ],
    )
    .context("failed to insert console transcript")?;

    summary.console_transcript_bytes = raw_bytes.len();
    Ok(summary)
}

fn ingest_codex_sessions(
    db_path: &Path,
    run_id: &str,
    session_files: &[PathBuf],
) -> Result<ImportSummary> {
    let conn = Connection::open(db_path)
        .with_context(|| format!("failed to open {}", db_path.display()))?;
    configure_db(&conn)?;

    let mut summary = ImportSummary::default();
    for session_file in session_files {
        ingest_codex_session_file(&conn, run_id, session_file, &mut summary)?;
    }
    Ok(summary)
}

fn ingest_codex_session_file(
    conn: &Connection,
    run_id: &str,
    session_file: &Path,
    summary: &mut ImportSummary,
) -> Result<()> {
    let metadata = fs::metadata(session_file)
        .with_context(|| format!("failed to read metadata for {}", session_file.display()))?;
    let session_id = session_file
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("unknown-session")
        .to_string();

    let file = File::open(session_file)
        .with_context(|| format!("failed to open {}", session_file.display()))?;
    let mut raw_event_count = 0usize;

    conn.execute(
        "insert or replace into sessions (
            session_id,
            run_id,
            source_path,
            source_modified_ms,
            imported_at_ms,
            raw_event_count
        ) values (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            &session_id,
            run_id,
            session_file.display().to_string(),
            session_file_state(&metadata).modified_ms as i64,
            unix_millis() as i64,
            0i64,
        ],
    )
    .with_context(|| format!("failed to insert session {}", session_id))?;

    for line in BufReader::new(file).lines() {
        let line = line.with_context(|| format!("failed to read {}", session_file.display()))?;
        if line.trim().is_empty() {
            continue;
        }
        raw_event_count += 1;
        let event: Value = serde_json::from_str(&line)
            .with_context(|| format!("failed to parse {}", session_file.display()))?;
        ingest_codex_event(conn, run_id, &session_id, &event, summary)?;
    }

    conn.execute(
        "update sessions set raw_event_count = ?2 where session_id = ?1",
        params![&session_id, raw_event_count as i64],
    )
    .with_context(|| format!("failed to update raw event count for {}", session_id))?;

    summary.session_count += 1;
    Ok(())
}

fn insert_env_access(
    conn: &Connection,
    run_id: &str,
    record: &EnvTraceRecord,
    raw_json: &str,
) -> Result<()> {
    conn.execute(
        "insert into env_accesses (
            run_id,
            created_at_ms,
            process_id,
            parent_process_id,
            operation,
            key,
            found,
            value,
            executable,
            raw_json
        ) values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            run_id,
            record.ts_ms,
            record.pid,
            record.ppid,
            record.operation,
            record.key,
            if record.found { 1 } else { 0 },
            record.value,
            record.executable,
            raw_json,
        ],
    )
    .context("failed to insert env access")?;
    Ok(())
}

fn ingest_codex_event(
    conn: &Connection,
    run_id: &str,
    session_id: &str,
    event: &Value,
    summary: &mut ImportSummary,
) -> Result<()> {
    let event_kind = event
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let timestamp = event
        .get("timestamp")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let payload = event.get("payload").unwrap_or(&Value::Null);
    let payload_type = payload
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or_default();

    if event_kind != "event_msg" {
        return Ok(());
    }

    match payload_type {
        "user_message" => {
            insert_message(
                conn,
                MessageInsert {
                    run_id,
                    session_id,
                    turn_id: payload.get("turn_id").and_then(Value::as_str),
                    role: "user",
                    phase: None,
                    content: payload
                        .get("message")
                        .and_then(Value::as_str)
                        .unwrap_or_default(),
                    timestamp,
                },
            )?;
            summary.message_count += 1;
        }
        "agent_message" => {
            insert_message(
                conn,
                MessageInsert {
                    run_id,
                    session_id,
                    turn_id: payload.get("turn_id").and_then(Value::as_str),
                    role: "assistant",
                    phase: payload.get("phase").and_then(Value::as_str),
                    content: payload
                        .get("message")
                        .and_then(Value::as_str)
                        .unwrap_or_default(),
                    timestamp,
                },
            )?;
            summary.message_count += 1;
        }
        "token_count" => {
            insert_token_usage(conn, run_id, session_id, payload, timestamp)?;
            summary.token_count_events += 1;
            summary.latest_total_tokens =
                extract_total_tokens(payload).or(summary.latest_total_tokens);
        }
        "exec_command_end" => {
            insert_exec_command(conn, run_id, session_id, payload, timestamp)?;
            insert_exec_file_touches(conn, run_id, session_id, payload, timestamp, summary)?;
            summary.exec_command_count += 1;
        }
        "web_search_end" => {
            insert_web_search(conn, run_id, session_id, payload, timestamp)?;
            summary.web_search_count += 1;
        }
        "patch_apply_end" => {
            insert_patch_event(conn, run_id, session_id, payload, timestamp)?;
            insert_patch_file_touches(conn, run_id, session_id, payload, timestamp, summary)?;
            summary.patch_event_count += 1;
        }
        _ => {}
    }

    Ok(())
}

fn insert_message(conn: &Connection, row: MessageInsert<'_>) -> Result<()> {
    conn.execute(
        "insert into messages (
            run_id,
            session_id,
            turn_id,
            role,
            phase,
            content,
            created_at
        ) values (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            row.run_id,
            row.session_id,
            row.turn_id,
            row.role,
            row.phase,
            row.content,
            row.timestamp
        ],
    )
    .context("failed to insert message")?;
    Ok(())
}

fn insert_token_usage(
    conn: &Connection,
    run_id: &str,
    session_id: &str,
    payload: &Value,
    timestamp: &str,
) -> Result<()> {
    let usage = payload
        .get("info")
        .and_then(|value| value.get("total_token_usage"))
        .unwrap_or(&Value::Null);
    conn.execute(
        "insert into token_usage (
            run_id,
            session_id,
            turn_id,
            created_at,
            input_tokens,
            cached_input_tokens,
            output_tokens,
            reasoning_output_tokens,
            total_tokens,
            raw_json
        ) values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            run_id,
            session_id,
            payload.get("turn_id").and_then(Value::as_str),
            timestamp,
            usage.get("input_tokens").and_then(Value::as_i64),
            usage.get("cached_input_tokens").and_then(Value::as_i64),
            usage.get("output_tokens").and_then(Value::as_i64),
            usage.get("reasoning_output_tokens").and_then(Value::as_i64),
            usage.get("total_tokens").and_then(Value::as_i64),
            serde_json::to_string(payload)?,
        ],
    )
    .context("failed to insert token usage")?;
    Ok(())
}

fn insert_exec_command(
    conn: &Connection,
    run_id: &str,
    session_id: &str,
    payload: &Value,
    timestamp: &str,
) -> Result<()> {
    let shell_command = payload
        .get("command")
        .and_then(Value::as_array)
        .map(|parts| {
            parts
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_default();
    let duration_ms = payload
        .get("duration")
        .and_then(duration_to_millis)
        .map(|value| value as i64);

    conn.execute(
        "insert into exec_commands (
            run_id,
            session_id,
            turn_id,
            call_id,
            process_id,
            created_at,
            shell_command,
            cwd,
            parsed_cmd_json,
            exit_code,
            duration_ms,
            status,
            aggregated_output,
            raw_json
        ) values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
        params![
            run_id,
            session_id,
            payload.get("turn_id").and_then(Value::as_str),
            payload.get("call_id").and_then(Value::as_str),
            payload.get("process_id").and_then(Value::as_str),
            timestamp,
            shell_command,
            payload.get("cwd").and_then(Value::as_str),
            payload
                .get("parsed_cmd")
                .map(serde_json::to_string)
                .transpose()?,
            payload.get("exit_code").and_then(Value::as_i64),
            duration_ms,
            payload.get("status").and_then(Value::as_str),
            payload.get("aggregated_output").and_then(Value::as_str),
            serde_json::to_string(payload)?,
        ],
    )
    .context("failed to insert exec command")?;
    Ok(())
}

fn insert_web_search(
    conn: &Connection,
    run_id: &str,
    session_id: &str,
    payload: &Value,
    timestamp: &str,
) -> Result<()> {
    conn.execute(
        "insert into web_searches (
            run_id,
            session_id,
            turn_id,
            call_id,
            created_at,
            query,
            action_type,
            queries_json,
            raw_json
        ) values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            run_id,
            session_id,
            payload.get("turn_id").and_then(Value::as_str),
            payload.get("call_id").and_then(Value::as_str),
            timestamp,
            payload
                .get("query")
                .and_then(Value::as_str)
                .unwrap_or_default(),
            payload
                .get("action")
                .and_then(|value| value.get("type"))
                .and_then(Value::as_str),
            payload
                .get("action")
                .and_then(|value| value.get("queries"))
                .map(serde_json::to_string)
                .transpose()?,
            serde_json::to_string(payload)?,
        ],
    )
    .context("failed to insert web search")?;
    Ok(())
}

fn insert_patch_event(
    conn: &Connection,
    run_id: &str,
    session_id: &str,
    payload: &Value,
    timestamp: &str,
) -> Result<()> {
    conn.execute(
        "insert into patch_events (
            run_id,
            session_id,
            turn_id,
            call_id,
            created_at,
            success,
            stdout,
            stderr,
            changes_json,
            raw_json
        ) values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            run_id,
            session_id,
            payload.get("turn_id").and_then(Value::as_str),
            payload.get("call_id").and_then(Value::as_str),
            timestamp,
            if payload
                .get("success")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                1
            } else {
                0
            },
            payload.get("stdout").and_then(Value::as_str),
            payload.get("stderr").and_then(Value::as_str),
            payload
                .get("changes")
                .map(serde_json::to_string)
                .transpose()?,
            serde_json::to_string(payload)?,
        ],
    )
    .context("failed to insert patch event")?;
    Ok(())
}

fn insert_exec_file_touches(
    conn: &Connection,
    run_id: &str,
    session_id: &str,
    payload: &Value,
    timestamp: &str,
    summary: &mut ImportSummary,
) -> Result<()> {
    let mut touches = BTreeSet::new();
    if let Some(parsed_cmd) = payload.get("parsed_cmd") {
        collect_file_touches_from_parsed_cmd(parsed_cmd, None, &mut touches);
    }
    for (path, op) in touches {
        insert_file_touch(
            conn,
            FileTouchInsert {
                run_id,
                session_id,
                turn_id: payload.get("turn_id").and_then(Value::as_str),
                timestamp,
                path: &path,
                op: &op,
                source: "exec_command",
            },
        )?;
        summary.file_touch_count += 1;
    }
    Ok(())
}

fn insert_patch_file_touches(
    conn: &Connection,
    run_id: &str,
    session_id: &str,
    payload: &Value,
    timestamp: &str,
    summary: &mut ImportSummary,
) -> Result<()> {
    let Some(changes) = payload.get("changes").and_then(Value::as_object) else {
        return Ok(());
    };

    for (path, change) in changes {
        let op = change
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or("patch");
        insert_file_touch(
            conn,
            FileTouchInsert {
                run_id,
                session_id,
                turn_id: payload.get("turn_id").and_then(Value::as_str),
                timestamp,
                path,
                op,
                source: "patch_apply",
            },
        )?;
        summary.file_touch_count += 1;
    }
    Ok(())
}

fn insert_file_touch(conn: &Connection, row: FileTouchInsert<'_>) -> Result<()> {
    conn.execute(
        "insert into file_touches (
            run_id,
            session_id,
            turn_id,
            created_at,
            path,
            op,
            source
        ) values (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            row.run_id,
            row.session_id,
            row.turn_id,
            row.timestamp,
            row.path,
            row.op,
            row.source
        ],
    )
    .context("failed to insert file touch")?;
    Ok(())
}

fn collect_file_touches_from_parsed_cmd(
    value: &Value,
    inherited_op: Option<&str>,
    touches: &mut BTreeSet<(String, String)>,
) {
    match value {
        Value::Array(items) => {
            for item in items {
                collect_file_touches_from_parsed_cmd(item, inherited_op, touches);
            }
        }
        Value::Object(map) => {
            let op = map
                .get("type")
                .and_then(Value::as_str)
                .or(inherited_op)
                .unwrap_or("unknown");

            if let Some(path) = map.get("path").and_then(Value::as_str) {
                touches.insert((path.to_string(), op.to_string()));
            }

            if let Some(path) = map.get("move_path").and_then(Value::as_str) {
                touches.insert((path.to_string(), "move".to_string()));
            }

            if let Some(paths) = map.get("paths").and_then(Value::as_array) {
                for path in paths.iter().filter_map(Value::as_str) {
                    touches.insert((path.to_string(), op.to_string()));
                }
            }

            for child in map.values() {
                collect_file_touches_from_parsed_cmd(child, Some(op), touches);
            }
        }
        _ => {}
    }
}

fn extract_total_tokens(payload: &Value) -> Option<i64> {
    payload
        .get("info")
        .and_then(|value| value.get("total_token_usage"))
        .and_then(|value| value.get("total_tokens"))
        .and_then(Value::as_i64)
}

fn duration_to_millis(value: &Value) -> Option<u128> {
    let secs = value.get("secs").and_then(Value::as_u64)? as u128;
    let nanos = value.get("nanos").and_then(Value::as_u64)? as u128;
    Some((secs * 1_000) + (nanos / 1_000_000))
}

#[cfg(test)]
mod tests {
    use super::{
        ImportSummary, LiveRunServer, LiveRunSnapshot, apply_summary_to_snapshot,
        changed_session_files, collect_file_touches_from_parsed_cmd, configure_db,
        console_transcript_preview, fetch_live_snapshot, ingest_codex_session_file,
        ingest_console_transcript_file, ingest_env_trace_file, init_schema, live_transcript_status,
        prepare_socket_path, sanitize_transcript_preview, snapshot_session_files, socket_path,
        unique_run_id,
    };
    #[cfg(target_os = "linux")]
    use crate::env_trace;
    use rusqlite::Connection;
    use serde_json::json;
    use std::{
        fs,
        path::{Path, PathBuf},
        process::ExitCode,
    };
    use tempfile::tempdir;

    #[test]
    fn collects_paths_from_nested_parsed_commands() {
        let value = json!([
            {
                "type": "read",
                "path": "/tmp/a.txt"
            },
            {
                "type": "move",
                "path": "/tmp/b.txt",
                "move_path": "/tmp/c.txt"
            }
        ]);
        let mut touches = std::collections::BTreeSet::new();
        collect_file_touches_from_parsed_cmd(&value, None, &mut touches);
        assert!(touches.contains(&(String::from("/tmp/a.txt"), String::from("read"))));
        assert!(touches.contains(&(String::from("/tmp/b.txt"), String::from("move"))));
        assert!(touches.contains(&(String::from("/tmp/c.txt"), String::from("move"))));
    }

    #[test]
    fn ingests_codex_session_jsonl_into_sqlite() {
        let dir = tempdir().unwrap();
        let session_path = dir.path().join("rollout-test-session.jsonl");
        fs::write(
            &session_path,
            [
                r#"{"timestamp":"2026-04-10T12:00:00Z","type":"event_msg","payload":{"type":"user_message","message":"hello","images":[],"local_images":[],"text_elements":[]}}"#,
                r#"{"timestamp":"2026-04-10T12:00:01Z","type":"event_msg","payload":{"type":"agent_message","message":"world","phase":"final_answer","turn_id":"turn-1"}}"#,
                r#"{"timestamp":"2026-04-10T12:00:02Z","type":"event_msg","payload":{"type":"token_count","turn_id":"turn-1","info":{"total_token_usage":{"input_tokens":10,"cached_input_tokens":2,"output_tokens":3,"reasoning_output_tokens":1,"total_tokens":13}}}}"#,
                r#"{"timestamp":"2026-04-10T12:00:03Z","type":"event_msg","payload":{"type":"exec_command_end","turn_id":"turn-1","call_id":"call-1","process_id":"123","command":["/bin/zsh","-lc","cat /tmp/example.txt"],"cwd":"/tmp","parsed_cmd":[{"type":"read","path":"/tmp/example.txt"}],"exit_code":0,"duration":{"secs":1,"nanos":500000000},"status":"completed","aggregated_output":"content"}}"#,
                r#"{"timestamp":"2026-04-10T12:00:04Z","type":"event_msg","payload":{"type":"web_search_end","turn_id":"turn-1","call_id":"ws-1","query":"example query","action":{"type":"search","queries":["example query"]}}}"#,
                r#"{"timestamp":"2026-04-10T12:00:05Z","type":"event_msg","payload":{"type":"patch_apply_end","turn_id":"turn-1","call_id":"patch-1","success":true,"stdout":"updated","stderr":"","changes":{"/tmp/example.txt":{"type":"update"}}}}"#,
            ]
            .join("\n"),
        )
        .unwrap();

        let db_path = dir.path().join("events.sqlite");
        let conn = Connection::open(&db_path).unwrap();
        configure_db(&conn).unwrap();
        init_schema(&conn).unwrap();
        conn.execute(
            "insert into runs (
                run_id,
                agent,
                root,
                command,
                agent_args_json,
                started_at_ms,
                status,
                analysis_json,
                sandbox_plan_json
            ) values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            rusqlite::params![
                "run-1",
                "codex",
                "/tmp/project",
                "codex",
                "[]",
                1i64,
                "running",
                "{}",
                "{}",
            ],
        )
        .unwrap();

        let mut summary = ImportSummary::default();
        ingest_codex_session_file(&conn, "run-1", &session_path, &mut summary).unwrap();

        assert_eq!(summary.session_count, 1);
        assert_eq!(summary.message_count, 2);
        assert_eq!(summary.token_count_events, 1);
        assert_eq!(summary.exec_command_count, 1);
        assert_eq!(summary.web_search_count, 1);
        assert_eq!(summary.patch_event_count, 1);
        assert_eq!(summary.file_touch_count, 2);
        assert_eq!(summary.latest_total_tokens, Some(13));

        let message_count: i64 = conn
            .query_row("select count(*) from messages", [], |row| row.get(0))
            .unwrap();
        let command_count: i64 = conn
            .query_row("select count(*) from exec_commands", [], |row| row.get(0))
            .unwrap();
        let touch_count: i64 = conn
            .query_row("select count(*) from file_touches", [], |row| row.get(0))
            .unwrap();

        assert_eq!(message_count, 2);
        assert_eq!(command_count, 1);
        assert_eq!(touch_count, 2);
    }

    #[test]
    fn prefers_new_session_files_over_modified_existing_files() {
        let dir = tempdir().unwrap();
        let existing = dir.path().join("existing.jsonl");
        fs::write(&existing, "one\n").unwrap();
        let before = snapshot_session_files(dir.path()).unwrap();

        fs::write(&existing, "one\ntwo\n").unwrap();
        let created = dir.path().join("created.jsonl");
        fs::write(&created, "three\n").unwrap();

        let changed = changed_session_files(dir.path(), &before).unwrap();
        assert_eq!(changed, vec![created]);
    }

    #[test]
    fn unique_run_ids_do_not_collide() {
        let first = unique_run_id("codex");
        let second = unique_run_id("codex");
        assert_ne!(first, second);
    }

    #[test]
    fn applies_summary_to_live_snapshot() {
        let mut snapshot = LiveRunSnapshot::new(
            Path::new("/tmp/project"),
            "codex",
            "codex exec hello",
            true,
            Some("run-1".to_string()),
            None,
            None,
        );
        let summary = ImportSummary {
            session_count: 1,
            message_count: 2,
            token_count_events: 3,
            exec_command_count: 4,
            web_search_count: 5,
            patch_event_count: 6,
            file_touch_count: 7,
            env_access_count: 8,
            console_transcript_bytes: 9,
            latest_total_tokens: Some(42),
        };
        apply_summary_to_snapshot(&mut snapshot, &summary);
        assert_eq!(snapshot.message_count, 2);
        assert_eq!(snapshot.token_count_events, 3);
        assert_eq!(snapshot.exec_command_count, 4);
        assert_eq!(snapshot.web_search_count, 5);
        assert_eq!(snapshot.patch_event_count, 6);
        assert_eq!(snapshot.file_touch_count, 7);
        assert_eq!(snapshot.env_access_count, 8);
        assert_eq!(snapshot.console_transcript_bytes, 9);
        assert_eq!(snapshot.latest_total_tokens, Some(42));
    }

    #[test]
    fn ingests_env_trace_file_into_sqlite() {
        let dir = tempdir().unwrap();
        let trace_path = dir.path().join("env-access.jsonl");
        fs::write(
            &trace_path,
            [
                r#"{"ts_ms":1,"pid":100,"ppid":10,"operation":"getenv","key":"PATH","found":true,"value":"/bin:/usr/bin","executable":"/tmp/probe"}"#,
                r#"{"ts_ms":2,"pid":100,"ppid":10,"operation":"getenv","key":"AWS_SECRET_KEY","found":true,"value":"secret","executable":"/tmp/probe"}"#,
            ]
            .join("\n"),
        )
        .unwrap();

        let db_path = dir.path().join("events.sqlite");
        let conn = Connection::open(&db_path).unwrap();
        configure_db(&conn).unwrap();
        init_schema(&conn).unwrap();
        conn.execute(
            "insert into runs (
                run_id,
                agent,
                root,
                command,
                agent_args_json,
                started_at_ms,
                status,
                analysis_json,
                sandbox_plan_json
            ) values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            rusqlite::params![
                "run-1",
                "claude",
                "/tmp/project",
                "claude",
                "[]",
                1i64,
                "running",
                "{}",
                "{}",
            ],
        )
        .unwrap();

        let summary = ingest_env_trace_file(&db_path, "run-1", &trace_path).unwrap();
        assert_eq!(summary.env_access_count, 2);

        let env_count: i64 = conn
            .query_row("select count(*) from env_accesses", [], |row| row.get(0))
            .unwrap();
        let secret: String = conn
            .query_row(
                "select value from env_accesses where key = 'AWS_SECRET_KEY' limit 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(env_count, 2);
        assert_eq!(secret, "secret");
    }

    #[test]
    fn ingests_console_transcript_into_sqlite() {
        let dir = tempdir().unwrap();
        let transcript_path = dir.path().join("console.typescript");
        fs::write(
            &transcript_path,
            "\u{1b}[2J\u{1b}[H> hello\nClaude says hi\n",
        )
        .unwrap();
        let expected_len = fs::metadata(&transcript_path).unwrap().len() as usize;

        let db_path = dir.path().join("events.sqlite");
        let conn = Connection::open(&db_path).unwrap();
        configure_db(&conn).unwrap();
        init_schema(&conn).unwrap();
        conn.execute(
            "insert into runs (
                run_id,
                agent,
                root,
                command,
                agent_args_json,
                started_at_ms,
                status,
                analysis_json,
                sandbox_plan_json
            ) values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            rusqlite::params![
                "run-1",
                "claude",
                "/tmp/project",
                "claude",
                "[]",
                1i64,
                "running",
                "{}",
                "{}",
            ],
        )
        .unwrap();

        let summary = ingest_console_transcript_file(&db_path, "run-1", &transcript_path).unwrap();
        assert_eq!(summary.console_transcript_bytes, expected_len);

        let stored_bytes: i64 = conn
            .query_row(
                "select byte_count from console_transcripts where run_id = 'run-1' limit 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let preview = console_transcript_preview(&conn, "run-1").unwrap();

        assert_eq!(stored_bytes, expected_len as i64);
        assert_eq!(preview.as_deref(), Some("> hello | Claude says hi"));
    }

    #[test]
    fn transcript_preview_sanitizes_ansi_sequences() {
        let preview = sanitize_transcript_preview(
            "\u{1b}[2J\u{1b}[HOpenAI Codex\n\n\u{1b}[33mwarning\u{1b}[0m\n",
        );
        assert_eq!(preview, "OpenAI Codex | warning");
    }

    #[test]
    fn live_transcript_status_reports_preview_and_size() {
        let dir = tempdir().unwrap();
        let transcript = dir.path().join("console.typescript");
        fs::write(&transcript, "\u{1b}[2JOpenAI Codex\nhello\n").unwrap();
        let expected_len = fs::metadata(&transcript).unwrap().len() as usize;

        let status = live_transcript_status(&transcript).unwrap();
        assert_eq!(
            status,
            Some((expected_len, "OpenAI Codex | hello".to_string()))
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn preload_trace_captures_getenv_calls() {
        let dir = tempdir().unwrap();
        let source = dir.path().join("probe.c");
        let binary = dir.path().join("probe");
        let log_path = dir.path().join("env-access.jsonl");
        let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
        let cc = std::env::var("CC").unwrap_or_else(|_| "cc".to_string());
        fs::write(
            &source,
            r#"
#include <stdlib.h>

int main(void) {
    (void)getenv("PATH");
    (void)getenv("AWS_SECRET_KEY");
    return 0;
}
"#,
        )
        .unwrap();

        let status = std::process::Command::new(&cargo)
            .arg("build")
            .arg("--lib")
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .status()
            .unwrap();
        assert!(status.success());

        let status = std::process::Command::new(&cc)
            .arg(&source)
            .arg("-o")
            .arg(&binary)
            .status()
            .unwrap();
        assert!(status.success());

        let mut command = std::process::Command::new(&binary);
        command.env("AWS_SECRET_KEY", "trace-secret");
        for (key, value) in env_trace::build_injection_env(&log_path).unwrap() {
            command.env(key, value);
        }
        let status = command.status().unwrap();
        assert!(status.success());

        let contents = fs::read_to_string(&log_path).unwrap();
        assert!(contents.contains("\"key\":\"PATH\""));
        assert!(contents.contains("\"key\":\"AWS_SECRET_KEY\""));
        assert!(contents.contains("\"value\":\"trace-secret\""));
    }

    #[test]
    fn live_run_server_serves_snapshots_and_removes_socket_on_drop() {
        let dir = tempdir().unwrap();
        let socket = socket_path(dir.path());
        let server = LiveRunServer::start(
            dir.path(),
            LiveRunSnapshot::new(
                dir.path(),
                "codex",
                "codex exec hello",
                false,
                None,
                None,
                None,
            ),
        )
        .unwrap();

        let snapshot = fetch_live_snapshot(&socket).unwrap();
        assert_eq!(snapshot.state, "starting");
        assert_eq!(snapshot.agent, "codex");

        server.update(|snapshot| snapshot.state = "running".to_string());
        let snapshot = fetch_live_snapshot(&socket).unwrap();
        assert_eq!(snapshot.state, "running");

        server.finish(ExitCode::SUCCESS);
        let snapshot = fetch_live_snapshot(&socket).unwrap();
        assert_eq!(snapshot.state, "completed");

        drop(server);
        assert!(!socket.exists());
    }

    #[test]
    fn prepare_socket_path_removes_stale_entries() {
        let dir = tempdir().unwrap();
        let socket = socket_path(dir.path());
        fs::write(&socket, "stale").unwrap();

        prepare_socket_path(&socket).unwrap();

        assert!(!socket.exists());
    }

    #[test]
    fn long_roots_use_temp_socket_path() {
        let long_root = PathBuf::from(format!("/tmp/{}", "a".repeat(140)));
        let socket = socket_path(&long_root);
        assert!(socket.starts_with(std::env::temp_dir()));
        assert!(socket.to_string_lossy().contains("explicit-observe-"));
    }
}
