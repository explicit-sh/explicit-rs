use std::collections::BTreeSet;
use std::fs;
use std::io::{self, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Output, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Context, Result, anyhow};
use serde_json::Value as JsonValue;
use serde_yaml::{Mapping as YamlMapping, Value as YamlValue};

use crate::analysis::{Analysis, ServiceRequirement};
use crate::host_tools::preferred_command_path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VerifyMode {
    User,
    StopHook,
    GitHook,
}

impl VerifyMode {
    fn from_flags(stop_hook: bool, git_hook: bool) -> Self {
        if stop_hook {
            Self::StopHook
        } else if git_hook {
            Self::GitHook
        } else {
            Self::User
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProjectCheck {
    ordinal: usize,
    kind: &'static str,
    command: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CheckFailure {
    kind: &'static str,
    subject: String,
    exit_code: Option<i32>,
    summary: String,
    duration: Option<Duration>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StopHookClient {
    Claude,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VerifyOutputStyle {
    Interactive,
    Compact,
}

#[derive(Debug, Default)]
struct WorkflowAudit {
    syntax_errors: Vec<String>,
    has_automatic_trigger: bool,
    run_steps: Vec<String>,
}

#[derive(Debug)]
struct CheckOutput {
    output: Output,
    duration: Duration,
}

#[derive(Debug)]
struct CheckExecution {
    check: ProjectCheck,
    output: CheckOutput,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CommandProgress {
    note_message: Option<String>,
    live_prefix: String,
    progress_probe: Option<ProgressProbeSpec>,
    start_message: String,
    wait_prefix: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LiveOutputConfig {
    prefix: String,
}

#[derive(Debug, Default)]
struct LiveOutputState {
    last_line: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ProgressProbeSpec {
    JavaScriptInstall { root: PathBuf },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProgressProbeState {
    spec: ProgressProbeSpec,
    initial_npx_dirs: BTreeSet<PathBuf>,
    last_message: Option<String>,
    started_at: SystemTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StartedServices {
    processes: Vec<&'static str>,
    duration: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ServiceStartResult {
    NotNeeded,
    Started(StartedServices),
    Failed(CheckFailure),
}

pub fn prepare_verify_environment(root: &Path, analysis: &Analysis) -> Result<()> {
    if existing_devenv_root(root).is_none() {
        crate::runtime::ensure_managed_devenv_files(root, analysis)?;
    }
    Ok(())
}

pub fn run_project_checks(
    root: &Path,
    analysis: &Analysis,
    stop_hook: bool,
    git_hook: bool,
) -> Result<ExitCode> {
    let mode = VerifyMode::from_flags(stop_hook, git_hook);
    let hook_client = detect_stop_hook_client(mode);
    let output_style = verify_output_style(mode);
    let checks = project_checks(analysis);
    let total_checks = checks.len() + project_policy_check_count(analysis);
    let displayed_checks = displayed_check_count(checks.len(), total_checks);

    if total_checks == 0 {
        if output_style == VerifyOutputStyle::Interactive {
            eprintln!("No lint/build/test or repository checks detected.");
        } else {
            print_compact_pass();
        }
        return Ok(ExitCode::SUCCESS);
    }

    if output_style == VerifyOutputStyle::Interactive {
        eprintln!("Running {} project checks...", displayed_checks);
    }

    if let Some(failure) = first_project_policy_failure(root, analysis)? {
        return report_single_failure(root, mode, hook_client, failure);
    }

    match start_verify_services(root, analysis, output_style)? {
        ServiceStartResult::NotNeeded => {}
        ServiceStartResult::Started(started) => {
            if output_style == VerifyOutputStyle::Interactive {
                print_started_services(&started);
            }
        }
        ServiceStartResult::Failed(failure) => {
            return report_single_failure(root, mode, hook_client, failure);
        }
    }

    let executions = execute_checks(root, analysis, &checks, output_style)?;
    for execution in executions {
        let check = execution.check;
        let output = execution.output;
        if output.output.status.success() {
            if output_style == VerifyOutputStyle::Interactive {
                eprintln!(
                    "ok   {:<5} {} ({})",
                    check.kind,
                    check.command,
                    format_duration(output.duration)
                );
            }
            continue;
        }

        let failure = CheckFailure {
            kind: check.kind,
            subject: check.command.clone(),
            exit_code: output.output.status.code(),
            summary: summarize_failure(check.kind, &check.command, &output.output),
            duration: Some(output.duration),
        };
        return report_single_failure(root, mode, hook_client, failure);
    }

    if output_style == VerifyOutputStyle::Interactive {
        eprintln!("All project checks passed ({} total).", displayed_checks);
    } else {
        print_compact_pass();
    }
    Ok(ExitCode::SUCCESS)
}

fn report_single_failure(
    root: &Path,
    mode: VerifyMode,
    hook_client: StopHookClient,
    failure: CheckFailure,
) -> Result<ExitCode> {
    if mode == VerifyMode::StopHook && hook_client == StopHookClient::Claude {
        print_claude_stop_block_json(&failure)?;
        return Ok(ExitCode::SUCCESS);
    }
    let _ = io::stdout().flush();
    let _ = io::stderr().flush();
    print_failure_report(root, mode, &failure);
    Ok(ExitCode::from(2))
}

fn project_checks(analysis: &Analysis) -> Vec<ProjectCheck> {
    let mut checks = Vec::new();
    for command in &analysis.lint_commands {
        checks.push(ProjectCheck {
            ordinal: checks.len(),
            kind: "lint",
            command: command.clone(),
        });
    }
    for command in &analysis.build_commands {
        checks.push(ProjectCheck {
            ordinal: checks.len(),
            kind: "build",
            command: command.clone(),
        });
    }
    for command in &analysis.test_commands {
        checks.push(ProjectCheck {
            ordinal: checks.len(),
            kind: "test",
            command: command.clone(),
        });
    }
    checks
}

fn execute_checks(
    root: &Path,
    analysis: &Analysis,
    checks: &[ProjectCheck],
    output_style: VerifyOutputStyle,
) -> Result<Vec<CheckExecution>> {
    let lanes = build_check_lanes(checks);
    if lanes.is_empty() {
        return Ok(Vec::new());
    }
    if lanes.len() == 1 || should_use_devenv(root) {
        return lanes
            .into_iter()
            .flatten()
            .map(|check| {
                let progress = check_progress(&check, root, checks.len(), output_style);
                let output = run_check(root, analysis, &check.command, progress.as_ref())?;
                Ok(CheckExecution { check, output })
            })
            .collect();
    }

    let root = root.to_path_buf();
    let mut executions = Vec::new();
    let handles = lanes
        .into_iter()
        .map(|lane| {
            let root = root.clone();
            let analysis = analysis.clone();
            let total_checks = checks.len();
            thread::spawn(move || -> Result<Vec<CheckExecution>> {
                lane.into_iter()
                    .map(|check| {
                        let progress = check_progress(&check, &root, total_checks, output_style);
                        let output =
                            run_check(&root, &analysis, &check.command, progress.as_ref())?;
                        Ok(CheckExecution { check, output })
                    })
                    .collect()
            })
        })
        .collect::<Vec<_>>();

    for handle in handles {
        let lane_results = handle
            .join()
            .map_err(|_| anyhow!("verification worker thread panicked"))??;
        executions.extend(lane_results);
    }
    executions.sort_by_key(|execution| execution.check.ordinal);
    Ok(executions)
}

fn build_check_lanes(checks: &[ProjectCheck]) -> Vec<Vec<ProjectCheck>> {
    let mut lane_order = Vec::new();
    let mut lanes = std::collections::BTreeMap::<String, Vec<ProjectCheck>>::new();
    for check in checks {
        let key = check_lane_key(check);
        if !lanes.contains_key(&key) {
            lane_order.push(key.clone());
        }
        lanes.entry(key).or_default().push(check.clone());
    }
    lane_order
        .into_iter()
        .filter_map(|key| lanes.remove(&key))
        .collect()
}

fn check_lane_key(check: &ProjectCheck) -> String {
    let command = check.command.trim();
    if command.starts_with("cargo fmt") {
        return "cargo-fmt".to_string();
    }
    if command.starts_with("cargo clippy")
        || command.starts_with("cargo build")
        || command.starts_with("cargo test")
        || command.starts_with("cargo check")
    {
        return "cargo-target".to_string();
    }
    command.to_string()
}

fn project_policy_check_count(analysis: &Analysis) -> usize {
    let mut count = 0;
    if analysis.repository.is_git_repository {
        count += 1;
    }
    if analysis.repository.has_workflows() {
        count += 1;
    }
    if analysis.repository.is_public_github_repository() {
        count += 2;
    }
    count
}

fn first_project_policy_failure(root: &Path, analysis: &Analysis) -> Result<Option<CheckFailure>> {
    if analysis.repository.is_git_repository && !analysis.repository.has_readme() {
        return Ok(Some(CheckFailure {
            kind: "docs",
            subject: "README.md".to_string(),
            exit_code: None,
            summary: "git repositories must include a top-level README.md".to_string(),
            duration: None,
        }));
    }

    if analysis.repository.is_public_github_repository() && !analysis.repository.has_license() {
        return Ok(Some(CheckFailure {
            kind: "license",
            subject: "LICENSE".to_string(),
            exit_code: None,
            summary: "public GitHub repositories must include a LICENSE file".to_string(),
            duration: None,
        }));
    }

    if analysis.repository.is_public_github_repository() && !analysis.repository.has_workflows() {
        return Ok(Some(CheckFailure {
            kind: "ci",
            subject: ".github/workflows".to_string(),
            exit_code: None,
            summary: "public GitHub repositories must include GitHub Actions workflows".to_string(),
            duration: None,
        }));
    }

    let workflow_audit = if analysis.repository.has_workflows()
        || analysis.repository.is_public_github_repository()
    {
        Some(audit_workflows(root, &analysis.repository.workflow_files)?)
    } else {
        None
    };

    if let Some(audit) = workflow_audit.as_ref()
        && !audit.syntax_errors.is_empty()
    {
        return Ok(Some(CheckFailure {
            kind: "ci",
            subject: ".github/workflows".to_string(),
            exit_code: None,
            summary: format!(
                "GitHub Actions workflow syntax is invalid: {}",
                audit
                    .syntax_errors
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "unknown workflow syntax error".to_string())
            ),
            duration: None,
        }));
    }

    if analysis.repository.is_public_github_repository()
        && let Some(audit) = workflow_audit.as_ref()
        && audit.syntax_errors.is_empty()
    {
        if !audit.has_automatic_trigger {
            return Ok(Some(CheckFailure {
                kind: "ci",
                subject: ".github/workflows".to_string(),
                exit_code: None,
                summary: "GitHub Actions must run automatically on push, pull_request, pull_request_target, or merge_group".to_string(),
                duration: None,
            }));
        }

        let missing_commands = missing_workflow_commands(analysis, &audit.run_steps);
        if let Some(command) = missing_commands.first() {
            return Ok(Some(CheckFailure {
                kind: "ci",
                subject: command.clone(),
                exit_code: None,
                summary: format!(
                    "GitHub Actions do not run the detected check automatically: {command}"
                ),
                duration: None,
            }));
        }
    }

    Ok(None)
}

fn audit_workflows(root: &Path, workflow_files: &[String]) -> Result<WorkflowAudit> {
    let mut audit = WorkflowAudit::default();
    for relative in workflow_files {
        let path = root.join(relative);
        let contents = fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        let value = match serde_yaml::from_str::<YamlValue>(&contents) {
            Ok(value) => value,
            Err(error) => {
                audit.syntax_errors.push(format!("{relative}: {error}"));
                continue;
            }
        };
        let Some(root_map) = value.as_mapping() else {
            audit
                .syntax_errors
                .push(format!("{relative}: root document must be a mapping"));
            continue;
        };

        let Some(jobs) = workflow_mapping_get(root_map, "jobs") else {
            audit
                .syntax_errors
                .push(format!("{relative}: missing top-level `jobs`"));
            continue;
        };
        let Some(jobs_map) = jobs.as_mapping() else {
            audit
                .syntax_errors
                .push(format!("{relative}: top-level `jobs` must be a mapping"));
            continue;
        };

        let events = workflow_mapping_get(root_map, "on")
            .map(extract_workflow_events)
            .unwrap_or_default();
        if events
            .iter()
            .any(|event| is_automatic_workflow_event(event))
        {
            audit.has_automatic_trigger = true;
        }

        collect_run_steps_from_jobs(jobs_map, &mut audit.run_steps);
    }
    if audit.syntax_errors.is_empty() {
        audit
            .syntax_errors
            .extend(actionlint_errors(root, workflow_files)?);
    }
    Ok(audit)
}

fn actionlint_errors(root: &Path, workflow_files: &[String]) -> Result<Vec<String>> {
    let Some(actionlint) = preferred_command_path("actionlint") else {
        return Ok(Vec::new());
    };
    if workflow_files.is_empty() {
        return Ok(Vec::new());
    }

    let output = Command::new(actionlint)
        .current_dir(root)
        .arg("-oneline")
        .args(workflow_files)
        .stdin(Stdio::null())
        .output()
        .context("failed to run actionlint")?;
    if output.status.success() {
        return Ok(Vec::new());
    }

    let lines = String::from_utf8_lossy(&output.stderr)
        .lines()
        .chain(String::from_utf8_lossy(&output.stdout).lines())
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>();
    if lines.is_empty() {
        return Ok(vec!["actionlint reported a workflow error".to_string()]);
    }
    Ok(lines)
}

fn workflow_mapping_get<'a>(mapping: &'a YamlMapping, key: &str) -> Option<&'a YamlValue> {
    mapping
        .iter()
        .find_map(|(candidate, value)| match candidate {
            YamlValue::String(name) if name == key => Some(value),
            YamlValue::Bool(true) if key == "on" => Some(value),
            _ => None,
        })
}

fn extract_workflow_events(value: &YamlValue) -> Vec<String> {
    match value {
        YamlValue::String(event) => vec![event.clone()],
        YamlValue::Sequence(items) => items
            .iter()
            .filter_map(YamlValue::as_str)
            .map(str::to_string)
            .collect(),
        YamlValue::Mapping(mapping) => mapping
            .keys()
            .filter_map(|key| match key {
                YamlValue::String(event) => Some(event.to_string()),
                YamlValue::Bool(true) => Some("on".to_string()),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    }
}

fn is_automatic_workflow_event(event: &str) -> bool {
    matches!(
        event,
        "push" | "pull_request" | "pull_request_target" | "merge_group"
    )
}

fn collect_run_steps_from_jobs(jobs: &YamlMapping, run_steps: &mut Vec<String>) {
    for job in jobs.values() {
        let Some(job_map) = job.as_mapping() else {
            continue;
        };
        let Some(steps) = workflow_mapping_get(job_map, "steps") else {
            continue;
        };
        let Some(steps) = steps.as_sequence() else {
            continue;
        };
        for step in steps {
            let Some(step_map) = step.as_mapping() else {
                continue;
            };
            let Some(run) = workflow_mapping_get(step_map, "run").and_then(YamlValue::as_str)
            else {
                continue;
            };
            run_steps.push(run.to_string());
        }
    }
}

fn missing_workflow_commands(analysis: &Analysis, run_steps: &[String]) -> Vec<String> {
    let required_checks = analysis
        .lint_commands
        .iter()
        .chain(analysis.build_commands.iter())
        .chain(analysis.test_commands.iter())
        .collect::<Vec<_>>();

    required_checks
        .into_iter()
        .filter(|command| !workflow_runs_command(run_steps, command))
        .cloned()
        .collect()
}

fn workflow_runs_command(run_steps: &[String], command: &str) -> bool {
    let expected_tokens = command.split_whitespace().collect::<Vec<_>>();
    run_steps.iter().any(|run| {
        split_shell_segments(run).into_iter().any(|segment| {
            let actual_tokens = segment.split_whitespace().collect::<Vec<_>>();
            tokens_are_subsequence(&actual_tokens, &expected_tokens)
        })
    })
}

fn split_shell_segments(run: &str) -> Vec<&str> {
    run.lines()
        .flat_map(|line| line.split("&&"))
        .flat_map(|segment| segment.split(';'))
        .map(str::trim)
        .filter(|segment| !segment.is_empty())
        .collect()
}

fn tokens_are_subsequence(actual: &[&str], expected: &[&str]) -> bool {
    if expected.is_empty() {
        return true;
    }
    let mut expected_index = 0;
    for token in actual {
        if *token == expected[expected_index] {
            expected_index += 1;
            if expected_index == expected.len() {
                return true;
            }
        }
    }
    false
}

fn run_check(
    root: &Path,
    analysis: &Analysis,
    command: &str,
    progress: Option<&CommandProgress>,
) -> Result<CheckOutput> {
    let mut child = if should_use_devenv(root) {
        let devenv_root =
            devenv_root_for_check(root).expect("devenv root should exist when shell usage is set");
        let mut child = Command::new("devenv");
        child.current_dir(&devenv_root);
        if progress.is_some() {
            child.args(["--trace-output", "stderr", "--trace-format", "json"]);
        }
        child
            .args(["shell", "--no-tui", "--no-reload", "--", "bash", "-lc"])
            .arg(command_in_devenv_shell(
                root,
                &devenv_root,
                analysis,
                command,
            ));
        child
    } else {
        let mut child = Command::new("bash");
        child.current_dir(root).args([
            "-lc",
            &command_with_runtime_env(root, None, analysis, command),
        ]);
        child
    };
    run_captured_command(
        &mut child,
        &format!("failed to run check command `{command}`"),
        progress,
    )
}

fn run_captured_command(
    child: &mut Command,
    failure_context: &str,
    progress: Option<&CommandProgress>,
) -> Result<CheckOutput> {
    child
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(progress) = progress {
        if let Some(note_message) = &progress.note_message {
            eprintln!("{note_message}");
        }
        eprintln!("{}", progress.start_message);
    }

    let start = Instant::now();
    let mut child = child.spawn().with_context(|| failure_context.to_string())?;
    let mut progress_probe = progress
        .and_then(|progress| progress.progress_probe.clone())
        .map(init_progress_probe);
    let live_output = progress.map(|progress| LiveOutputConfig {
        prefix: progress.live_prefix.clone(),
    });
    let live_state = Arc::new(Mutex::new(LiveOutputState::default()));
    let mut stdout = child
        .stdout
        .take()
        .context("failed to capture command stdout")?;
    let stdout_live_output = live_output.clone();
    let stdout_live_state = Arc::clone(&live_state);
    let stdout_reader = thread::spawn(move || -> std::io::Result<Vec<u8>> {
        read_command_stream(&mut stdout, stdout_live_output.as_ref(), &stdout_live_state)
    });
    let mut stderr = child
        .stderr
        .take()
        .context("failed to capture command stderr")?;
    let stderr_live_state = Arc::clone(&live_state);
    let stderr_reader = thread::spawn(move || -> std::io::Result<Vec<u8>> {
        read_command_stream(&mut stderr, live_output.as_ref(), &stderr_live_state)
    });

    let mut next_heartbeat = heartbeat_interval(Duration::ZERO);
    let status = loop {
        if let Some(status) = child
            .try_wait()
            .with_context(|| failure_context.to_string())?
        {
            break status;
        }

        let elapsed = start.elapsed();
        if let Some(progress) = progress
            && elapsed >= next_heartbeat
        {
            let _output_guard = live_state.lock().ok();
            eprintln!("{}... {}s elapsed", progress.wait_prefix, elapsed.as_secs());
            if let Some(detail) = progress_probe.as_mut().and_then(progress_probe_detail) {
                eprintln!("{detail}");
            }
            next_heartbeat += heartbeat_interval(elapsed);
        }

        thread::sleep(Duration::from_millis(250));
    };

    let stdout = stdout_reader
        .join()
        .map_err(|_| anyhow!("command stdout reader thread panicked"))?
        .context("failed to read command stdout")?;
    let stderr = stderr_reader
        .join()
        .map_err(|_| anyhow!("command stderr reader thread panicked"))?
        .context("failed to read command stderr")?;
    Ok(CheckOutput {
        output: Output {
            status,
            stdout,
            stderr,
        },
        duration: start.elapsed(),
    })
}

fn check_progress(
    check: &ProjectCheck,
    root: &Path,
    total_checks: usize,
    output_style: VerifyOutputStyle,
) -> Option<CommandProgress> {
    if output_style != VerifyOutputStyle::Interactive {
        return None;
    }
    let ordinal = check.ordinal + 1;
    let prefix = format!("[{ordinal}/{total_checks}]");
    Some(CommandProgress {
        note_message: check_preflight_note(check, root, total_checks),
        live_prefix: format!("live {prefix} {:<5}", check.kind),
        progress_probe: check_progress_probe(check, root),
        start_message: format!("run  {prefix} {:<5} {}...", check.kind, check.command),
        wait_prefix: format!("wait {prefix} {:<5} {}", check.kind, check.command),
    })
}

fn service_progress(
    processes: &[&'static str],
    output_style: VerifyOutputStyle,
) -> Option<CommandProgress> {
    if output_style != VerifyOutputStyle::Interactive {
        return None;
    }
    let names = processes.join(", ");
    Some(CommandProgress {
        note_message: None,
        live_prefix: "svc ".to_string(),
        progress_probe: None,
        start_message: format!("svc  starting {names}..."),
        wait_prefix: format!("svc  {names}"),
    })
}

fn check_preflight_note(check: &ProjectCheck, root: &Path, total_checks: usize) -> Option<String> {
    if !is_javascript_package_manager_command(&check.command) {
        return None;
    }
    if !root.join("package.json").is_file() || root.join("node_modules").exists() {
        return None;
    }

    let ordinal = check.ordinal + 1;
    Some(format!(
        "note [{ordinal}/{total_checks}] `node_modules` is missing; the first run may need a large JavaScript dependency download or a separate install before `{}` can really start.",
        check.command
    ))
}

fn check_progress_probe(check: &ProjectCheck, root: &Path) -> Option<ProgressProbeSpec> {
    if !is_javascript_package_manager_command(&check.command) {
        return None;
    }
    if !root.join("package.json").is_file() || root.join("node_modules").exists() {
        return None;
    }
    Some(ProgressProbeSpec::JavaScriptInstall {
        root: root.to_path_buf(),
    })
}

fn is_javascript_package_manager_command(command: &str) -> bool {
    let command = command.trim();
    command.starts_with("yarn ")
        || command.starts_with("npm ")
        || command.starts_with("pnpm ")
        || command.starts_with("npx ")
        || command.starts_with("bun ")
}

fn read_command_stream(
    reader: &mut impl Read,
    live_output: Option<&LiveOutputConfig>,
    live_state: &Arc<Mutex<LiveOutputState>>,
) -> std::io::Result<Vec<u8>> {
    let mut collected = Vec::new();
    let mut chunk = [0u8; 4096];
    let mut pending = Vec::new();

    loop {
        let read = reader.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        let bytes = &chunk[..read];
        collected.extend_from_slice(bytes);
        pending.extend_from_slice(bytes);
        emit_pending_live_output(&mut pending, false, live_output, live_state);
    }

    emit_pending_live_output(&mut pending, true, live_output, live_state);
    Ok(collected)
}

fn emit_pending_live_output(
    pending: &mut Vec<u8>,
    flush_remainder: bool,
    live_output: Option<&LiveOutputConfig>,
    live_state: &Arc<Mutex<LiveOutputState>>,
) {
    let Some(live_output) = live_output else {
        pending.clear();
        return;
    };

    loop {
        let delimiter = pending
            .iter()
            .position(|byte| *byte == b'\n' || *byte == b'\r');
        let Some(delimiter) = delimiter else {
            break;
        };

        let line = pending.drain(..=delimiter).collect::<Vec<_>>();
        emit_live_line(&line, live_output, live_state);
        while pending
            .first()
            .is_some_and(|byte| *byte == b'\n' || *byte == b'\r')
        {
            pending.remove(0);
        }
    }

    if flush_remainder && !pending.is_empty() {
        let line = std::mem::take(pending);
        emit_live_line(&line, live_output, live_state);
    }
}

fn emit_live_line(
    line: &[u8],
    live_output: &LiveOutputConfig,
    live_state: &Arc<Mutex<LiveOutputState>>,
) {
    let text = String::from_utf8_lossy(line);
    let trimmed = text.trim();
    let Some(message) = humanize_live_output(trimmed) else {
        return;
    };
    let Ok(mut state) = live_state.lock() else {
        return;
    };
    if state.last_line.as_deref() == Some(message.as_str()) {
        return;
    }
    state.last_line = Some(message.clone());
    eprintln!("{} {}", live_output.prefix, message);
}

fn humanize_live_output(line: &str) -> Option<String> {
    if line.is_empty() {
        return None;
    }
    if line.starts_with('{') {
        return humanize_devenv_trace_line(line);
    }
    humanize_plain_live_output(line)
}

fn humanize_plain_live_output(line: &str) -> Option<String> {
    let trimmed = line.trim().trim_start_matches('•').trim();
    if trimmed.is_empty() {
        return None;
    }
    if is_interesting_live_output(trimmed) {
        return Some(trimmed.to_string());
    }
    None
}

fn humanize_devenv_trace_line(line: &str) -> Option<String> {
    let value = serde_json::from_str::<JsonValue>(line).ok()?;
    let fields = value.get("fields")?;

    if fields.get("devenv.ui.message").and_then(JsonValue::as_bool) == Some(true)
        && fields
            .get("devenv.span_event_kind")
            .and_then(JsonValue::as_i64)
            == Some(0)
    {
        let message = fields
            .get("message")
            .and_then(JsonValue::as_str)
            .map(str::to_string)?;
        if message == "Configuring shell" {
            return Some(message);
        }
        return None;
    }

    let event = fields.get("event")?;
    let activity_kind = event.get("activity_kind").and_then(JsonValue::as_str)?;
    let event_kind = event.get("event").and_then(JsonValue::as_str)?;

    match (activity_kind, event_kind) {
        ("fetch", "start") => {
            let name = event
                .get("name")
                .and_then(JsonValue::as_str)
                .map(short_progress_name)?;
            let host = event
                .get("url")
                .and_then(JsonValue::as_str)
                .and_then(trace_url_host);
            Some(match host {
                Some(host) => format!("Fetching {name} from {host}"),
                None => format!("Fetching {name}"),
            })
        }
        ("fetch", "complete") => event
            .get("name")
            .and_then(JsonValue::as_str)
            .map(short_progress_name)
            .map(|name| format!("Fetched {name}")),
        ("build", "start") => event
            .get("name")
            .and_then(JsonValue::as_str)
            .map(short_progress_name)
            .map(|name| format!("Building {name}")),
        ("evaluate", "start") => {
            let name = event.get("name").and_then(JsonValue::as_str)?;
            if name == "Evaluating shell" {
                Some(name.to_string())
            } else {
                None
            }
        }
        _ => None,
    }
}

fn short_progress_name(name: &str) -> String {
    Path::new(name)
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or(name)
        .to_string()
}

fn heartbeat_interval(elapsed: Duration) -> Duration {
    if elapsed < Duration::from_secs(30) {
        Duration::from_secs(5)
    } else if elapsed < Duration::from_secs(120) {
        Duration::from_secs(15)
    } else {
        Duration::from_secs(30)
    }
}

fn trace_url_host(url: &str) -> Option<&str> {
    let (_, remainder) = url.split_once("://")?;
    Some(remainder.split('/').next().unwrap_or(remainder))
}

fn is_interesting_live_output(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    lower.contains("configuring shell")
        || lower.contains("installing")
        || lower.contains("resolving packages")
        || lower.contains("fetching packages")
        || lower.contains("linking dependencies")
        || lower.contains("building fresh packages")
        || lower.contains("downloading")
        || lower.contains("extracting")
        || lower.contains("need to install the following packages")
        || lower.contains("the following package was not found and will be installed")
        || lower.contains("added ")
        || lower.contains("audited ")
        || lower.contains("yn0000")
        || lower.contains("yn0007")
        || lower.contains("yn0013")
        || lower.contains("yn0085")
}

fn init_progress_probe(spec: ProgressProbeSpec) -> ProgressProbeState {
    ProgressProbeState {
        spec,
        initial_npx_dirs: snapshot_npx_dirs(),
        last_message: None,
        started_at: SystemTime::now(),
    }
}

fn progress_probe_detail(state: &mut ProgressProbeState) -> Option<String> {
    let message = match &state.spec {
        ProgressProbeSpec::JavaScriptInstall { root } => {
            javascript_install_progress_detail(root, &state.initial_npx_dirs, state.started_at)
        }
    }?;

    if state.last_message.as_deref() == Some(message.as_str()) {
        return None;
    }
    state.last_message = Some(message.clone());
    Some(message)
}

fn javascript_install_progress_detail(
    root: &Path,
    initial_npx_dirs: &BTreeSet<PathBuf>,
    started_at: SystemTime,
) -> Option<String> {
    let project_node_modules = root.join("node_modules");
    if project_node_modules.exists() {
        let entries = count_dir_entries(&project_node_modules)?;
        return Some(format!(
            "prog js project node_modules: {entries} top-level entries materialized"
        ));
    }

    let npx_dir = active_npx_cache_dir(initial_npx_dirs, started_at)?;
    let npx_node_modules = npx_dir.join("node_modules");
    let entries = count_dir_entries(&npx_node_modules).unwrap_or(0);
    let staged_entries = count_dir_entries(&npx_dir).unwrap_or(0);
    let label = npx_dir
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("npx");

    if entries > 0 {
        Some(format!(
            "prog js npx cache `{label}`: {entries} top-level entries materialized"
        ))
    } else if staged_entries > 0 {
        Some(format!(
            "prog js npx cache `{label}`: {staged_entries} staged entries created"
        ))
    } else {
        Some(format!(
            "prog js npx cache `{label}` created; waiting for package contents"
        ))
    }
}

fn active_npx_cache_dir(
    initial_npx_dirs: &BTreeSet<PathBuf>,
    started_at: SystemTime,
) -> Option<PathBuf> {
    snapshot_npx_dirs()
        .into_iter()
        .filter_map(|path| {
            let modified = path.metadata().and_then(|meta| meta.modified()).ok()?;
            Some((path, modified))
        })
        .filter(|(path, modified)| *modified >= started_at || !initial_npx_dirs.contains(path))
        .max_by_key(|(_, modified)| *modified)
        .map(|(path, _)| path)
}

fn snapshot_npx_dirs() -> BTreeSet<PathBuf> {
    let Some(home) = dirs::home_dir() else {
        return BTreeSet::new();
    };
    let root = home.join(".npm/_npx");
    fs::read_dir(root)
        .ok()
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .collect()
}

fn count_dir_entries(path: &Path) -> Option<usize> {
    fs::read_dir(path).ok().map(|entries| entries.count())
}

fn start_verify_services(
    root: &Path,
    analysis: &Analysis,
    output_style: VerifyOutputStyle,
) -> Result<ServiceStartResult> {
    let Some(devenv_root) = existing_devenv_root(root) else {
        return Ok(ServiceStartResult::NotNeeded);
    };
    if analysis.services.is_empty() || preferred_command_path("devenv").is_none() {
        return Ok(ServiceStartResult::NotNeeded);
    }

    let processes = service_process_names(&analysis.services);
    if processes.is_empty() {
        return Ok(ServiceStartResult::NotNeeded);
    }

    let command = format!("devenv up --detach {}", processes.join(" "));
    let progress = service_progress(&processes, output_style);
    let mut child = Command::new("devenv");
    child
        .current_dir(&devenv_root)
        .arg("--verbose")
        .args(["up", "--detach", "--no-tui", "--no-reload"])
        .args(&processes);
    let output = run_captured_command(
        &mut child,
        &format!("failed to run `{command}`"),
        progress.as_ref(),
    )?;

    if output.output.status.success() {
        return Ok(ServiceStartResult::Started(StartedServices {
            processes,
            duration: output.duration,
        }));
    }

    Ok(ServiceStartResult::Failed(CheckFailure {
        kind: "service",
        subject: command.clone(),
        exit_code: output.output.status.code(),
        summary: summarize_failure("service", &command, &output.output),
        duration: Some(output.duration),
    }))
}

fn summarize_failure(kind: &str, command: &str, output: &Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined = format!("{stderr}\n{stdout}");
    let lines = combined
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();

    if lines.is_empty() {
        return fallback_summary(kind, command, output.status.code());
    }

    if is_format_check(command) {
        return "formatting changes are required".to_string();
    }

    if command.contains("cargo clippy") {
        if let Some(line) = pick_line(&lines, &["error:", "warning:"]) {
            return normalize_summary(line);
        }
        return "clippy reported warnings or errors".to_string();
    }

    if kind == "test" {
        if let Some(line) = pick_following_detail(&lines, &["Validation Error", "FAILURES"]) {
            return normalize_summary(line);
        }
        if let Some(line) = pick_line(
            &lines,
            &[
                "test result: FAILED",
                "Cannot find module",
                "not found",
                "Exception",
                "Traceback",
                "failed",
                "Failure/Error:",
                "FAILURES",
            ],
        ) {
            return normalize_summary(line);
        }
        return "one or more tests failed".to_string();
    }

    if let Some(line) = pick_line(
        &lines,
        &[
            "error:",
            "Error:",
            "ERROR:",
            "Compilation error",
            "could not compile",
            "undefined",
            "No such file",
            "not found",
            "failed",
            "Failure/Error:",
            "Traceback",
            "Exception",
        ],
    ) {
        return normalize_summary(line);
    }

    normalize_summary(lines.last().copied().unwrap_or_default())
}

fn fallback_summary(kind: &str, command: &str, exit_code: Option<i32>) -> String {
    let code = exit_code
        .map(|value| value.to_string())
        .unwrap_or_else(|| "signal".to_string());
    if is_format_check(command) || kind == "lint" && command.contains("format") {
        return format!("formatting check exited with {code}");
    }
    format!("{kind} command exited with {code}")
}

fn is_format_check(command: &str) -> bool {
    command.contains("fmt --check") || command.contains("format --check")
}

fn pick_line<'a>(lines: &'a [&'a str], needles: &[&str]) -> Option<&'a str> {
    for needle in needles {
        if let Some(line) = lines
            .iter()
            .copied()
            .find(|line| line.contains(needle) && !is_noise_failure_line(line))
        {
            return Some(line);
        }
    }
    None
}

fn pick_following_detail<'a>(lines: &'a [&'a str], anchors: &[&str]) -> Option<&'a str> {
    for anchor in anchors {
        if let Some(index) = lines
            .iter()
            .position(|line| line.contains(anchor) && !is_noise_failure_line(line))
        {
            for line in lines.iter().copied().skip(index + 1) {
                if is_noise_failure_line(line) {
                    continue;
                }
                if line.ends_with(':') && line.len() <= 32 {
                    continue;
                }
                return Some(line);
            }
        }
    }
    None
}

fn is_noise_failure_line(line: &str) -> bool {
    let trimmed = line.trim();
    let lower = trimmed.to_ascii_lowercase();
    trimmed.is_empty()
        || lower.starts_with("configuring shell")
        || lower.starts_with("loading tasks")
        || lower.starts_with("running tasks")
        || lower.starts_with("running ")
        || lower.starts_with("succeeded ")
        || lower.starts_with("no command ")
        || lower.starts_with("run explicit apply")
        || lower.starts_with("run `explicit verify")
        || lower.starts_with("yarn run v")
        || lower.starts_with("$ npx ")
        || lower.starts_with("npm warn ")
        || lower.starts_with("info visit ")
        || lower == "1 skipped, 2 succeeded"
        || lower.starts_with("error command failed with exit code")
}

fn normalize_summary(line: &str) -> String {
    let mut value = line
        .replace('\u{1b}', "")
        .replace("● ", "")
        .replace("error: ", "")
        .replace("Error: ", "")
        .replace("ERROR: ", "");
    if value.len() > 180 {
        value.truncate(177);
        value.push_str("...");
    }
    value
}

fn format_duration(duration: Duration) -> String {
    let seconds = duration.as_secs_f64();
    if seconds >= 10.0 {
        format!("{seconds:.1}s")
    } else if seconds >= 1.0 {
        format!("{seconds:.2}s")
    } else {
        format!("{:.0}ms", duration.as_secs_f64() * 1000.0)
    }
}

fn print_failure_report(root: &Path, mode: VerifyMode, failure: &CheckFailure) {
    match mode {
        VerifyMode::User => {
            eprintln!();
            eprintln!("Verification failed.");
        }
        VerifyMode::StopHook => {
            eprintln!("Stop blocked because the project checks are still failing:");
        }
        VerifyMode::GitHook => {
            eprintln!("Push blocked because the project checks are failing:");
        }
    }

    let timing_suffix = failure
        .duration
        .map(|duration| format!(" ({})", format_duration(duration)))
        .unwrap_or_default();
    match failure.exit_code {
        Some(code) => eprintln!(
            " - {} [{}]: {}{}",
            failure.kind, code, failure.subject, timing_suffix
        ),
        None => eprintln!(" - {}: {}{}", failure.kind, failure.subject, timing_suffix),
    }
    eprintln!("   {}", failure.summary);
    eprintln!();
    eprintln!(
        "Run `explicit verify --root {}` after fixing the project.",
        root.display()
    );
    if mode == VerifyMode::StopHook {
        eprintln!("The agent must continue until all verification checks pass.");
    }
}

fn print_claude_stop_block_json(failure: &CheckFailure) -> Result<()> {
    let reason = build_stop_reason(failure);
    println!(
        "{}",
        serde_json::to_string(&serde_json::json!({
            "decision": "block",
            "reason": reason
        }))?
    );
    Ok(())
}

fn build_stop_reason(failure: &CheckFailure) -> String {
    format!(
        "Project checks are still failing. Continue working until this passes: {} `{}`: {}.",
        failure.kind, failure.subject, failure.summary
    )
}

fn detect_stop_hook_client(mode: VerifyMode) -> StopHookClient {
    if mode != VerifyMode::StopHook {
        return StopHookClient::Other;
    }

    if std::env::vars().any(|(key, _)| key.starts_with("CLAUDE_")) {
        return StopHookClient::Claude;
    }

    if io::stdin().is_terminal() {
        return StopHookClient::Other;
    }

    let mut stdin = io::stdin().lock();
    let mut payload = String::new();
    if stdin.read_to_string(&mut payload).is_err() {
        return StopHookClient::Other;
    }
    let Ok(value) = serde_json::from_str::<JsonValue>(&payload) else {
        return StopHookClient::Other;
    };
    let transcript_path = value
        .get("transcript_path")
        .and_then(JsonValue::as_str)
        .unwrap_or_default();
    if transcript_path.contains("/.claude/") || transcript_path.contains("\\.claude\\") {
        return StopHookClient::Claude;
    }

    StopHookClient::Other
}

fn verify_output_style(mode: VerifyMode) -> VerifyOutputStyle {
    verify_output_style_with_stderr_terminal(mode, io::stderr().is_terminal())
}

fn verify_output_style_with_stderr_terminal(
    mode: VerifyMode,
    stderr_is_terminal: bool,
) -> VerifyOutputStyle {
    if mode == VerifyMode::User && stderr_is_terminal {
        VerifyOutputStyle::Interactive
    } else {
        VerifyOutputStyle::Compact
    }
}

fn print_started_services(started: &StartedServices) {
    eprintln!(
        "svc  {} ({})",
        started.processes.join(", "),
        format_duration(started.duration)
    );
}

fn print_compact_pass() {
    eprintln!("[PASS]");
}

fn displayed_check_count(command_checks: usize, total_checks: usize) -> usize {
    if command_checks > 0 {
        command_checks
    } else {
        total_checks
    }
}

fn should_use_devenv(root: &Path) -> bool {
    devenv_root_for_check_with_env(
        root,
        preferred_command_path("devenv").is_some(),
        current_devenv_root().as_deref(),
    )
    .is_some()
}

fn devenv_root_for_check(root: &Path) -> Option<std::path::PathBuf> {
    devenv_root_for_check_with_env(
        root,
        preferred_command_path("devenv").is_some(),
        current_devenv_root().as_deref(),
    )
}

fn devenv_root_for_check_with_env(
    root: &Path,
    has_devenv_binary: bool,
    current_devenv_root: Option<&Path>,
) -> Option<std::path::PathBuf> {
    if !has_devenv_binary {
        return None;
    }

    let devenv_root = existing_devenv_root(root)?;
    if is_matching_devenv_root(&devenv_root, current_devenv_root) {
        return None;
    }

    Some(devenv_root)
}

fn existing_devenv_root(root: &Path) -> Option<std::path::PathBuf> {
    root.ancestors()
        .find(|candidate| candidate.join("devenv.nix").is_file())
        .map(Path::to_path_buf)
}

fn current_devenv_root() -> Option<std::path::PathBuf> {
    std::env::var_os("DEVENV_ROOT")
        .filter(|value| !value.is_empty())
        .map(std::path::PathBuf::from)
}

fn command_in_devenv_shell(
    root: &Path,
    devenv_root: &Path,
    analysis: &Analysis,
    command: &str,
) -> String {
    command_with_runtime_env(root, Some(devenv_root), analysis, command)
}

fn command_with_runtime_env(
    root: &Path,
    devenv_root: Option<&Path>,
    analysis: &Analysis,
    command: &str,
) -> String {
    let mut segments = Vec::new();
    if analysis.services.contains(&ServiceRequirement::Postgres)
        && postgres_env_available(root, devenv_root)
    {
        segments.push("export PGHOST=\"${DEVENV_RUNTIME}/postgres\"".to_string());
        segments.push("export PGHOSTADDR=\"127.0.0.1\"".to_string());
    }
    if let Some(devenv_root) = devenv_root
        && !is_matching_devenv_root(root, Some(devenv_root))
    {
        segments.push(format!("cd {}", shell_quote(root)));
    }
    segments.push(command.to_string());
    segments.join(" && ")
}

fn postgres_env_available(root: &Path, devenv_root: Option<&Path>) -> bool {
    match devenv_root {
        Some(_) => true,
        None => existing_devenv_root(root)
            .as_deref()
            .is_some_and(|resolved_root| {
                is_matching_devenv_root(resolved_root, current_devenv_root().as_deref())
            }),
    }
}

fn service_process_names(services: &[ServiceRequirement]) -> Vec<&'static str> {
    let mut processes = Vec::new();
    for service in services {
        let process = match service {
            ServiceRequirement::Mysql => "mysql",
            ServiceRequirement::Postgres => "postgres",
            ServiceRequirement::Redis => "redis",
        };
        if !processes.contains(&process) {
            processes.push(process);
        }
    }
    processes
}

fn is_matching_devenv_root(root: &Path, current_devenv_root: Option<&Path>) -> bool {
    let Some(current_devenv_root) = current_devenv_root else {
        return false;
    };

    if root == current_devenv_root {
        return true;
    }

    match (root.canonicalize(), current_devenv_root.canonicalize()) {
        (Ok(root), Ok(current)) => root == current,
        _ => false,
    }
}

fn shell_quote(path: &Path) -> String {
    format!("'{}'", path.display().to_string().replace('\'', r#"'"'"'"#))
}

#[cfg(test)]
mod tests {
    use super::{
        ProjectCheck, VerifyMode, build_stop_reason, check_preflight_note, command_in_devenv_shell,
        command_with_runtime_env, devenv_root_for_check_with_env, existing_devenv_root,
        first_project_policy_failure, humanize_devenv_trace_line, humanize_live_output,
        is_matching_devenv_root, missing_workflow_commands, normalize_summary,
        prepare_verify_environment, project_checks, service_process_names, shell_quote,
        should_use_devenv, summarize_failure, tokens_are_subsequence,
        verify_output_style_with_stderr_terminal, workflow_runs_command,
    };
    use crate::analysis::{
        Analysis, GitHubRepository, GitHubVisibility, RepositoryMetadata, SandboxPlan,
        ServiceRequirement,
    };
    use std::os::unix::process::ExitStatusExt;
    use std::path::PathBuf;
    use std::process::Output;
    use std::time::Duration;

    fn analysis_with_checks() -> Analysis {
        Analysis {
            root: PathBuf::from("/tmp/project"),
            markers: Vec::new(),
            manifests: Vec::new(),
            detected_languages: Vec::new(),
            detected_versions: Vec::new(),
            language_hints: Vec::new(),
            packages: Vec::new(),
            services: Vec::new(),
            nix_options: Vec::new(),
            requires_allow_unfree: false,
            lint_commands: vec!["lint-a".to_string()],
            build_commands: vec!["build-a".to_string()],
            test_commands: vec!["test-a".to_string()],
            notes: Vec::new(),
            repository: RepositoryMetadata::default(),
            sandbox_plan: SandboxPlan {
                root: PathBuf::from("/tmp/project"),
                read_write_files: Vec::new(),
                read_write_dirs: Vec::new(),
                read_only_files: Vec::new(),
                read_only_dirs: Vec::new(),
                notes: Vec::new(),
            },
        }
    }

    fn failed_output(stdout: &str, stderr: &str) -> Output {
        Output {
            status: ExitStatusExt::from_raw(256),
            stdout: stdout.as_bytes().to_vec(),
            stderr: stderr.as_bytes().to_vec(),
        }
    }

    #[test]
    fn collects_checks_in_lint_build_test_order() {
        let checks = project_checks(&analysis_with_checks());
        assert_eq!(checks.len(), 3);
        assert_eq!(checks[0].kind, "lint");
        assert_eq!(checks[1].kind, "build");
        assert_eq!(checks[2].kind, "test");
        assert_eq!(checks[0].ordinal, 0);
        assert_eq!(checks[1].ordinal, 1);
        assert_eq!(checks[2].ordinal, 2);
    }

    #[test]
    fn only_uses_devenv_when_config_and_binary_exist() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!should_use_devenv(dir.path()));
        std::fs::write(dir.path().join("devenv.nix"), "{ pkgs, ... }: {}\n").unwrap();
        let _ = should_use_devenv(dir.path());
    }

    #[test]
    fn finds_nearest_ancestor_devenv_root() {
        let dir = tempfile::tempdir().unwrap();
        let workspace = dir.path().join("workspace");
        let service = workspace.join("services/stuffix");
        std::fs::create_dir_all(&service).unwrap();
        std::fs::write(workspace.join("devenv.nix"), "{ pkgs, ... }: {}\n").unwrap();
        assert_eq!(existing_devenv_root(&service), Some(workspace));
    }

    #[test]
    fn matches_current_devenv_root_for_same_project() {
        let dir = tempfile::tempdir().unwrap();
        assert!(is_matching_devenv_root(dir.path(), Some(dir.path())));
    }

    #[test]
    fn skips_nested_devenv_shell_for_matching_root() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("devenv.nix"), "{ pkgs, ... }: {}\n").unwrap();
        assert_eq!(
            devenv_root_for_check_with_env(dir.path(), true, Some(dir.path())),
            None
        );
    }

    #[test]
    fn still_uses_devenv_for_other_project_shells() {
        let dir = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("devenv.nix"), "{ pkgs, ... }: {}\n").unwrap();
        assert_eq!(
            devenv_root_for_check_with_env(dir.path(), true, Some(other.path())),
            Some(dir.path().to_path_buf())
        );
    }

    #[test]
    fn uses_ancestor_devenv_root_for_nested_project_checks() {
        let dir = tempfile::tempdir().unwrap();
        let workspace = dir.path().join("workspace");
        let service = workspace.join("services/stuffix");
        std::fs::create_dir_all(&service).unwrap();
        std::fs::write(workspace.join("devenv.nix"), "{ pkgs, ... }: {}\n").unwrap();
        assert_eq!(
            devenv_root_for_check_with_env(&service, true, None),
            Some(workspace)
        );
    }

    #[test]
    fn reuses_ancestor_devenv_shell_without_nesting() {
        let dir = tempfile::tempdir().unwrap();
        let workspace = dir.path().join("workspace");
        let service = workspace.join("services/stuffix");
        std::fs::create_dir_all(&service).unwrap();
        std::fs::write(workspace.join("devenv.nix"), "{ pkgs, ... }: {}\n").unwrap();
        assert_eq!(
            devenv_root_for_check_with_env(&service, true, Some(&workspace)),
            None
        );
    }

    #[test]
    fn prepare_verify_environment_keeps_existing_ancestor_devenv() {
        let dir = tempfile::tempdir().unwrap();
        let workspace = dir.path().join("workspace");
        let service = workspace.join("services/stuffix");
        std::fs::create_dir_all(&service).unwrap();
        std::fs::write(workspace.join("devenv.nix"), "{ pkgs, ... }: {}\n").unwrap();

        let analysis = analysis_with_checks();
        prepare_verify_environment(&service, &analysis).unwrap();

        assert!(!service.join("devenv.nix").exists());
    }

    #[test]
    fn prepare_verify_environment_creates_local_devenv_without_ancestor() {
        let dir = tempfile::tempdir().unwrap();
        let analysis = analysis_with_checks();

        prepare_verify_environment(dir.path(), &analysis).unwrap();

        assert!(dir.path().join("devenv.nix").is_file());
    }

    #[test]
    fn nested_project_commands_cd_back_to_original_root() {
        let dir = tempfile::tempdir().unwrap();
        let workspace = dir.path().join("workspace");
        let service = workspace.join("services/stuffix");
        std::fs::create_dir_all(&service).unwrap();
        let command =
            command_in_devenv_shell(&service, &workspace, &analysis_with_checks(), "mix test");
        assert_eq!(command, format!("cd {} && mix test", shell_quote(&service)));
    }

    #[test]
    fn postgres_commands_export_socket_env_inside_devenv() {
        let dir = tempfile::tempdir().unwrap();
        let mut analysis = analysis_with_checks();
        analysis.services = vec![ServiceRequirement::Postgres];
        let command = command_with_runtime_env(dir.path(), Some(dir.path()), &analysis, "mix test");
        assert_eq!(
            command,
            "export PGHOST=\"${DEVENV_RUNTIME}/postgres\" && export PGHOSTADDR=\"127.0.0.1\" && mix test"
        );
    }

    #[test]
    fn service_process_names_match_detected_services() {
        assert_eq!(
            service_process_names(&[
                ServiceRequirement::Postgres,
                ServiceRequirement::Redis,
                ServiceRequirement::Postgres,
            ]),
            vec!["postgres", "redis"]
        );
    }

    #[test]
    fn missing_node_modules_gets_a_preflight_note() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("package.json"), "{}\n").unwrap();
        let check = ProjectCheck {
            ordinal: 0,
            kind: "test",
            command: "yarn test".to_string(),
        };

        let note = check_preflight_note(&check, dir.path(), 2).expect("expected note");
        assert!(note.contains("node_modules"));
        assert!(note.contains("large JavaScript dependency download"));
    }

    #[test]
    fn humanizes_devenv_trace_fetch_events() {
        let line = r#"{"fields":{"event":{"activity_kind":"fetch","event":"start","name":"android-ndk-r26b-darwin.zip","url":"https://cache.nixos.org","timestamp":"2026-04-12T06:18:17.052521000Z"}},"level":"TRACE","target":"devenv::activity","timestamp":"2026-04-12T06:18:17.052536Z"}"#;
        assert_eq!(
            humanize_devenv_trace_line(line).as_deref(),
            Some("Fetching android-ndk-r26b-darwin.zip from cache.nixos.org")
        );
    }

    #[test]
    fn humanize_live_output_ignores_uninteresting_trace_json() {
        let line = r#"{"fields":{"event":{"activity_kind":"evaluate","event":"op","id":9223372036854775812,"op":{"kind":"evaluated_file","source":"/tmp/default.nix"}},"level":"TRACE","target":"devenv::activity","timestamp":"2026-04-12T06:18:14.352347Z"}"#;
        assert_eq!(humanize_live_output(line), None);
    }

    #[test]
    fn humanize_live_output_ignores_internal_task_lines() {
        assert_eq!(
            humanize_live_output("Running           devenv:enterShell"),
            None
        );
        assert_eq!(
            humanize_live_output("Succeeded         devenv:enterShell (24.24ms)"),
            None
        );
    }

    #[test]
    fn summarize_format_failures_concisely() {
        let summary = summarize_failure(
            "lint",
            "cargo fmt --check",
            &failed_output("", "Diff in src/main.rs:1:\n"),
        );
        assert_eq!(summary, "formatting changes are required");
    }

    #[test]
    fn summarize_build_failures_from_error_lines() {
        let summary = summarize_failure(
            "build",
            "cargo build --release",
            &failed_output(
                "",
                "error: could not compile `demo` due to 1 previous error\n",
            ),
        );
        assert_eq!(summary, "could not compile `demo` due to 1 previous error");
    }

    #[test]
    fn summarize_test_failures_skips_package_manager_wrapper_noise() {
        let output = failed_output(
            "yarn run v1.22.22\n$ npx test-runner\n● Validation Error:\n\n  Preset example-preset not found relative to rootDir /tmp/project.\n\n  Configuration Documentation:\n  https://example.test/docs/configuration\n\nerror Command failed with exit code 1.\n",
            "",
        );
        let summary = summarize_failure("test", "yarn test", &output);
        assert_eq!(
            summary,
            "Preset example-preset not found relative to rootDir /tmp/project."
        );
    }

    #[test]
    fn builds_short_stop_reason() {
        let reason = build_stop_reason(&super::CheckFailure {
            kind: "lint",
            subject: "cargo fmt --check".to_string(),
            exit_code: Some(1),
            summary: "formatting changes are required".to_string(),
            duration: Some(Duration::from_millis(150)),
        });
        assert!(reason.contains("Project checks are still failing"));
        assert!(reason.contains("cargo fmt --check"));
    }

    #[test]
    fn formats_short_durations_compactly() {
        assert_eq!(super::format_duration(Duration::from_millis(42)), "42ms");
        assert_eq!(super::format_duration(Duration::from_millis(1250)), "1.25s");
        assert_eq!(
            super::format_duration(Duration::from_millis(12_340)),
            "12.3s"
        );
    }

    #[test]
    fn normalizes_summary_length() {
        let line = format!("error: {}", "x".repeat(300));
        let summary = normalize_summary(&line);
        assert!(summary.len() <= 180);
    }

    #[test]
    fn verify_mode_prefers_stop_hook_over_git_hook() {
        assert_eq!(VerifyMode::from_flags(true, true), VerifyMode::StopHook);
        assert_eq!(VerifyMode::from_flags(false, true), VerifyMode::GitHook);
        assert_eq!(VerifyMode::from_flags(false, false), VerifyMode::User);
    }

    #[test]
    fn interactive_output_is_only_for_user_terminal_sessions() {
        assert_eq!(
            verify_output_style_with_stderr_terminal(VerifyMode::User, true),
            super::VerifyOutputStyle::Interactive
        );
        assert_eq!(
            verify_output_style_with_stderr_terminal(VerifyMode::User, false),
            super::VerifyOutputStyle::Compact
        );
        assert_eq!(
            verify_output_style_with_stderr_terminal(VerifyMode::StopHook, true),
            super::VerifyOutputStyle::Compact
        );
        assert_eq!(
            verify_output_style_with_stderr_terminal(VerifyMode::GitHook, true),
            super::VerifyOutputStyle::Compact
        );
    }

    #[test]
    fn requires_readme_for_git_repositories() {
        let dir = tempfile::tempdir().unwrap();
        let mut analysis = analysis_with_checks();
        analysis.repository = RepositoryMetadata {
            is_git_repository: true,
            ..RepositoryMetadata::default()
        };

        let failure = first_project_policy_failure(dir.path(), &analysis)
            .unwrap()
            .expect("expected readme failure");
        assert_eq!(failure.kind, "docs");
        assert_eq!(failure.subject, "README.md");
        assert!(failure.summary.contains("README.md"));
    }

    #[test]
    fn requires_license_for_public_github_repositories() {
        let dir = tempfile::tempdir().unwrap();
        let mut analysis = analysis_with_checks();
        analysis.repository = RepositoryMetadata {
            github: Some(GitHubRepository {
                slug: "example/demo".to_string(),
                visibility: GitHubVisibility::Public,
            }),
            ..RepositoryMetadata::default()
        };

        let failure = first_project_policy_failure(dir.path(), &analysis)
            .unwrap()
            .expect("expected license failure");
        assert_eq!(failure.kind, "license");
        assert_eq!(failure.subject, "LICENSE");
    }

    #[test]
    fn validates_workflow_coverage_for_public_repositories() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".github/workflows")).unwrap();
        std::fs::write(
            dir.path().join(".github/workflows/ci.yml"),
            r#"
name: CI
on:
  push:
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: cargo test --locked
"#,
        )
        .unwrap();

        let mut analysis = analysis_with_checks();
        analysis.repository = RepositoryMetadata {
            github: Some(GitHubRepository {
                slug: "example/demo".to_string(),
                visibility: GitHubVisibility::Public,
            }),
            license_path: Some("LICENSE".to_string()),
            workflow_files: vec![".github/workflows/ci.yml".to_string()],
            ..RepositoryMetadata::default()
        };

        let failure = first_project_policy_failure(dir.path(), &analysis)
            .unwrap()
            .expect("expected workflow coverage failure");
        assert_eq!(failure.kind, "ci");
        assert_eq!(failure.subject, "lint-a");
        assert!(failure.summary.contains("lint-a"));
    }

    #[test]
    fn detects_invalid_workflow_yaml() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".github/workflows")).unwrap();
        std::fs::write(
            dir.path().join(".github/workflows/ci.yml"),
            "name: [broken\n",
        )
        .unwrap();

        let mut analysis = analysis_with_checks();
        analysis.repository = RepositoryMetadata {
            workflow_files: vec![".github/workflows/ci.yml".to_string()],
            ..RepositoryMetadata::default()
        };

        let failure = first_project_policy_failure(dir.path(), &analysis)
            .unwrap()
            .expect("expected workflow syntax failure");
        assert_eq!(failure.kind, "ci");
        assert_eq!(failure.subject, ".github/workflows");
        assert!(failure.summary.contains("syntax is invalid"));
    }

    #[test]
    fn prioritizes_repository_prerequisites_one_at_a_time() {
        let dir = tempfile::tempdir().unwrap();
        let mut analysis = analysis_with_checks();
        analysis.repository = RepositoryMetadata {
            is_git_repository: true,
            github: Some(GitHubRepository {
                slug: "example/demo".to_string(),
                visibility: GitHubVisibility::Public,
            }),
            ..RepositoryMetadata::default()
        };

        let failure = first_project_policy_failure(dir.path(), &analysis)
            .unwrap()
            .expect("expected first failure");
        assert_eq!(failure.subject, "README.md");

        analysis.repository.readme_path = Some("README.md".to_string());
        let failure = first_project_policy_failure(dir.path(), &analysis)
            .unwrap()
            .expect("expected second failure");
        assert_eq!(failure.subject, "LICENSE");
    }

    #[test]
    fn workflow_command_matching_accepts_wrapped_commands() {
        assert!(workflow_runs_command(
            &[String::from("rtk cargo test --locked")],
            "cargo test"
        ));
        assert!(tokens_are_subsequence(
            &["rtk", "cargo", "build", "--release"],
            &["cargo", "build", "--release"]
        ));
    }

    #[test]
    fn missing_workflow_commands_reports_uncovered_checks() {
        let analysis = analysis_with_checks();
        let missing = missing_workflow_commands(&analysis, &[String::from("lint-a && test-a")]);
        assert_eq!(missing, vec!["build-a".to_string()]);
    }

    #[test]
    fn cargo_build_family_shares_a_lane() {
        let checks = project_checks(&analysis_with_checks());
        let lanes = super::build_check_lanes(&checks);
        assert_eq!(lanes.len(), 3);
        assert_eq!(
            lanes[0]
                .iter()
                .map(|check| check.command.as_str())
                .collect::<Vec<_>>(),
            vec!["lint-a"]
        );

        let cargo_checks = [
            ProjectCheck {
                ordinal: 0,
                kind: "lint",
                command: "cargo fmt --check".to_string(),
            },
            ProjectCheck {
                ordinal: 1,
                kind: "lint",
                command: "cargo clippy --all-targets".to_string(),
            },
            ProjectCheck {
                ordinal: 2,
                kind: "build",
                command: "cargo build --release".to_string(),
            },
            ProjectCheck {
                ordinal: 3,
                kind: "test",
                command: "cargo test".to_string(),
            },
        ];
        let lanes = super::build_check_lanes(&cargo_checks);
        assert_eq!(lanes.len(), 2);
        assert_eq!(lanes[0].len(), 1);
        assert_eq!(lanes[1].len(), 3);
    }
}
