use std::collections::BTreeSet;
use std::fs;
use std::io::{self, IsTerminal, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, ExitCode, Output, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Context, Result, anyhow};
use pulldown_cmark::{Event, HeadingLevel, Parser, Tag, TagEnd};
use serde_json::Value as JsonValue;
use serde_yaml::{Mapping as YamlMapping, Value as YamlValue};

use crate::analysis::{Analysis, MigrationCheck, MigrationCheckKind, ServiceRequirement};
use crate::host_tools::preferred_command_path;
use crate::runtime::{devenv_already_running_pid, stale_devenv_cache_detected};

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
    reused_pid: Option<String>,
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

pub fn session_start_note(root: &Path) -> Result<Option<String>> {
    let Some(failure) = stop_hook_remote_sync_failure(root)? else {
        return Ok(None);
    };
    Ok(Some(format!(
        "explicit: {} Finish by pushing branch and creating or updating the pull request before stopping.",
        failure.summary
    )))
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
    let checks = project_checks(analysis, mode);
    let command_checks = analysis.migration_checks.len() + checks.len();
    let total_checks = command_checks + project_policy_check_count(analysis, mode);
    let displayed_checks = displayed_check_count(command_checks, total_checks);

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
        print_workspace_notes(analysis);
    }

    if let Some(failure) = first_project_policy_failure(root, analysis, mode)? {
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

    if let Some(failure) = run_migration_checks(
        root,
        analysis,
        mode,
        output_style,
        analysis.migration_checks.len(),
        checks.len(),
    )? {
        return report_single_failure(root, mode, hook_client, failure);
    }

    let executions = execute_checks(root, analysis, &checks, output_style)?;
    for execution in executions {
        let check = execution.check;
        let output = maybe_apply_safe_lint_autofix(
            root,
            analysis,
            mode,
            &check,
            execution.output,
            output_style,
            checks.len(),
        )?;
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

fn maybe_apply_safe_lint_autofix(
    root: &Path,
    analysis: &Analysis,
    mode: VerifyMode,
    check: &ProjectCheck,
    output: CheckOutput,
    output_style: VerifyOutputStyle,
    total_checks: usize,
) -> Result<CheckOutput> {
    if output.output.status.success() || !should_attempt_safe_autofix(mode, check) {
        return Ok(output);
    }

    let Some(autofix_command) = safe_lint_autofix_command(&check.command) else {
        return Ok(output);
    };

    let autofix_progress =
        (output_style == VerifyOutputStyle::Interactive).then(|| CommandProgress {
            note_message: None,
            live_prefix: format!(
                "fix  [{}/{}] {:<5}",
                check.ordinal + 1,
                total_checks,
                check.kind
            ),
            progress_probe: None,
            start_message: format!(
                "fix  [{}/{}] {:<5} {}...",
                check.ordinal + 1,
                total_checks,
                check.kind,
                autofix_command
            ),
            wait_prefix: format!(
                "fix  [{}/{}] {:<5} {}",
                check.ordinal + 1,
                total_checks,
                check.kind,
                autofix_command
            ),
        });
    let autofix_output = run_check(root, analysis, &autofix_command, autofix_progress.as_ref())?;
    if !autofix_output.output.status.success() {
        return Ok(output);
    }

    let rerun_progress = check_progress(check, root, total_checks, output_style);
    let rerun_output = run_check(root, analysis, &check.command, rerun_progress.as_ref())?;
    if output_style == VerifyOutputStyle::Interactive && rerun_output.output.status.success() {
        eprintln!(
            "fix  [{}/{}] {:<5} safe formatter correction passed",
            check.ordinal + 1,
            total_checks,
            check.kind
        );
    }
    Ok(rerun_output)
}

fn should_attempt_safe_autofix(mode: VerifyMode, check: &ProjectCheck) -> bool {
    mode != VerifyMode::GitHook && check.kind == "lint"
}

fn safe_lint_autofix_command(command: &str) -> Option<String> {
    safe_command_rewrite(command, "mix format --check-formatted", "mix format")
        .or_else(|| safe_command_rewrite(command, "cargo fmt --check", "cargo fmt"))
        .or_else(|| safe_command_rewrite(command, "tofu fmt -check", "tofu fmt"))
        .or_else(|| safe_command_rewrite(command, "terraform fmt -check", "terraform fmt"))
}

fn safe_command_rewrite(command: &str, needle: &str, replacement: &str) -> Option<String> {
    command
        .contains(needle)
        .then(|| command.replacen(needle, replacement, 1))
}

fn print_workspace_notes(analysis: &Analysis) {
    for note in analysis.notes.iter().filter(|note| {
        note.starts_with("Workspace: ")
            || note.starts_with("Workspace members:")
            || note.starts_with("Workspace excludes:")
    }) {
        eprintln!("note {note}");
    }
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

fn project_checks(analysis: &Analysis, mode: VerifyMode) -> Vec<ProjectCheck> {
    let mut checks = Vec::new();
    let base_ordinal = analysis.migration_checks.len();
    for command in &analysis.lint_commands {
        checks.push(ProjectCheck {
            ordinal: base_ordinal + checks.len(),
            kind: "lint",
            command: command.clone(),
        });
    }
    for command in &analysis.build_commands {
        checks.push(ProjectCheck {
            ordinal: base_ordinal + checks.len(),
            kind: "build",
            command: command.clone(),
        });
    }
    for command in &analysis.test_commands {
        checks.push(ProjectCheck {
            ordinal: base_ordinal + checks.len(),
            kind: "test",
            command: command.clone(),
        });
    }
    // Coverage is skipped in git-hook mode: it belongs in CI, not in pre-push hooks.
    if mode != VerifyMode::GitHook {
        for command in &analysis.coverage_commands {
            checks.push(ProjectCheck {
                ordinal: base_ordinal + checks.len(),
                kind: "coverage",
                command: command.clone(),
            });
        }
    }
    checks
}

fn run_migration_checks(
    root: &Path,
    analysis: &Analysis,
    mode: VerifyMode,
    output_style: VerifyOutputStyle,
    migration_checks: usize,
    normal_checks: usize,
) -> Result<Option<CheckFailure>> {
    if analysis.migration_checks.is_empty() {
        return Ok(None);
    }

    let total_checks = migration_checks + normal_checks;
    for (index, check) in analysis.migration_checks.iter().enumerate() {
        let progress =
            migration_check_progress(index, total_checks, &check.status_command, output_style);
        let output = run_check(root, analysis, &check.status_command, progress.as_ref())?;
        if !output.output.status.success() {
            return Ok(Some(CheckFailure {
                kind: "migration",
                subject: check.subject.clone(),
                exit_code: output.output.status.code(),
                summary: summarize_failure("migration", &check.status_command, &output.output),
                duration: Some(output.duration),
            }));
        }

        let pending = pending_migration_entries(check, &output.output);
        if pending.is_empty() {
            if output_style == VerifyOutputStyle::Interactive {
                eprintln!(
                    "ok   {:<9} {} ({})",
                    "migration",
                    check.status_command,
                    format_duration(output.duration)
                );
            }
            continue;
        }

        if mode == VerifyMode::StopHook {
            let apply_progress =
                migration_apply_progress(index, total_checks, &check.apply_command, output_style);
            let apply_output = run_check(
                root,
                analysis,
                &check.apply_command,
                apply_progress.as_ref(),
            )?;
            if !apply_output.output.status.success() {
                return Ok(Some(CheckFailure {
                    kind: "migration",
                    subject: check.apply_command.clone(),
                    exit_code: apply_output.output.status.code(),
                    summary: summarize_failure(
                        "migration",
                        &check.apply_command,
                        &apply_output.output,
                    ),
                    duration: Some(apply_output.duration),
                }));
            }

            let rerun_progress =
                migration_check_progress(index, total_checks, &check.status_command, output_style);
            let rerun_output = run_check(
                root,
                analysis,
                &check.status_command,
                rerun_progress.as_ref(),
            )?;
            if !rerun_output.output.status.success() {
                return Ok(Some(CheckFailure {
                    kind: "migration",
                    subject: check.subject.clone(),
                    exit_code: rerun_output.output.status.code(),
                    summary: summarize_failure(
                        "migration",
                        &check.status_command,
                        &rerun_output.output,
                    ),
                    duration: Some(rerun_output.duration),
                }));
            }
            let still_pending = pending_migration_entries(check, &rerun_output.output);
            if !still_pending.is_empty() {
                return Ok(Some(CheckFailure {
                    kind: "migration",
                    subject: check.subject.clone(),
                    exit_code: None,
                    summary: format!(
                        "pending migrations remain after `{}`: {}",
                        check.apply_command,
                        format_pending_migration_entries(&still_pending)
                    ),
                    duration: Some(rerun_output.duration),
                }));
            }
            if output_style == VerifyOutputStyle::Interactive {
                eprintln!(
                    "fix  [{}/{}] migration applied pending migrations with `{}`",
                    index + 1,
                    total_checks,
                    check.apply_command
                );
            }
            continue;
        }

        return Ok(Some(CheckFailure {
            kind: "migration",
            subject: check.subject.clone(),
            exit_code: None,
            summary: format!(
                "pending migrations detected: {}. Run `{}`.",
                format_pending_migration_entries(&pending),
                check.apply_command
            ),
            duration: Some(output.duration),
        }));
    }

    Ok(None)
}

fn execute_checks(
    root: &Path,
    analysis: &Analysis,
    checks: &[ProjectCheck],
    output_style: VerifyOutputStyle,
) -> Result<Vec<CheckExecution>> {
    let mut executions = Vec::new();
    let mut phase_start = 0;
    while phase_start < checks.len() {
        let phase_kind = checks[phase_start].kind;
        let phase_end = checks[phase_start..]
            .iter()
            .position(|check| check.kind != phase_kind)
            .map(|offset| phase_start + offset)
            .unwrap_or(checks.len());
        let phase_checks = &checks[phase_start..phase_end];
        let mut phase_executions =
            execute_phase_checks(root, analysis, phase_checks, checks.len(), output_style)?;
        let phase_failed = phase_executions
            .iter()
            .any(|execution| !execution.output.output.status.success());
        executions.append(&mut phase_executions);
        if phase_failed {
            break;
        }
        phase_start = phase_end;
    }
    Ok(executions)
}

fn execute_phase_checks(
    root: &Path,
    analysis: &Analysis,
    checks: &[ProjectCheck],
    total_checks: usize,
    output_style: VerifyOutputStyle,
) -> Result<Vec<CheckExecution>> {
    let lanes = build_check_lanes(checks);
    if lanes.is_empty() {
        return Ok(Vec::new());
    }
    if lanes.len() == 1 || should_use_devenv(root) {
        let mut executions = Vec::new();
        for check in lanes.into_iter().flatten() {
            let progress = check_progress(&check, root, total_checks, output_style);
            let output = run_check(root, analysis, &check.command, progress.as_ref())?;
            let succeeded = output.output.status.success();
            executions.push(CheckExecution { check, output });
            if !succeeded {
                break;
            }
        }
        return Ok(executions);
    }

    let root = root.to_path_buf();
    let handles = lanes
        .into_iter()
        .map(|lane| {
            let root = root.clone();
            let analysis = analysis.clone();
            thread::spawn(move || -> Result<Vec<CheckExecution>> {
                execute_check_lane(&root, &analysis, &lane, total_checks, output_style)
            })
        })
        .collect::<Vec<_>>();

    let mut executions = Vec::new();
    for handle in handles {
        let lane_results = handle
            .join()
            .map_err(|_| anyhow!("verification worker thread panicked"))??;
        executions.extend(lane_results);
    }
    executions.sort_by_key(|execution| execution.check.ordinal);
    Ok(executions)
}

fn execute_check_lane(
    root: &Path,
    analysis: &Analysis,
    lane: &[ProjectCheck],
    total_checks: usize,
    output_style: VerifyOutputStyle,
) -> Result<Vec<CheckExecution>> {
    let mut executions = Vec::new();
    for check in lane {
        let progress = check_progress(check, root, total_checks, output_style);
        let output = run_check(root, analysis, &check.command, progress.as_ref())?;
        let succeeded = output.output.status.success();
        executions.push(CheckExecution {
            check: check.clone(),
            output,
        });
        if !succeeded {
            break;
        }
    }
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
    if command.starts_with("cargo ") {
        return "cargo-target".to_string();
    }
    if command.starts_with("mix ") {
        return "mix-target".to_string();
    }
    command.to_string()
}

fn project_policy_check_count(analysis: &Analysis, mode: VerifyMode) -> usize {
    let mut count = 0;
    if analysis.repository.is_git_repository {
        count += 4 + analysis.install_directories.len();
        if mode == VerifyMode::StopHook {
            count += 1;
        }
    }
    count += analysis.required_checks.len();
    if analysis.repository.has_workflows() {
        count += 1;
    }
    if analysis.repository.is_public_github_repository() {
        count += 2;
    }
    count
}

fn first_project_policy_failure(
    root: &Path,
    analysis: &Analysis,
    mode: VerifyMode,
) -> Result<Option<CheckFailure>> {
    if analysis.repository.is_git_repository && !analysis.repository.has_readme() {
        return Ok(Some(CheckFailure {
            kind: "docs",
            subject: "README.md".to_string(),
            exit_code: None,
            summary: "git repositories must include a top-level README.md".to_string(),
            duration: None,
        }));
    }

    if analysis.repository.is_git_repository
        && let Some(summary) = first_invalid_readme_local_link(root, analysis)?
    {
        return Ok(Some(CheckFailure {
            kind: "docs",
            subject: "README.md#Links".to_string(),
            exit_code: None,
            summary,
            duration: None,
        }));
    }

    if analysis.repository.is_git_repository && !readme_has_license_section(root, analysis)? {
        return Ok(Some(CheckFailure {
            kind: "docs",
            subject: "README.md#License".to_string(),
            exit_code: None,
            summary: "git repositories must end README.md with exactly one `## License` section containing at least one word of paragraph content".to_string(),
            duration: None,
        }));
    }

    if analysis.repository.is_git_repository
        && let Some(failure) = first_package_install_directory_failure(root, analysis)?
    {
        return Ok(Some(failure));
    }

    if analysis.repository.is_git_repository && !ds_store_is_gitignored(root)? {
        return Ok(Some(CheckFailure {
            kind: "ignore",
            subject: ".gitignore".to_string(),
            exit_code: None,
            summary: "git repositories must ignore .DS_Store".to_string(),
            duration: None,
        }));
    }

    if let Some(requirement) = analysis.required_checks.first() {
        return Ok(Some(CheckFailure {
            kind: requirement.kind.as_str(),
            subject: requirement.subject.clone(),
            exit_code: None,
            summary: requirement.summary.clone(),
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

    if mode == VerifyMode::StopHook
        && analysis.repository.is_git_repository
        && let Some(failure) = stop_hook_remote_sync_failure(root)?
    {
        return Ok(Some(failure));
    }

    Ok(None)
}

fn stop_hook_remote_sync_failure(root: &Path) -> Result<Option<CheckFailure>> {
    let Some(branch) = git_stdout_optional(root, &["rev-parse", "--abbrev-ref", "HEAD"])? else {
        return Ok(None);
    };
    let branch = branch.trim();
    if branch.is_empty() || branch == "HEAD" {
        return Ok(None);
    }

    let upstream = git_stdout_optional(
        root,
        &[
            "rev-parse",
            "--abbrev-ref",
            "--symbolic-full-name",
            "@{upstream}",
        ],
    )?;
    let Some(upstream) = upstream.map(|value| value.trim().to_string()) else {
        return Ok(Some(CheckFailure {
            kind: "git",
            subject: branch.to_string(),
            exit_code: None,
            summary: format!(
                "branch `{branch}` has no upstream remote branch. Push it and create a pull request before stopping (for example: `git push -u origin HEAD`)."
            ),
            duration: None,
        }));
    };
    if upstream.is_empty() {
        return Ok(None);
    }

    let ahead = git_stdout(root, &["rev-list", "--count", &format!("{upstream}..HEAD")])?;
    let ahead = ahead.trim().parse::<usize>().unwrap_or(0);
    if ahead == 0 {
        return Ok(None);
    }

    let commit_word = if ahead == 1 { "commit" } else { "commits" };
    Ok(Some(CheckFailure {
        kind: "git",
        subject: branch.to_string(),
        exit_code: None,
        summary: format!(
            "branch `{branch}` is {ahead} {commit_word} ahead of `{upstream}`. Push your branch and create or update the pull request before stopping."
        ),
        duration: None,
    }))
}

fn git_stdout(root: &Path, args: &[&str]) -> Result<String> {
    let output = Command::new("git")
        .current_dir(root)
        .args(args)
        .output()
        .with_context(|| format!("failed to run git {}", args.join(" ")))?;
    if !output.status.success() {
        anyhow::bail!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn git_stdout_optional(root: &Path, args: &[&str]) -> Result<Option<String>> {
    let output = match Command::new("git").current_dir(root).args(args).output() {
        Ok(output) => output,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to run git {}", args.join(" ")));
        }
    };
    if output.status.success() {
        return Ok(Some(
            String::from_utf8_lossy(&output.stdout).trim().to_string(),
        ));
    }
    if output.status.code() == Some(128) {
        return Ok(None);
    }
    anyhow::bail!(
        "git {} failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr).trim()
    );
}

fn readme_has_license_section(root: &Path, analysis: &Analysis) -> Result<bool> {
    let Some(readme_path) = analysis.repository.readme_path.as_deref() else {
        return Ok(false);
    };
    let readme_path = root.join(readme_path);
    let contents = fs::read_to_string(&readme_path)
        .with_context(|| format!("failed to read {}", readme_path.display()))?;
    Ok(markdown_has_terminal_license_section(&contents))
}

fn first_invalid_readme_local_link(root: &Path, analysis: &Analysis) -> Result<Option<String>> {
    let Some(readme_path) = analysis.repository.readme_path.as_deref() else {
        return Ok(None);
    };
    let readme_path = root.join(readme_path);
    let contents = fs::read_to_string(&readme_path)
        .with_context(|| format!("failed to read {}", readme_path.display()))?;
    Ok(first_invalid_markdown_local_link(
        &contents,
        root,
        &readme_path,
    ))
}

fn first_invalid_markdown_local_link(
    contents: &str,
    repo_root: &Path,
    readme_path: &Path,
) -> Option<String> {
    let readme_dir = readme_path.parent().unwrap_or(repo_root);
    for event in Parser::new(contents) {
        let destination = match event {
            Event::Start(Tag::Link { dest_url, .. })
            | Event::Start(Tag::Image { dest_url, .. }) => dest_url.to_string(),
            _ => continue,
        };
        if let Some(reason) =
            invalid_local_markdown_link_reason(repo_root, readme_dir, &destination)
        {
            return Some(format!(
                "README.md local file links must be relative, stay inside the git repository, and point to existing files ({reason})"
            ));
        }
    }
    None
}

fn invalid_local_markdown_link_reason(
    repo_root: &Path,
    readme_dir: &Path,
    destination: &str,
) -> Option<String> {
    let destination = destination.trim();
    if destination.is_empty() || destination.starts_with('#') {
        return None;
    }

    match markdown_link_scheme(destination) {
        Some("file") => return Some(format!("`{destination}` uses a disallowed file URL")),
        Some("http" | "https" | "mailto" | "tel") => return None,
        Some(_) => return None,
        None => {}
    }

    let path_part = destination
        .split(['#', '?'])
        .next()
        .unwrap_or(destination)
        .trim();
    if path_part.is_empty() {
        return None;
    }

    if path_part.starts_with('/') || Path::new(path_part).is_absolute() {
        return Some(format!("`{destination}` is an absolute path"));
    }

    let Some(resolved_path) = resolve_relative_markdown_link_path(repo_root, readme_dir, path_part)
    else {
        return Some(format!("`{destination}` escapes the git repository"));
    };

    if !resolved_path.exists() {
        return Some(format!(
            "`{destination}` does not exist in the git repository"
        ));
    }

    None
}

fn markdown_link_scheme(destination: &str) -> Option<&str> {
    let (scheme, rest) = destination.split_once(':')?;
    if scheme.len() < 2
        || !scheme.chars().enumerate().all(|(index, ch)| {
            if index == 0 {
                ch.is_ascii_alphabetic()
            } else {
                ch.is_ascii_alphanumeric() || matches!(ch, '+' | '-' | '.')
            }
        })
    {
        return None;
    }
    if rest.is_empty() {
        return None;
    }
    Some(scheme)
}

fn resolve_relative_markdown_link_path(
    repo_root: &Path,
    readme_dir: &Path,
    link_path: &str,
) -> Option<PathBuf> {
    let Ok(base_relative) = readme_dir.strip_prefix(repo_root) else {
        return None;
    };
    let joined = base_relative.join(link_path);
    let normalized = normalize_relative_repo_path(&joined)?;
    Some(repo_root.join(normalized))
}

fn normalize_relative_repo_path(path: &Path) -> Option<PathBuf> {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(segment) => normalized.push(segment),
            Component::ParentDir => {
                if !normalized.pop() {
                    return None;
                }
            }
            Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    Some(normalized)
}

fn markdown_has_terminal_license_section(contents: &str) -> bool {
    let mut current_heading_level = None;
    let mut current_heading_text = String::new();
    let mut current_paragraph_text = String::new();
    let mut active_level2_heading = None::<String>;
    let mut last_level2_heading = None::<String>;
    let mut license_heading_count = 0usize;
    let mut license_paragraph_words = 0usize;

    for event in Parser::new(contents) {
        match event {
            Event::Start(Tag::Heading { level, .. }) => {
                current_heading_level = Some(level);
                current_heading_text.clear();
            }
            Event::End(TagEnd::Heading(level)) => {
                let heading_text = current_heading_text.trim().to_string();
                if level == HeadingLevel::H2 {
                    if heading_text == "License" {
                        license_heading_count += 1;
                    }
                    last_level2_heading = Some(heading_text.clone());
                    active_level2_heading = Some(heading_text);
                }
                current_heading_level = None;
                current_heading_text.clear();
            }
            Event::Start(Tag::Paragraph) => {
                current_paragraph_text.clear();
            }
            Event::End(TagEnd::Paragraph) => {
                if active_level2_heading.as_deref() == Some("License") {
                    license_paragraph_words += count_words(&current_paragraph_text);
                }
                current_paragraph_text.clear();
            }
            Event::Text(text) | Event::Code(text) => {
                if current_heading_level.is_some() {
                    current_heading_text.push_str(text.as_ref());
                } else {
                    current_paragraph_text.push_str(text.as_ref());
                }
            }
            Event::SoftBreak | Event::HardBreak => {
                if current_heading_level.is_some() {
                    current_heading_text.push(' ');
                } else {
                    current_paragraph_text.push(' ');
                }
            }
            _ => {}
        }
    }

    license_heading_count == 1
        && last_level2_heading.as_deref() == Some("License")
        && license_paragraph_words > 0
}

fn count_words(contents: &str) -> usize {
    contents
        .split_whitespace()
        .filter(|word| word.chars().any(|ch| ch.is_alphanumeric()))
        .count()
}

fn ds_store_is_gitignored(root: &Path) -> Result<bool> {
    path_is_gitignored(root, ".DS_Store")
}

fn first_package_install_directory_failure(
    root: &Path,
    analysis: &Analysis,
) -> Result<Option<CheckFailure>> {
    for directory in &analysis.install_directories {
        let gitignored = path_is_gitignored(root, directory)?;
        let tracked = path_has_tracked_git_entries(root, directory)?;
        if gitignored && !tracked {
            continue;
        }

        let summary = if tracked && !gitignored {
            format!(
                "package-manager install directory `{directory}` must be gitignored and removed from the repository"
            )
        } else if tracked {
            format!(
                "package-manager install directory `{directory}` is tracked by git and must be removed from the repository"
            )
        } else {
            format!("package-manager install directory `{directory}` must be gitignored")
        };

        return Ok(Some(CheckFailure {
            kind: "ignore",
            subject: directory.clone(),
            exit_code: None,
            summary,
            duration: None,
        }));
    }

    Ok(None)
}

fn path_is_gitignored(root: &Path, relative_path: &str) -> Result<bool> {
    for candidate in gitignore_probe_paths(relative_path) {
        let output = Command::new("git")
            .current_dir(root)
            .args(["check-ignore", "--no-index", &candidate])
            .output()
            .with_context(|| {
                format!(
                    "failed to check ignore rules for `{relative_path}` in {}",
                    root.display(),
                )
            })?;

        if output.status.success() {
            return Ok(true);
        }
        if output.status.code() == Some(1) {
            continue;
        }

        anyhow::bail!(
            "git check-ignore failed while checking `{relative_path}` ignore rules: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(false)
}

fn gitignore_probe_paths(relative_path: &str) -> Vec<String> {
    let trimmed = relative_path.trim_end_matches('/');
    if trimmed.is_empty() {
        return vec![relative_path.to_string()];
    }
    vec![
        trimmed.to_string(),
        format!("{trimmed}/.explicit-ignore-probe"),
    ]
}

fn path_has_tracked_git_entries(root: &Path, relative_path: &str) -> Result<bool> {
    let output = Command::new("git")
        .current_dir(root)
        .args(["ls-files", "--cached", "--", relative_path])
        .output()
        .with_context(|| {
            format!(
                "failed to inspect tracked git entries for `{relative_path}` in {}",
                root.display(),
            )
        })?;
    if !output.status.success() {
        anyhow::bail!(
            "git ls-files failed while checking `{relative_path}`: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(!String::from_utf8_lossy(&output.stdout).trim().is_empty())
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
        .chain(analysis.coverage_commands.iter())
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
    run_check_with_retry(root, analysis, command, progress, false)
}

fn run_check_with_retry(
    root: &Path,
    analysis: &Analysis,
    command: &str,
    progress: Option<&CommandProgress>,
    refresh_cache: bool,
) -> Result<CheckOutput> {
    let mut child = if should_use_devenv(root) {
        let devenv_root =
            devenv_root_for_check(root).expect("devenv root should exist when shell usage is set");
        devenv_check_command(
            root,
            &devenv_root,
            analysis,
            command,
            progress.is_some(),
            refresh_cache,
        )
    } else {
        let mut child = Command::new("bash");
        child.current_dir(root).args([
            "-lc",
            &command_with_runtime_env(root, None, analysis, command),
        ]);
        child
    };
    let output = run_captured_command(
        &mut child,
        &format!("failed to run check command `{command}`"),
        progress,
    )?;

    if !refresh_cache && should_use_devenv(root) {
        let combined = format!(
            "{}\n{}",
            String::from_utf8_lossy(&output.output.stderr),
            String::from_utf8_lossy(&output.output.stdout)
        );
        if stale_devenv_cache_detected(&combined) {
            if let Some(progress) = progress {
                eprintln!("{}... refreshing stale devenv cache", progress.wait_prefix);
            }
            return run_check_with_retry(root, analysis, command, progress, true);
        }
    }

    Ok(output)
}

fn devenv_check_command(
    root: &Path,
    devenv_root: &Path,
    analysis: &Analysis,
    command: &str,
    with_trace_output: bool,
    refresh_cache: bool,
) -> Command {
    let mut child = Command::new("devenv");
    child.current_dir(devenv_root);
    if with_trace_output {
        child.args(["--trace-output", "stderr", "--trace-format", "json"]);
    }
    if refresh_cache {
        child.args(["--refresh-eval-cache", "--refresh-task-cache"]);
    }
    child
        .args(["shell", "--no-tui", "--no-reload", "--", "bash", "-lc"])
        .arg(command_in_devenv_shell(
            root,
            devenv_root,
            analysis,
            command,
        ));
    child
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

fn migration_check_progress(
    ordinal: usize,
    total_checks: usize,
    command: &str,
    output_style: VerifyOutputStyle,
) -> Option<CommandProgress> {
    if output_style != VerifyOutputStyle::Interactive {
        return None;
    }
    let prefix = format!("[{}/{}]", ordinal + 1, total_checks);
    Some(CommandProgress {
        note_message: None,
        live_prefix: format!("live {prefix} {:<9}", "migration"),
        progress_probe: None,
        start_message: format!("run  {prefix} {:<9} {}...", "migration", command),
        wait_prefix: format!("wait {prefix} {:<9} {}", "migration", command),
    })
}

fn migration_apply_progress(
    ordinal: usize,
    total_checks: usize,
    command: &str,
    output_style: VerifyOutputStyle,
) -> Option<CommandProgress> {
    if output_style != VerifyOutputStyle::Interactive {
        return None;
    }
    let prefix = format!("[{}/{}]", ordinal + 1, total_checks);
    Some(CommandProgress {
        note_message: None,
        live_prefix: format!("fix  {prefix} {:<9}", "migration"),
        progress_probe: None,
        start_message: format!("fix  {prefix} {:<9} {}...", "migration", command),
        wait_prefix: format!("fix  {prefix} {:<9} {}", "migration", command),
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
    start_verify_services_with_retry(root, analysis, output_style, false)
}

fn start_verify_services_with_retry(
    root: &Path,
    analysis: &Analysis,
    output_style: VerifyOutputStyle,
    refresh_cache: bool,
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
    child.current_dir(&devenv_root).arg("--verbose");
    if refresh_cache {
        child.args(["--refresh-eval-cache", "--refresh-task-cache"]);
    }
    child
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
            reused_pid: None,
        }));
    }

    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.output.stderr),
        String::from_utf8_lossy(&output.output.stdout)
    );
    if let Some(pid) = devenv_already_running_pid(&combined) {
        return Ok(ServiceStartResult::Started(StartedServices {
            processes,
            duration: output.duration,
            reused_pid: Some(pid),
        }));
    }

    if !refresh_cache && stale_devenv_cache_detected(&combined) {
        if output_style == VerifyOutputStyle::Interactive {
            eprintln!("svc  refreshing stale devenv cache...");
        }
        return start_verify_services_with_retry(root, analysis, output_style, true);
    }

    Ok(ServiceStartResult::Failed(CheckFailure {
        kind: "service",
        subject: command.clone(),
        exit_code: output.output.status.code(),
        summary: summarize_failure("service", &command, &output.output),
        duration: Some(output.duration),
    }))
}

fn pending_migration_entries(check: &MigrationCheck, output: &Output) -> Vec<String> {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}\n{stderr}");
    match check.kind {
        MigrationCheckKind::Ecto => combined
            .lines()
            .map(str::trim)
            .filter(|line| line.starts_with("down "))
            .filter_map(|line| {
                let parts = line.split_whitespace().collect::<Vec<_>>();
                if parts.len() < 3 {
                    return None;
                }
                Some(format!("{} {}", parts[1], parts[2]))
            })
            .collect(),
    }
}

fn format_pending_migration_entries(entries: &[String]) -> String {
    let preview = entries.iter().take(3).cloned().collect::<Vec<_>>();
    if entries.len() > preview.len() {
        format!(
            "{} (+{} more)",
            preview.join(", "),
            entries.len() - preview.len()
        )
    } else {
        preview.join(", ")
    }
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
        if let Some(summary) = summarize_format_failure(&lines) {
            return summary;
        }
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

    if kind == "coverage" {
        if let Some(line) = pick_line(
            &lines,
            &[
                "fail-under",
                "coverage is below",
                "coverage threshold",
                "[TOTAL]",
                "TOTAL",
                "coverage:",
            ],
        ) {
            return normalize_summary(line);
        }
        if let Some(line) = lines
            .iter()
            .copied()
            .find(|line| line.contains('%') && line.to_ascii_lowercase().contains("coverage"))
        {
            return normalize_summary(line);
        }
        return "coverage is below the required threshold or the coverage run failed".to_string();
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

fn summarize_format_failure(lines: &[&str]) -> Option<String> {
    if let Some(line) = lines
        .iter()
        .copied()
        .find(|line| line.starts_with("Diff in ") && !is_noise_failure_line(line))
    {
        return Some(normalize_summary(line));
    }

    let paths = lines
        .iter()
        .copied()
        .filter(|line| !is_noise_failure_line(line))
        .filter(|line| looks_like_local_path(line))
        .take(3)
        .collect::<Vec<_>>();
    if !paths.is_empty() {
        return Some(normalize_summary(&paths.join(", ")));
    }

    let line = lines
        .iter()
        .copied()
        .find(|line| !is_noise_failure_line(line) && !line.ends_with(':'))?;
    Some(normalize_summary(line))
}

fn looks_like_local_path(line: &str) -> bool {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.contains(' ') {
        return false;
    }
    if trimmed.starts_with('/') || trimmed.starts_with("./") || trimmed.starts_with("../") {
        return true;
    }
    trimmed.contains('/')
        && trimmed
            .rsplit('.')
            .next()
            .is_some_and(|ext| ext.chars().all(|ch| ch.is_ascii_alphanumeric()) && ext.len() <= 8)
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
    match started.reused_pid.as_deref() {
        Some(pid) => eprintln!(
            "svc  {} (reused PID {}, {})",
            started.processes.join(", "),
            pid,
            format_duration(started.duration)
        ),
        None => eprintln!(
            "svc  {} ({})",
            started.processes.join(", "),
            format_duration(started.duration)
        ),
    }
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
        ProjectCheck, VerifyMode, VerifyOutputStyle, build_stop_reason, check_preflight_note,
        command_in_devenv_shell, command_with_runtime_env, devenv_check_command,
        devenv_root_for_check_with_env, existing_devenv_root, first_invalid_markdown_local_link,
        first_project_policy_failure, humanize_devenv_trace_line, humanize_live_output,
        is_matching_devenv_root, markdown_has_terminal_license_section, missing_workflow_commands,
        normalize_summary, prepare_verify_environment, project_checks, safe_lint_autofix_command,
        service_process_names, session_start_note, shell_quote, should_attempt_safe_autofix,
        should_use_devenv, summarize_failure, tokens_are_subsequence,
        verify_output_style_with_stderr_terminal, workflow_runs_command,
    };
    use crate::analysis::{
        Analysis, GitHubRepository, GitHubVisibility, ProjectRequirement, RepositoryMetadata,
        RequirementKind, SandboxPlan, ServiceRequirement,
    };
    use std::fs;
    use std::os::unix::process::ExitStatusExt;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Output};
    use std::time::Duration;

    fn analysis_with_checks() -> Analysis {
        Analysis {
            root: PathBuf::from("/tmp/project"),
            markers: Vec::new(),
            manifests: Vec::new(),
            install_directories: Vec::new(),
            detected_languages: Vec::new(),
            detected_versions: Vec::new(),
            language_hints: Vec::new(),
            packages: Vec::new(),
            services: Vec::new(),
            nix_options: Vec::new(),
            requires_allow_unfree: false,
            deploy_hosts: Vec::new(),
            deploy_use_ssh_agent: false,
            deploy_ssh_agent_hosts: Vec::new(),
            dev_server_commands: Vec::new(),
            lint_commands: vec!["lint-a".to_string()],
            build_commands: vec!["build-a".to_string()],
            test_commands: vec!["test-a".to_string()],
            coverage_commands: Vec::new(),
            required_checks: Vec::new(),
            migration_checks: Vec::new(),
            notes: Vec::new(),
            repository: RepositoryMetadata::default(),
            sandbox_plan: SandboxPlan {
                root: PathBuf::from("/tmp/project"),
                read_write_files: Vec::new(),
                read_write_dirs: Vec::new(),
                read_only_files: Vec::new(),
                read_only_dirs: Vec::new(),
                protected_write_files: Vec::new(),
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
        let checks = project_checks(&analysis_with_checks(), VerifyMode::User);
        assert_eq!(checks.len(), 3);
        assert_eq!(checks[0].kind, "lint");
        assert_eq!(checks[1].kind, "build");
        assert_eq!(checks[2].kind, "test");
        assert_eq!(checks[0].ordinal, 0);
        assert_eq!(checks[1].ordinal, 1);
        assert_eq!(checks[2].ordinal, 2);
    }

    #[test]
    fn appends_coverage_checks_after_tests() {
        let mut analysis = analysis_with_checks();
        analysis.coverage_commands = vec!["cargo llvm-cov --summary-only".to_string()];

        let checks = project_checks(&analysis, VerifyMode::User);
        assert_eq!(checks.len(), 4);
        assert_eq!(checks[3].kind, "coverage");
        assert_eq!(checks[3].command, "cargo llvm-cov --summary-only");
        assert_eq!(checks[3].ordinal, 3);
    }

    #[test]
    fn git_hook_mode_skips_coverage_checks() {
        let mut analysis = analysis_with_checks();
        analysis.coverage_commands = vec!["cargo llvm-cov --summary-only".to_string()];

        let checks = project_checks(&analysis, VerifyMode::GitHook);
        assert_eq!(
            checks.len(),
            3,
            "coverage should be excluded in git-hook mode"
        );
        assert!(checks.iter().all(|c| c.kind != "coverage"));
    }

    #[test]
    fn stop_hook_mode_includes_coverage_checks() {
        let mut analysis = analysis_with_checks();
        analysis.coverage_commands = vec!["cargo llvm-cov --summary-only".to_string()];

        let checks = project_checks(&analysis, VerifyMode::StopHook);
        assert_eq!(checks.len(), 4);
        assert_eq!(checks[3].kind, "coverage");
    }

    #[test]
    fn parses_pending_ecto_migrations() {
        let check = crate::analysis::MigrationCheck {
            kind: crate::analysis::MigrationCheckKind::Ecto,
            status_command: "mix ecto.migrations".to_string(),
            apply_command: "mix ecto.migrate".to_string(),
            subject: "mix.exs#migrations".to_string(),
        };
        let output = Output {
            status: ExitStatusExt::from_raw(0),
            stdout: b"Repo migrations status\nup   20260401000000 create_users\n down 20260409045614 enable_pg_stat_statements\n down 20260412120000 add_oban_jobs_table\n".to_vec(),
            stderr: Vec::new(),
        };

        assert_eq!(
            super::pending_migration_entries(&check, &output),
            vec![
                "20260409045614 enable_pg_stat_statements".to_string(),
                "20260412120000 add_oban_jobs_table".to_string()
            ]
        );
    }

    #[test]
    fn stop_hook_runs_pending_ecto_migrations_before_other_checks() {
        let dir = tempfile::tempdir().unwrap();
        let migrated = dir.path().join("migrated");
        let script = dir.path().join("mix");
        fs::write(
            &script,
            format!(
                r#"#!/bin/sh
set -eu
case "$1" in
  "ecto.migrations")
    if [ -f "{}" ]; then
      echo "up 20260413101000 add_processing_to_crawl_urls"
    else
      echo "down 20260413101000 add_processing_to_crawl_urls"
    fi
    ;;
  "ecto.migrate")
    touch "{}"
    ;;
  *)
    echo "unexpected mix invocation: $1" >&2
    exit 1
    ;;
esac
"#,
                migrated.display(),
                migrated.display()
            ),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = fs::metadata(&script).unwrap().permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(&script, permissions).unwrap();
        }

        let mut analysis = analysis_with_checks();
        analysis.lint_commands.clear();
        analysis.build_commands.clear();
        analysis.test_commands.clear();
        analysis.migration_checks = vec![crate::analysis::MigrationCheck {
            kind: crate::analysis::MigrationCheckKind::Ecto,
            status_command: format!("{} ecto.migrations", script.display()),
            apply_command: format!("{} ecto.migrate", script.display()),
            subject: "mix.exs#migrations".to_string(),
        }];

        let failure = super::run_migration_checks(
            dir.path(),
            &analysis,
            VerifyMode::StopHook,
            VerifyOutputStyle::Compact,
            analysis.migration_checks.len(),
            0,
        )
        .unwrap();

        assert!(failure.is_none());
        assert!(migrated.exists());
    }

    #[test]
    fn stop_hook_reports_failed_pending_migration_apply_output() {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("mix");
        fs::write(
            &script,
            r#"#!/bin/sh
set -eu
case "$1" in
  "ecto.migrations")
    echo "down 20260413101000 add_processing_to_crawl_urls"
    ;;
  "ecto.migrate")
    echo "migration failed badly" >&2
    exit 1
    ;;
  *)
    echo "unexpected mix invocation: $1" >&2
    exit 1
    ;;
esac
"#,
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = fs::metadata(&script).unwrap().permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(&script, permissions).unwrap();
        }

        let mut analysis = analysis_with_checks();
        analysis.lint_commands.clear();
        analysis.build_commands.clear();
        analysis.test_commands.clear();
        analysis.migration_checks = vec![crate::analysis::MigrationCheck {
            kind: crate::analysis::MigrationCheckKind::Ecto,
            status_command: format!("{} ecto.migrations", script.display()),
            apply_command: format!("{} ecto.migrate", script.display()),
            subject: "mix.exs#migrations".to_string(),
        }];

        let failure = super::run_migration_checks(
            dir.path(),
            &analysis,
            VerifyMode::StopHook,
            VerifyOutputStyle::Compact,
            analysis.migration_checks.len(),
            0,
        )
        .unwrap()
        .expect("expected migration failure");

        assert_eq!(failure.kind, "migration");
        assert!(failure.summary.contains("migration failed badly"));
    }

    #[test]
    fn user_verify_suggests_running_pending_ecto_migrations() {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("mix");
        fs::write(
            &script,
            r#"#!/bin/sh
set -eu
case "$1" in
  "ecto.migrations")
    echo "down 20260413101000 add_processing_to_crawl_urls"
    ;;
  *)
    echo "unexpected mix invocation: $1" >&2
    exit 1
    ;;
esac
"#,
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = fs::metadata(&script).unwrap().permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(&script, permissions).unwrap();
        }

        let mut analysis = analysis_with_checks();
        analysis.lint_commands.clear();
        analysis.build_commands.clear();
        analysis.test_commands.clear();
        analysis.migration_checks = vec![crate::analysis::MigrationCheck {
            kind: crate::analysis::MigrationCheckKind::Ecto,
            status_command: format!("{} ecto.migrations", script.display()),
            apply_command: format!("{} ecto.migrate", script.display()),
            subject: "mix.exs#migrations".to_string(),
        }];

        let failure = super::run_migration_checks(
            dir.path(),
            &analysis,
            VerifyMode::User,
            VerifyOutputStyle::Compact,
            analysis.migration_checks.len(),
            0,
        )
        .unwrap()
        .expect("expected migration failure");

        assert!(failure.summary.contains("pending migrations detected"));
        assert!(failure.summary.contains("ecto.migrate"));
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
    fn devenv_check_retry_adds_refresh_flags() {
        let dir = tempfile::tempdir().unwrap();
        let command = devenv_check_command(
            dir.path(),
            dir.path(),
            &analysis_with_checks(),
            "mix test",
            false,
            true,
        );
        let args = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert!(args.contains(&"--refresh-eval-cache".to_string()));
        assert!(args.contains(&"--refresh-task-cache".to_string()));
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
    fn safe_lint_autofix_rewrites_known_formatter_checks() {
        assert_eq!(
            safe_lint_autofix_command("mix format --check-formatted"),
            Some("mix format".to_string())
        );
        assert_eq!(
            safe_lint_autofix_command("cd 'infra' && tofu fmt -check -recursive"),
            Some("cd 'infra' && tofu fmt -recursive".to_string())
        );
        assert_eq!(
            safe_lint_autofix_command("cargo fmt --check --all"),
            Some("cargo fmt --all".to_string())
        );
    }

    #[test]
    fn safe_lint_autofix_ignores_non_formatter_lints_and_git_hooks() {
        assert_eq!(safe_lint_autofix_command("mix credo --strict"), None);
        let check = ProjectCheck {
            ordinal: 0,
            kind: "lint",
            command: "mix format --check-formatted".to_string(),
        };
        assert!(should_attempt_safe_autofix(VerifyMode::User, &check));
        assert!(should_attempt_safe_autofix(VerifyMode::StopHook, &check));
        assert!(!should_attempt_safe_autofix(VerifyMode::GitHook, &check));
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
    fn summarize_format_failures_include_diff_header_when_available() {
        let summary = summarize_failure(
            "lint",
            "cargo fmt --check",
            &failed_output("", "Diff in src/main.rs:1:\n"),
        );
        assert_eq!(summary, "Diff in src/main.rs:1:");
    }

    #[test]
    fn summarize_format_failures_include_changed_paths_when_available() {
        let summary = summarize_failure(
            "lint",
            "mix format --check-formatted",
            &failed_output("", "lib/foo.ex\nlib/bar.ex\n"),
        );
        assert_eq!(summary, "lib/foo.ex, lib/bar.ex");
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
    fn summarize_coverage_failures_surfaces_threshold_details() {
        let output = failed_output("", "TOTAL 412 78.24%\nerror: coverage threshold not met\n");
        let summary =
            summarize_failure("coverage", "cargo llvm-cov --fail-under-lines 80", &output);
        assert_eq!(summary, "coverage threshold not met");
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

        let failure = first_project_policy_failure(dir.path(), &analysis, VerifyMode::User)
            .unwrap()
            .expect("expected readme failure");
        assert_eq!(failure.kind, "docs");
        assert_eq!(failure.subject, "README.md");
        assert!(failure.summary.contains("README.md"));
    }

    #[test]
    fn requires_license_section_in_readme_for_git_repositories() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("README.md"),
            "# Demo\n\n## Usage\nTry it.\n",
        )
        .unwrap();

        let mut analysis = analysis_with_checks();
        analysis.repository = RepositoryMetadata {
            is_git_repository: true,
            readme_path: Some("README.md".to_string()),
            ..RepositoryMetadata::default()
        };

        let failure = first_project_policy_failure(dir.path(), &analysis, VerifyMode::User)
            .unwrap()
            .expect("expected readme license section failure");
        assert_eq!(failure.kind, "docs");
        assert_eq!(failure.subject, "README.md#License");
        assert!(failure.summary.contains("## License"));
    }

    #[test]
    fn requires_repo_relative_readme_links_for_git_repositories() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("README.md"),
            "# Demo\n\nSee [LICENSE](/Users/example/project/LICENSE).\n\n## License\nMIT\n",
        )
        .unwrap();

        let mut analysis = analysis_with_checks();
        analysis.repository = RepositoryMetadata {
            is_git_repository: true,
            readme_path: Some("README.md".to_string()),
            ..RepositoryMetadata::default()
        };

        let failure = first_project_policy_failure(dir.path(), &analysis, VerifyMode::User)
            .unwrap()
            .expect("expected readme link failure");
        assert_eq!(failure.kind, "docs");
        assert_eq!(failure.subject, "README.md#Links");
        assert!(failure.summary.contains("relative"));
        assert!(failure.summary.contains("absolute path"));
    }

    #[test]
    fn requires_ds_store_ignore_for_git_repositories() {
        let dir = tempfile::tempdir().unwrap();
        Command::new("git")
            .arg("init")
            .arg("-q")
            .arg(dir.path())
            .status()
            .unwrap();
        std::fs::write(dir.path().join("README.md"), "# Demo\n\n## License\nMIT\n").unwrap();

        let mut analysis = analysis_with_checks();
        analysis.repository = RepositoryMetadata {
            is_git_repository: true,
            readme_path: Some("README.md".to_string()),
            ..RepositoryMetadata::default()
        };

        let failure = first_project_policy_failure(dir.path(), &analysis, VerifyMode::User)
            .unwrap()
            .expect("expected ds_store ignore failure");
        assert_eq!(failure.kind, "ignore");
        assert_eq!(failure.subject, ".gitignore");
        assert!(failure.summary.contains(".DS_Store"));
    }

    #[test]
    fn requires_package_install_directories_to_be_gitignored() {
        let dir = tempfile::tempdir().unwrap();
        Command::new("git")
            .arg("init")
            .arg("-q")
            .arg(dir.path())
            .status()
            .unwrap();
        std::fs::write(dir.path().join("README.md"), "# Demo\n\n## License\nMIT\n").unwrap();

        let mut analysis = analysis_with_checks();
        analysis.repository = RepositoryMetadata {
            is_git_repository: true,
            readme_path: Some("README.md".to_string()),
            ..RepositoryMetadata::default()
        };
        analysis.install_directories = vec!["node_modules".to_string()];

        let failure = first_project_policy_failure(dir.path(), &analysis, VerifyMode::User)
            .unwrap()
            .expect("expected install-directory failure");
        assert_eq!(failure.kind, "ignore");
        assert_eq!(failure.subject, "node_modules");
        assert!(failure.summary.contains("must be gitignored"));
    }

    #[test]
    fn requires_removing_tracked_package_install_directories() {
        let dir = tempfile::tempdir().unwrap();
        Command::new("git")
            .arg("init")
            .arg("-q")
            .arg(dir.path())
            .status()
            .unwrap();
        std::fs::write(dir.path().join("README.md"), "# Demo\n\n## License\nMIT\n").unwrap();
        std::fs::write(dir.path().join(".gitignore"), ".DS_Store\nnode_modules/\n").unwrap();
        std::fs::create_dir_all(dir.path().join("node_modules/pkg")).unwrap();
        std::fs::write(
            dir.path().join("node_modules/pkg/index.js"),
            "module.exports = {};\n",
        )
        .unwrap();
        Command::new("git")
            .current_dir(dir.path())
            .args(["add", "-f", "node_modules/pkg/index.js"])
            .status()
            .unwrap();

        let mut analysis = analysis_with_checks();
        analysis.repository = RepositoryMetadata {
            is_git_repository: true,
            readme_path: Some("README.md".to_string()),
            ..RepositoryMetadata::default()
        };
        analysis.install_directories = vec!["node_modules".to_string()];

        let failure = first_project_policy_failure(dir.path(), &analysis, VerifyMode::User)
            .unwrap()
            .expect("expected tracked install-directory failure");
        assert_eq!(failure.kind, "ignore");
        assert_eq!(failure.subject, "node_modules");
        assert!(failure.summary.contains("tracked by git"));
    }

    #[test]
    fn accepts_readme_with_license_section_as_last_section() {
        assert!(markdown_has_terminal_license_section(
            "# Demo\n\n## Usage\nTry it.\n\n## License\nMIT\n"
        ));
    }

    #[test]
    fn accepts_repo_relative_markdown_links_within_root() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("docs")).unwrap();
        std::fs::write(dir.path().join("docs/guide.md"), "# Guide\n").unwrap();
        std::fs::write(dir.path().join("LICENSE"), "MIT\n").unwrap();
        assert_eq!(
            first_invalid_markdown_local_link(
                "# Demo\n\nSee [Guide](docs/guide.md), [License](./LICENSE#mit), and [Site](https://example.com).\n",
                dir.path(),
                &dir.path().join("README.md"),
            ),
            None
        );
    }

    #[test]
    fn rejects_absolute_markdown_file_links() {
        let failure = first_invalid_markdown_local_link(
            "# Demo\n\nSee [License](/Users/example/project/LICENSE).\n",
            Path::new("/tmp/project"),
            Path::new("/tmp/project/README.md"),
        )
        .expect("expected invalid link");
        assert!(failure.contains("absolute path"));
    }

    #[test]
    fn rejects_markdown_links_that_escape_repo_root() {
        let failure = first_invalid_markdown_local_link(
            "# Demo\n\nSee [License](../../LICENSE).\n",
            Path::new("/tmp/project"),
            Path::new("/tmp/project/docs/README.md"),
        )
        .expect("expected invalid link");
        assert!(failure.contains("escapes the git repository"));
    }

    #[test]
    fn rejects_markdown_links_for_missing_local_files() {
        let failure = first_invalid_markdown_local_link(
            "# Demo\n\nSee [Guide](docs/missing.md).\n",
            Path::new("/tmp/project"),
            Path::new("/tmp/project/README.md"),
        )
        .expect("expected invalid link");
        assert!(failure.contains("does not exist"));
    }

    #[test]
    fn rejects_readme_when_license_section_is_not_last() {
        assert!(!markdown_has_terminal_license_section(
            "# Demo\n\n## License\nMIT\n\n## Usage\nTry it.\n"
        ));
    }

    #[test]
    fn rejects_readme_when_license_section_lacks_paragraph_words() {
        assert!(!markdown_has_terminal_license_section(
            "# Demo\n\n## License\n- \n"
        ));
        assert!(!markdown_has_terminal_license_section(
            "# Demo\n\n## License\n\n```text\nMIT\n```\n"
        ));
    }

    #[test]
    fn rejects_readme_when_license_section_is_duplicated() {
        assert!(!markdown_has_terminal_license_section(
            "# Demo\n\n## License\nMIT\n\n## Usage\nTry it.\n\n## License\nApache-2.0\n"
        ));
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

        let failure = first_project_policy_failure(dir.path(), &analysis, VerifyMode::User)
            .unwrap()
            .expect("expected license failure");
        assert_eq!(failure.kind, "license");
        assert_eq!(failure.subject, "LICENSE");
    }

    #[test]
    fn requires_credo_for_elixir_projects() {
        let dir = tempfile::tempdir().unwrap();
        let mut analysis = analysis_with_checks();
        analysis.required_checks = vec![ProjectRequirement {
            kind: RequirementKind::Lint,
            subject: "mix.exs".to_string(),
            summary: "Elixir projects must include Credo and pass `mix credo --strict`."
                .to_string(),
        }];

        let failure = first_project_policy_failure(dir.path(), &analysis, VerifyMode::User)
            .unwrap()
            .expect("expected credo failure");
        assert_eq!(failure.kind, "lint");
        assert_eq!(failure.subject, "mix.exs");
        assert!(failure.summary.contains("Credo"));
        assert!(failure.summary.contains("mix credo --strict"));
    }

    #[test]
    fn requires_coverage_for_projects_with_coverage_requirement() {
        let dir = tempfile::tempdir().unwrap();
        let mut analysis = analysis_with_checks();
        analysis.required_checks = vec![ProjectRequirement {
            kind: RequirementKind::Coverage,
            subject: "mix.exs#test_coverage".to_string(),
            summary: "Elixir projects must enforce at least 80% test coverage.".to_string(),
        }];

        let failure = first_project_policy_failure(dir.path(), &analysis, VerifyMode::User)
            .unwrap()
            .expect("expected coverage requirement");
        assert_eq!(failure.kind, "coverage");
        assert_eq!(failure.subject, "mix.exs#test_coverage");
        assert!(failure.summary.contains("80%"));
    }

    #[test]
    fn requires_replacing_default_starter_pages() {
        let dir = tempfile::tempdir().unwrap();
        let mut analysis = analysis_with_checks();
        analysis.required_checks = vec![ProjectRequirement {
            kind: RequirementKind::Starter,
            subject: "lib/demo_web/controllers/page_html/home.html.heex".to_string(),
            summary:
                "Phoenix projects must replace the default getting started home page before using the generated stop hook."
                    .to_string(),
        }];

        let failure = first_project_policy_failure(dir.path(), &analysis, VerifyMode::User)
            .unwrap()
            .expect("expected starter page failure");
        assert_eq!(failure.kind, "starter");
        assert_eq!(
            failure.subject,
            "lib/demo_web/controllers/page_html/home.html.heex"
        );
        assert!(
            failure
                .summary
                .contains("default getting started home page")
        );
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

        let failure = first_project_policy_failure(dir.path(), &analysis, VerifyMode::User)
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

        let failure = first_project_policy_failure(dir.path(), &analysis, VerifyMode::User)
            .unwrap()
            .expect("expected workflow syntax failure");
        assert_eq!(failure.kind, "ci");
        assert_eq!(failure.subject, ".github/workflows");
        assert!(failure.summary.contains("syntax is invalid"));
    }

    #[test]
    fn prioritizes_repository_prerequisites_one_at_a_time() {
        let dir = tempfile::tempdir().unwrap();
        Command::new("git")
            .arg("init")
            .arg("-q")
            .arg(dir.path())
            .status()
            .unwrap();
        let mut analysis = analysis_with_checks();
        analysis.repository = RepositoryMetadata {
            is_git_repository: true,
            github: Some(GitHubRepository {
                slug: "example/demo".to_string(),
                visibility: GitHubVisibility::Public,
            }),
            ..RepositoryMetadata::default()
        };
        analysis.required_checks = vec![ProjectRequirement {
            kind: RequirementKind::Lint,
            subject: "mix.exs".to_string(),
            summary: "Elixir projects must include Credo and pass `mix credo --strict`."
                .to_string(),
        }];

        let failure = first_project_policy_failure(dir.path(), &analysis, VerifyMode::User)
            .unwrap()
            .expect("expected first failure");
        assert_eq!(failure.subject, "README.md");

        analysis.repository.readme_path = Some("README.md".to_string());
        std::fs::write(
            dir.path().join("README.md"),
            "# Demo\n\nSee [LICENSE](/tmp/demo/LICENSE).\n\n## Usage\nTry it.\n",
        )
        .unwrap();
        let failure = first_project_policy_failure(dir.path(), &analysis, VerifyMode::User)
            .unwrap()
            .expect("expected second failure");
        assert_eq!(failure.subject, "README.md#Links");

        std::fs::write(
            dir.path().join("README.md"),
            "# Demo\n\nSee [README](README.md).\n\n## Usage\nTry it.\n",
        )
        .unwrap();
        let failure = first_project_policy_failure(dir.path(), &analysis, VerifyMode::User)
            .unwrap()
            .expect("expected third failure");
        assert_eq!(failure.subject, "README.md#License");

        std::fs::write(dir.path().join("README.md"), "# Demo\n\n## License\nMIT\n").unwrap();
        analysis.install_directories = vec!["node_modules".to_string()];
        let failure = first_project_policy_failure(dir.path(), &analysis, VerifyMode::User)
            .unwrap()
            .expect("expected fourth failure");
        assert_eq!(failure.subject, "node_modules");

        std::fs::write(dir.path().join(".gitignore"), "node_modules/\n").unwrap();
        analysis.install_directories = Vec::new();
        let failure = first_project_policy_failure(dir.path(), &analysis, VerifyMode::User)
            .unwrap()
            .expect("expected fifth failure");
        assert_eq!(failure.subject, ".gitignore");

        std::fs::write(dir.path().join(".gitignore"), ".DS_Store\n").unwrap();
        let failure = first_project_policy_failure(dir.path(), &analysis, VerifyMode::User)
            .unwrap()
            .expect("expected sixth failure");
        assert_eq!(failure.subject, "mix.exs");

        analysis.required_checks = Vec::new();
        let failure = first_project_policy_failure(dir.path(), &analysis, VerifyMode::User)
            .unwrap()
            .expect("expected seventh failure");
        assert_eq!(failure.subject, "LICENSE");
    }

    #[test]
    fn stop_hook_blocks_when_branch_is_ahead_of_upstream() {
        let dir = tempfile::tempdir().unwrap();
        let remote = tempfile::tempdir().unwrap();

        Command::new("git")
            .arg("init")
            .arg("--bare")
            .arg(remote.path())
            .status()
            .unwrap();
        Command::new("git")
            .arg("init")
            .arg("-q")
            .arg(dir.path())
            .status()
            .unwrap();
        Command::new("git")
            .current_dir(dir.path())
            .args(["config", "user.name", "Explicit Test"])
            .status()
            .unwrap();
        Command::new("git")
            .current_dir(dir.path())
            .args(["config", "user.email", "explicit@example.com"])
            .status()
            .unwrap();
        Command::new("git")
            .current_dir(dir.path())
            .args([
                "remote",
                "add",
                "origin",
                &remote.path().display().to_string(),
            ])
            .status()
            .unwrap();

        fs::write(dir.path().join("README.md"), "# Demo\n\n## License\nMIT\n").unwrap();
        fs::write(dir.path().join(".gitignore"), ".DS_Store\n").unwrap();
        Command::new("git")
            .current_dir(dir.path())
            .args(["add", "README.md", ".gitignore"])
            .status()
            .unwrap();
        Command::new("git")
            .current_dir(dir.path())
            .args(["-c", "commit.gpgsign=false", "commit", "-m", "initial"])
            .status()
            .unwrap();
        Command::new("git")
            .current_dir(dir.path())
            .args(["push", "-u", "origin", "HEAD"])
            .status()
            .unwrap();

        fs::write(dir.path().join("local.txt"), "ahead\n").unwrap();
        Command::new("git")
            .current_dir(dir.path())
            .args(["add", "local.txt"])
            .status()
            .unwrap();
        Command::new("git")
            .current_dir(dir.path())
            .args(["-c", "commit.gpgsign=false", "commit", "-m", "ahead"])
            .status()
            .unwrap();

        let mut analysis = analysis_with_checks();
        analysis.repository = RepositoryMetadata {
            is_git_repository: true,
            readme_path: Some("README.md".to_string()),
            ..RepositoryMetadata::default()
        };

        let failure = first_project_policy_failure(dir.path(), &analysis, VerifyMode::StopHook)
            .unwrap()
            .expect("expected ahead-of-upstream failure");
        assert_eq!(failure.kind, "git");
        assert!(failure.summary.contains("ahead"));
        assert!(failure.summary.contains("Push your branch"));
        assert!(failure.summary.contains("pull request"));
    }

    #[test]
    fn session_start_note_mentions_push_and_pull_request_when_ahead() {
        let dir = tempfile::tempdir().unwrap();
        let remote = tempfile::tempdir().unwrap();

        Command::new("git")
            .arg("init")
            .arg("--bare")
            .arg(remote.path())
            .status()
            .unwrap();
        Command::new("git")
            .arg("init")
            .arg("-q")
            .arg(dir.path())
            .status()
            .unwrap();
        Command::new("git")
            .current_dir(dir.path())
            .args(["config", "user.name", "Explicit Test"])
            .status()
            .unwrap();
        Command::new("git")
            .current_dir(dir.path())
            .args(["config", "user.email", "explicit@example.com"])
            .status()
            .unwrap();
        Command::new("git")
            .current_dir(dir.path())
            .args([
                "remote",
                "add",
                "origin",
                &remote.path().display().to_string(),
            ])
            .status()
            .unwrap();
        fs::write(dir.path().join("README.md"), "# Demo\n").unwrap();
        Command::new("git")
            .current_dir(dir.path())
            .args(["add", "README.md"])
            .status()
            .unwrap();
        Command::new("git")
            .current_dir(dir.path())
            .args(["-c", "commit.gpgsign=false", "commit", "-m", "initial"])
            .status()
            .unwrap();
        Command::new("git")
            .current_dir(dir.path())
            .args(["push", "-u", "origin", "HEAD"])
            .status()
            .unwrap();
        fs::write(dir.path().join("local.txt"), "ahead\n").unwrap();
        Command::new("git")
            .current_dir(dir.path())
            .args(["add", "local.txt"])
            .status()
            .unwrap();
        Command::new("git")
            .current_dir(dir.path())
            .args(["-c", "commit.gpgsign=false", "commit", "-m", "ahead"])
            .status()
            .unwrap();

        let note = session_start_note(dir.path())
            .unwrap()
            .expect("expected session start note");
        assert!(note.contains("ahead"));
        assert!(note.contains("pushing"));
        assert!(note.contains("pull request"));
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
    fn missing_workflow_commands_include_coverage_checks() {
        let mut analysis = analysis_with_checks();
        analysis.coverage_commands = vec!["cargo llvm-cov --summary-only".to_string()];
        let missing =
            missing_workflow_commands(&analysis, &[String::from("lint-a && build-a && test-a")]);
        assert_eq!(missing, vec!["cargo llvm-cov --summary-only".to_string()]);
    }

    #[test]
    fn cargo_and_mix_build_families_share_lanes() {
        let checks = project_checks(&analysis_with_checks(), VerifyMode::User);
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

        let mix_checks = [
            ProjectCheck {
                ordinal: 0,
                kind: "lint",
                command: "mix format --check-formatted".to_string(),
            },
            ProjectCheck {
                ordinal: 1,
                kind: "build",
                command: "mix compile --warnings-as-errors".to_string(),
            },
            ProjectCheck {
                ordinal: 2,
                kind: "test",
                command: "mix test".to_string(),
            },
            ProjectCheck {
                ordinal: 3,
                kind: "coverage",
                command: "mix test --cover".to_string(),
            },
        ];
        let lanes = super::build_check_lanes(&mix_checks);
        assert_eq!(lanes.len(), 1);
        assert_eq!(lanes[0].len(), 4);
    }
}
