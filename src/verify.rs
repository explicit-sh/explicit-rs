use std::fs;
use std::io::{self, IsTerminal, Read, Write};
use std::path::Path;
use std::process::{Command, ExitCode, Output, Stdio};

use anyhow::{Context, Result};
use serde_json::Value as JsonValue;
use serde_yaml::{Mapping as YamlMapping, Value as YamlValue};

use crate::analysis::Analysis;
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
    kind: &'static str,
    command: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CheckFailure {
    kind: &'static str,
    subject: String,
    exit_code: Option<i32>,
    summary: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StopHookClient {
    Claude,
    Other,
}

#[derive(Debug, Default)]
struct WorkflowAudit {
    syntax_errors: Vec<String>,
    has_automatic_trigger: bool,
    run_steps: Vec<String>,
}

pub fn run_project_checks(
    root: &Path,
    analysis: &Analysis,
    stop_hook: bool,
    git_hook: bool,
) -> Result<ExitCode> {
    let mode = VerifyMode::from_flags(stop_hook, git_hook);
    let hook_client = detect_stop_hook_client(mode);
    let checks = project_checks(analysis);
    let mut failures = project_policy_failures(root, analysis)?;
    let total_checks = checks.len() + project_policy_check_count(analysis);

    if total_checks == 0 {
        if mode == VerifyMode::User {
            eprintln!("No lint/build/test or repository checks detected.");
        }
        return Ok(ExitCode::SUCCESS);
    }

    if mode == VerifyMode::User {
        eprintln!("Running {} project checks...", total_checks);
    }

    for check in &checks {
        let output = run_check(root, &check.command)?;
        if output.status.success() {
            if mode == VerifyMode::User {
                eprintln!("ok   {:<5} {}", check.kind, check.command);
            }
            continue;
        }

        let failure = CheckFailure {
            kind: check.kind,
            subject: check.command.clone(),
            exit_code: output.status.code(),
            summary: summarize_failure(check.kind, &check.command, &output),
        };
        if mode == VerifyMode::User {
            eprintln!("fail {:<7} {}", failure.kind, failure.subject);
            eprintln!("  reason: {}", failure.summary);
        }
        failures.push(failure);
    }

    if failures.is_empty() {
        if mode == VerifyMode::User {
            eprintln!("All project checks passed ({} total).", total_checks);
        }
        return Ok(ExitCode::SUCCESS);
    }

    if mode == VerifyMode::StopHook && hook_client == StopHookClient::Claude {
        print_claude_stop_block_json(&failures)?;
        return Ok(ExitCode::SUCCESS);
    }

    let _ = io::stdout().flush();
    let _ = io::stderr().flush();
    print_failure_report(root, mode, &failures);
    Ok(ExitCode::from(2))
}

fn project_checks(analysis: &Analysis) -> Vec<ProjectCheck> {
    let mut checks = Vec::new();
    for command in &analysis.lint_commands {
        checks.push(ProjectCheck {
            kind: "lint",
            command: command.clone(),
        });
    }
    for command in &analysis.build_commands {
        checks.push(ProjectCheck {
            kind: "build",
            command: command.clone(),
        });
    }
    for command in &analysis.test_commands {
        checks.push(ProjectCheck {
            kind: "test",
            command: command.clone(),
        });
    }
    checks
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

fn project_policy_failures(root: &Path, analysis: &Analysis) -> Result<Vec<CheckFailure>> {
    let mut failures = Vec::new();

    if analysis.repository.is_git_repository && !analysis.repository.has_readme() {
        failures.push(CheckFailure {
            kind: "docs",
            subject: "README.md".to_string(),
            exit_code: None,
            summary: "git repositories must include a top-level README.md".to_string(),
        });
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
        failures.push(CheckFailure {
            kind: "ci",
            subject: ".github/workflows".to_string(),
            exit_code: None,
            summary: format!(
                "GitHub Actions workflow syntax is invalid: {}",
                audit.syntax_errors.join("; ")
            ),
        });
    }

    if analysis.repository.is_public_github_repository() {
        if !analysis.repository.has_license() {
            failures.push(CheckFailure {
                kind: "license",
                subject: "LICENSE".to_string(),
                exit_code: None,
                summary: "public GitHub repositories must include a LICENSE file".to_string(),
            });
        }

        if !analysis.repository.has_workflows() {
            failures.push(CheckFailure {
                kind: "ci",
                subject: ".github/workflows".to_string(),
                exit_code: None,
                summary: "public GitHub repositories must include GitHub Actions workflows"
                    .to_string(),
            });
        } else if let Some(audit) = workflow_audit.as_ref()
            && audit.syntax_errors.is_empty()
        {
            if !audit.has_automatic_trigger {
                failures.push(CheckFailure {
                    kind: "ci",
                    subject: ".github/workflows".to_string(),
                    exit_code: None,
                    summary: "GitHub Actions must run automatically on push, pull_request, pull_request_target, or merge_group".to_string(),
                });
            }

            let missing_commands = missing_workflow_commands(analysis, &audit.run_steps);
            if !missing_commands.is_empty() {
                failures.push(CheckFailure {
                    kind: "ci",
                    subject: "GitHub Actions coverage".to_string(),
                    exit_code: None,
                    summary: format!(
                        "GitHub Actions do not run these detected checks automatically: {}",
                        missing_commands.join(", ")
                    ),
                });
            }
        }
    }

    Ok(failures)
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

fn run_check(root: &Path, command: &str) -> Result<Output> {
    let mut child = if should_use_devenv(root) {
        let mut child = Command::new("devenv");
        child
            .current_dir(root)
            .args(["shell", "--no-tui", "--no-reload", "--", "bash", "-lc"])
            .arg(command);
        child
    } else {
        let mut child = Command::new("bash");
        child.current_dir(root).args(["-lc", command]);
        child
    };
    child.stdin(Stdio::null());
    child
        .output()
        .with_context(|| format!("failed to run check command `{command}`"))
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
        if let Some(line) = pick_line(
            &lines,
            &[
                "test result: FAILED",
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
        if let Some(line) = lines.iter().copied().find(|line| line.contains(needle)) {
            return Some(line);
        }
    }
    None
}

fn normalize_summary(line: &str) -> String {
    let mut value = line
        .replace('\u{1b}', "")
        .replace("error: ", "")
        .replace("Error: ", "")
        .replace("ERROR: ", "");
    if value.len() > 180 {
        value.truncate(177);
        value.push_str("...");
    }
    value
}

fn print_failure_report(root: &Path, mode: VerifyMode, failures: &[CheckFailure]) {
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

    for failure in failures {
        match failure.exit_code {
            Some(code) => eprintln!(" - {} [{}]: {}", failure.kind, code, failure.subject),
            None => eprintln!(" - {}: {}", failure.kind, failure.subject),
        }
        eprintln!("   {}", failure.summary);
    }
    eprintln!();
    eprintln!(
        "Run `explicit verify --root {}` after fixing the project.",
        root.display()
    );
    if mode == VerifyMode::StopHook {
        eprintln!("The agent must continue until all verification checks pass.");
    }
}

fn print_claude_stop_block_json(failures: &[CheckFailure]) -> Result<()> {
    let reason = build_stop_reason(failures);
    println!(
        "{}",
        serde_json::to_string(&serde_json::json!({
            "decision": "block",
            "reason": reason
        }))?
    );
    Ok(())
}

fn build_stop_reason(failures: &[CheckFailure]) -> String {
    let mut items = failures
        .iter()
        .take(2)
        .map(|failure| {
            format!(
                "{} `{}`: {}",
                failure.kind, failure.subject, failure.summary
            )
        })
        .collect::<Vec<_>>();
    if failures.len() > 2 {
        items.push(format!("{} more failing checks", failures.len() - 2));
    }
    format!(
        "Project checks are still failing. Continue working until they pass: {}.",
        items.join("; ")
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

fn should_use_devenv(root: &Path) -> bool {
    root.join("devenv.nix").is_file() && preferred_command_path("devenv").is_some()
}

#[cfg(test)]
mod tests {
    use super::{
        VerifyMode, build_stop_reason, missing_workflow_commands, normalize_summary,
        project_checks, project_policy_failures, should_use_devenv, summarize_failure,
        tokens_are_subsequence, workflow_runs_command,
    };
    use crate::analysis::{
        Analysis, GitHubRepository, GitHubVisibility, RepositoryMetadata, SandboxPlan,
    };
    use std::os::unix::process::ExitStatusExt;
    use std::path::PathBuf;
    use std::process::Output;

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
    }

    #[test]
    fn only_uses_devenv_when_config_and_binary_exist() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!should_use_devenv(dir.path()));
        std::fs::write(dir.path().join("devenv.nix"), "{ pkgs, ... }: {}\n").unwrap();
        let _ = should_use_devenv(dir.path());
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
    fn builds_short_stop_reason() {
        let reason = build_stop_reason(&[
            super::CheckFailure {
                kind: "lint",
                subject: "cargo fmt --check".to_string(),
                exit_code: Some(1),
                summary: "formatting changes are required".to_string(),
            },
            super::CheckFailure {
                kind: "test",
                subject: "cargo test".to_string(),
                exit_code: Some(1),
                summary: "test result: FAILED".to_string(),
            },
        ]);
        assert!(reason.contains("Project checks are still failing"));
        assert!(reason.contains("cargo fmt --check"));
        assert!(reason.contains("cargo test"));
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
    fn requires_readme_for_git_repositories() {
        let dir = tempfile::tempdir().unwrap();
        let mut analysis = analysis_with_checks();
        analysis.repository = RepositoryMetadata {
            is_git_repository: true,
            ..RepositoryMetadata::default()
        };

        let failures = project_policy_failures(dir.path(), &analysis).unwrap();
        assert!(failures.iter().any(|failure| {
            failure.kind == "docs"
                && failure.subject == "README.md"
                && failure.summary.contains("README.md")
        }));
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

        let failures = project_policy_failures(dir.path(), &analysis).unwrap();
        assert!(
            failures
                .iter()
                .any(|failure| failure.kind == "license" && failure.subject == "LICENSE")
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

        let failures = project_policy_failures(dir.path(), &analysis).unwrap();
        assert!(failures.iter().any(|failure| {
            failure.kind == "ci"
                && failure.subject == "GitHub Actions coverage"
                && failure.summary.contains("lint-a")
        }));
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

        let failures = project_policy_failures(dir.path(), &analysis).unwrap();
        assert!(failures.iter().any(|failure| {
            failure.kind == "ci"
                && failure.subject == ".github/workflows"
                && failure.summary.contains("syntax is invalid")
        }));
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
}
