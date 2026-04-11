use std::io::{self, IsTerminal, Read};
use std::path::Path;
use std::process::{Command, ExitCode, Output, Stdio};

use anyhow::{Context, Result};
use serde_json::Value as JsonValue;

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
    command: String,
    exit_code: Option<i32>,
    summary: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StopHookClient {
    Claude,
    Other,
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
    if checks.is_empty() {
        if mode == VerifyMode::User {
            println!("No lint/build/test commands detected.");
        }
        return Ok(ExitCode::SUCCESS);
    }

    if mode == VerifyMode::User {
        println!("Running {} project checks...", checks.len());
    }

    let mut failures = Vec::new();
    for check in &checks {
        let output = run_check(root, &check.command)?;
        if output.status.success() {
            if mode == VerifyMode::User {
                println!("ok   {:<5} {}", check.kind, check.command);
            }
            continue;
        }

        let failure = CheckFailure {
            kind: check.kind,
            command: check.command.clone(),
            exit_code: output.status.code(),
            summary: summarize_failure(check.kind, &check.command, &output),
        };
        if mode == VerifyMode::User {
            eprintln!("fail {:<5} {}", failure.kind, failure.command);
            eprintln!("  reason: {}", failure.summary);
        }
        failures.push(failure);
    }

    if failures.is_empty() {
        if mode == VerifyMode::User {
            println!("All project checks passed ({} total).", checks.len());
        }
        return Ok(ExitCode::SUCCESS);
    }

    if mode == VerifyMode::StopHook && hook_client == StopHookClient::Claude {
        print_claude_stop_block_json(&failures)?;
        return Ok(ExitCode::SUCCESS);
    }

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
            Some(code) => eprintln!(" - {} [{}]: {}", failure.kind, code, failure.command),
            None => eprintln!(" - {} [signal]: {}", failure.kind, failure.command),
        }
        eprintln!("   {}", failure.summary);
    }
    eprintln!();
    eprintln!(
        "Run `explicit verify --root {}` after fixing the project.",
        root.display()
    );
    if mode == VerifyMode::StopHook {
        eprintln!("The agent must continue until lint, build, and test checks pass.");
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
                failure.kind, failure.command, failure.summary
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
        VerifyMode, build_stop_reason, normalize_summary, project_checks, should_use_devenv,
        summarize_failure,
    };
    use crate::analysis::{Analysis, SandboxPlan};
    use std::os::unix::process::ExitStatusExt;
    use std::path::PathBuf;
    use std::process::Output;

    fn analysis_with_checks() -> Analysis {
        Analysis {
            root: PathBuf::from("/tmp/project"),
            markers: Vec::new(),
            manifests: Vec::new(),
            detected_languages: Vec::new(),
            language_hints: Vec::new(),
            packages: Vec::new(),
            services: Vec::new(),
            nix_options: Vec::new(),
            requires_allow_unfree: false,
            lint_commands: vec!["lint-a".to_string()],
            build_commands: vec!["build-a".to_string()],
            test_commands: vec!["test-a".to_string()],
            notes: Vec::new(),
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
                command: "cargo fmt --check".to_string(),
                exit_code: Some(1),
                summary: "formatting changes are required".to_string(),
            },
            super::CheckFailure {
                kind: "test",
                command: "cargo test".to_string(),
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
}
