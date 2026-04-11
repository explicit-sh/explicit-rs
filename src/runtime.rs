use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::{Command, ExitCode, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};

use crate::analysis::{Analysis, SandboxPlan};
use crate::devenv_file::{
    GENERATED_DEPS_FILE, ensure_devenv_file, ensure_devenv_yaml, render_generated_nix,
};
use crate::eol;
use crate::hooks::write_stop_hook_assets;
use crate::host_tools::host_command_paths;

#[derive(Debug, Clone, Default)]
pub struct LaunchShellOptions<'a> {
    pub command: Option<&'a str>,
    pub block_network: bool,
    pub no_services: bool,
    pub dangerously_use_end_of_life_versions: bool,
    pub extra_env: Option<&'a BTreeMap<String, String>>,
    pub transcript_path: Option<&'a Path>,
}

pub fn apply_project(root: &Path, analysis: &Analysis) -> Result<()> {
    ensure_devenv_file(root)?;
    ensure_devenv_yaml(root, analysis)?;
    write_if_changed(
        root.join(GENERATED_DEPS_FILE),
        render_generated_nix(analysis),
    )
    .with_context(|| format!("failed to write {GENERATED_DEPS_FILE}"))?;
    let legacy_generated = root.join("devenv.generated.nix");
    if legacy_generated.exists() {
        fs::remove_file(&legacy_generated)
            .with_context(|| format!("failed to remove {}", legacy_generated.display()))?;
    }
    fs::create_dir_all(root.join(".nono")).context("failed to create .nono directory")?;
    write_if_changed(
        root.join(".nono/analysis.json"),
        serde_json::to_string_pretty(analysis)?,
    )
    .context("failed to write .nono/analysis.json")?;
    write_if_changed(
        root.join(".nono/sandbox-plan.json"),
        serde_json::to_string_pretty(&analysis.sandbox_plan)?,
    )
    .context("failed to write .nono/sandbox-plan.json")?;
    write_stop_hook_assets(root, analysis)?;
    Ok(())
}

fn write_if_changed(path: impl AsRef<Path>, content: impl AsRef<[u8]>) -> Result<()> {
    let path = path.as_ref();
    let content = content.as_ref();
    if fs::read(path).ok().as_deref() == Some(content) {
        return Ok(());
    }
    fs::write(path, content).with_context(|| format!("failed to write {}", path.display()))
}

pub fn print_doctor(analysis: &Analysis) -> Result<()> {
    println!(
        "Markers: {}",
        if analysis.markers.is_empty() {
            "none".to_string()
        } else {
            analysis.markers.join(", ")
        }
    );
    println!(
        "Languages: {}",
        if analysis.detected_languages.is_empty() {
            "none".to_string()
        } else {
            analysis
                .detected_languages
                .iter()
                .map(|lang| format!("{lang:?}").to_lowercase())
                .collect::<Vec<_>>()
                .join(", ")
        }
    );
    println!(
        "Language versions: {}",
        if analysis.detected_versions.is_empty() {
            "none".to_string()
        } else {
            analysis.doctor_versions().join(", ")
        }
    );
    let doctor_packages = analysis.doctor_packages();
    println!(
        "Packages: {}",
        if doctor_packages.is_empty() {
            "none".to_string()
        } else {
            doctor_packages.join(", ")
        }
    );
    println!(
        "Services: {}",
        if analysis.services.is_empty() {
            "none".to_string()
        } else {
            analysis
                .services
                .iter()
                .map(|service| format!("{service:?}").to_lowercase())
                .collect::<Vec<_>>()
                .join(", ")
        }
    );
    println!(
        "Nix options: {}",
        if analysis.nix_options.is_empty() {
            "none".to_string()
        } else {
            analysis.nix_options.join(", ")
        }
    );
    println!(
        "Allow unfree: {}",
        if analysis.requires_allow_unfree {
            "true"
        } else {
            "false"
        }
    );
    println!(
        "Lint commands: {}",
        if analysis.lint_commands.is_empty() {
            "none".to_string()
        } else {
            analysis.lint_commands.join(", ")
        }
    );
    println!(
        "Build commands: {}",
        if analysis.build_commands.is_empty() {
            "none".to_string()
        } else {
            analysis.build_commands.join(", ")
        }
    );
    println!(
        "Test commands: {}",
        if analysis.test_commands.is_empty() {
            "none".to_string()
        } else {
            analysis.test_commands.join(", ")
        }
    );
    if !analysis.notes.is_empty() {
        println!("Notes:");
        for note in &analysis.notes {
            println!("  - {note}");
        }
    }
    Ok(())
}

pub fn launch_shell(
    root: &Path,
    analysis: &Analysis,
    options: LaunchShellOptions<'_>,
) -> Result<ExitCode> {
    print_version_summary(analysis);
    eol::ensure_supported_runtime_versions(
        &analysis.detected_versions,
        options.dangerously_use_end_of_life_versions,
    )?;
    apply_project(root, analysis)?;
    let total_steps = if !options.no_services && !analysis.services.is_empty() {
        3
    } else {
        2
    };

    let mut env_map = capture_devenv_env(root, 1, total_steps)?;
    if !options.no_services && !analysis.services.is_empty() {
        run_devenv_up(root, 2, total_steps)?;
    }

    let runtime_dir = root.join(".nono/runtime");
    fs::create_dir_all(&runtime_dir).context("failed to create .nono/runtime")?;
    let env_file = runtime_dir.join("shell-env.json");
    let plan_file = runtime_dir.join("shell-plan.json");

    let mut plan = analysis.sandbox_plan.clone();
    if options.block_network {
        plan.notes
            .push("network access blocked for this shell invocation".to_string());
    }

    if let Some(extra_env) = options.extra_env {
        env_map.extend(extra_env.clone());
    }

    write_if_changed(&env_file, serde_json::to_string_pretty(&env_map)?)
        .context("failed to write shell env file")?;
    write_if_changed(&plan_file, serde_json::to_string_pretty(&plan)?)
        .context("failed to write shell plan file")?;

    let launch_step = if !options.no_services && !analysis.services.is_empty() {
        3
    } else {
        2
    };
    print_step_start(launch_step, total_steps, "Launching sandbox shell");

    let current_exe = std::env::current_exe().context("failed to resolve current executable")?;
    let mut child = build_sandbox_command(
        &current_exe,
        root,
        &env_file,
        &plan_file,
        options.command,
        options.transcript_path,
    );
    if options.block_network {
        child.env("DEVENV_NONO_BLOCK_NETWORK", "1");
    } else {
        child.env_remove("DEVENV_NONO_BLOCK_NETWORK");
    }

    let status = child.status().context("failed to launch sandbox child")?;
    if let Some(code) = status.code() {
        if code == 0 {
            return Ok(ExitCode::SUCCESS);
        }
        return Ok(ExitCode::from(code as u8));
    }
    if let Some(signal) = status.signal() {
        bail!("sandboxed shell exited from signal {signal}");
    }
    bail!("sandboxed shell failed without an exit code")
}

fn print_version_summary(analysis: &Analysis) {
    if analysis.detected_versions.is_empty() {
        return;
    }

    println!("Detected runtime versions:");
    for version in &analysis.detected_versions {
        println!("  - {}", version.summary());
    }
}

fn build_sandbox_command(
    current_exe: &Path,
    root: &Path,
    env_file: &Path,
    plan_file: &Path,
    command: Option<&str>,
    transcript_path: Option<&Path>,
) -> Command {
    let sandbox_args = sandbox_exec_args(root, env_file, plan_file, command);
    match transcript_path {
        Some(transcript_path) => {
            script_wrapped_sandbox_command(current_exe, root, transcript_path, &sandbox_args)
        }
        None => {
            let mut child = Command::new(current_exe);
            child
                .current_dir(root)
                .stdin(Stdio::inherit())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .args(&sandbox_args);
            child
        }
    }
}

fn sandbox_exec_args(
    root: &Path,
    env_file: &Path,
    plan_file: &Path,
    command: Option<&str>,
) -> Vec<OsString> {
    let mut args = vec![
        OsString::from("__sandbox-exec"),
        OsString::from("--root"),
        root.as_os_str().to_os_string(),
        OsString::from("--env-file"),
        env_file.as_os_str().to_os_string(),
        OsString::from("--plan-file"),
        plan_file.as_os_str().to_os_string(),
    ];
    if let Some(command) = command {
        args.push(OsString::from("--command"));
        args.push(OsString::from(command));
    }
    args
}

fn script_wrapped_sandbox_command(
    current_exe: &Path,
    root: &Path,
    transcript_path: &Path,
    sandbox_args: &[OsString],
) -> Command {
    let transcript_arg = transcript_path
        .strip_prefix(root)
        .map(Path::to_path_buf)
        .unwrap_or_else(|_| transcript_path.to_path_buf());
    let mut child = Command::new("script");
    child
        .current_dir(root)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    #[cfg(target_os = "macos")]
    {
        child
            .arg("-q")
            .arg("-F")
            .arg("-e")
            .arg("-k")
            .arg(&transcript_arg)
            .arg(current_exe)
            .args(sandbox_args);
    }

    #[cfg(target_os = "linux")]
    {
        child
            .arg("--quiet")
            .arg("--flush")
            .arg("--return")
            .arg(&transcript_arg)
            .arg("--")
            .arg(current_exe)
            .args(sandbox_args);
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = transcript_path;
        child.arg(current_exe).args(sandbox_args);
    }

    child
}

fn capture_devenv_env(
    root: &Path,
    step: usize,
    total_steps: usize,
) -> Result<BTreeMap<String, String>> {
    print_step_start(step, total_steps, "Realizing devenv environment");
    let start = Instant::now();
    let progress = Arc::new(Mutex::new(ProgressSnapshot::default()));
    let mut child = Command::new("devenv")
        .current_dir(root)
        .args(["shell", "--no-tui", "--no-reload", "--", "env", "-0"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to invoke `devenv shell env -0`")?;

    let mut stdout = child
        .stdout
        .take()
        .context("failed to capture `devenv shell env -0` stdout")?;
    let reader = thread::spawn(move || -> std::io::Result<Vec<u8>> {
        let mut buffer = Vec::new();
        stdout.read_to_end(&mut buffer)?;
        Ok(buffer)
    });
    let stderr = child
        .stderr
        .take()
        .context("failed to capture `devenv shell env -0` stderr")?;
    let stderr_progress = Arc::clone(&progress);
    let stderr_reader = thread::spawn(move || -> std::io::Result<()> {
        read_devenv_stderr(stderr, step, total_steps, stderr_progress)
    });

    let mut next_heartbeat = Duration::from_secs(5);
    let child_pid = child.id();
    let status = loop {
        if let Some(status) = child
            .try_wait()
            .context("failed to poll `devenv shell env -0`")?
        {
            break status;
        }

        let elapsed = start.elapsed();
        if elapsed >= next_heartbeat {
            let current_activity = current_activity_summary(&progress, child_pid);
            print_step_waiting(
                step,
                total_steps,
                "Still realizing devenv environment",
                elapsed,
                current_activity.as_deref(),
            );
            next_heartbeat += Duration::from_secs(5);
        }
        thread::sleep(Duration::from_millis(250));
    };

    let stdout = reader
        .join()
        .map_err(|_| anyhow!("failed to join `devenv shell env -0` reader thread"))?
        .context("failed to read `devenv shell env -0` stdout")?;
    stderr_reader
        .join()
        .map_err(|_| anyhow!("failed to join `devenv shell env -0` stderr reader thread"))?
        .context("failed to read `devenv shell env -0` stderr")?;

    if !status.success() {
        bail!("`devenv shell env -0` failed with status {status}");
    }
    print_step_done(
        step,
        total_steps,
        "Devenv environment ready",
        start.elapsed(),
    );

    let mut env_map = BTreeMap::new();
    for entry in stdout
        .split(|byte| *byte == 0)
        .filter(|entry| !entry.is_empty())
    {
        let line = String::from_utf8_lossy(entry);
        if let Some((key, value)) = line.split_once('=') {
            env_map.insert(key.to_string(), value.to_string());
        }
    }
    merge_host_agent_paths(&mut env_map)?;
    harmonize_tls_certificate_env(&mut env_map);
    env_map.insert(
        "HISTFILE".to_string(),
        root.join(".nono/bash_history").display().to_string(),
    );
    Ok(env_map)
}

fn run_devenv_up(root: &Path, step: usize, total_steps: usize) -> Result<()> {
    print_step_start(step, total_steps, "Starting devenv services");
    let start = Instant::now();
    let status = Command::new("devenv")
        .current_dir(root)
        .arg("--verbose")
        .args(["up", "--detach", "--no-tui", "--no-reload"])
        .status()
        .context("failed to invoke `devenv up --detach`")?;
    if !status.success() {
        bail!("`devenv up --detach` failed with status {status}");
    }
    print_step_done(step, total_steps, "Services are ready", start.elapsed());
    Ok(())
}

fn print_step_start(step: usize, total_steps: usize, message: &str) {
    eprintln!("{} {message}...", progress_prefix(step, total_steps));
}

fn print_step_done(step: usize, total_steps: usize, message: &str, elapsed: Duration) {
    eprintln!(
        "{} {message} ({:.1}s)",
        progress_prefix(step, total_steps),
        elapsed.as_secs_f32()
    );
}

fn print_step_waiting(
    step: usize,
    total_steps: usize,
    message: &str,
    elapsed: Duration,
    current_activity: Option<&str>,
) {
    let prefix = progress_prefix(step, total_steps);
    eprintln!("{prefix} {message}... {}s elapsed", elapsed.as_secs());
    if let Some(current_activity) = current_activity {
        eprintln!("{prefix} Current activity: {current_activity}");
    }
}

fn progress_prefix(step: usize, total_steps: usize) -> String {
    let total_width = 10;
    let filled = ((step * total_width) + total_steps.saturating_sub(1)) / total_steps.max(1);
    let bar = format!(
        "[{}{}]",
        "#".repeat(filled.min(total_width)),
        ".".repeat(total_width.saturating_sub(filled.min(total_width)))
    );
    format!("[{step}/{total_steps}] {bar}")
}

fn merge_host_agent_paths(env_map: &mut BTreeMap<String, String>) -> Result<()> {
    let mut path_entries = env_map
        .get("PATH")
        .map(std::env::split_paths)
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();

    for command in ["codex", "claude"] {
        for path in host_command_paths(command) {
            let Some(parent) = path.parent() else {
                continue;
            };
            let parent = parent.to_path_buf();
            if !path_entries.contains(&parent) {
                path_entries.push(parent);
            }
        }
    }

    if !path_entries.is_empty() {
        let joined = std::env::join_paths(path_entries).context("failed to build sandbox PATH")?;
        env_map.insert("PATH".to_string(), joined.to_string_lossy().into_owned());
    }

    Ok(())
}

fn harmonize_tls_certificate_env(env_map: &mut BTreeMap<String, String>) {
    let cert_path = env_map
        .get("SSL_CERT_FILE")
        .filter(|value| !value.is_empty())
        .cloned()
        .or_else(|| {
            env_map
                .get("NIX_SSL_CERT_FILE")
                .filter(|value| !value.is_empty())
                .cloned()
        })
        .or_else(|| {
            let fallback = Path::new("/etc/ssl/certs/ca-certificates.crt");
            fallback.exists().then(|| fallback.display().to_string())
        });

    let Some(cert_path) = cert_path else {
        return;
    };

    if env_map
        .get("SSL_CERT_FILE")
        .map(|value| value.is_empty())
        .unwrap_or(true)
    {
        env_map.insert("SSL_CERT_FILE".to_string(), cert_path.clone());
    }
    if env_map
        .get("CURL_CA_BUNDLE")
        .map(|value| value.is_empty())
        .unwrap_or(true)
    {
        env_map.insert("CURL_CA_BUNDLE".to_string(), cert_path.clone());
    }
    if env_map
        .get("NIX_SSL_CERT_FILE")
        .map(|value| value.is_empty())
        .unwrap_or(true)
    {
        env_map.insert("NIX_SSL_CERT_FILE".to_string(), cert_path);
    }
}
fn active_process_summary(root_pid: u32) -> Option<String> {
    let output = Command::new("ps")
        .args(["-axo", "pid=,ppid=,command="])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    summarize_process_tree(&String::from_utf8_lossy(&output.stdout), root_pid)
}

fn current_activity_summary(
    progress: &Arc<Mutex<ProgressSnapshot>>,
    root_pid: u32,
) -> Option<String> {
    let current_phase = progress
        .lock()
        .ok()
        .and_then(|snapshot| snapshot.last_status.clone());

    let process_activity = active_process_summary(root_pid)
        .as_deref()
        .and_then(humanize_process_command);

    process_activity.or(current_phase)
}

fn read_devenv_stderr(
    stderr: impl Read,
    step: usize,
    total_steps: usize,
    progress: Arc<Mutex<ProgressSnapshot>>,
) -> std::io::Result<()> {
    let mut last_emitted = None::<String>;
    for line in BufReader::new(stderr).lines() {
        let line = line?;
        let Some(update) = classify_devenv_stderr_line(&line) else {
            continue;
        };
        if let Some(status) = update.status.clone() {
            if let Ok(mut snapshot) = progress.lock() {
                snapshot.last_status = Some(status.clone());
            }
            if last_emitted.as_deref() != Some(status.as_str()) {
                eprintln!("{} {}", progress_prefix(step, total_steps), status);
                last_emitted = Some(status);
            }
        }
        if let Some(detail) = update.detail {
            eprintln!("{} {}", progress_prefix(step, total_steps), detail);
        }
    }
    Ok(())
}

fn classify_devenv_stderr_line(line: &str) -> Option<DevenvProgressLine> {
    let trimmed = line.trim().trim_start_matches('•').trim();
    if trimmed.is_empty() {
        return None;
    }

    if trimmed.starts_with("attr_path:")
        || trimmed.starts_with("eval_import_with_primops:")
        || trimmed.starts_with("Added substituter:")
        || (trimmed.starts_with("Adding ") && trimmed.contains("trusted public keys"))
        || (trimmed.starts_with("Added ") && trimmed.contains("trusted public keys"))
    {
        return None;
    }

    if trimmed == "Configuring shell" {
        return Some(DevenvProgressLine::status("Configuring shell"));
    }
    if trimmed == "Evaluating" {
        return Some(DevenvProgressLine::status(
            "Evaluating devenv configuration",
        ));
    }
    if trimmed.starts_with("Evaluating in ") {
        return None;
    }
    if trimmed.starts_with("Eval caching enabled") {
        return Some(DevenvProgressLine::status("Using eval cache"));
    }
    if trimmed == "Cache hit" {
        return Some(DevenvProgressLine::status("Eval cache hit"));
    }
    if trimmed == "Cache miss" || trimmed.contains("Cached eval invalidated") {
        return Some(DevenvProgressLine::status("Refreshing eval cache"));
    }
    if let Some(build) = humanize_nix_build_line(trimmed) {
        return Some(DevenvProgressLine::status(build));
    }
    if let Some(copy) = humanize_nix_copy_line(trimmed) {
        return Some(DevenvProgressLine::status(copy));
    }
    if looks_like_error_line(trimmed) {
        return Some(DevenvProgressLine::detail(trimmed));
    }

    None
}

fn humanize_nix_build_line(line: &str) -> Option<String> {
    let path = extract_quoted_path_after(line, "building '")?;
    Some(format!("Building {}", humanize_store_path(&path)))
}

fn humanize_nix_copy_line(line: &str) -> Option<String> {
    let path = extract_quoted_path_after(line, "copying path '")?;
    Some(format!("Fetching {}", humanize_store_path(&path)))
}

fn extract_quoted_path_after(line: &str, prefix: &str) -> Option<String> {
    let rest = line.strip_prefix(prefix)?;
    let value = rest.split('\'').next()?.trim();
    if value.is_empty() {
        return None;
    }
    Some(value.to_string())
}

fn humanize_store_path(path: &str) -> String {
    Path::new(path)
        .file_name()
        .and_then(|value| value.to_str())
        .map(|value| value.to_string())
        .unwrap_or_else(|| path.to_string())
}

fn looks_like_error_line(line: &str) -> bool {
    let lower = line.to_lowercase();
    lower.starts_with("error:")
        || lower.starts_with("warning:")
        || lower.contains(" failed")
        || lower.contains("failure")
        || lower.contains("panicked")
}

fn humanize_process_command(command: &str) -> Option<String> {
    let trimmed = command.trim();
    if trimmed.is_empty() {
        return None;
    }

    if let Some(url) = trimmed.strip_prefix("curl ") {
        let target = url.split_whitespace().next().unwrap_or(url);
        let filename = target
            .split('/')
            .next_back()
            .unwrap_or(target)
            .split('?')
            .next()
            .unwrap_or(target);
        return Some(format!("Downloading {filename}"));
    }

    let lower = trimmed.to_lowercase();
    if lower.starts_with("devenv ") || lower.contains(" devenv ") {
        return None;
    }
    if lower.contains("nix build") {
        return Some("Building Nix derivations".to_string());
    }

    Some(truncate_command(trimmed, 120))
}

fn summarize_process_tree(snapshot: &str, root_pid: u32) -> Option<String> {
    let processes = parse_process_snapshot(snapshot);
    if processes.is_empty() {
        return None;
    }

    let mut descendants = Vec::new();
    let mut stack = vec![(root_pid, 0usize)];
    while let Some((pid, depth)) = stack.pop() {
        descendants.push((pid, depth));
        for process in processes.values().filter(|process| process.ppid == pid) {
            stack.push((process.pid, depth + 1));
        }
    }

    descendants
        .into_iter()
        .filter_map(|(pid, depth)| {
            let process = processes.get(&pid)?;
            let has_children = processes.values().any(|candidate| candidate.ppid == pid);
            Some((
                process_rank(process, depth, has_children),
                process.command.as_str(),
            ))
        })
        .max_by_key(|(rank, _)| *rank)
        .map(|(_, command)| truncate_command(command, 140))
}

fn truncate_command(command: &str, max_len: usize) -> String {
    let char_count = command.chars().count();
    if char_count <= max_len {
        return command.to_string();
    }
    let truncated = command
        .chars()
        .take(max_len.saturating_sub(1))
        .collect::<String>();
    format!("{truncated}…")
}

fn process_rank(process: &ProcessSnapshot, depth: usize, has_children: bool) -> (u8, usize, usize) {
    let lower = process.command.to_lowercase();
    let interest = if lower.starts_with("curl ") {
        6
    } else if lower.contains("nix build")
        || lower.contains("/nix/store/")
        || lower.starts_with("nix ")
    {
        5
    } else if lower.contains("gradle")
        || lower.contains("cargo ")
        || lower.contains("clang")
        || lower.contains("javac")
    {
        4
    } else if lower.starts_with("sh -c") || lower.starts_with("bash -lc") {
        1
    } else {
        2
    };
    let leaf_bonus = if has_children { 0 } else { 1 };
    (interest + leaf_bonus, depth, process.command.len())
}

#[derive(Debug, Clone)]
struct ProcessSnapshot {
    pid: u32,
    ppid: u32,
    command: String,
}

#[derive(Default)]
struct ProgressSnapshot {
    last_status: Option<String>,
}

struct DevenvProgressLine {
    status: Option<String>,
    detail: Option<String>,
}

impl DevenvProgressLine {
    fn status(status: impl Into<String>) -> Self {
        Self {
            status: Some(status.into()),
            detail: None,
        }
    }

    fn detail(detail: impl Into<String>) -> Self {
        Self {
            status: None,
            detail: Some(detail.into()),
        }
    }
}

fn parse_process_snapshot(snapshot: &str) -> BTreeMap<u32, ProcessSnapshot> {
    let mut processes = BTreeMap::new();
    for line in snapshot.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let mut parts = trimmed.split_whitespace();
        let Some(pid) = parts.next().and_then(|value| value.parse::<u32>().ok()) else {
            continue;
        };
        let Some(ppid) = parts.next().and_then(|value| value.parse::<u32>().ok()) else {
            continue;
        };
        let command = parts.collect::<Vec<_>>().join(" ");
        if command.is_empty() {
            continue;
        }

        processes.insert(pid, ProcessSnapshot { pid, ppid, command });
    }
    processes
}

#[allow(dead_code)]
fn _write_sandbox_plan(path: &Path, plan: &SandboxPlan) -> Result<()> {
    fs::write(path, serde_json::to_string_pretty(plan)?).context("failed to write sandbox plan")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        build_sandbox_command, classify_devenv_stderr_line, harmonize_tls_certificate_env,
        humanize_process_command, parse_process_snapshot, summarize_process_tree,
    };
    use std::{collections::BTreeMap, path::Path};

    #[test]
    fn summarize_process_tree_prefers_interesting_leaf_processes() {
        let snapshot = "\
100 1 devenv --verbose shell --no-tui --no-reload -- env -0
101 100 sh -c nix build .#devShell
102 101 nix build .#devShell
103 102 curl https://dl.google.com/android/repository/emulator-darwin_aarch64.zip
";
        let summary = summarize_process_tree(snapshot, 100).expect("expected summary");
        assert_eq!(
            summary,
            "curl https://dl.google.com/android/repository/emulator-darwin_aarch64.zip"
        );
    }

    #[test]
    fn parse_process_snapshot_ignores_invalid_rows() {
        let snapshot = "\
not-a-row
100 1 devenv shell
";
        let processes = parse_process_snapshot(snapshot);
        assert_eq!(processes.len(), 1);
        assert_eq!(processes.get(&100).unwrap().command, "devenv shell");
    }

    #[test]
    fn summarize_process_tree_falls_back_to_root_process() {
        let snapshot = "100 1 devenv --verbose shell --no-tui --no-reload -- env -0\n";
        let summary = summarize_process_tree(snapshot, 100).expect("expected summary");
        assert_eq!(
            summary,
            "devenv --verbose shell --no-tui --no-reload -- env -0"
        );
    }

    #[test]
    fn classify_devenv_stderr_line_humanizes_shell_setup() {
        let status = classify_devenv_stderr_line("• Configuring shell")
            .and_then(|line| line.status)
            .expect("expected status");
        assert_eq!(status, "Configuring shell");
    }

    #[test]
    fn humanize_process_command_reports_downloads() {
        let detail = humanize_process_command(
            "curl https://dl.google.com/android/repository/emulator-darwin_aarch64-14518053.zip",
        )
        .expect("expected detail");
        assert_eq!(detail, "Downloading emulator-darwin_aarch64-14518053.zip");
    }

    #[test]
    fn harmonize_tls_certificate_env_uses_nix_bundle_when_available() {
        let mut env_map = BTreeMap::from([(
            "NIX_SSL_CERT_FILE".to_string(),
            "/etc/ssl/certs/ca-certificates.crt".to_string(),
        )]);
        harmonize_tls_certificate_env(&mut env_map);
        assert_eq!(
            env_map.get("SSL_CERT_FILE").map(String::as_str),
            Some("/etc/ssl/certs/ca-certificates.crt")
        );
        assert_eq!(
            env_map.get("CURL_CA_BUNDLE").map(String::as_str),
            Some("/etc/ssl/certs/ca-certificates.crt")
        );
    }

    #[test]
    fn harmonize_tls_certificate_env_preserves_existing_ssl_cert_file() {
        let mut env_map = BTreeMap::from([
            (
                "SSL_CERT_FILE".to_string(),
                "/custom/ca-bundle.crt".to_string(),
            ),
            (
                "NIX_SSL_CERT_FILE".to_string(),
                "/etc/ssl/certs/ca-certificates.crt".to_string(),
            ),
        ]);
        harmonize_tls_certificate_env(&mut env_map);
        assert_eq!(
            env_map.get("SSL_CERT_FILE").map(String::as_str),
            Some("/custom/ca-bundle.crt")
        );
        assert_eq!(
            env_map.get("CURL_CA_BUNDLE").map(String::as_str),
            Some("/custom/ca-bundle.crt")
        );
        assert_eq!(
            env_map.get("NIX_SSL_CERT_FILE").map(String::as_str),
            Some("/etc/ssl/certs/ca-certificates.crt")
        );
    }

    #[test]
    fn transcript_capture_wraps_sandbox_with_script() {
        let command = build_sandbox_command(
            Path::new("/tmp/explicit"),
            Path::new("/tmp/project"),
            Path::new("/tmp/shell-env.json"),
            Path::new("/tmp/shell-plan.json"),
            Some("claude -p hello"),
            Some(Path::new("/tmp/console.typescript")),
        );
        assert_eq!(command.get_program().to_string_lossy(), "script");
        let args = command
            .get_args()
            .map(|value| value.to_string_lossy().into_owned())
            .collect::<Vec<_>>();

        #[cfg(target_os = "macos")]
        assert_eq!(
            args,
            vec![
                "-q",
                "-F",
                "-e",
                "-k",
                "/tmp/console.typescript",
                "/tmp/explicit",
                "__sandbox-exec",
                "--root",
                "/tmp/project",
                "--env-file",
                "/tmp/shell-env.json",
                "--plan-file",
                "/tmp/shell-plan.json",
                "--command",
                "claude -p hello",
            ]
        );

        #[cfg(target_os = "linux")]
        assert_eq!(
            args,
            vec![
                "--quiet",
                "--flush",
                "--return",
                "/tmp/console.typescript",
                "--",
                "/tmp/explicit",
                "__sandbox-exec",
                "--root",
                "/tmp/project",
                "--env-file",
                "/tmp/shell-env.json",
                "--plan-file",
                "/tmp/shell-plan.json",
                "--command",
                "claude -p hello",
            ]
        );
    }
}
