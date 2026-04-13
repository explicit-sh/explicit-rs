use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::os::unix::fs::{PermissionsExt, symlink};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitCode, Stdio};
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
use crate::host_tools::{host_command_paths, preferred_command_path};

#[derive(Debug, Clone, Default)]
pub struct LaunchShellOptions<'a> {
    pub agent: Option<&'a str>,
    pub command: Option<&'a str>,
    pub block_network: bool,
    pub no_services: bool,
    pub dangerously_use_end_of_life_versions: bool,
    pub extra_env: Option<&'a BTreeMap<String, String>>,
    pub transcript_path: Option<&'a Path>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DeploySshSetup {
    configured_hosts: Vec<String>,
    matched_hosts: Vec<String>,
    fetched_hosts: Vec<String>,
    missing_hosts: Vec<String>,
    configured_aliases: Vec<String>,
    ssh_agent_hosts: Vec<String>,
    missing_ssh_agent: Vec<String>,
}

struct DevServerProcess {
    child: Child,
}

impl Drop for DevServerProcess {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_some() {
            return;
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub(crate) fn ensure_managed_devenv_files(root: &Path, analysis: &Analysis) -> Result<()> {
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
    Ok(())
}

pub fn apply_project(root: &Path, analysis: &Analysis) -> Result<()> {
    ensure_managed_devenv_files(root, analysis)?;
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
    print!("{}", doctor_report(analysis));
    Ok(())
}

pub(crate) fn doctor_report(analysis: &Analysis) -> String {
    let mut report = String::new();
    let doctor_packages = analysis.doctor_packages();
    append_doctor_line(
        &mut report,
        "Markers",
        join_or_none(analysis.markers.clone()),
    );
    append_doctor_line(
        &mut report,
        "Languages",
        join_or_none(
            analysis
                .detected_languages
                .iter()
                .map(|lang| format!("{lang:?}").to_lowercase())
                .collect::<Vec<_>>(),
        ),
    );
    append_doctor_line(
        &mut report,
        "Language versions",
        join_or_none(analysis.doctor_versions()),
    );
    append_doctor_line(
        &mut report,
        "Packages",
        join_or_none(
            doctor_packages
                .into_iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
        ),
    );
    append_doctor_line(
        &mut report,
        "Services",
        join_or_none(
            analysis
                .services
                .iter()
                .map(|service| format!("{service:?}").to_lowercase())
                .collect::<Vec<_>>(),
        ),
    );
    append_doctor_line(
        &mut report,
        "Nix options",
        join_or_none(analysis.nix_options.clone()),
    );
    append_doctor_line(
        &mut report,
        "Allow unfree",
        if analysis.requires_allow_unfree {
            "true".to_string()
        } else {
            "false".to_string()
        },
    );
    append_doctor_line(
        &mut report,
        "Deploy hosts",
        join_or_none(analysis.deploy_hosts.clone()),
    );
    append_doctor_line(
        &mut report,
        "SSH agent hosts",
        if analysis.deploy_use_ssh_agent {
            "all deploy hosts".to_string()
        } else {
            join_or_none(analysis.deploy_ssh_agent_hosts.clone())
        },
    );
    append_doctor_line(
        &mut report,
        "Dev servers",
        join_or_none(analysis.dev_server_commands.clone()),
    );
    append_doctor_line(
        &mut report,
        "Lint commands",
        join_or_none(analysis.lint_commands.clone()),
    );
    append_doctor_line(
        &mut report,
        "Build commands",
        join_or_none(analysis.build_commands.clone()),
    );
    append_doctor_line(
        &mut report,
        "Test commands",
        join_or_none(analysis.test_commands.clone()),
    );
    append_doctor_line(
        &mut report,
        "Coverage commands",
        join_or_none(analysis.coverage_commands.clone()),
    );
    append_doctor_line(
        &mut report,
        "Requirements",
        join_or_none(
            analysis
                .required_checks
                .iter()
                .map(|requirement| format!("{} {}", requirement.kind.as_str(), requirement.summary))
                .collect::<Vec<_>>(),
        ),
    );
    if !analysis.notes.is_empty() {
        report.push_str("Notes:\n");
        for note in &analysis.notes {
            report.push_str("  - ");
            report.push_str(note);
            report.push('\n');
        }
    }
    report
}

fn append_doctor_line(report: &mut String, label: &str, value: String) {
    report.push_str(label);
    report.push_str(": ");
    report.push_str(&value);
    report.push('\n');
}

fn join_or_none(values: Vec<String>) -> String {
    if values.is_empty() {
        "none".to_string()
    } else {
        values.join(", ")
    }
}

pub fn launch_shell(
    root: &Path,
    analysis: &Analysis,
    options: LaunchShellOptions<'_>,
) -> Result<ExitCode> {
    print_version_summary(analysis);
    print_workspace_summary(analysis);
    eol::ensure_supported_runtime_versions(
        &analysis.detected_versions,
        options.dangerously_use_end_of_life_versions,
    )?;
    apply_project(root, analysis)?;
    let start_dev_servers = options.agent.is_some() && !analysis.dev_server_commands.is_empty();
    let total_steps = shell_total_steps(
        !options.no_services && !analysis.services.is_empty(),
        start_dev_servers,
    );
    let current_exe = std::env::current_exe().context("failed to resolve current executable")?;

    let mut env_map = capture_devenv_env(root, 1, total_steps)?;
    if !options.no_services && !analysis.services.is_empty() {
        run_devenv_up(root, 2, total_steps)?;
        if let Err(err) = ensure_postgres_shell_user(root, analysis, &env_map) {
            eprintln!("svc  postgres shell user setup failed: {err:#}");
        }
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

    if let Some(setup) = prepare_deploy_ssh(root, analysis, &runtime_dir, &mut env_map, &mut plan)?
    {
        print_deploy_ssh_summary(&setup);
    }

    prepare_postgres_shell_environment(root, analysis, &mut env_map)?;
    let _dev_servers = if start_dev_servers {
        Some(start_dev_servers_for_agent(
            root,
            &analysis.dev_server_commands,
            &env_map,
            &runtime_dir,
            if !options.no_services && !analysis.services.is_empty() {
                3
            } else {
                2
            },
            total_steps,
        )?)
    } else {
        None
    };
    prepare_agent_runtime(options.agent, &runtime_dir, &mut env_map, &mut plan)?;

    if let Some(extra_env) = options.extra_env {
        env_map.extend(extra_env.clone());
    }
    prioritize_launch_executable(&mut env_map, &mut plan, &current_exe);

    write_if_changed(&env_file, serde_json::to_string_pretty(&env_map)?)
        .context("failed to write shell env file")?;
    write_if_changed(&plan_file, serde_json::to_string_pretty(&plan)?)
        .context("failed to write shell plan file")?;

    let launch_step = shell_launch_step(
        !options.no_services && !analysis.services.is_empty(),
        start_dev_servers,
    );
    print_step_start(launch_step, total_steps, "Launching sandbox shell");
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

fn print_workspace_summary(analysis: &Analysis) {
    for note in analysis.notes.iter().filter(|note| {
        note.starts_with("Workspace: ")
            || note.starts_with("Workspace members:")
            || note.starts_with("Workspace excludes:")
    }) {
        println!("{note}");
    }
}

fn shell_total_steps(starts_services: bool, starts_dev_servers: bool) -> usize {
    2 + usize::from(starts_services) + usize::from(starts_dev_servers)
}

fn shell_launch_step(starts_services: bool, starts_dev_servers: bool) -> usize {
    shell_total_steps(starts_services, starts_dev_servers)
}

fn start_dev_servers_for_agent(
    root: &Path,
    commands: &[String],
    env_map: &BTreeMap<String, String>,
    runtime_dir: &Path,
    step: usize,
    total_steps: usize,
) -> Result<Vec<DevServerProcess>> {
    if commands.is_empty() {
        return Ok(Vec::new());
    }

    print_step_start(step, total_steps, "Starting development servers");
    let start = Instant::now();
    let server_dir = runtime_dir.join("dev-servers");
    fs::create_dir_all(&server_dir)
        .with_context(|| format!("failed to create {}", server_dir.display()))?;

    let mut started = Vec::new();
    for (index, command) in commands.iter().enumerate() {
        let log_path = server_dir.join(format!("{:02}.log", index + 1));
        let log_file = fs::File::create(&log_path)
            .with_context(|| format!("failed to create {}", log_path.display()))?;
        let stderr_file = log_file
            .try_clone()
            .with_context(|| format!("failed to clone {}", log_path.display()))?;
        let mut child = Command::new("bash");
        child
            .current_dir(root)
            .env_clear()
            .envs(env_map)
            .args(["-lc", command])
            .stdout(Stdio::from(log_file))
            .stderr(Stdio::from(stderr_file));
        let mut child = child
            .spawn()
            .with_context(|| format!("failed to start development server `{command}`"))?;

        thread::sleep(Duration::from_millis(500));
        if let Some(status) = child.try_wait()? {
            let details = summarize_dev_server_failure(&log_path).unwrap_or_else(|| {
                if status.success() {
                    "exited immediately".to_string()
                } else {
                    format!("exited immediately with status {status}")
                }
            });
            eprintln!(
                "app  failed to start `{}`: {} (log: {})",
                command,
                details,
                log_path.display()
            );
            continue;
        }

        println!("app  started `{}` (log: {})", command, log_path.display());
        started.push(DevServerProcess { child });
    }

    print_step_done(
        step,
        total_steps,
        "Development servers are ready",
        start.elapsed(),
    );
    Ok(started)
}

fn summarize_dev_server_failure(log_path: &Path) -> Option<String> {
    let contents = fs::read_to_string(log_path).ok()?;
    for line in contents.lines().map(str::trim) {
        if !line.is_empty() {
            return Some(line.to_string());
        }
    }
    None
}

fn prepare_deploy_ssh(
    root: &Path,
    analysis: &Analysis,
    runtime_dir: &Path,
    env_map: &mut BTreeMap<String, String>,
    plan: &mut SandboxPlan,
) -> Result<Option<DeploySshSetup>> {
    let effective_hosts = collect_effective_deploy_hosts(root, analysis)?;
    if effective_hosts.is_empty() {
        return Ok(None);
    }

    let home = dirs::home_dir().context("failed to resolve home directory for deploy SSH setup")?;
    let known_hosts_source = home.join(".ssh/known_hosts");
    let known_hosts_path = runtime_dir.join("known_hosts");
    let ssh_config_path = runtime_dir.join("ssh_config");
    let wrapper_dir = runtime_dir.join("ssh-bin");
    fs::create_dir_all(&wrapper_dir)
        .with_context(|| format!("failed to create {}", wrapper_dir.display()))?;
    let ssh_agent_hosts = effective_ssh_agent_hosts(&effective_hosts, analysis);
    let ssh_auth_sock = resolve_host_ssh_auth_sock(&ssh_agent_hosts)?;

    let mut setup =
        write_project_known_hosts(&known_hosts_source, &known_hosts_path, &effective_hosts)?;
    setup.ssh_agent_hosts = ssh_agent_hosts.clone();
    if !ssh_agent_hosts.is_empty() && ssh_auth_sock.is_none() {
        setup.missing_ssh_agent = ssh_agent_hosts.clone();
    }
    setup.configured_aliases = write_project_ssh_config(
        &ssh_config_path,
        &effective_hosts,
        &ssh_agent_hosts,
        ssh_auth_sock.as_deref(),
    )?;
    write_ssh_wrapper_scripts(&wrapper_dir)?;

    prepend_path(env_map, &wrapper_dir);
    env_map.insert(
        "EXPLICIT_DEPLOY_KNOWN_HOSTS_FILE".to_string(),
        known_hosts_path.display().to_string(),
    );
    env_map.insert(
        "EXPLICIT_DEPLOY_SSH_CONFIG_FILE".to_string(),
        ssh_config_path.display().to_string(),
    );
    env_map.insert(
        "EXPLICIT_DEPLOY_ROOT".to_string(),
        root.display().to_string(),
    );
    env_map.insert(
        "GIT_SSH".to_string(),
        wrapper_dir.join("ssh").display().to_string(),
    );
    env_map.insert(
        "GIT_SSH_COMMAND".to_string(),
        shell_escape_for_env(&wrapper_dir.join("ssh").display().to_string()),
    );
    plan.notes.push(format!(
        "deploy SSH host verification enabled for: {}",
        effective_hosts.join(", ")
    ));
    if !plan.read_write_files.contains(&known_hosts_path) {
        plan.read_write_files.push(known_hosts_path.clone());
    }
    for support_file in project_ssh_public_key_support_files(&effective_hosts)? {
        push_unique_file_with_realpath(&mut plan.read_only_files, support_file);
    }
    if let Some(socket) = ssh_auth_sock {
        push_unique_file_with_realpath(&mut plan.read_write_files, socket);
    }

    Ok(Some(setup))
}

fn prepare_postgres_shell_environment(
    root: &Path,
    analysis: &Analysis,
    env_map: &mut BTreeMap<String, String>,
) -> Result<()> {
    if !uses_postgres_shell(analysis) {
        return Ok(());
    }

    let devenv_dir = root.join(".devenv");
    fs::create_dir_all(&devenv_dir)
        .with_context(|| format!("failed to create {}", devenv_dir.display()))?;
    env_map.insert(
        "PSQL_HISTORY".to_string(),
        devenv_dir.join(".psql_history").display().to_string(),
    );
    Ok(())
}

fn uses_postgres_shell(analysis: &Analysis) -> bool {
    analysis
        .services
        .contains(&crate::analysis::ServiceRequirement::Postgres)
        || analysis
            .packages
            .iter()
            .any(|package| package == "postgresql")
}

fn ensure_postgres_shell_user(
    root: &Path,
    analysis: &Analysis,
    env_map: &BTreeMap<String, String>,
) -> Result<()> {
    if !analysis
        .services
        .contains(&crate::analysis::ServiceRequirement::Postgres)
    {
        return Ok(());
    }

    let Some(user) = current_shell_user(env_map)? else {
        return Ok(());
    };

    let output = Command::new("bash")
        .current_dir(root)
        .env_clear()
        .envs(env_map)
        .args(["-lc", &postgres_shell_user_ensure_command(&user)])
        .output()
        .context("failed to invoke PostgreSQL shell user setup")?;

    if output.status.success() {
        return Ok(());
    }

    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stderr).trim(),
        String::from_utf8_lossy(&output.stdout).trim()
    )
    .trim()
    .to_string();

    if combined.is_empty() {
        bail!(
            "postgres shell user setup failed with status {}",
            output.status
        );
    }
    bail!("{combined}")
}

fn current_shell_user(env_map: &BTreeMap<String, String>) -> Result<Option<String>> {
    if let Some(user) = env_map.get("USER").filter(|value| !value.trim().is_empty()) {
        return Ok(Some(user.trim().to_string()));
    }
    if let Ok(user) = std::env::var("USER")
        && !user.trim().is_empty()
    {
        return Ok(Some(user.trim().to_string()));
    }

    let output = Command::new("id")
        .arg("-nu")
        .output()
        .context("failed to resolve current shell user with `id -nu`")?;
    if !output.status.success() {
        return Ok(None);
    }
    let user = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if user.is_empty() {
        Ok(None)
    } else {
        Ok(Some(user))
    }
}

fn postgres_shell_user_ensure_command(user: &str) -> String {
    let user_literal = sql_string_literal(user);
    format!(
        "psql --dbname postgres -v ON_ERROR_STOP=1 <<'SQL'\nSELECT format('CREATE ROLE %I LOGIN', {user_literal})\nWHERE NOT EXISTS (\n  SELECT 1 FROM pg_roles WHERE rolname = {user_literal}\n)\n\\gexec\nSELECT format('CREATE DATABASE %I OWNER %I', {user_literal}, {user_literal})\nWHERE NOT EXISTS (\n  SELECT 1 FROM pg_database WHERE datname = {user_literal}\n)\n\\gexec\nSQL"
    )
}

fn sql_string_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn print_deploy_ssh_summary(setup: &DeploySshSetup) {
    if setup.configured_hosts.is_empty() {
        return;
    }
    let prepared_hosts = setup
        .matched_hosts
        .iter()
        .chain(setup.fetched_hosts.iter())
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if setup.missing_hosts.is_empty() {
        println!(
            "SSH known_hosts: prepared project-scoped host verification for {}.",
            prepared_hosts.join(", ")
        );
    } else if prepared_hosts.is_empty() {
        println!(
            "SSH known_hosts: could not prepare host verification for {}; SSH connections may fail until keys are added or the host is reachable for keyscan.",
            setup.missing_hosts.join(", ")
        );
    } else {
        println!(
            "SSH known_hosts: prepared {}. Could not resolve host keys for {}.",
            prepared_hosts.join(", "),
            setup.missing_hosts.join(", ")
        );
    }
    if !setup.fetched_hosts.is_empty() {
        println!(
            "SSH known_hosts: fetched host keys for {} into the project-scoped known_hosts file.",
            setup.fetched_hosts.join(", ")
        );
    }
    if !setup.configured_aliases.is_empty() {
        println!(
            "SSH config: prepared project-scoped aliases for {}.",
            setup.configured_aliases.join(", ")
        );
    }
    if !setup.ssh_agent_hosts.is_empty() && setup.missing_ssh_agent.is_empty() {
        println!(
            "SSH agent: configured IdentityAgent for {}.",
            setup.ssh_agent_hosts.join(", ")
        );
    } else if !setup.missing_ssh_agent.is_empty() {
        println!(
            "SSH agent: requested for {} but SSH_AUTH_SOCK is not available on the host.",
            setup.missing_ssh_agent.join(", ")
        );
    }
}

fn prepare_agent_runtime(
    agent: Option<&str>,
    runtime_dir: &Path,
    env_map: &mut BTreeMap<String, String>,
    plan: &mut SandboxPlan,
) -> Result<()> {
    match agent {
        Some("claude") => prepare_claude_home_overlay(runtime_dir, env_map, plan),
        _ => Ok(()),
    }
}

fn prepare_claude_home_overlay(
    runtime_dir: &Path,
    env_map: &mut BTreeMap<String, String>,
    plan: &mut SandboxPlan,
) -> Result<()> {
    let home = dirs::home_dir().context("failed to resolve home directory for Claude runtime")?;
    prepare_claude_home_overlay_from(runtime_dir, &home, env_map, plan)
}

fn prepare_claude_home_overlay_from(
    runtime_dir: &Path,
    home: &Path,
    env_map: &mut BTreeMap<String, String>,
    plan: &mut SandboxPlan,
) -> Result<()> {
    let overlay_home = runtime_dir.join("claude-home");
    fs::create_dir_all(&overlay_home)
        .with_context(|| format!("failed to create {}", overlay_home.display()))?;
    remove_stale_claude_overlay_shell_files(&overlay_home)?;

    let claude_dir = home.join(".claude");
    if claude_dir.exists() {
        ensure_symlink(&claude_dir, &overlay_home.join(".claude"))?;
        push_unique_path(&mut plan.read_write_dirs, claude_dir);
    }

    let agents_dir = home.join(".agents");
    if agents_dir.exists() {
        ensure_symlink(&agents_dir, &overlay_home.join(".agents"))?;
        push_unique_path(&mut plan.read_only_dirs, agents_dir);
    }

    let global_config = home.join(".claude.json");
    if global_config.is_file() {
        let content = fs::read(&global_config)
            .with_context(|| format!("failed to read {}", global_config.display()))?;
        write_if_changed(overlay_home.join(".claude.json"), content)?;
    }

    prepare_claude_overlay_ssh(overlay_home.as_path(), env_map)?;

    env_map.insert("EXPLICIT_HOST_HOME".to_string(), home.display().to_string());
    env_map.insert("HOME".to_string(), overlay_home.display().to_string());
    push_unique_path(&mut plan.read_write_dirs, overlay_home.clone());
    plan.notes.push(format!(
        "Claude home overlay enabled at {}",
        overlay_home.display()
    ));
    Ok(())
}

fn remove_stale_claude_overlay_shell_files(overlay_home: &Path) -> Result<()> {
    for relative in [
        ".profile",
        ".bash_profile",
        ".bash_login",
        ".bashrc",
        ".zprofile",
        ".zshrc",
        ".zshenv",
    ] {
        let path = overlay_home.join(relative);
        if !path.exists() {
            continue;
        }
        fs::remove_file(&path).with_context(|| format!("failed to remove {}", path.display()))?;
    }
    Ok(())
}

fn prepare_claude_overlay_ssh(
    overlay_home: &Path,
    env_map: &BTreeMap<String, String>,
) -> Result<()> {
    let Some(known_hosts) = env_map.get("EXPLICIT_DEPLOY_KNOWN_HOSTS_FILE") else {
        return Ok(());
    };

    let ssh_dir = overlay_home.join(".ssh");
    fs::create_dir_all(&ssh_dir)
        .with_context(|| format!("failed to create {}", ssh_dir.display()))?;
    ensure_symlink(Path::new(known_hosts), &ssh_dir.join("known_hosts"))?;

    let mut config_lines = Vec::new();
    if let Some(config) = env_map.get("EXPLICIT_DEPLOY_SSH_CONFIG_FILE") {
        config_lines.push(format!("Include {}", ssh_config_value(config)));
    }
    config_lines.extend([
        "Host *".to_string(),
        format!("  UserKnownHostsFile {}", ssh_config_value(known_hosts)),
        "  GlobalKnownHostsFile /dev/null".to_string(),
        "  StrictHostKeyChecking yes".to_string(),
    ]);
    write_if_changed(
        ssh_dir.join("config"),
        format!("{}\n", config_lines.join("\n")),
    )?;
    Ok(())
}

fn ssh_config_value(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

fn ensure_symlink(target: &Path, link: &Path) -> Result<()> {
    if let Ok(existing) = fs::read_link(link)
        && existing == target
    {
        return Ok(());
    }
    if link.exists() || fs::symlink_metadata(link).is_ok() {
        let metadata = fs::symlink_metadata(link)
            .with_context(|| format!("failed to stat {}", link.display()))?;
        if metadata.is_dir() && !metadata.file_type().is_symlink() {
            fs::remove_dir_all(link)
                .with_context(|| format!("failed to remove {}", link.display()))?;
        } else {
            fs::remove_file(link)
                .with_context(|| format!("failed to remove {}", link.display()))?;
        }
    }
    symlink(target, link).with_context(|| {
        format!(
            "failed to symlink {} -> {}",
            link.display(),
            target.display()
        )
    })
}

fn push_unique_path(paths: &mut Vec<PathBuf>, path: PathBuf) {
    if !paths.contains(&path) {
        paths.push(path);
    }
}

fn push_unique_file_with_realpath(paths: &mut Vec<PathBuf>, path: PathBuf) {
    push_unique_path(paths, path.clone());
    if let Ok(real_path) = fs::canonicalize(&path) {
        push_unique_path(paths, real_path);
    }
}

fn write_project_known_hosts(
    source: &Path,
    destination: &Path,
    deploy_hosts: &[String],
) -> Result<DeploySshSetup> {
    let mut entries = BTreeSet::new();
    let mut matched_hosts = Vec::new();
    let mut fetched_hosts = Vec::new();
    let mut missing_hosts = Vec::new();

    for host in deploy_hosts {
        let host_entries = matching_known_host_entries(source, host)?;
        if host_entries.is_empty() {
            let scanned_entries = ssh_keyscan_known_host_entries(host)?;
            if scanned_entries.is_empty() {
                missing_hosts.push(host.clone());
                continue;
            }
            fetched_hosts.push(host.clone());
            entries.extend(scanned_entries);
        } else {
            matched_hosts.push(host.clone());
            entries.extend(host_entries);
        }
    }

    let rendered = if entries.is_empty() {
        String::new()
    } else {
        let mut rendered = entries.into_iter().collect::<Vec<_>>().join("\n");
        rendered.push('\n');
        rendered
    };
    write_if_changed(destination, rendered)
        .with_context(|| format!("failed to write {}", destination.display()))?;

    Ok(DeploySshSetup {
        configured_hosts: deploy_hosts.to_vec(),
        matched_hosts,
        fetched_hosts,
        missing_hosts,
        configured_aliases: Vec::new(),
        ssh_agent_hosts: Vec::new(),
        missing_ssh_agent: Vec::new(),
    })
}

fn collect_effective_deploy_hosts(root: &Path, analysis: &Analysis) -> Result<Vec<String>> {
    let mut hosts = Vec::new();
    for host in &analysis.deploy_hosts {
        push_unique_host(&mut hosts, host);
    }
    for host in git_remote_ssh_hosts(root)? {
        push_unique_host(&mut hosts, &host);
    }
    Ok(hosts)
}

fn push_unique_host(hosts: &mut Vec<String>, host: &str) {
    let trimmed = host.trim();
    if trimmed.is_empty() {
        return;
    }
    if !hosts.iter().any(|existing| existing == trimmed) {
        hosts.push(trimmed.to_string());
    }
}

fn effective_ssh_agent_hosts(effective_hosts: &[String], analysis: &Analysis) -> Vec<String> {
    if analysis.deploy_use_ssh_agent {
        return effective_hosts.to_vec();
    }

    analysis
        .deploy_ssh_agent_hosts
        .iter()
        .filter(|host| effective_hosts.iter().any(|effective| effective == *host))
        .cloned()
        .collect()
}

fn resolve_host_ssh_auth_sock(ssh_agent_hosts: &[String]) -> Result<Option<PathBuf>> {
    if ssh_agent_hosts.is_empty() {
        return Ok(None);
    }

    let socket = std::env::var_os("SSH_AUTH_SOCK")
        .or_else(|| std::env::var_os("EXPLICIT_HOST_SSH_AUTH_SOCK"));
    let Some(socket) = socket else {
        return Ok(None);
    };
    let path = PathBuf::from(socket);
    if path.as_os_str().is_empty() {
        return Ok(None);
    }
    if !path.exists() {
        return Ok(None);
    }
    Ok(Some(path))
}

fn write_project_ssh_config(
    destination: &Path,
    deploy_hosts: &[String],
    ssh_agent_hosts: &[String],
    ssh_auth_sock: Option<&Path>,
) -> Result<Vec<String>> {
    let mut rendered = String::new();
    let mut configured_aliases = Vec::new();
    let ssh_agent_hosts = ssh_agent_hosts.iter().collect::<BTreeSet<_>>();

    for host in deploy_hosts {
        let Some(block) =
            resolve_project_ssh_config_block(host, ssh_agent_hosts.contains(host), ssh_auth_sock)?
        else {
            continue;
        };
        configured_aliases.push(host.clone());
        rendered.push_str(&block);
    }

    write_if_changed(destination, rendered)
        .with_context(|| format!("failed to write {}", destination.display()))?;
    Ok(configured_aliases)
}

fn matching_known_host_entries(source: &Path, host: &str) -> Result<BTreeSet<String>> {
    if !source.is_file() {
        return Ok(BTreeSet::new());
    }

    let ssh_keygen =
        preferred_command_path("ssh-keygen").unwrap_or_else(|| PathBuf::from("ssh-keygen"));
    let mut entries = BTreeSet::new();
    let mut queries = BTreeSet::new();
    queries.extend(deploy_host_lookup_queries(host));
    queries.extend(resolve_ssh_config_host_queries(host)?);
    for query in queries {
        let output = Command::new(&ssh_keygen)
            .args(["-F", &query, "-f"])
            .arg(source)
            .output()
            .with_context(|| format!("failed to query {} with ssh-keygen", source.display()))?;
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines().map(str::trim) {
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                entries.insert(line.to_string());
            }
            continue;
        }
        if output.status.code() == Some(1) {
            continue;
        }
        bail!(
            "ssh-keygen -F failed while reading {}: {}",
            source.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(entries)
}

fn ssh_keyscan_known_host_entries(host: &str) -> Result<BTreeSet<String>> {
    let Some(ssh_keyscan) = preferred_command_path("ssh-keyscan") else {
        return Ok(BTreeSet::new());
    };

    let mut entries = BTreeSet::new();
    for target in ssh_scan_targets(host)? {
        let mut command = Command::new(&ssh_keyscan);
        command.arg("-T").arg("5");
        if let Some(port) = target.port {
            command.arg("-p").arg(port.to_string());
        }
        command.arg(&target.host);
        let Ok(output) = command.output() else {
            continue;
        };
        for line in String::from_utf8_lossy(&output.stdout)
            .lines()
            .map(str::trim)
        {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            entries.insert(line.to_string());
        }
    }
    Ok(entries)
}

fn git_remote_ssh_hosts(root: &Path) -> Result<Vec<String>> {
    let git = preferred_command_path("git").unwrap_or_else(|| PathBuf::from("git"));
    let output = Command::new(&git)
        .arg("-C")
        .arg(root)
        .args(["config", "--get-regexp", r"^remote\..*\.url$"])
        .output()
        .context("failed to inspect git remotes for SSH hosts")?;
    if !output.status.success() {
        return Ok(Vec::new());
    }

    let mut hosts = Vec::new();
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let Some((_, url)) = line.split_once(char::is_whitespace) else {
            continue;
        };
        if let Some(host) = ssh_host_from_remote_url(url.trim()) {
            push_unique_host(&mut hosts, &host);
        }
    }
    Ok(hosts)
}

fn ssh_host_from_remote_url(url: &str) -> Option<String> {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.starts_with("http://")
        || trimmed.starts_with("https://")
        || trimmed.starts_with("git://")
        || trimmed.starts_with("file://")
        || trimmed.starts_with('/')
        || trimmed.starts_with('.')
    {
        return None;
    }
    if let Some(rest) = trimmed.strip_prefix("ssh://") {
        return host_from_ssh_authority(rest);
    }
    if let Some((prefix, _)) = trimmed.split_once(':')
        && !prefix.contains('/')
        && !prefix.is_empty()
    {
        let host = prefix
            .rsplit_once('@')
            .map(|(_, host)| host)
            .unwrap_or(prefix)
            .trim();
        if !host.is_empty() {
            return Some(host.to_string());
        }
    }
    None
}

fn host_from_ssh_authority(authority_and_path: &str) -> Option<String> {
    let authority = authority_and_path.split('/').next()?.trim();
    if authority.is_empty() {
        return None;
    }
    let authority = authority
        .rsplit_once('@')
        .map(|(_, host)| host)
        .unwrap_or(authority)
        .trim();
    if authority.is_empty() {
        return None;
    }
    if authority.starts_with('[') {
        let closing = authority.find(']')?;
        let host = &authority[1..closing];
        let rest = authority.get(closing + 1..).unwrap_or_default();
        if let Some(port) = rest.strip_prefix(':')
            && !port.is_empty()
        {
            return Some(format!("{host}:{port}"));
        }
        return Some(host.to_string());
    }
    if let Some((host, port)) = authority.rsplit_once(':')
        && port.chars().all(|ch| ch.is_ascii_digit())
        && !host.is_empty()
    {
        return Some(format!("{host}:{port}"));
    }
    Some(authority.to_string())
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct SshScanTarget {
    host: String,
    port: Option<u16>,
}

fn ssh_scan_targets(host: &str) -> Result<Vec<SshScanTarget>> {
    let mut targets = BTreeSet::new();
    if let Some(target) = parse_ssh_scan_target(host) {
        targets.insert(target);
    }

    if is_plain_ssh_host_alias(host)
        && let Some(details) = resolve_ssh_config_details(host)?
    {
        targets.insert(SshScanTarget {
            host: details.hostname,
            port: details.port,
        });
    }

    Ok(targets.into_iter().collect())
}

fn parse_ssh_scan_target(host: &str) -> Option<SshScanTarget> {
    let trimmed = host.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(rest) = trimmed.strip_prefix("ssh://") {
        return host_from_ssh_authority(rest).and_then(|resolved| parse_ssh_scan_target(&resolved));
    }
    if trimmed.starts_with('[') {
        let closing = trimmed.find(']')?;
        let hostname = trimmed[1..closing].trim();
        if hostname.is_empty() {
            return None;
        }
        let rest = trimmed.get(closing + 1..).unwrap_or_default();
        let port = rest
            .strip_prefix(':')
            .and_then(|value| value.parse::<u16>().ok());
        return Some(SshScanTarget {
            host: hostname.to_string(),
            port,
        });
    }
    if let Some((hostname, port)) = trimmed.rsplit_once(':')
        && port.chars().all(|ch| ch.is_ascii_digit())
        && !hostname.is_empty()
    {
        return Some(SshScanTarget {
            host: hostname.to_string(),
            port: port.parse::<u16>().ok(),
        });
    }
    Some(SshScanTarget {
        host: trimmed.to_string(),
        port: None,
    })
}

fn resolve_ssh_config_details(host: &str) -> Result<Option<SshConfigDetails>> {
    let Some(ssh) = preferred_command_path("ssh") else {
        return Ok(None);
    };
    let output = Command::new(&ssh)
        .args(["-G", host])
        .output()
        .with_context(|| format!("failed to inspect ssh config for `{host}`"))?;
    if !output.status.success() {
        return Ok(None);
    }
    Ok(parse_ssh_config_details(&String::from_utf8_lossy(
        &output.stdout,
    )))
}

fn resolve_ssh_config_host_queries(host: &str) -> Result<Vec<String>> {
    if !is_plain_ssh_host_alias(host) {
        return Ok(Vec::new());
    }

    let Some(details) = resolve_ssh_config_details(host)? else {
        return Ok(Vec::new());
    };
    let resolved = match details.port {
        Some(port) => format!("{}:{port}", details.hostname),
        None => details.hostname,
    };
    Ok(deploy_host_lookup_queries(&resolved))
}

fn resolve_project_ssh_config_block(
    host: &str,
    include_identity_agent: bool,
    ssh_auth_sock: Option<&Path>,
) -> Result<Option<String>> {
    if !is_plain_ssh_host_alias(host) {
        return Ok(None);
    }

    let ssh = preferred_command_path("ssh").unwrap_or_else(|| PathBuf::from("ssh"));
    let output = Command::new(&ssh)
        .args(["-G", host])
        .output()
        .with_context(|| format!("failed to inspect ssh config for `{host}`"))?;
    if !output.status.success() {
        return Ok(None);
    }

    Ok(render_project_ssh_config_block(
        host,
        &String::from_utf8_lossy(&output.stdout),
        include_identity_agent.then_some(ssh_auth_sock).flatten(),
    ))
}

fn project_ssh_public_key_support_files(hosts: &[String]) -> Result<Vec<PathBuf>> {
    let mut files = BTreeSet::new();
    for host in hosts {
        if !is_plain_ssh_host_alias(host) {
            continue;
        }
        let Some(ssh) = preferred_command_path("ssh") else {
            continue;
        };
        let output = Command::new(&ssh)
            .args(["-G", host])
            .output()
            .with_context(|| format!("failed to inspect ssh config for `{host}`"))?;
        if !output.status.success() {
            continue;
        }
        files.extend(extract_project_ssh_public_key_files(
            &String::from_utf8_lossy(&output.stdout),
        ));
    }
    Ok(files.into_iter().collect())
}

fn is_plain_ssh_host_alias(host: &str) -> bool {
    let host = host.trim();
    !host.is_empty()
        && !host.contains('/')
        && !host.contains('@')
        && !host.contains('[')
        && !host.contains(']')
}

#[derive(Debug, PartialEq, Eq)]
struct SshConfigDetails {
    hostname: String,
    port: Option<u16>,
}

fn parse_ssh_config_details(output: &str) -> Option<SshConfigDetails> {
    let mut hostname = None;
    let mut port = None;

    for line in output.lines() {
        let trimmed = line.trim();
        let Some((key, value)) = trimmed.split_once(char::is_whitespace) else {
            continue;
        };
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        match key {
            "hostname" => hostname = Some(value.to_string()),
            "port" => port = value.parse::<u16>().ok(),
            _ => {}
        }
    }

    hostname.map(|hostname| SshConfigDetails { hostname, port })
}

fn render_project_ssh_config_block(
    host: &str,
    output: &str,
    ssh_auth_sock: Option<&Path>,
) -> Option<String> {
    parse_ssh_config_details(output)?;

    let mut lines = Vec::new();
    for line in output.lines() {
        let trimmed = line.trim();
        let Some((key, value)) = trimmed.split_once(char::is_whitespace) else {
            continue;
        };
        let value = value.trim();
        if value.is_empty() || should_skip_project_ssh_config_key(key) {
            continue;
        }
        lines.push(format!("  {key} {value}"));
    }

    if lines.is_empty() {
        return None;
    }
    if let Some(socket) = ssh_auth_sock {
        lines.push(format!(
            "  IdentityAgent {}",
            ssh_config_value(&socket.display().to_string())
        ));
    }

    let mut rendered = format!("Host {host}\n");
    for line in lines {
        rendered.push_str(&line);
        rendered.push('\n');
    }
    Some(rendered)
}

fn extract_project_ssh_public_key_files(output: &str) -> Vec<PathBuf> {
    let mut files = BTreeSet::new();
    let home = dirs::home_dir();
    for line in output.lines() {
        let trimmed = line.trim();
        let Some((key, value)) = trimmed.split_once(char::is_whitespace) else {
            continue;
        };
        if key != "identityfile" {
            continue;
        }
        let candidate = value.trim();
        if !candidate.ends_with(".pub") {
            continue;
        }
        let path = expand_home_like_path(home.as_deref(), candidate);
        if !path.is_absolute() || !path.is_file() {
            continue;
        }
        files.insert(path);
    }
    files.into_iter().collect()
}

fn expand_home_like_path(home: Option<&Path>, raw: &str) -> PathBuf {
    let Some(home) = home else {
        return PathBuf::from(raw);
    };
    if raw == "~" {
        return home.to_path_buf();
    }
    if let Some(rest) = raw.strip_prefix("~/") {
        return home.join(rest);
    }
    if let Some(rest) = raw.strip_prefix("$HOME/") {
        return home.join(rest);
    }
    if let Some(rest) = raw.strip_prefix("${HOME}/") {
        return home.join(rest);
    }
    PathBuf::from(raw)
}

fn should_skip_project_ssh_config_key(key: &str) -> bool {
    matches!(
        key,
        "host" | "globalknownhostsfile" | "userknownhostsfile" | "stricthostkeychecking"
    )
}

fn deploy_host_lookup_queries(host: &str) -> Vec<String> {
    let trimmed = host.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }

    let mut queries = BTreeSet::new();
    queries.insert(trimmed.to_string());

    let mut normalized = trimmed
        .trim_start_matches("ssh://")
        .split('/')
        .next()
        .unwrap_or(trimmed)
        .trim()
        .to_string();
    if let Some((_, rest)) = normalized.rsplit_once('@') {
        normalized = rest.to_string();
    }
    if let Some((prefix, _)) = normalized.split_once(':')
        && trimmed.contains('@')
        && !trimmed.starts_with("ssh://")
    {
        normalized = prefix.to_string();
    }
    if let Some((host_only, port)) = normalized.rsplit_once(':')
        && port.chars().all(|ch| ch.is_ascii_digit())
        && !host_only.contains(']')
        && !host_only.is_empty()
    {
        queries.insert(format!("[{host_only}]:{port}"));
        queries.insert(host_only.to_string());
    } else if !normalized.is_empty() {
        queries.insert(normalized);
    }

    queries.into_iter().collect()
}

fn write_ssh_wrapper_scripts(wrapper_dir: &Path) -> Result<()> {
    for command in ["ssh", "scp", "sftp"] {
        let Some(binary) = preferred_command_path(command) else {
            continue;
        };
        let wrapper_path = wrapper_dir.join(command);
        let content = format!(
            "#!/bin/sh\nexec {} -F \"$EXPLICIT_DEPLOY_SSH_CONFIG_FILE\" -o UserKnownHostsFile=\"$EXPLICIT_DEPLOY_KNOWN_HOSTS_FILE\" -o GlobalKnownHostsFile=/dev/null -o StrictHostKeyChecking=yes \"$@\"\n",
            binary.display()
        );
        write_if_changed(&wrapper_path, content)
            .with_context(|| format!("failed to write {}", wrapper_path.display()))?;
        let mut permissions = fs::metadata(&wrapper_path)
            .with_context(|| format!("failed to stat {}", wrapper_path.display()))?
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&wrapper_path, permissions)
            .with_context(|| format!("failed to chmod {}", wrapper_path.display()))?;
    }
    Ok(())
}

fn prepend_path(env_map: &mut BTreeMap<String, String>, prefix: &Path) {
    let prefix = prefix.display().to_string();
    match env_map.get_mut("PATH") {
        Some(path) if !path.is_empty() => {
            *path = format!("{prefix}:{path}");
        }
        Some(path) => {
            *path = prefix;
        }
        None => {
            env_map.insert("PATH".to_string(), prefix);
        }
    }
}

fn prioritize_launch_executable(
    env_map: &mut BTreeMap<String, String>,
    plan: &mut SandboxPlan,
    current_exe: &Path,
) {
    let Some(parent) = current_exe.parent() else {
        return;
    };
    prepend_path(env_map, parent);
    push_unique_path(&mut plan.read_only_dirs, parent.to_path_buf());
}

fn shell_escape_for_env(value: &str) -> String {
    if !value.is_empty()
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.' | '/' | ':'))
    {
        return value.to_string();
    }
    format!("'{}'", value.replace('\'', r#"'"'"'"#))
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
    capture_devenv_env_with_retry(root, step, total_steps, false)
}

fn capture_devenv_env_with_retry(
    root: &Path,
    step: usize,
    total_steps: usize,
    refresh_cache: bool,
) -> Result<BTreeMap<String, String>> {
    print_step_start(step, total_steps, "Realizing devenv environment");
    let start = Instant::now();
    let progress = Arc::new(Mutex::new(ProgressSnapshot::default()));
    let mut child = devenv_shell_env_command(root, refresh_cache)
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
    let stderr_reader = thread::spawn(move || -> std::io::Result<String> {
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
    let stderr_output = stderr_reader
        .join()
        .map_err(|_| anyhow!("failed to join `devenv shell env -0` stderr reader thread"))?
        .context("failed to read `devenv shell env -0` stderr")?;

    if !status.success() {
        if !refresh_cache && stale_devenv_cache_detected(&stderr_output) {
            eprintln!(
                "{} Retrying with refreshed devenv cache...",
                progress_prefix(step, total_steps)
            );
            return capture_devenv_env_with_retry(root, step, total_steps, true);
        }
        let stderr_output = stderr_output.trim();
        if stderr_output.is_empty() {
            bail!("`devenv shell env -0` failed with status {status}");
        }
        bail!("`devenv shell env -0` failed with status {status}\n{stderr_output}");
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
    run_devenv_up_with_retry(root, step, total_steps, false)
}

fn run_devenv_up_with_retry(
    root: &Path,
    step: usize,
    total_steps: usize,
    refresh_cache: bool,
) -> Result<()> {
    print_step_start(step, total_steps, "Starting devenv services");
    let start = Instant::now();
    let output = devenv_up_command(root, refresh_cache)
        .output()
        .context("failed to invoke `devenv up --detach`")?;
    if output.status.success() {
        print_step_done(step, total_steps, "Services are ready", start.elapsed());
        return Ok(());
    }

    let combined = String::from_utf8_lossy(&output.stderr).to_string()
        + "\n"
        + &String::from_utf8_lossy(&output.stdout);
    if let Some(pid) = devenv_already_running_pid(&combined) {
        print_step_done(
            step,
            total_steps,
            &format!("Reusing already-running services (PID {pid})"),
            start.elapsed(),
        );
        return Ok(());
    }

    if !refresh_cache && stale_devenv_cache_detected(&combined) {
        eprintln!(
            "{} Retrying with refreshed devenv cache...",
            progress_prefix(step, total_steps)
        );
        return run_devenv_up_with_retry(root, step, total_steps, true);
    }

    let summary = summarize_devenv_failure(&combined);
    if summary.is_empty() {
        bail!("`devenv up --detach` failed with status {}", output.status);
    }
    bail!(
        "`devenv up --detach` failed with status {}: {summary}",
        output.status
    );
}

pub(crate) fn devenv_already_running_pid(output: &str) -> Option<String> {
    let marker = "Processes already running with PID ";
    for line in output.lines() {
        let trimmed = line.trim();
        let Some((_, rest)) = trimmed.split_once(marker) else {
            continue;
        };
        let pid = rest
            .chars()
            .take_while(|ch| ch.is_ascii_digit())
            .collect::<String>();
        if !pid.is_empty() {
            return Some(pid);
        }
    }
    None
}

pub(crate) fn stale_devenv_cache_detected(output: &str) -> bool {
    let normalized = output.split_whitespace().collect::<Vec<_>>().join(" ");
    normalized.contains("Cached paths no longer exist (garbage collected?)")
        || normalized.contains("Cached env path no longer exists")
        || ((normalized.contains("does not exist and cannot be created")
            || (normalized.contains("does not exist and")
                && normalized.contains("cannot be created")))
            && normalized.contains("devenv-"))
}

fn devenv_shell_env_command(root: &Path, refresh_cache: bool) -> Command {
    let mut command = Command::new("devenv");
    command.current_dir(root);
    if refresh_cache {
        command.args(["--refresh-eval-cache", "--refresh-task-cache"]);
    }
    command
        .args(["shell", "--no-tui", "--no-reload", "--", "env", "-0"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

fn devenv_up_command(root: &Path, refresh_cache: bool) -> Command {
    let mut command = Command::new("devenv");
    command.current_dir(root).arg("--verbose");
    if refresh_cache {
        command.args(["--refresh-eval-cache", "--refresh-task-cache"]);
    }
    command.args(["up", "--detach", "--no-tui", "--no-reload"]);
    command
}

fn summarize_devenv_failure(output: &str) -> String {
    let lines = output
        .lines()
        .map(strip_ansi_codes)
        .map(|line| normalize_devenv_failure_line(&line))
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();

    lines
        .iter()
        .rev()
        .map(String::as_str)
        .find(|line| {
            line.contains("error:")
                || line.starts_with("Error:")
                || line.contains("failed")
                || line.contains("Stop them first")
        })
        .or_else(|| lines.last().map(String::as_str))
        .unwrap_or_default()
        .to_string()
}

fn strip_ansi_codes(line: &str) -> String {
    let mut cleaned = String::with_capacity(line.len());
    let mut chars = line.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\u{1b}' && chars.peek() == Some(&'[') {
            let _ = chars.next();
            for next in chars.by_ref() {
                if ('@'..='~').contains(&next) {
                    break;
                }
            }
            continue;
        }
        cleaned.push(ch);
    }
    cleaned
}

fn normalize_devenv_failure_line(line: &str) -> String {
    line.trim()
        .trim_start_matches("╰─▶")
        .trim_start_matches('•')
        .trim()
        .to_string()
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
) -> std::io::Result<String> {
    let mut last_emitted = None::<String>;
    let mut captured = Vec::new();
    for line in BufReader::new(stderr).lines() {
        let line = line?;
        captured.push(line.clone());
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
    Ok(captured.join("\n"))
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
        build_sandbox_command, classify_devenv_stderr_line, current_shell_user,
        deploy_host_lookup_queries, devenv_already_running_pid, doctor_report,
        effective_ssh_agent_hosts, extract_project_ssh_public_key_files, git_remote_ssh_hosts,
        harmonize_tls_certificate_env, humanize_process_command, is_plain_ssh_host_alias,
        parse_process_snapshot, parse_ssh_config_details, parse_ssh_scan_target,
        postgres_shell_user_ensure_command, prepare_claude_home_overlay_from, prepare_deploy_ssh,
        prepare_postgres_shell_environment, prepend_path, prioritize_launch_executable,
        render_project_ssh_config_block, shell_escape_for_env, shell_total_steps, ssh_config_value,
        ssh_host_from_remote_url, stale_devenv_cache_detected, summarize_devenv_failure,
        summarize_process_tree, uses_postgres_shell, write_project_known_hosts,
        write_ssh_wrapper_scripts,
    };
    use crate::analysis::{
        Analysis, DetectedVersion, LanguageRequirement, ProjectRequirement, RepositoryMetadata,
        RequirementKind, RuntimeKind, SandboxPlan, ServiceRequirement, VersionKind,
    };
    use std::{
        collections::BTreeMap,
        env, fs,
        path::{Path, PathBuf},
        process::Command,
        sync::{Mutex, OnceLock},
    };
    use tempfile::tempdir;

    fn empty_analysis() -> Analysis {
        Analysis {
            root: Path::new("/tmp/project").to_path_buf(),
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
            lint_commands: Vec::new(),
            build_commands: Vec::new(),
            test_commands: Vec::new(),
            coverage_commands: Vec::new(),
            required_checks: Vec::new(),
            migration_checks: Vec::new(),
            notes: Vec::new(),
            repository: RepositoryMetadata::default(),
            sandbox_plan: SandboxPlan {
                root: Path::new("/tmp/project").to_path_buf(),
                read_write_files: Vec::new(),
                read_write_dirs: Vec::new(),
                read_only_files: Vec::new(),
                read_only_dirs: Vec::new(),
                protected_write_files: Vec::new(),
                notes: Vec::new(),
            },
        }
    }

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
    fn detects_already_running_devenv_process_pid() {
        let output = "Error:   × Processes already running with PID 23984. Stop them first with: devenv processes down";
        assert_eq!(devenv_already_running_pid(output).as_deref(), Some("23984"));
    }

    #[test]
    fn detects_stale_devenv_cache_failures() {
        assert!(stale_devenv_cache_detected(
            "Cached paths no longer exist (garbage collected?)"
        ));
        assert!(stale_devenv_cache_detected(
            "error: path '/nix/store/demo-devenv-shell.drv' does not exist and cannot be created"
        ));
        assert!(stale_devenv_cache_detected(
            "Error:   × Failed to get dev environment from derivation\n  ╰─▶ error: path '/nix/store/demo-devenv-shell.drv' does not exist and\n      cannot be created"
        ));
        assert!(!stale_devenv_cache_detected(
            "Error:   × Could not bind localhost:5432"
        ));
    }

    #[test]
    fn summarizes_devenv_failures_from_last_relevant_line() {
        let output = "\
some trace noise
Error:   × Could not bind localhost:5432
";
        assert_eq!(
            summarize_devenv_failure(output),
            "Error:   × Could not bind localhost:5432"
        );
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
    fn doctor_report_formats_versions_requirements_and_notes() {
        let mut analysis = empty_analysis();
        analysis.markers = vec!["mix.exs".to_string(), "workspace".to_string()];
        analysis.detected_languages = vec![LanguageRequirement::Elixir];
        analysis.detected_versions = vec![DetectedVersion {
            runtime: RuntimeKind::Elixir,
            version: "1.15.7".to_string(),
            source: ".tool-versions".to_string(),
            kind: VersionKind::Exact,
            config_lines: Vec::new(),
        }];
        analysis.services = vec![ServiceRequirement::Postgres];
        analysis.deploy_hosts = vec!["deploy-alias".to_string()];
        analysis.deploy_ssh_agent_hosts = vec!["deploy-alias".to_string()];
        analysis.dev_server_commands = vec!["mix phx.server".to_string()];
        analysis.lint_commands = vec!["mix format --check-formatted".to_string()];
        analysis.coverage_commands = vec!["mix test --cover".to_string()];
        analysis.required_checks = vec![ProjectRequirement {
            kind: RequirementKind::Lint,
            subject: "mix.exs".to_string(),
            summary: "Elixir projects must include Credo and pass `mix credo --strict`."
                .to_string(),
        }];
        analysis.notes = vec![
            "Workspace: merged 2 leaf projects into the root analysis (2 auto-discovered, 0 configured)."
                .to_string(),
            "Workspace members: infra (*.tf), services/stuffix (mix.exs).".to_string(),
        ];

        let report = doctor_report(&analysis);
        assert!(report.contains("Markers: mix.exs, workspace"));
        assert!(report.contains("Languages: elixir"));
        assert!(report.contains("Language versions: elixir 1.15.7 (.tool-versions)"));
        assert!(report.contains("Services: postgres"));
        assert!(report.contains("Deploy hosts: deploy-alias"));
        assert!(report.contains("SSH agent hosts: deploy-alias"));
        assert!(report.contains("Dev servers: mix phx.server"));
        assert!(report.contains("Coverage commands: mix test --cover"));
        assert!(report.contains("Requirements: lint Elixir projects must include Credo"));
        assert!(report.contains("Notes:\n  - Workspace: merged 2 leaf projects"));
    }

    #[test]
    fn shell_total_steps_counts_services_and_dev_servers() {
        assert_eq!(shell_total_steps(false, false), 2);
        assert_eq!(shell_total_steps(true, false), 3);
        assert_eq!(shell_total_steps(false, true), 3);
        assert_eq!(shell_total_steps(true, true), 4);
    }

    #[test]
    fn doctor_report_prints_none_for_empty_sections() {
        let report = doctor_report(&empty_analysis());
        assert!(report.contains("Markers: none"));
        assert!(report.contains("Packages: none"));
        assert!(report.contains("Requirements: none"));
        assert!(!report.contains("Notes:\n"));
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

    #[test]
    fn deploy_host_queries_normalize_common_ssh_forms() {
        assert_eq!(
            deploy_host_lookup_queries("ssh://git@deploy.example.com:2222/app"),
            vec![
                "[deploy.example.com]:2222".to_string(),
                "deploy.example.com".to_string(),
                "ssh://git@deploy.example.com:2222/app".to_string(),
            ]
        );
        assert_eq!(
            deploy_host_lookup_queries("git@github.com:openai/example.git"),
            vec![
                "git@github.com:openai/example.git".to_string(),
                "github.com".to_string(),
            ]
        );
        assert_eq!(
            deploy_host_lookup_queries("deploy.example.com:2201"),
            vec![
                "[deploy.example.com]:2201".to_string(),
                "deploy.example.com".to_string(),
                "deploy.example.com:2201".to_string(),
            ]
        );
    }

    #[test]
    fn parses_ssh_config_hostname_and_port() {
        let details = parse_ssh_config_details(
            "host deploy-alias\nuser deploy\nhostname 192.0.2.10\nport 22\n",
        )
        .expect("expected ssh config details");
        assert_eq!(
            details,
            super::SshConfigDetails {
                hostname: "192.0.2.10".to_string(),
                port: Some(22),
            }
        );
    }

    #[test]
    fn only_plain_hosts_use_ssh_config_resolution() {
        assert!(is_plain_ssh_host_alias("deploy-alias"));
        assert!(is_plain_ssh_host_alias("deploy.example.com"));
        assert!(!is_plain_ssh_host_alias(
            "ssh://git@deploy.example.com:2222/app"
        ));
        assert!(!is_plain_ssh_host_alias(
            "git@github.com:openai/example.git"
        ));
        assert!(!is_plain_ssh_host_alias("[deploy.example.com]:2222"));
    }

    #[test]
    fn prepend_path_puts_wrapper_dir_first() {
        let mut env_map = BTreeMap::from([("PATH".to_string(), "/usr/bin:/bin".to_string())]);
        prepend_path(
            &mut env_map,
            Path::new("/tmp/project/.nono/runtime/ssh-bin"),
        );
        assert_eq!(
            env_map.get("PATH").map(String::as_str),
            Some("/tmp/project/.nono/runtime/ssh-bin:/usr/bin:/bin")
        );
    }

    #[test]
    fn prioritize_launch_executable_puts_current_explicit_first_and_allows_it() {
        let mut env_map = BTreeMap::from([(
            "PATH".to_string(),
            "/tmp/project/.nono/runtime/ssh-bin:/usr/bin:/bin".to_string(),
        )]);
        let mut plan = SandboxPlan {
            root: PathBuf::from("/tmp/project"),
            read_write_files: Vec::new(),
            read_write_dirs: Vec::new(),
            read_only_files: Vec::new(),
            read_only_dirs: Vec::new(),
            protected_write_files: Vec::new(),
            notes: Vec::new(),
        };
        prioritize_launch_executable(
            &mut env_map,
            &mut plan,
            Path::new("/opt/explicit/bin/explicit"),
        );
        assert_eq!(
            env_map.get("PATH").map(String::as_str),
            Some("/opt/explicit/bin:/tmp/project/.nono/runtime/ssh-bin:/usr/bin:/bin")
        );
        assert!(
            plan.read_only_dirs
                .contains(&PathBuf::from("/opt/explicit/bin"))
        );
    }

    #[test]
    fn postgres_shell_user_setup_command_creates_role_and_database() {
        let command = postgres_shell_user_ensure_command("demo-user");
        assert!(command.contains("CREATE ROLE %I LOGIN"));
        assert!(command.contains("CREATE DATABASE %I OWNER %I"));
        assert!(command.contains("rolname = 'demo-user'"));
        assert!(command.contains("datname = 'demo-user'"));
    }

    #[test]
    fn postgres_shell_user_setup_command_escapes_quotes() {
        let command = postgres_shell_user_ensure_command("o'connor");
        assert!(command.contains("rolname = 'o''connor'"));
        assert!(command.contains("datname = 'o''connor'"));
    }

    #[test]
    fn current_shell_user_prefers_env_map_user() {
        let env_map = BTreeMap::from([("USER".to_string(), "sandbox-user".to_string())]);
        assert_eq!(
            current_shell_user(&env_map).unwrap(),
            Some("sandbox-user".to_string())
        );
    }

    #[test]
    fn prepare_postgres_shell_environment_sets_project_local_history() {
        let dir = tempdir().unwrap();
        let mut env_map = BTreeMap::new();
        let mut analysis = empty_analysis();
        analysis.services = vec![ServiceRequirement::Postgres];

        prepare_postgres_shell_environment(dir.path(), &analysis, &mut env_map).unwrap();

        assert_eq!(
            env_map.get("PSQL_HISTORY").map(String::as_str),
            Some(
                dir.path()
                    .join(".devenv/.psql_history")
                    .to_string_lossy()
                    .as_ref()
            )
        );
        assert!(dir.path().join(".devenv").is_dir());
    }

    #[test]
    fn uses_postgres_shell_detects_service_or_package() {
        let mut analysis = empty_analysis();
        assert!(!uses_postgres_shell(&analysis));

        analysis.services = vec![ServiceRequirement::Postgres];
        assert!(uses_postgres_shell(&analysis));

        analysis.services.clear();
        analysis.packages.push("postgresql".to_string());
        assert!(uses_postgres_shell(&analysis));
    }

    #[test]
    fn shell_escape_for_env_quotes_paths_with_spaces() {
        assert_eq!(
            shell_escape_for_env("/tmp/project/.nono/runtime/ssh-bin/ssh"),
            "/tmp/project/.nono/runtime/ssh-bin/ssh"
        );
        assert_eq!(
            shell_escape_for_env("/tmp/My Project/.nono/runtime/ssh-bin/ssh"),
            "'/tmp/My Project/.nono/runtime/ssh-bin/ssh'"
        );
    }

    #[test]
    fn claude_runtime_uses_project_scoped_home_overlay() {
        let dir = tempdir().unwrap();
        let home = dir.path().join("home");
        let runtime = dir.path().join("runtime");
        fs::create_dir_all(home.join(".claude")).unwrap();
        fs::create_dir_all(home.join(".agents")).unwrap();
        fs::write(home.join(".claude.json"), "{\"theme\":\"light\"}\n").unwrap();
        fs::write(home.join(".agents/AGENTS.md"), "demo\n").unwrap();

        let mut env_map = BTreeMap::new();
        let mut plan = SandboxPlan {
            root: PathBuf::from("/tmp/project"),
            read_write_files: Vec::new(),
            read_write_dirs: Vec::new(),
            read_only_files: Vec::new(),
            read_only_dirs: Vec::new(),
            protected_write_files: Vec::new(),
            notes: Vec::new(),
        };

        prepare_claude_home_overlay_from(&runtime, &home, &mut env_map, &mut plan).unwrap();

        let overlay_home = runtime.join("claude-home");
        assert_eq!(
            env_map.get("HOME").map(String::as_str),
            Some(overlay_home.to_string_lossy().as_ref())
        );
        assert_eq!(
            fs::read_to_string(overlay_home.join(".claude.json")).unwrap(),
            "{\"theme\":\"light\"}\n"
        );
        assert!(!overlay_home.join(".profile").exists());
        assert_eq!(
            fs::read_link(overlay_home.join(".claude")).unwrap(),
            home.join(".claude")
        );
        assert!(plan.read_write_dirs.contains(&overlay_home));
        assert!(plan.read_write_dirs.contains(&home.join(".claude")));
        assert!(plan.read_only_dirs.contains(&home.join(".agents")));
        assert!(
            plan.notes
                .iter()
                .any(|note| note.contains("Claude home overlay enabled"))
        );
    }

    #[test]
    fn claude_runtime_removes_stale_shell_startup_files_from_overlay() {
        let dir = tempdir().unwrap();
        let home = dir.path().join("home");
        let runtime = dir.path().join("runtime");
        let overlay_home = runtime.join("claude-home");
        fs::create_dir_all(home.join(".claude")).unwrap();
        fs::create_dir_all(&overlay_home).unwrap();
        fs::write(overlay_home.join(".profile"), "broken\n").unwrap();

        let mut env_map = BTreeMap::new();
        let mut plan = SandboxPlan {
            root: PathBuf::from("/tmp/project"),
            read_write_files: Vec::new(),
            read_write_dirs: Vec::new(),
            read_only_files: Vec::new(),
            read_only_dirs: Vec::new(),
            protected_write_files: Vec::new(),
            notes: Vec::new(),
        };

        prepare_claude_home_overlay_from(&runtime, &home, &mut env_map, &mut plan).unwrap();
        assert!(!overlay_home.join(".profile").exists());
    }

    #[test]
    fn claude_runtime_writes_project_scoped_ssh_overlay() {
        let dir = tempdir().unwrap();
        let home = dir.path().join("home");
        let runtime = dir.path().join("runtime");
        let overlay_home = runtime.join("claude-home");
        let known_hosts = runtime.join("known_hosts");
        let ssh_config = runtime.join("ssh_config");
        fs::create_dir_all(home.join(".claude")).unwrap();
        fs::create_dir_all(&runtime).unwrap();
        fs::write(&known_hosts, "example ssh-ed25519 AAAA\n").unwrap();
        fs::write(&ssh_config, "Host deploy-alias\n  HostName 192.0.2.10\n").unwrap();

        let mut env_map = BTreeMap::from([
            (
                "EXPLICIT_DEPLOY_KNOWN_HOSTS_FILE".to_string(),
                known_hosts.display().to_string(),
            ),
            (
                "EXPLICIT_DEPLOY_SSH_CONFIG_FILE".to_string(),
                ssh_config.display().to_string(),
            ),
        ]);
        let mut plan = SandboxPlan {
            root: PathBuf::from("/tmp/project"),
            read_write_files: Vec::new(),
            read_write_dirs: Vec::new(),
            read_only_files: Vec::new(),
            read_only_dirs: Vec::new(),
            protected_write_files: Vec::new(),
            notes: Vec::new(),
        };

        prepare_claude_home_overlay_from(&runtime, &home, &mut env_map, &mut plan).unwrap();

        assert_eq!(
            fs::read_link(overlay_home.join(".ssh/known_hosts")).unwrap(),
            known_hosts
        );
        let config = fs::read_to_string(overlay_home.join(".ssh/config")).unwrap();
        assert!(config.contains(&format!(
            "Include {}",
            ssh_config_value(&ssh_config.display().to_string())
        )));
        assert!(config.contains(&format!(
            "  UserKnownHostsFile {}",
            ssh_config_value(&runtime.join("known_hosts").display().to_string())
        )));
        assert!(config.contains("  StrictHostKeyChecking yes"));
    }

    #[test]
    fn ssh_wrappers_force_project_known_hosts() {
        if super::preferred_command_path("ssh").is_none() {
            return;
        }
        let dir = tempdir().unwrap();
        write_ssh_wrapper_scripts(dir.path()).unwrap();
        let ssh_wrapper = std::fs::read_to_string(dir.path().join("ssh")).unwrap();
        assert!(ssh_wrapper.contains("-F \"$EXPLICIT_DEPLOY_SSH_CONFIG_FILE\""));
        assert!(ssh_wrapper.contains("UserKnownHostsFile=\"$EXPLICIT_DEPLOY_KNOWN_HOSTS_FILE\""));
        assert!(ssh_wrapper.contains("GlobalKnownHostsFile=/dev/null"));
        assert!(ssh_wrapper.contains("StrictHostKeyChecking=yes"));
    }

    #[test]
    fn renders_project_ssh_config_block_for_alias() {
        let block = render_project_ssh_config_block(
            "deploy-alias",
            "host deploy-alias\nuser deploy\nhostname 192.0.2.10\nport 22\nuserknownhostsfile /Users/demo/.ssh/known_hosts\nstricthostkeychecking ask\nidentityagent /tmp/agent.sock\n",
            None,
        )
        .expect("expected ssh config block");
        assert!(block.starts_with("Host deploy-alias\n"));
        assert!(block.contains("  hostname 192.0.2.10\n"));
        assert!(block.contains("  user deploy\n"));
        assert!(block.contains("  port 22\n"));
        assert!(block.contains("  identityagent /tmp/agent.sock\n"));
        assert!(!block.contains("userknownhostsfile"));
        assert!(!block.contains("stricthostkeychecking"));
        assert!(!block.contains("\nhost deploy-alias\n"));
    }

    #[test]
    fn renders_project_ssh_config_block_with_identity_agent_when_requested() {
        let block = render_project_ssh_config_block(
            "github.com",
            "host github.com\nhostname github.com\nport 22\n",
            Some(Path::new("/tmp/ssh auth.sock")),
        )
        .expect("expected ssh config block");
        assert!(block.contains("  IdentityAgent \"/tmp/ssh auth.sock\"\n"));
    }

    #[test]
    fn extracts_only_public_identity_files_from_ssh_config_output() {
        let dir = tempdir().unwrap();
        let public_key = dir.path().join("github_secretive.pub");
        let private_key = dir.path().join("id_ed25519");
        fs::write(&public_key, "ssh-ed25519 AAAATEST\n").unwrap();
        fs::write(&private_key, "PRIVATE\n").unwrap();

        let files = extract_project_ssh_public_key_files(&format!(
            "identityfile {}\nidentityfile {}\nidentityfile relative.pub\nidentityfile ~/github_secretive.pub\n",
            public_key.display(),
            private_key.display()
        ));
        assert_eq!(files, vec![public_key]);
    }

    #[test]
    fn project_known_hosts_includes_plain_alias_entries() {
        if super::preferred_command_path("ssh-keygen").is_none() {
            return;
        }
        let dir = tempdir().unwrap();
        let source = dir.path().join("known_hosts");
        let destination = dir.path().join("project-known_hosts");
        let alias = "deploy-alias";
        fs::write(
            &source,
            format!(
                "{alias} ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIN2y6n8wV9x8m8Yq7r2VJX0R2wQnJ2lG0f4sJmR5pL1K\n"
            ),
        )
        .unwrap();

        let setup = write_project_known_hosts(&source, &destination, &[alias.to_string()]).unwrap();
        assert_eq!(setup.matched_hosts, vec![alias.to_string()]);
        assert!(setup.missing_hosts.is_empty());
        assert_eq!(
            fs::read_to_string(destination).unwrap(),
            format!(
                "{alias} ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIN2y6n8wV9x8m8Yq7r2VJX0R2wQnJ2lG0f4sJmR5pL1K\n"
            )
        );
    }

    #[test]
    fn ssh_remote_url_parser_extracts_ssh_hosts() {
        assert_eq!(
            ssh_host_from_remote_url("git@github.com:owner/repo.git").as_deref(),
            Some("github.com")
        );
        assert_eq!(
            ssh_host_from_remote_url("ssh://git@example.com:2222/owner/repo.git").as_deref(),
            Some("example.com:2222")
        );
        assert_eq!(
            ssh_host_from_remote_url("ssh://git@[2001:db8::1]:2222/owner/repo.git").as_deref(),
            Some("2001:db8::1:2222")
        );
        assert_eq!(
            ssh_host_from_remote_url("https://github.com/owner/repo.git"),
            None
        );
    }

    #[test]
    fn git_remote_ssh_hosts_reads_hosts_from_repo_config() {
        let dir = tempdir().unwrap();
        let git = super::preferred_command_path("git").unwrap_or_else(|| PathBuf::from("git"));
        Command::new(&git)
            .arg("init")
            .arg("-q")
            .arg(dir.path())
            .status()
            .unwrap();
        Command::new(&git)
            .arg("-C")
            .arg(dir.path())
            .args([
                "remote",
                "add",
                "origin",
                "git@github.com:example/project.git",
            ])
            .status()
            .unwrap();
        Command::new(&git)
            .arg("-C")
            .arg(dir.path())
            .args([
                "remote",
                "add",
                "deploy",
                "ssh://git@deploy.example.com:2222/example/project.git",
            ])
            .status()
            .unwrap();

        let hosts = git_remote_ssh_hosts(dir.path()).unwrap();
        assert_eq!(
            hosts,
            vec![
                "github.com".to_string(),
                "deploy.example.com:2222".to_string()
            ]
        );
    }

    #[test]
    fn project_known_hosts_fetches_missing_entries_with_ssh_keyscan() {
        let _guard = path_env_lock().lock().unwrap();
        let dir = tempdir().unwrap();
        let bin_dir = dir.path().join("bin");
        fs::create_dir_all(&bin_dir).unwrap();
        let script = bin_dir.join("ssh-keyscan");
        fs::write(
            &script,
            "#!/bin/sh\nif [ \"$1\" = \"-T\" ]; then shift 2; fi\nif [ \"$1\" = \"-p\" ]; then port=\"$2\"; shift 2; else port=22; fi\nhost=\"$1\"\nprintf '# %s:%s SSH-2.0-test\\n' \"$host\" \"$port\"\nprintf '%s ssh-ed25519 AAAATESTKEY\\n' \"$host\"\n",
        )
        .unwrap();
        let mut permissions = fs::metadata(&script).unwrap().permissions();
        use std::os::unix::fs::PermissionsExt;
        permissions.set_mode(0o755);
        fs::set_permissions(&script, permissions).unwrap();

        let previous = env::var_os("PATH");
        let mut path_entries = vec![bin_dir.clone()];
        path_entries.extend(
            previous
                .as_deref()
                .map(env::split_paths)
                .into_iter()
                .flatten(),
        );
        let path = env::join_paths(path_entries).unwrap();
        unsafe { env::set_var("PATH", &path) };

        let source = dir.path().join("known_hosts");
        let destination = dir.path().join("project-known_hosts");
        let setup =
            write_project_known_hosts(&source, &destination, &["github.com".to_string()]).unwrap();

        restore_path(previous);

        assert!(setup.matched_hosts.is_empty());
        assert_eq!(setup.fetched_hosts, vec!["github.com".to_string()]);
        assert!(setup.missing_hosts.is_empty());
        assert_eq!(
            fs::read_to_string(destination).unwrap(),
            "github.com ssh-ed25519 AAAATESTKEY\n"
        );
    }

    #[test]
    fn prepare_deploy_ssh_adds_runtime_known_hosts_to_writeable_files() {
        let dir = tempdir().unwrap();
        let git = super::preferred_command_path("git").unwrap_or_else(|| PathBuf::from("git"));
        Command::new(&git)
            .arg("init")
            .arg("-q")
            .arg(dir.path())
            .status()
            .unwrap();
        Command::new(&git)
            .arg("-C")
            .arg(dir.path())
            .args([
                "remote",
                "add",
                "origin",
                "git@github.com:example/project.git",
            ])
            .status()
            .unwrap();
        let runtime_dir = dir.path().join(".nono/runtime");
        fs::create_dir_all(&runtime_dir).unwrap();
        let mut env_map = BTreeMap::new();
        let mut plan = SandboxPlan {
            root: dir.path().to_path_buf(),
            read_write_files: Vec::new(),
            read_write_dirs: Vec::new(),
            read_only_files: Vec::new(),
            read_only_dirs: Vec::new(),
            protected_write_files: Vec::new(),
            notes: Vec::new(),
        };

        let setup = prepare_deploy_ssh(
            dir.path(),
            &empty_analysis(),
            &runtime_dir,
            &mut env_map,
            &mut plan,
        )
        .unwrap()
        .expect("expected deploy ssh setup");

        assert!(setup.configured_hosts.contains(&"github.com".to_string()));
        assert!(
            plan.read_write_files
                .contains(&runtime_dir.join("known_hosts"))
        );
    }

    #[test]
    fn prepare_deploy_ssh_adds_identity_agent_for_allowed_hosts() {
        let _guard = path_env_lock().lock().unwrap();
        let dir = tempdir().unwrap();
        let git = super::preferred_command_path("git").unwrap_or_else(|| PathBuf::from("git"));
        Command::new(&git)
            .arg("init")
            .arg("-q")
            .arg(dir.path())
            .status()
            .unwrap();
        Command::new(&git)
            .arg("-C")
            .arg(dir.path())
            .args([
                "remote",
                "add",
                "origin",
                "git@github.com:example/project.git",
            ])
            .status()
            .unwrap();
        let runtime_dir = dir.path().join(".nono/runtime");
        fs::create_dir_all(&runtime_dir).unwrap();
        let socket = dir.path().join("agent.sock");
        fs::write(&socket, "placeholder").unwrap();
        let previous = env::var_os("SSH_AUTH_SOCK");
        unsafe { env::set_var("SSH_AUTH_SOCK", &socket) };

        let mut analysis = empty_analysis();
        analysis.deploy_ssh_agent_hosts = vec!["github.com".to_string()];
        let mut env_map = BTreeMap::new();
        let mut plan = SandboxPlan {
            root: dir.path().to_path_buf(),
            read_write_files: Vec::new(),
            read_write_dirs: Vec::new(),
            read_only_files: Vec::new(),
            read_only_dirs: Vec::new(),
            protected_write_files: Vec::new(),
            notes: Vec::new(),
        };

        prepare_deploy_ssh(dir.path(), &analysis, &runtime_dir, &mut env_map, &mut plan)
            .unwrap()
            .expect("expected deploy ssh setup");
        restore_ssh_auth_sock(previous);

        assert!(plan.read_write_files.contains(&socket));
        let ssh_config = fs::read_to_string(runtime_dir.join("ssh_config")).unwrap();
        assert!(ssh_config.contains(&format!(
            "IdentityAgent {}",
            ssh_config_value(&socket.display().to_string())
        )));
    }

    #[test]
    fn effective_ssh_agent_hosts_respects_explicit_allowlist() {
        let mut analysis = empty_analysis();
        analysis.deploy_ssh_agent_hosts = vec!["github.com".to_string(), "missing".to_string()];
        let effective = effective_ssh_agent_hosts(
            &["github.com".to_string(), "stuffix-one".to_string()],
            &analysis,
        );
        assert_eq!(effective, vec!["github.com".to_string()]);
    }

    #[test]
    fn effective_ssh_agent_hosts_can_enable_all_deploy_hosts() {
        let mut analysis = empty_analysis();
        analysis.deploy_use_ssh_agent = true;
        let effective = effective_ssh_agent_hosts(
            &["github.com".to_string(), "stuffix-one".to_string()],
            &analysis,
        );
        assert_eq!(
            effective,
            vec!["github.com".to_string(), "stuffix-one".to_string()]
        );
    }

    #[test]
    fn parse_ssh_scan_target_preserves_explicit_ports() {
        assert_eq!(
            parse_ssh_scan_target("github.com"),
            Some(super::SshScanTarget {
                host: "github.com".to_string(),
                port: None,
            })
        );
        assert_eq!(
            parse_ssh_scan_target("deploy.example.com:2201"),
            Some(super::SshScanTarget {
                host: "deploy.example.com".to_string(),
                port: Some(2201),
            })
        );
    }

    fn path_env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn restore_path(previous: Option<std::ffi::OsString>) {
        match previous {
            Some(value) => unsafe {
                env::set_var("PATH", value);
            },
            None => unsafe {
                env::remove_var("PATH");
            },
        }
    }

    fn restore_ssh_auth_sock(previous: Option<std::ffi::OsString>) {
        match previous {
            Some(value) => unsafe {
                env::set_var("SSH_AUTH_SOCK", value);
            },
            None => unsafe {
                env::remove_var("SSH_AUTH_SOCK");
            },
        }
    }
}
