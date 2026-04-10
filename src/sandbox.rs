use std::collections::BTreeMap;
use std::fs;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use nono::{AccessMode, CapabilitySet, Sandbox};
use serde::Deserialize;

use crate::analysis::SandboxPlan;

#[derive(Debug, Deserialize)]
struct ShellSpec {
    shell: String,
    args: Vec<String>,
}

pub fn run_sandbox_exec(
    root: PathBuf,
    env_file: PathBuf,
    plan_file: PathBuf,
    command: Option<String>,
) -> Result<()> {
    let env_map: BTreeMap<String, String> =
        serde_json::from_str(&fs::read_to_string(&env_file).context("failed to read env file")?)
            .context("failed to parse env file")?;
    let plan: SandboxPlan =
        serde_json::from_str(&fs::read_to_string(&plan_file).context("failed to read plan file")?)
            .context("failed to parse plan file")?;

    let capabilities = build_capabilities(&plan)?;
    apply_sandbox(&capabilities)?;

    std::env::set_current_dir(&root)
        .with_context(|| format!("failed to enter {}", root.display()))?;
    let shell = choose_shell(&env_map, &command);
    let error = Command::new(&shell.shell)
        .env_clear()
        .envs(&env_map)
        .args(&shell.args)
        .exec();
    bail!("failed to exec sandbox shell: {error}")
}

fn choose_shell(env_map: &BTreeMap<String, String>, command: &Option<String>) -> ShellSpec {
    let shell_path = env_map
        .get("SHELL")
        .cloned()
        .or_else(|| std::env::var("SHELL").ok())
        .unwrap_or_else(|| "/bin/bash".to_string());
    let file_name = Path::new(&shell_path)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("bash");

    match (file_name, command) {
        ("zsh", Some(command)) => ShellSpec {
            shell: shell_path,
            args: vec!["-f".to_string(), "-c".to_string(), command.clone()],
        },
        ("zsh", None) => ShellSpec {
            shell: shell_path,
            args: vec!["-f".to_string(), "-i".to_string()],
        },
        (_, Some(command)) => ShellSpec {
            shell: shell_path,
            args: vec![
                "--noprofile".to_string(),
                "--norc".to_string(),
                "-c".to_string(),
                command.clone(),
            ],
        },
        _ => ShellSpec {
            shell: shell_path,
            args: vec![
                "--noprofile".to_string(),
                "--norc".to_string(),
                "-i".to_string(),
            ],
        },
    }
}

fn build_capabilities(plan: &SandboxPlan) -> Result<CapabilitySet> {
    let mut caps = CapabilitySet::new();
    for path in &plan.read_write_dirs {
        if path.exists() {
            caps = caps.allow_path(path, AccessMode::ReadWrite)?;
        }
    }
    for path in &plan.read_only_dirs {
        if path.exists() {
            caps = caps.allow_path(path, AccessMode::Read)?;
        }
    }
    if std::env::var("DEVENV_NONO_BLOCK_NETWORK").as_deref() == Ok("1") {
        caps = caps.block_network();
    }
    Ok(caps)
}

fn apply_sandbox(caps: &CapabilitySet) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        let _ = Sandbox::apply(caps)?;
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        Sandbox::apply(caps)?;
        Ok(())
    }
}
