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

    let shell = choose_shell(&env_map, &command);
    let capabilities = build_capabilities(&plan)?;
    apply_sandbox(&capabilities)?;

    std::env::set_current_dir(&root)
        .with_context(|| format!("failed to enter {}", root.display()))?;
    let error = Command::new(&shell.shell)
        .env_clear()
        .envs(&env_map)
        .args(&shell.args)
        .exec();
    bail!("failed to exec sandbox shell: {error}")
}

fn choose_shell(env_map: &BTreeMap<String, String>, command: &Option<String>) -> ShellSpec {
    let shell_path = preferred_shell_path(env_map);
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

fn preferred_shell_path(env_map: &BTreeMap<String, String>) -> String {
    for candidate in ["/bin/bash", "/bin/zsh"] {
        if Path::new(candidate).is_file() {
            return candidate.to_string();
        }
    }

    env_map
        .get("SHELL")
        .cloned()
        .or_else(|| std::env::var("SHELL").ok())
        .unwrap_or_else(|| "/bin/bash".to_string())
}

fn build_capabilities(plan: &SandboxPlan) -> Result<CapabilitySet> {
    let mut caps = CapabilitySet::new();
    for path in &plan.read_write_files {
        if path.exists() {
            caps = caps.allow_file(path, AccessMode::ReadWrite)?;
        }
    }
    for path in &plan.read_write_dirs {
        if path.exists() {
            caps = caps.allow_path(path, AccessMode::ReadWrite)?;
        }
    }
    for path in &plan.read_only_files {
        if path.exists() {
            caps = caps.allow_file(path, AccessMode::Read)?;
        }
    }
    for path in &plan.read_only_dirs {
        if path.exists() {
            caps = caps.allow_path(path, AccessMode::Read)?;
        }
    }
    add_protected_write_file_rules(&mut caps, &plan.protected_write_files)?;
    if std::env::var("DEVENV_NONO_BLOCK_NETWORK").as_deref() == Ok("1") {
        caps = caps.block_network();
    }
    Ok(caps)
}

fn add_protected_write_file_rules(caps: &mut CapabilitySet, paths: &[PathBuf]) -> Result<()> {
    #[cfg(target_os = "macos")]
    for path in paths {
        let escaped = escape_seatbelt_path(path)?;
        caps.add_platform_rule(format!("(deny file-write* (literal \"{escaped}\"))"))?;
    }

    #[cfg(not(target_os = "macos"))]
    let _ = (caps, paths);

    Ok(())
}

fn escape_seatbelt_path(path: &Path) -> Result<String> {
    let raw = path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("path is not valid UTF-8: {}", path.display()))?;
    if raw.contains('"') || raw.contains('\n') || raw.contains('\r') {
        bail!(
            "path cannot be protected by macOS sandbox deny rule: {}",
            path.display()
        );
    }
    Ok(raw.replace('\\', "\\\\"))
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

#[cfg(test)]
mod tests {
    use super::{choose_shell, escape_seatbelt_path, preferred_shell_path};
    use std::collections::BTreeMap;
    use std::path::Path;

    #[test]
    fn prefers_known_system_shell_over_env_shell() {
        let mut env_map = BTreeMap::new();
        env_map.insert("SHELL".to_string(), "/opt/homebrew/bin/fish".to_string());

        let shell = preferred_shell_path(&env_map);
        assert!(shell == "/bin/bash" || shell == "/bin/zsh");
    }

    #[test]
    fn command_mode_uses_non_interactive_bash_flags() {
        let shell = choose_shell(&BTreeMap::new(), &Some("codex".to_string()));
        assert_eq!(shell.args[0], "--noprofile");
        assert_eq!(shell.args[1], "--norc");
        assert_eq!(shell.args[2], "-c");
        assert_eq!(shell.args[3], "codex");
    }

    #[test]
    fn escape_seatbelt_path_rejects_unsafe_characters() {
        assert!(escape_seatbelt_path(Path::new("/tmp/ok.toml")).is_ok());
        assert!(escape_seatbelt_path(Path::new("/tmp/bad\"quote")).is_err());
    }
}
