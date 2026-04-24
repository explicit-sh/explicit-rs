use std::collections::BTreeMap;
use std::fs;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use nono::{AccessMode, CapabilitySet, Sandbox};
use serde::Deserialize;
use serde_json::Value as JsonValue;

use crate::analysis::SandboxPlan;

const SECRET_ENV_FORWARDING_JSON: &str = "EXPLICIT_SECRET_ENV_FORWARDING_JSON";

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
    let mut env_map = env_map;
    merge_secret_forwarded_env(&mut env_map)?;
    let plan: SandboxPlan =
        serde_json::from_str(&fs::read_to_string(&plan_file).context("failed to read plan file")?)
            .context("failed to parse plan file")?;

    let shell = choose_shell(&env_map, &command);
    if std::env::var("EXPLICIT_NO_SANDBOX").as_deref() != Ok("1") {
        let capabilities = build_capabilities(&plan)?;
        apply_sandbox(&capabilities)?;
    }

    std::env::set_current_dir(&root)
        .with_context(|| format!("failed to enter {}", root.display()))?;
    let error = Command::new(&shell.shell)
        .env_clear()
        .envs(&env_map)
        .args(&shell.args)
        .exec();
    bail!("failed to exec sandbox shell: {error}")
}

fn merge_secret_forwarded_env(env_map: &mut BTreeMap<String, String>) -> Result<()> {
    let Ok(payload) = std::env::var(SECRET_ENV_FORWARDING_JSON) else {
        return Ok(());
    };
    let parsed = serde_json::from_str::<JsonValue>(&payload)
        .context("failed to parse secret env payload")?;
    let object = parsed
        .as_object()
        .context("secret env payload is not a JSON object")?;
    for (key, value) in object {
        let Some(value) = value.as_str() else {
            continue;
        };
        env_map.insert(key.clone(), value.to_string());
    }
    Ok(())
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
    use super::{
        choose_shell, escape_seatbelt_path, merge_secret_forwarded_env, preferred_shell_path,
    };
    use std::collections::BTreeMap;
    use std::path::Path;
    use std::sync::Mutex;

    // Serialize env-var tests to prevent races on process-wide env state.
    static SECRET_ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn prefers_known_system_shell_over_env_shell() {
        let mut env_map = BTreeMap::new();
        env_map.insert("SHELL".to_string(), "/opt/homebrew/bin/fish".to_string());

        let shell = preferred_shell_path(&env_map);
        assert!(shell == "/bin/bash" || shell == "/bin/zsh");
    }

    #[test]
    fn preferred_shell_fallback_from_env_map() {
        // Simulate no /bin/bash or /bin/zsh present (they do exist in tests, so this
        // just verifies the function returns *something* on current platform).
        let mut env_map = BTreeMap::new();
        env_map.insert("SHELL".to_string(), "/custom/shell".to_string());
        let shell = preferred_shell_path(&env_map);
        // On macOS both /bin/bash and /bin/zsh exist, so one of them is returned.
        assert!(!shell.is_empty());
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
    fn interactive_mode_uses_interactive_flag() {
        let shell = choose_shell(&BTreeMap::new(), &None);
        assert!(
            shell.args.contains(&"-i".to_string()),
            "interactive mode should use -i: {:?}",
            shell.args
        );
    }

    #[test]
    fn choose_shell_zsh_command_mode() {
        let env_map = BTreeMap::new();
        let shell_path = preferred_shell_path(&env_map);
        let shell = choose_shell(&env_map, &Some("echo hi".to_string()));
        if shell_path.ends_with("zsh") {
            assert_eq!(shell.args[0], "-f");
            assert_eq!(shell.args[1], "-c");
        } else {
            assert_eq!(shell.args[0], "--noprofile");
        }
    }

    #[test]
    fn escape_seatbelt_path_rejects_unsafe_characters() {
        assert!(escape_seatbelt_path(Path::new("/tmp/ok.toml")).is_ok());
        assert!(escape_seatbelt_path(Path::new("/tmp/bad\"quote")).is_err());
    }

    #[test]
    fn build_capabilities_with_empty_plan_succeeds() {
        use crate::analysis::SandboxPlan;
        use std::path::PathBuf;
        let plan = SandboxPlan {
            root: PathBuf::from("/tmp"),
            read_write_files: Vec::new(),
            read_write_dirs: Vec::new(),
            read_only_files: Vec::new(),
            read_only_dirs: Vec::new(),
            protected_write_files: Vec::new(),
            notes: Vec::new(),
        };
        // Just check it doesn't panic or error for an empty plan.
        let result = super::build_capabilities(&plan);
        assert!(result.is_ok());
    }

    #[test]
    fn build_capabilities_with_existing_read_only_dir() {
        use crate::analysis::SandboxPlan;
        use tempfile::tempdir;
        let dir = tempdir().unwrap();
        let plan = SandboxPlan {
            root: dir.path().to_path_buf(),
            read_write_files: Vec::new(),
            read_write_dirs: Vec::new(),
            read_only_files: Vec::new(),
            read_only_dirs: vec![dir.path().to_path_buf()],
            protected_write_files: Vec::new(),
            notes: Vec::new(),
        };
        let result = super::build_capabilities(&plan);
        assert!(result.is_ok());
    }

    #[test]
    fn merge_secret_forwarded_env_does_nothing_when_var_absent() {
        let _guard = SECRET_ENV_LOCK.lock().unwrap();
        // Safety: test-only env manipulation, serialized by SECRET_ENV_LOCK.
        unsafe { std::env::remove_var("EXPLICIT_SECRET_ENV_FORWARDING_JSON") };
        let mut env = BTreeMap::new();
        merge_secret_forwarded_env(&mut env).unwrap();
        assert!(env.is_empty());
    }

    #[test]
    fn merge_secret_forwarded_env_merges_json_object() {
        let _guard = SECRET_ENV_LOCK.lock().unwrap();
        // Safety: test-only env manipulation, serialized by SECRET_ENV_LOCK.
        unsafe {
            std::env::set_var(
                "EXPLICIT_SECRET_ENV_FORWARDING_JSON",
                r#"{"MY_SECRET":"abc","ANOTHER":"def"}"#,
            )
        };
        let mut env = BTreeMap::new();
        merge_secret_forwarded_env(&mut env).unwrap();
        unsafe { std::env::remove_var("EXPLICIT_SECRET_ENV_FORWARDING_JSON") };
        assert_eq!(env.get("MY_SECRET").map(String::as_str), Some("abc"));
        assert_eq!(env.get("ANOTHER").map(String::as_str), Some("def"));
    }

    #[test]
    fn merge_secret_forwarded_env_skips_non_string_values() {
        let _guard = SECRET_ENV_LOCK.lock().unwrap();
        // Safety: test-only env manipulation, serialized by SECRET_ENV_LOCK.
        unsafe {
            std::env::set_var(
                "EXPLICIT_SECRET_ENV_FORWARDING_JSON",
                r#"{"NUM":42,"STR":"ok"}"#,
            )
        };
        let mut env = BTreeMap::new();
        merge_secret_forwarded_env(&mut env).unwrap();
        unsafe { std::env::remove_var("EXPLICIT_SECRET_ENV_FORWARDING_JSON") };
        // 42 is not a string — skipped
        assert!(!env.contains_key("NUM"));
        assert_eq!(env.get("STR").map(String::as_str), Some("ok"));
    }
}
