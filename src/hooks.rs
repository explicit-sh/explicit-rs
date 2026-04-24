use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::fs::symlink;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Value as JsonValue, json};
use toml::{Table as TomlTable, Value as TomlValue};

use crate::analysis::Analysis;

const EXPLICIT_BIN_PATH: &str = "./.nono/explicit-bin";
const GIT_PRE_PUSH_SCRIPT_PATH: &str = "./.nono/pre-push-verify.sh";
const MANAGED_PRE_PUSH_MARKER: &str = "# explicit-managed-pre-push";

#[derive(Debug, Serialize)]
struct GuardCommand<'a> {
    kind: &'a str,
    command: &'a str,
}

#[derive(Debug, Serialize)]
struct GuardConfig<'a> {
    commands: Vec<GuardCommand<'a>>,
    notes: &'a [String],
}

pub fn write_stop_hook_assets(root: &Path, analysis: &Analysis) -> Result<()> {
    fs::create_dir_all(root.join(".nono")).context("failed to create .nono")?;
    write_guard_commands(root, analysis)?;
    write_explicit_bin_path(root)?;
    write_git_verify_script(root)?;
    install_git_pre_push_hook(root)?;
    write_claude_settings(root)?;
    write_codex_hooks(root)?;
    write_codex_config(root)?;
    Ok(())
}

fn write_guard_commands(root: &Path, analysis: &Analysis) -> Result<()> {
    let mut commands = Vec::new();
    for command in &analysis.lint_commands {
        commands.push(GuardCommand {
            kind: "lint",
            command,
        });
    }
    for command in &analysis.build_commands {
        commands.push(GuardCommand {
            kind: "build",
            command,
        });
    }
    for command in &analysis.test_commands {
        commands.push(GuardCommand {
            kind: "test",
            command,
        });
    }
    for command in &analysis.coverage_commands {
        commands.push(GuardCommand {
            kind: "coverage",
            command,
        });
    }

    let payload = GuardConfig {
        commands,
        notes: &analysis.notes,
    };
    write_if_changed(
        &root.join(".nono/guard-commands.json"),
        serde_json::to_string_pretty(&payload)?,
    )
    .context("failed to write .nono/guard-commands.json")?;
    Ok(())
}

fn write_explicit_bin_path(root: &Path) -> Result<()> {
    let current_exe = std::env::current_exe().context("failed to resolve current executable")?;
    let path = root.join(EXPLICIT_BIN_PATH.trim_start_matches("./"));
    if let Ok(existing) = fs::read_link(&path)
        && existing == current_exe
    {
        return Ok(());
    }
    if let Ok(metadata) = fs::symlink_metadata(&path) {
        if metadata.is_dir() && !metadata.file_type().is_symlink() {
            fs::remove_dir_all(&path)
                .with_context(|| format!("failed to remove {}", path.display()))?;
        } else {
            fs::remove_file(&path)
                .with_context(|| format!("failed to remove {}", path.display()))?;
        }
    }
    symlink(&current_exe, &path).with_context(|| {
        format!(
            "failed to symlink {} -> {}",
            path.display(),
            current_exe.display()
        )
    })?;
    Ok(())
}

fn write_git_verify_script(root: &Path) -> Result<()> {
    let path = root.join(GIT_PRE_PUSH_SCRIPT_PATH.trim_start_matches("./"));
    let script = r#"#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EXPLICIT_BIN_FILE="$ROOT_DIR/.nono/explicit-bin"

resolve_explicit() {
  if [[ -n "${EXPLICIT_BIN:-}" && -x "${EXPLICIT_BIN}" ]]; then
    printf '%s\n' "${EXPLICIT_BIN}"
    return 0
  fi
  if [[ -x "$EXPLICIT_BIN_FILE" ]]; then
    printf '%s\n' "$EXPLICIT_BIN_FILE"
    return 0
  fi
  if [[ -f "$EXPLICIT_BIN_FILE" ]]; then
    local candidate
    candidate="$(<"$EXPLICIT_BIN_FILE")"
    if [[ -n "$candidate" && -x "$candidate" ]]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  fi
  if command -v explicit >/dev/null 2>&1; then
    command -v explicit
    return 0
  fi
  return 1
}

if ! EXPLICIT_BIN="$(resolve_explicit)"; then
  echo "Push blocked because explicit could not be found for verification. Run 'explicit apply' again." >&2
  exit 2
fi

cd "$ROOT_DIR"
exec "$EXPLICIT_BIN" verify --root "$ROOT_DIR" --git-hook
"#;
    write_executable_script(&path, script)?;
    Ok(())
}

fn install_git_pre_push_hook(root: &Path) -> Result<()> {
    let Some(hooks_dir) = resolve_git_hooks_dir(root)? else {
        return Ok(());
    };
    fs::create_dir_all(&hooks_dir)
        .with_context(|| format!("failed to create {}", hooks_dir.display()))?;
    let hook_path = hooks_dir.join("pre-push");
    let backup_path = hooks_dir.join("pre-push.explicit-user");

    if hook_path.exists() && !is_managed_pre_push_hook(&hook_path)? {
        fs::copy(&hook_path, &backup_path).with_context(|| {
            format!(
                "failed to preserve existing git pre-push hook at {}",
                hook_path.display()
            )
        })?;
    }

    let script = format!(
        r#"#!/usr/bin/env bash
{marker}
set -euo pipefail

ROOT_DIR={root}
USER_HOOK={user_hook}

if [[ -x "$USER_HOOK" ]]; then
  "$USER_HOOK" "$@"
fi

exec "$ROOT_DIR/.nono/pre-push-verify.sh" "$@"
"#,
        marker = MANAGED_PRE_PUSH_MARKER,
        root = shell_quote(root),
        user_hook = shell_quote(&backup_path),
    );
    write_executable_script(&hook_path, &script)?;
    Ok(())
}

fn resolve_git_hooks_dir(root: &Path) -> Result<Option<std::path::PathBuf>> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["rev-parse", "--git-path", "hooks"])
        .output()
        .context("failed to inspect git hooks path")?;
    if !output.status.success() {
        return Ok(None);
    }
    let raw = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if raw.is_empty() {
        return Ok(None);
    }
    let path = std::path::PathBuf::from(raw);
    if path.is_absolute() {
        Ok(Some(path))
    } else {
        Ok(Some(root.join(path)))
    }
}

fn is_managed_pre_push_hook(path: &Path) -> Result<bool> {
    let content =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    Ok(content.contains(MANAGED_PRE_PUSH_MARKER))
}

fn write_executable_script(path: &Path, script: &str) -> Result<()> {
    write_if_changed(path, script)
        .with_context(|| format!("failed to write {}", path.display()))?;
    let mut permissions = fs::metadata(path)
        .with_context(|| format!("failed to read {}", path.display()))?
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions)
        .with_context(|| format!("failed to chmod {}", path.display()))?;
    Ok(())
}

fn shell_quote(path: &Path) -> String {
    format!("'{}'", path.display().to_string().replace('\'', r#"'"'"'"#))
}

fn write_claude_settings(root: &Path) -> Result<()> {
    let dir = root.join(".claude");
    ensure_config_dir(&dir)?;
    let path = dir.join("settings.local.json");
    let mut payload = read_json_object_or_empty(&path)?;
    let hooks = payload
        .as_object_mut()
        .context("claude settings root is not a JSON object")?
        .entry("hooks")
        .or_insert_with(|| json!({}));
    let hooks = hooks
        .as_object_mut()
        .context("claude hooks entry is not a JSON object")?;
    hooks.insert("Stop".to_string(), managed_claude_stop_hook(root));
    upsert_claude_pre_tool_use_bash_hook(hooks, root);
    write_if_changed(&path, serde_json::to_string_pretty(&payload)?)
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

fn write_codex_hooks(root: &Path) -> Result<()> {
    let dir = root.join(".codex");
    ensure_config_dir(&dir)?;
    let path = dir.join("hooks.json");
    let mut payload = read_json_object_or_empty(&path)?;
    let root_object = payload
        .as_object_mut()
        .context("codex hooks root is not a JSON object")?;
    let legacy_keys = root_object
        .keys()
        .filter(|key| key.as_str() != "hooks")
        .cloned()
        .collect::<Vec<_>>();
    let mut legacy_entries = Vec::new();
    for key in legacy_keys {
        if let Some(value) = root_object.remove(&key) {
            legacy_entries.push((key, value));
        }
    }
    let hooks = root_object.entry("hooks").or_insert_with(|| json!({}));
    let hooks = hooks
        .as_object_mut()
        .context("codex hooks entry is not a JSON object")?;
    for (key, value) in legacy_entries {
        hooks.entry(key).or_insert(value);
    }
    hooks.insert(
        "Stop".to_string(),
        json!([{
            "hooks": [{
                "type": "command",
                "command": hook_verify_command(root, true),
                "timeout": 900
            }]
        }]),
    );
    write_if_changed(&path, serde_json::to_string_pretty(&payload)?)
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

fn write_codex_config(root: &Path) -> Result<()> {
    let dir = root.join(".codex");
    ensure_config_dir(&dir)?;
    let path = dir.join("config.toml");
    let mut payload = read_toml_table_or_empty(&path)?;
    let features = payload
        .entry("features")
        .or_insert_with(|| TomlValue::Table(Default::default()));
    let features = features
        .as_table_mut()
        .context("codex config features entry is not a TOML table")?;
    features.insert("codex_hooks".to_string(), TomlValue::Boolean(true));
    write_if_changed(&path, toml::to_string_pretty(&payload)?)
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

fn write_if_changed(path: &Path, content: impl AsRef<[u8]>) -> Result<()> {
    let content = content.as_ref();
    if fs::read(path).ok().as_deref() == Some(content) {
        return Ok(());
    }
    fs::write(path, content).with_context(|| format!("failed to write {}", path.display()))
}

fn ensure_config_dir(path: &Path) -> Result<()> {
    if let Ok(target) = fs::read_link(path) {
        let resolved = if target.is_absolute() {
            target
        } else {
            path.parent().unwrap_or_else(|| Path::new("/")).join(target)
        };
        if resolved == path {
            fs::remove_file(path)
                .with_context(|| format!("failed to remove {}", path.display()))?;
        }
    }
    if let Ok(metadata) = fs::symlink_metadata(path)
        && (!metadata.is_dir() || metadata.file_type().is_symlink())
    {
        if metadata.is_dir() && !metadata.file_type().is_symlink() {
            fs::remove_dir_all(path)
                .with_context(|| format!("failed to remove {}", path.display()))?;
        } else {
            fs::remove_file(path)
                .with_context(|| format!("failed to remove {}", path.display()))?;
        }
    }
    fs::create_dir_all(path).with_context(|| format!("failed to create {}", path.display()))
}

fn hook_verify_command(root: &Path, stop_hook: bool) -> String {
    let mode_flag = if stop_hook {
        "--stop-hook"
    } else {
        "--git-hook"
    };
    format!(
        "{} verify --root {} {mode_flag}",
        shell_quote(&root.join(EXPLICIT_BIN_PATH.trim_start_matches("./"))),
        shell_quote(root)
    )
}

fn hook_claude_pre_tool_use_command(root: &Path) -> String {
    format!(
        "{} __claude-pre-tool-use-bash",
        shell_quote(&root.join(EXPLICIT_BIN_PATH.trim_start_matches("./")))
    )
}

fn managed_claude_stop_hook(root: &Path) -> JsonValue {
    json!([{
        "hooks": [{
            "type": "command",
            "command": hook_verify_command(root, true)
        }]
    }])
}

fn managed_claude_pre_tool_use_bash_hook(root: &Path) -> JsonValue {
    json!([{
        "matcher": "Bash",
        "hooks": [{
            "type": "command",
            "command": hook_claude_pre_tool_use_command(root)
        }]
    }])
}

fn upsert_claude_pre_tool_use_bash_hook(
    hooks: &mut serde_json::Map<String, JsonValue>,
    root: &Path,
) {
    let managed_command = hook_claude_pre_tool_use_command(root);
    let existing = hooks
        .get("PreToolUse")
        .and_then(JsonValue::as_array)
        .cloned()
        .unwrap_or_default();

    let mut preserved = existing
        .into_iter()
        .filter(|entry| {
            let Some(command_hooks) = entry.get("hooks").and_then(JsonValue::as_array) else {
                return true;
            };
            !command_hooks.iter().any(|hook| {
                let command = hook.get("command").and_then(JsonValue::as_str);
                command == Some("explicit __claude-pre-tool-use-bash")
                    || command == Some(managed_command.as_str())
            })
        })
        .collect::<Vec<_>>();

    preserved.extend(
        managed_claude_pre_tool_use_bash_hook(root)
            .as_array()
            .into_iter()
            .flatten()
            .cloned(),
    );
    hooks.insert("PreToolUse".to_string(), JsonValue::Array(preserved));
}

#[derive(Debug, Deserialize)]
struct ClaudePreToolUsePayload {
    #[serde(default)]
    tool_name: String,
    #[serde(default)]
    tool_input: JsonValue,
}

#[derive(Debug, PartialEq, Eq)]
enum ClaudeBashGuardAction {
    Deny {
        reason: String,
    },
    Rewrite {
        command: String,
        reason: String,
        additional_context: String,
    },
}

pub fn run_claude_pre_tool_use_bash() -> Result<()> {
    let mut stdin_payload = String::new();
    if io::stdin().read_to_string(&mut stdin_payload).is_err() {
        return Ok(());
    }
    let env_map = std::env::vars().collect::<BTreeMap<_, _>>();
    if let Some(output) = build_claude_pre_tool_use_bash_output(&stdin_payload, &env_map) {
        serde_json::to_writer(io::stdout(), &output)?;
        io::stdout().write_all(b"\n")?;
    }
    Ok(())
}

fn build_claude_pre_tool_use_bash_output(
    stdin_payload: &str,
    env_map: &BTreeMap<String, String>,
) -> Option<JsonValue> {
    let payload = serde_json::from_str::<ClaudePreToolUsePayload>(stdin_payload).ok()?;
    if payload.tool_name != "Bash" {
        return None;
    }
    let command = payload.tool_input.get("command")?.as_str()?;
    let action = evaluate_claude_bash_command_guard(command, env_map)?;
    match action {
        ClaudeBashGuardAction::Deny { reason } => Some(json!({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason
            }
        })),
        ClaudeBashGuardAction::Rewrite {
            command,
            reason,
            additional_context,
        } => {
            let mut updated_input = payload.tool_input;
            let object = updated_input.as_object_mut()?;
            object.insert("command".to_string(), JsonValue::String(command));
            Some(json!({
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "allow",
                    "permissionDecisionReason": reason,
                    "updatedInput": updated_input,
                    "additionalContext": additional_context
                }
            }))
        }
    }
}

fn evaluate_claude_bash_command_guard(
    command: &str,
    env_map: &BTreeMap<String, String>,
) -> Option<ClaudeBashGuardAction> {
    let host_home = env_map
        .get("EXPLICIT_HOST_HOME")
        .filter(|value| !value.is_empty())
        .map(|value| value.trim_end_matches('/').to_string())?;
    let project_known_hosts = env_map
        .get("EXPLICIT_DEPLOY_KNOWN_HOSTS_FILE")
        .filter(|value| !value.is_empty())
        .cloned();

    if command_overrides_host_home_for_ssh(command, &host_home) {
        return Some(ClaudeBashGuardAction::Deny {
            reason: format!(
                "Do not override HOME to the host home inside explicit for SSH or Git commands. Keep the sandbox HOME and use the project-scoped SSH files instead{}.",
                project_known_hosts
                    .as_deref()
                    .map(|path| format!(" ({path})"))
                    .unwrap_or_default()
            ),
        });
    }

    let host_known_hosts = format!("{host_home}/.ssh/known_hosts");
    if !command.contains(&host_known_hosts) {
        return None;
    }

    if let Some(project_known_hosts) = project_known_hosts {
        let rewritten = command.replace(&host_known_hosts, &project_known_hosts);
        if rewritten != command {
            return Some(ClaudeBashGuardAction::Rewrite {
                command: rewritten,
                reason: "Rewrote the Bash command to use explicit's project-scoped SSH known_hosts file.".to_string(),
                additional_context: "explicit rewrote a host ~/.ssh/known_hosts path to the project-scoped SSH known_hosts file prepared for this sandbox. Keep using the default SSH configuration or EXPLICIT_DEPLOY_KNOWN_HOSTS_FILE instead of the host home path.".to_string(),
            });
        }
    }

    Some(ClaudeBashGuardAction::Deny {
        reason: "The host ~/.ssh/known_hosts file cannot be used inside explicit. Use the sandbox's default SSH configuration, ~/.ssh/known_hosts from the sandbox home overlay, or configure [deploy].hosts so explicit can prepare a project-scoped known_hosts file.".to_string(),
    })
}

fn command_overrides_host_home_for_ssh(command: &str, host_home: &str) -> bool {
    if !command_looks_ssh_related(command) {
        return false;
    }
    let quoted_single = format!("HOME='{host_home}'");
    let quoted_double = format!("HOME=\"{host_home}\"");
    let bare = format!("HOME={host_home}");
    let export_bare = format!("export HOME={host_home}");
    let export_single = format!("export HOME='{host_home}'");
    let export_double = format!("export HOME=\"{host_home}\"");
    [
        bare,
        quoted_single,
        quoted_double,
        export_bare,
        export_single,
        export_double,
    ]
    .iter()
    .any(|pattern| command.contains(pattern))
}

fn command_looks_ssh_related(command: &str) -> bool {
    let lowered = command.to_ascii_lowercase();
    [
        "git push",
        "git pull",
        "git fetch",
        "git clone",
        "git ls-remote",
        "git remote",
        "git submodule",
        "git@",
        "ssh ",
        "scp ",
        "sftp ",
        "rsync ",
        "knownhostsfile",
        "git_ssh_command",
    ]
    .iter()
    .any(|needle| lowered.contains(needle))
}

fn read_json_object_or_empty(path: &Path) -> Result<JsonValue> {
    if !path.exists() {
        return Ok(json!({}));
    }
    let payload: JsonValue = serde_json::from_str(
        &fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?,
    )
    .with_context(|| format!("failed to parse {}", path.display()))?;
    if payload.is_object() {
        Ok(payload)
    } else {
        bail!("{} must contain a top-level JSON object", path.display());
    }
}

fn read_toml_table_or_empty(path: &Path) -> Result<TomlTable> {
    if !path.exists() {
        return Ok(Default::default());
    }
    let payload =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    toml::from_str::<TomlTable>(&payload)
        .with_context(|| format!("failed to parse {}", path.display()))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::process::Command;

    use serde_json::Value as JsonValue;
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn preserves_existing_claude_settings() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::create_dir_all(root.join(".claude")).unwrap();
        fs::write(
            root.join(".claude/settings.local.json"),
            r#"{"enabledMcpjsonServers":["context7"]}"#,
        )
        .unwrap();

        write_claude_settings(root).unwrap();

        let payload: JsonValue = serde_json::from_str(
            &fs::read_to_string(root.join(".claude/settings.local.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(payload["enabledMcpjsonServers"][0], "context7");
        assert_eq!(
            payload["hooks"]["Stop"][0]["hooks"][0]["command"]
                .as_str()
                .unwrap(),
            hook_verify_command(root, true)
        );
        assert_eq!(
            payload["hooks"]["PreToolUse"][0]["matcher"]
                .as_str()
                .unwrap(),
            "Bash"
        );
        assert_eq!(
            payload["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
                .as_str()
                .unwrap(),
            hook_claude_pre_tool_use_command(root)
        );
    }

    #[test]
    fn preserves_existing_claude_pre_tool_use_entries() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::create_dir_all(root.join(".claude")).unwrap();
        fs::write(
            root.join(".claude/settings.local.json"),
            r#"{"hooks":{"PreToolUse":[{"matcher":"Read","hooks":[{"type":"command","command":"keep-me"}]}]}}"#,
        )
        .unwrap();

        write_claude_settings(root).unwrap();
        write_claude_settings(root).unwrap();

        let payload: JsonValue = serde_json::from_str(
            &fs::read_to_string(root.join(".claude/settings.local.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(
            payload["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
                .as_str()
                .unwrap(),
            "keep-me"
        );
        let managed_entries = payload["hooks"]["PreToolUse"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|entry| {
                entry["hooks"][0]["command"].as_str()
                    == Some(hook_claude_pre_tool_use_command(root).as_str())
            })
            .count();
        assert_eq!(managed_entries, 1);
    }

    #[test]
    fn enables_codex_hooks_feature() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::create_dir_all(root.join(".codex")).unwrap();
        fs::write(root.join(".codex/config.toml"), "[features]\nfoo = true\n").unwrap();

        write_codex_config(root).unwrap();

        let payload = fs::read_to_string(root.join(".codex/config.toml")).unwrap();
        assert!(payload.contains("foo = true"));
        assert!(payload.contains("codex_hooks = true"));
    }

    #[test]
    fn preserves_existing_codex_hook_keys() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::create_dir_all(root.join(".codex")).unwrap();
        fs::write(
            root.join(".codex/hooks.json"),
            r#"{"PreToolUse":[{"hooks":[]}]}"#,
        )
        .unwrap();

        write_codex_hooks(root).unwrap();

        let payload: JsonValue =
            serde_json::from_str(&fs::read_to_string(root.join(".codex/hooks.json")).unwrap())
                .unwrap();
        assert!(payload["hooks"].get("PreToolUse").is_some());
        assert_eq!(
            payload["hooks"]["Stop"][0]["hooks"][0]["command"]
                .as_str()
                .unwrap(),
            hook_verify_command(root, true)
        );
    }

    #[test]
    fn repairs_self_linked_agent_config_dirs() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        symlink(root.join(".claude"), root.join(".claude")).unwrap();
        symlink(root.join(".codex"), root.join(".codex")).unwrap();

        write_claude_settings(root).unwrap();
        write_codex_hooks(root).unwrap();
        write_codex_config(root).unwrap();

        assert!(root.join(".claude").is_dir());
        assert!(root.join(".codex").is_dir());
        assert!(root.join(".claude/settings.local.json").is_file());
        assert!(root.join(".codex/hooks.json").is_file());
        assert!(root.join(".codex/config.toml").is_file());
    }

    #[test]
    fn hook_verify_command_points_at_explicit_verify() {
        let root = Path::new("/tmp/project");
        let stop = hook_verify_command(root, true);
        let git = hook_verify_command(root, false);
        assert!(stop.contains("/tmp/project/.nono/explicit-bin"));
        assert!(stop.ends_with(" verify --root '/tmp/project' --stop-hook"));
        assert!(git.contains("/tmp/project/.nono/explicit-bin"));
        assert!(git.ends_with(" verify --root '/tmp/project' --git-hook"));
    }

    #[test]
    fn writes_explicit_bin_symlink() {
        let dir = tempdir().unwrap();
        fs::create_dir_all(dir.path().join(".nono")).unwrap();
        write_explicit_bin_path(dir.path()).unwrap();
        let written = fs::read_link(dir.path().join(".nono/explicit-bin")).unwrap();
        assert_eq!(written, std::env::current_exe().unwrap());
    }

    #[test]
    fn git_verify_script_invokes_explicit_verify() {
        let dir = tempdir().unwrap();
        fs::create_dir_all(dir.path().join(".nono")).unwrap();
        write_git_verify_script(dir.path()).unwrap();
        let script = fs::read_to_string(dir.path().join(".nono/pre-push-verify.sh")).unwrap();
        assert!(script.contains("verify --root \"$ROOT_DIR\" --git-hook"));
        assert!(script.contains(".nono/explicit-bin"));
    }

    #[test]
    fn installs_managed_pre_push_hook_and_preserves_existing_one() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        Command::new("git")
            .arg("init")
            .arg("-q")
            .arg(root)
            .status()
            .unwrap();
        let hooks_dir = resolve_git_hooks_dir(root).unwrap().unwrap();
        fs::create_dir_all(&hooks_dir).unwrap();
        fs::write(
            hooks_dir.join("pre-push"),
            "#!/usr/bin/env bash\necho user-hook\n",
        )
        .unwrap();

        install_git_pre_push_hook(root).unwrap();

        let managed = fs::read_to_string(hooks_dir.join("pre-push")).unwrap();
        assert!(managed.contains(MANAGED_PRE_PUSH_MARKER));
        assert!(managed.contains(".nono/pre-push-verify.sh"));

        let preserved = fs::read_to_string(hooks_dir.join("pre-push.explicit-user")).unwrap();
        assert!(preserved.contains("user-hook"));
    }

    #[test]
    fn rewrites_host_known_hosts_references_for_claude_bash() {
        let env_map = BTreeMap::from([
            ("EXPLICIT_HOST_HOME".to_string(), "/Users/demo".to_string()),
            (
                "EXPLICIT_DEPLOY_KNOWN_HOSTS_FILE".to_string(),
                "/repo/.nono/runtime/known_hosts".to_string(),
            ),
        ]);
        let payload = r#"{"tool_name":"Bash","tool_input":{"command":"GIT_SSH_COMMAND=\"ssh -o UserKnownHostsFile=/Users/demo/.ssh/known_hosts -o StrictHostKeyChecking=yes\" git push origin HEAD","description":"push"}} "#;

        let output = build_claude_pre_tool_use_bash_output(payload, &env_map).unwrap();

        assert_eq!(
            output["hookSpecificOutput"]["permissionDecision"]
                .as_str()
                .unwrap(),
            "allow"
        );
        let updated = output["hookSpecificOutput"]["updatedInput"]["command"]
            .as_str()
            .unwrap();
        assert!(updated.contains("/repo/.nono/runtime/known_hosts"));
        assert!(!updated.contains("/Users/demo/.ssh/known_hosts"));
    }

    #[test]
    fn denies_host_home_override_for_ssh_commands() {
        let env_map = BTreeMap::from([
            ("EXPLICIT_HOST_HOME".to_string(), "/Users/demo".to_string()),
            (
                "EXPLICIT_DEPLOY_KNOWN_HOSTS_FILE".to_string(),
                "/repo/.nono/runtime/known_hosts".to_string(),
            ),
        ]);
        let payload = r#"{"tool_name":"Bash","tool_input":{"command":"HOME=/Users/demo git push origin HEAD"}} "#;

        let output = build_claude_pre_tool_use_bash_output(payload, &env_map).unwrap();

        assert_eq!(
            output["hookSpecificOutput"]["permissionDecision"]
                .as_str()
                .unwrap(),
            "deny"
        );
        assert!(
            output["hookSpecificOutput"]["permissionDecisionReason"]
                .as_str()
                .unwrap()
                .contains("Do not override HOME")
        );
    }

    #[test]
    fn ignores_safe_sandbox_known_hosts_references() {
        let env_map =
            BTreeMap::from([("EXPLICIT_HOST_HOME".to_string(), "/Users/demo".to_string())]);
        let payload = r#"{"tool_name":"Bash","tool_input":{"command":"GIT_SSH_COMMAND=\"ssh -o UserKnownHostsFile=$HOME/.ssh/known_hosts\" git push origin HEAD"}} "#;

        assert!(build_claude_pre_tool_use_bash_output(payload, &env_map).is_none());
    }
}
