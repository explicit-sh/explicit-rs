use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail};
use serde::Serialize;
use serde_json::{Value as JsonValue, json};
use toml::{Table as TomlTable, Value as TomlValue};

use crate::analysis::Analysis;

const STOP_GUARD_PATH: &str = "./.nono/stop-guard.sh";
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
    write_stop_guard_script(root)?;
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
    write_if_changed(
        &root.join(EXPLICIT_BIN_PATH.trim_start_matches("./")),
        current_exe.display().to_string(),
    )
    .context("failed to write .nono/explicit-bin")?;
    Ok(())
}

fn write_stop_guard_script(root: &Path) -> Result<()> {
    let path = root.join(".nono/stop-guard.sh");
    let script = r#"#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EXPLICIT_BIN_FILE="$ROOT_DIR/.nono/explicit-bin"

resolve_explicit() {
  if [[ -n "${EXPLICIT_BIN:-}" && -x "${EXPLICIT_BIN}" ]]; then
    printf '%s\n' "${EXPLICIT_BIN}"
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
  echo "Stop blocked because explicit could not be found for verification. Run 'explicit apply' again." >&2
  exit 2
fi

cd "$ROOT_DIR"
exec "$EXPLICIT_BIN" verify --root "$ROOT_DIR" --stop-hook
"#;
    write_executable_script(&path, script)?;
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
    fs::create_dir_all(&dir).with_context(|| format!("failed to create {}", dir.display()))?;
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
    hooks.insert(
        "Stop".to_string(),
        json!([{
            "hooks": [{
                "type": "command",
                "command": STOP_GUARD_PATH
            }]
        }]),
    );
    write_if_changed(&path, serde_json::to_string_pretty(&payload)?)
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

fn write_codex_hooks(root: &Path) -> Result<()> {
    let dir = root.join(".codex");
    fs::create_dir_all(&dir).with_context(|| format!("failed to create {}", dir.display()))?;
    let path = dir.join("hooks.json");
    let mut payload = read_json_object_or_empty(&path)?;
    let object = payload
        .as_object_mut()
        .context("codex hooks root is not a JSON object")?;
    object.insert(
        "Stop".to_string(),
        json!([{
            "hooks": [{
                "type": "command",
                "command": STOP_GUARD_PATH,
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
    fs::create_dir_all(&dir).with_context(|| format!("failed to create {}", dir.display()))?;
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
            payload["hooks"]["Stop"][0]["hooks"][0]["command"],
            STOP_GUARD_PATH
        );
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
        assert!(payload.get("PreToolUse").is_some());
        assert_eq!(payload["Stop"][0]["hooks"][0]["command"], STOP_GUARD_PATH);
    }

    #[test]
    fn writes_explicit_bin_path() {
        let dir = tempdir().unwrap();
        fs::create_dir_all(dir.path().join(".nono")).unwrap();
        write_explicit_bin_path(dir.path()).unwrap();
        let written = fs::read_to_string(dir.path().join(".nono/explicit-bin")).unwrap();
        assert_eq!(
            written,
            std::env::current_exe().unwrap().display().to_string()
        );
    }

    #[test]
    fn stop_guard_script_invokes_explicit_verify() {
        let dir = tempdir().unwrap();
        fs::create_dir_all(dir.path().join(".nono")).unwrap();
        write_stop_guard_script(dir.path()).unwrap();
        let script = fs::read_to_string(dir.path().join(".nono/stop-guard.sh")).unwrap();
        assert!(script.contains("verify --root \"$ROOT_DIR\" --stop-hook"));
        assert!(script.contains(".nono/explicit-bin"));
        assert!(!script.contains("jq -r"));
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
}
