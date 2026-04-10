use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::Serialize;
use serde_json::{Value as JsonValue, json};
use toml::{Table as TomlTable, Value as TomlValue};

use crate::analysis::Analysis;

const STOP_GUARD_PATH: &str = "./.nono/stop-guard.sh";

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
    write_stop_guard_script(root)?;
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
    fs::write(
        root.join(".nono/guard-commands.json"),
        serde_json::to_string_pretty(&payload)?,
    )
    .context("failed to write .nono/guard-commands.json")?;
    Ok(())
}

fn write_stop_guard_script(root: &Path) -> Result<()> {
    let path = root.join(".nono/stop-guard.sh");
    let script = r#"#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_PATH="$ROOT_DIR/.nono/guard-commands.json"

if [[ ! -f "$CONFIG_PATH" ]]; then
  exit 0
fi

mapfile -t COMMANDS < <(
  jq -r '.commands[]? | "\(.kind)\t\(.command)"' "$CONFIG_PATH"
)

if [[ "${#COMMANDS[@]}" -eq 0 ]]; then
  exit 0
fi

failures=()
run_cmd() {
  local label="$1"
  local command="$2"
  if command -v devenv >/dev/null 2>&1 && [[ -f "$ROOT_DIR/devenv.nix" ]]; then
    if ! (cd "$ROOT_DIR" && devenv shell --no-tui --no-reload -- bash -lc "$command"); then
      failures+=("$label: $command")
    fi
  else
    if ! (cd "$ROOT_DIR" && bash -lc "$command"); then
      failures+=("$label: $command")
    fi
  fi
}

for entry in "${COMMANDS[@]}"; do
  kind="${entry%%$'\t'*}"
  command="${entry#*$'\t'}"
  run_cmd "$kind" "$command"
done

if [[ "${#failures[@]}" -gt 0 ]]; then
  {
    echo "Stop blocked because the project checks are failing:"
    printf ' - %s\n' "${failures[@]}"
    echo
    echo "Fix the failing lint/build/test command or update .nono/guard-commands.json before stopping."
  } >&2
  exit 2
fi
"#;
    fs::write(&path, script).with_context(|| format!("failed to write {}", path.display()))?;
    let mut permissions = fs::metadata(&path)
        .with_context(|| format!("failed to read {}", path.display()))?
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&path, permissions)
        .with_context(|| format!("failed to chmod {}", path.display()))?;
    Ok(())
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
    fs::write(&path, serde_json::to_string_pretty(&payload)?)
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
    fs::write(&path, serde_json::to_string_pretty(&payload)?)
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
    fs::write(&path, toml::to_string_pretty(&payload)?)
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
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
}
