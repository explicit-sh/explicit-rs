use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::observe;

const EXPLICIT_CONFIG_FILE: &str = "explicit.toml";
const DEFAULT_SESSION_ENV_KEY: &str = "EXPLICIT_PARALLEL_SESSION";
const DEFAULT_SLOT_ENV_KEY: &str = "EXPLICIT_PARALLEL_SLOT";
const DEFAULT_ISSUE_ENV_KEY: &str = "EXPLICIT_AGENT_ISSUE";

#[derive(Debug, Clone, Default)]
pub struct RoutedLaunch {
    pub root: PathBuf,
    pub extra_env: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Deserialize)]
struct ExplicitConfigFile {
    #[serde(default)]
    parallel: Option<ParallelConfig>,
}

#[derive(Debug, Clone, Deserialize)]
struct ParallelConfig {
    #[serde(default)]
    enabled: bool,
    worktree_root: Option<String>,
    base_branch: Option<String>,
    branch_prefix: Option<String>,
    session_env_key: Option<String>,
    slot_env_key: Option<String>,
    issue_env_key: Option<String>,
    #[serde(default)]
    env: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ParallelSessionMetadata {
    slot: u32,
    session: String,
    branch: String,
}

pub fn route_agent_launch(root: &Path, agent: &str) -> Result<RoutedLaunch> {
    let config = load_parallel_config(root)?;
    if !config.enabled {
        return Ok(RoutedLaunch {
            root: root.to_path_buf(),
            extra_env: BTreeMap::new(),
        });
    }

    let current_session = current_session_metadata(root)?;
    let requested_session = requested_session_name(&config)?;
    let route_reason = if requested_session
        .as_ref()
        .zip(current_session.as_ref())
        .is_some_and(|(requested, current)| requested != &current.session)
    {
        Some("requested session differs from current worktree session")
    } else if requested_session.is_some() {
        Some("requested session targets a dedicated worktree")
    } else if observe::live_socket_active(root)? {
        Some("live socket already active in this folder")
    } else {
        None
    };
    if route_reason.is_none() {
        return Ok(RoutedLaunch {
            root: root.to_path_buf(),
            extra_env: BTreeMap::new(),
        });
    }

    let worktree_root = resolve_worktree_root(root, &config)?;
    fs::create_dir_all(&worktree_root)
        .with_context(|| format!("failed to create {}", worktree_root.display()))?;

    let session_name = requested_session
        .unwrap_or_else(|| format!("slot-{:02}", next_parallel_slot(&worktree_root)));
    let target_root = worktree_root.join(&session_name);
    let metadata_path = target_root.join(".nono/parallel-session.json");
    let existing_metadata = if metadata_path.is_file() {
        Some(read_session_metadata(&metadata_path)?)
    } else {
        None
    };

    let slot = if let Some(metadata) = &existing_metadata {
        metadata.slot
    } else {
        requested_slot(&config)?.unwrap_or_else(|| next_parallel_slot(&worktree_root))
    };
    let branch_prefix = config
        .branch_prefix
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(agent);
    let branch = existing_metadata
        .as_ref()
        .map(|metadata| metadata.branch.clone())
        .unwrap_or_else(|| {
            format!(
                "{}/{}",
                sanitize_branch_component(branch_prefix),
                session_name
            )
        });

    ensure_worktree_exists(root, &target_root, &branch, config.base_branch.as_deref())?;
    fs::create_dir_all(target_root.join(".nono"))
        .with_context(|| format!("failed to create {}", target_root.join(".nono").display()))?;
    write_session_metadata(
        &metadata_path,
        &ParallelSessionMetadata {
            slot,
            session: session_name.clone(),
            branch: branch.clone(),
        },
    )?;

    let mut extra_env =
        render_parallel_env(&config.env, slot, &session_name, &branch, &target_root);
    extra_env.insert("EXPLICIT_PARALLEL_SLOT".to_string(), slot.to_string());
    extra_env.insert(
        "EXPLICIT_PARALLEL_SESSION".to_string(),
        session_name.clone(),
    );
    extra_env.insert("EXPLICIT_PARALLEL_BRANCH".to_string(), branch.clone());
    extra_env.insert(
        "EXPLICIT_PARALLEL_ROOT".to_string(),
        target_root.display().to_string(),
    );

    eprintln!(
        "parallel agent routed to {} on branch {} (slot {}): {}",
        target_root.display(),
        branch,
        slot,
        route_reason.unwrap_or("parallel routing enabled")
    );

    Ok(RoutedLaunch {
        root: target_root,
        extra_env,
    })
}

fn load_parallel_config(root: &Path) -> Result<ParallelConfig> {
    let path = root.join(EXPLICIT_CONFIG_FILE);
    if !path.is_file() {
        return Ok(ParallelConfig {
            enabled: true,
            worktree_root: None,
            base_branch: None,
            branch_prefix: None,
            session_env_key: None,
            slot_env_key: None,
            issue_env_key: None,
            env: BTreeMap::new(),
        });
    }
    let raw =
        fs::read_to_string(&path).with_context(|| format!("failed to read {}", path.display()))?;
    let config = toml::from_str::<ExplicitConfigFile>(&raw)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    Ok(config.parallel.unwrap_or(ParallelConfig {
        enabled: true,
        worktree_root: None,
        base_branch: None,
        branch_prefix: None,
        session_env_key: None,
        slot_env_key: None,
        issue_env_key: None,
        env: BTreeMap::new(),
    }))
}

fn resolve_worktree_root(root: &Path, config: &ParallelConfig) -> Result<PathBuf> {
    let config_base = git_common_root(root)?.unwrap_or_else(|| root.to_path_buf());
    if let Some(value) = &config.worktree_root {
        return expand_path(&config_base, value);
    }
    let repo_name = config_base
        .file_name()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty())
        .unwrap_or("project");
    Ok(config_base
        .parent()
        .unwrap_or(&config_base)
        .join(".explicit-worktrees")
        .join(repo_name))
}

fn expand_path(root: &Path, raw: &str) -> Result<PathBuf> {
    let path = if raw.starts_with("~/") {
        dirs::home_dir()
            .context("failed to resolve home directory")?
            .join(raw.trim_start_matches("~/"))
    } else if raw == "~" {
        dirs::home_dir().context("failed to resolve home directory")?
    } else {
        let path = PathBuf::from(raw);
        if path.is_absolute() {
            path
        } else {
            root.join(path)
        }
    };
    Ok(path)
}

pub(crate) fn git_common_root(root: &Path) -> Result<Option<PathBuf>> {
    let output = Command::new("git")
        .current_dir(root)
        .args(["rev-parse", "--git-common-dir"])
        .output();
    let Ok(output) = output else {
        return Ok(None);
    };
    if !output.status.success() {
        return Ok(None);
    }
    let raw = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if raw.is_empty() {
        return Ok(None);
    }
    let path = PathBuf::from(raw);
    let absolute = if path.is_absolute() {
        path
    } else {
        root.join(path)
    };
    Ok(absolute.parent().map(Path::to_path_buf))
}

fn requested_session_name(config: &ParallelConfig) -> Result<Option<String>> {
    let session_key = config
        .session_env_key
        .as_deref()
        .unwrap_or(DEFAULT_SESSION_ENV_KEY);
    let issue_key = config
        .issue_env_key
        .as_deref()
        .unwrap_or(DEFAULT_ISSUE_ENV_KEY);

    if let Some(value) = std::env::var_os(session_key)
        .and_then(|value| value.into_string().ok())
        .map(|value| sanitize_session_name(&value))
        .filter(|value| !value.is_empty())
    {
        return Ok(Some(value));
    }

    if let Some(value) = std::env::var_os(issue_key)
        .and_then(|value| value.into_string().ok())
        .map(|value| sanitize_session_name(&value))
        .filter(|value| !value.is_empty())
    {
        return Ok(Some(value));
    }

    Ok(None)
}

fn current_session_metadata(root: &Path) -> Result<Option<ParallelSessionMetadata>> {
    let path = root.join(".nono/parallel-session.json");
    if !path.is_file() {
        return Ok(None);
    }
    Ok(Some(read_session_metadata(&path)?))
}

fn requested_slot(config: &ParallelConfig) -> Result<Option<u32>> {
    let slot_key = config
        .slot_env_key
        .as_deref()
        .unwrap_or(DEFAULT_SLOT_ENV_KEY);
    let Some(raw) = std::env::var_os(slot_key).and_then(|value| value.into_string().ok()) else {
        return Ok(None);
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let slot = trimmed
        .parse::<u32>()
        .with_context(|| format!("{slot_key} must be a positive integer"))?;
    if slot == 0 {
        bail!("{slot_key} must be a positive integer");
    }
    Ok(Some(slot))
}

fn next_parallel_slot(worktree_root: &Path) -> u32 {
    let mut used = BTreeSet::from([1u32]);
    let Ok(entries) = fs::read_dir(worktree_root) else {
        return 2;
    };

    for entry in entries.flatten() {
        let path = entry.path().join(".nono/parallel-session.json");
        if !path.is_file() {
            continue;
        }
        if let Ok(metadata) = read_session_metadata(&path) {
            used.insert(metadata.slot);
        }
    }

    let mut candidate = 2u32;
    while used.contains(&candidate) {
        candidate += 1;
    }
    candidate
}

pub(crate) fn ensure_worktree_exists(
    root: &Path,
    target_root: &Path,
    branch: &str,
    base_branch: Option<&str>,
) -> Result<()> {
    if target_root.join(".git").exists() {
        return Ok(());
    }
    if target_root.exists() && target_root.read_dir()?.next().is_some() {
        bail!(
            "parallel worktree target already exists and is not a git worktree: {}",
            target_root.display()
        );
    }

    if let Some(parent) = target_root.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }

    let branch_exists = git_ref_exists(root, &format!("refs/heads/{branch}"))?;
    let base = base_branch
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("HEAD");
    let mut command = Command::new("git");
    command.current_dir(root).arg("worktree").arg("add");
    if branch_exists {
        command.arg(target_root).arg(branch);
    } else {
        command.arg("-b").arg(branch).arg(target_root).arg(base);
    }
    let output = command
        .output()
        .context("failed to run `git worktree add`")?;
    if !output.status.success() {
        bail!(
            "git worktree add failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

fn git_ref_exists(root: &Path, reference: &str) -> Result<bool> {
    let output = Command::new("git")
        .current_dir(root)
        .args(["show-ref", "--verify", "--quiet", reference])
        .output()
        .context("failed to inspect git refs")?;
    Ok(output.status.success())
}

fn write_session_metadata(path: &Path, metadata: &ParallelSessionMetadata) -> Result<()> {
    fs::write(path, serde_json::to_string_pretty(metadata)?)
        .with_context(|| format!("failed to write {}", path.display()))
}

fn read_session_metadata(path: &Path) -> Result<ParallelSessionMetadata> {
    let raw =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_str(&raw).with_context(|| format!("failed to parse {}", path.display()))
}

fn render_parallel_env(
    templates: &BTreeMap<String, String>,
    slot: u32,
    session: &str,
    branch: &str,
    target_root: &Path,
) -> BTreeMap<String, String> {
    let mut env = BTreeMap::new();
    for (key, value) in templates {
        let rendered = value
            .replace("{slot}", &slot.to_string())
            .replace("{session}", session)
            .replace("{branch}", branch)
            .replace("{worktree}", &target_root.display().to_string());
        env.insert(key.clone(), rendered);
    }
    env
}

fn sanitize_session_name(raw: &str) -> String {
    let mut result = String::new();
    let mut previous_dash = false;
    for ch in raw.chars() {
        let normalized = if ch.is_ascii_alphanumeric() {
            previous_dash = false;
            ch.to_ascii_lowercase()
        } else {
            if previous_dash {
                continue;
            }
            previous_dash = true;
            '-'
        };
        result.push(normalized);
    }
    result
        .trim_matches('-')
        .chars()
        .take(63)
        .collect::<String>()
}

fn sanitize_branch_component(raw: &str) -> String {
    let mut path = PathBuf::new();
    for component in Path::new(raw).components() {
        if let Component::Normal(value) = component {
            let cleaned = sanitize_session_name(&value.to_string_lossy());
            if !cleaned.is_empty() {
                path.push(cleaned);
            }
        }
    }
    let rendered = path.display().to_string();
    if rendered.is_empty() {
        "agent".to_string()
    } else {
        rendered
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ParallelConfig, ParallelSessionMetadata, next_parallel_slot, render_parallel_env,
        sanitize_branch_component, sanitize_session_name, write_session_metadata,
    };
    use std::collections::BTreeMap;
    use std::fs;
    use std::path::PathBuf;
    use tempfile::tempdir;

    #[test]
    fn sanitize_session_name_normalizes_issue_labels() {
        assert_eq!(
            sanitize_session_name("Issue #123 / Fix login"),
            "issue-123-fix-login"
        );
    }

    #[test]
    fn sanitize_branch_component_keeps_path_segments() {
        assert_eq!(
            sanitize_branch_component("agents/Issue #123"),
            "agents/issue-123"
        );
    }

    #[test]
    fn render_parallel_env_substitutes_placeholders() {
        let templates = BTreeMap::from([
            (
                "DATABASE_URL".to_string(),
                "ecto://localhost/stuffix_dev_{slot}".to_string(),
            ),
            ("MIX_TEST_PARTITION".to_string(), "{slot}".to_string()),
            ("EXPLICIT_SESSION".to_string(), "{session}".to_string()),
        ]);

        let rendered = render_parallel_env(
            &templates,
            2,
            "issue-123",
            "codex/issue-123",
            &PathBuf::from("/tmp/worktree"),
        );

        assert_eq!(
            rendered.get("DATABASE_URL").map(String::as_str),
            Some("ecto://localhost/stuffix_dev_2")
        );
        assert_eq!(
            rendered.get("MIX_TEST_PARTITION").map(String::as_str),
            Some("2")
        );
        assert_eq!(
            rendered.get("EXPLICIT_SESSION").map(String::as_str),
            Some("issue-123")
        );
    }

    #[test]
    fn next_parallel_slot_skips_existing_metadata() {
        let dir = tempdir().unwrap();
        let slot_two = dir.path().join("slot-02/.nono/parallel-session.json");
        fs::create_dir_all(slot_two.parent().unwrap()).unwrap();
        write_session_metadata(
            &slot_two,
            &ParallelSessionMetadata {
                slot: 2,
                session: "slot-02".to_string(),
                branch: "codex/slot-02".to_string(),
            },
        )
        .unwrap();

        assert_eq!(next_parallel_slot(dir.path()), 3);
    }

    #[test]
    fn parallel_config_defaults_to_disabled() {
        let config = ParallelConfig {
            enabled: false,
            worktree_root: None,
            base_branch: None,
            branch_prefix: None,
            session_env_key: None,
            slot_env_key: None,
            issue_env_key: None,
            env: BTreeMap::new(),
        };
        assert!(!config.enabled);
    }
}
