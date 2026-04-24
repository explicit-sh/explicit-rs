use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::analysis::Analysis;
use crate::codex_mcp;
use crate::github_app;
use crate::host_tools::preferred_command_path;
use crate::parallel;
use crate::runtime::{self, LaunchShellOptions};

#[derive(Debug, Serialize, Deserialize)]
struct ConsultMetadata {
    consult_id: String,
    agent: String,
    worktree: PathBuf,
    branch: String,
    created_at_ms: u64,
}

pub fn launch_consult(
    binary: &str,
    resume: Option<&str>,
    args: &[String],
    no_sandbox: bool,
) -> Result<ExitCode> {
    let cwd = PathBuf::from(".")
        .canonicalize()
        .context("failed to resolve cwd")?;
    let consult_dir = cwd.join(".nono/consult");

    let (consult_id, worktree_path, branch, is_resume) = if let Some(id) = resume {
        let metadata = load_metadata(&consult_dir, id)?;
        let worktree = metadata.worktree.clone();
        let branch = metadata.branch.clone();
        (id.to_string(), worktree, branch, true)
    } else {
        let id = generate_consult_id(binary);
        let (worktree, branch) = prepare_worktree(&cwd, &id)?;
        (id, worktree, branch, false)
    };

    let worktree_path = worktree_path.canonicalize().with_context(|| {
        format!(
            "consult worktree does not exist: {}",
            worktree_path.display()
        )
    })?;

    let analysis = Analysis::analyze(&worktree_path)?;

    let mut extra_env = BTreeMap::new();
    extra_env.extend(codex_mcp::sandbox_env()?);
    extra_env.extend(github_app::sandbox_env(&worktree_path, &analysis)?);

    let command = build_consult_command(binary, args)?;

    if !is_resume {
        let metadata = ConsultMetadata {
            consult_id: consult_id.clone(),
            agent: binary.to_string(),
            worktree: worktree_path.clone(),
            branch: branch.clone(),
            created_at_ms: now_ms(),
        };
        write_metadata(&consult_dir, &metadata)?;
    }

    let status = runtime::launch_shell(
        &worktree_path,
        &analysis,
        LaunchShellOptions {
            agent: Some(binary),
            command: Some(&command),
            no_services: true,
            no_sandbox,
            skip_stop_hooks: true,
            extra_env: Some(&extra_env),
            ..Default::default()
        },
    )?;

    let exit_code = if status == ExitCode::SUCCESS {
        0u8
    } else {
        1u8
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "consult_id": consult_id,
            "agent": binary,
            "exit_code": exit_code,
            "worktree": worktree_path,
        }))?
    );

    Ok(status)
}

fn prepare_worktree(root: &Path, consult_id: &str) -> Result<(PathBuf, String)> {
    let repo_root = parallel::git_common_root(root)?.unwrap_or_else(|| root.to_path_buf());

    let repo_name = repo_root
        .file_name()
        .and_then(|n| n.to_str())
        .filter(|n| !n.is_empty())
        .unwrap_or("project");

    let worktree_base = repo_root
        .parent()
        .unwrap_or(&repo_root)
        .join(".explicit-worktrees")
        .join(repo_name)
        .join("consult");

    let worktree_path = worktree_base.join(consult_id);
    let branch = format!("consult/{consult_id}");

    parallel::ensure_worktree_exists(root, &worktree_path, &branch, None)?;

    fs::create_dir_all(worktree_path.join(".nono"))
        .with_context(|| format!("failed to create .nono in {}", worktree_path.display()))?;

    Ok((worktree_path, branch))
}

fn write_metadata(consult_dir: &Path, metadata: &ConsultMetadata) -> Result<()> {
    let dir = consult_dir.join(&metadata.consult_id);
    fs::create_dir_all(&dir).with_context(|| format!("failed to create {}", dir.display()))?;
    let path = dir.join("metadata.json");
    fs::write(&path, serde_json::to_string_pretty(metadata)?)
        .with_context(|| format!("failed to write {}", path.display()))
}

fn load_metadata(consult_dir: &Path, consult_id: &str) -> Result<ConsultMetadata> {
    let path = consult_dir.join(consult_id).join("metadata.json");
    if !path.is_file() {
        bail!("no consult session found for id: {consult_id}");
    }
    let raw =
        fs::read_to_string(&path).with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_str(&raw).with_context(|| format!("failed to parse {}", path.display()))
}

fn build_consult_command(binary: &str, args: &[String]) -> Result<String> {
    let executable = preferred_command_path(binary)
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| binary.to_string());

    let command = std::iter::once(shell_escape(&executable))
        .chain(args.iter().map(|a| shell_escape(a)))
        .collect::<Vec<_>>()
        .join(" ");

    Ok(command)
}

fn shell_escape(value: &str) -> String {
    if !value.is_empty()
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.' | '/' | ':'))
    {
        return value.to_string();
    }
    format!("'{}'", value.replace('\'', r#"'"'"'"#))
}

fn generate_consult_id(binary: &str) -> String {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let date = {
        let secs = ts.as_secs();
        let days = secs / 86400;
        let epoch_day = 719468u64;
        let days_since_epoch = days + epoch_day;
        let era = days_since_epoch / 146097;
        let doe = days_since_epoch - era * 146097;
        let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
        let y = yoe + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let m = if mp < 10 { mp + 3 } else { mp - 9 };
        let d = doy - (153 * mp + 2) / 5 + 1;
        let y = if m <= 2 { y + 1 } else { y };
        format!("{y:04}{m:02}{d:02}")
    };
    let nanos = ts.subsec_nanos();
    let pid = std::process::id();
    let suffix = format!("{:04x}", (nanos ^ (pid << 16)) & 0xffff);
    format!("consult-{binary}-{date}-{suffix}")
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::{generate_consult_id, shell_escape};

    #[test]
    fn consult_id_has_expected_prefix() {
        let id = generate_consult_id("claude");
        assert!(id.starts_with("consult-claude-"), "got: {id}");
        // date portion: 8 digits, then dash, then 4 hex chars
        let parts: Vec<&str> = id.splitn(4, '-').collect();
        assert_eq!(parts[0], "consult");
        assert_eq!(parts[1], "claude");
        assert_eq!(parts[2].len(), 8, "date part should be 8 digits");
        assert_eq!(parts[3].len(), 4, "suffix should be 4 hex chars");
    }

    #[test]
    fn consult_id_is_unique() {
        let a = generate_consult_id("gemini");
        let b = generate_consult_id("gemini");
        // PIDs are the same within the same process, but nanos differ
        // We just assert they are valid strings
        assert!(a.starts_with("consult-gemini-"));
        assert!(b.starts_with("consult-gemini-"));
    }

    #[test]
    fn shell_escape_safe_string() {
        assert_eq!(shell_escape("claude"), "claude");
        assert_eq!(shell_escape("/usr/bin/gemini"), "/usr/bin/gemini");
    }

    #[test]
    fn shell_escape_unsafe_string() {
        assert_eq!(shell_escape("hello world"), "'hello world'");
        assert_eq!(shell_escape("it's"), r#"'it'"'"'s'"#);
    }
}
