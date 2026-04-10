use std::collections::BTreeMap;
use std::path::Path;

use anyhow::Result;

#[cfg(any(target_os = "linux", test))]
use std::path::PathBuf;

#[cfg(any(target_os = "linux", test))]
use anyhow::{Context, bail};

#[cfg(any(target_os = "linux", test))]
const TRACE_LOG_ENV: &str = "EXPLICIT_ENV_TRACE_LOG";

#[cfg(any(target_os = "linux", test))]
pub fn trace_log_env_key() -> &'static str {
    TRACE_LOG_ENV
}

pub fn build_injection_env(log_path: &Path) -> Result<BTreeMap<String, String>> {
    #[cfg(not(target_os = "linux"))]
    let _ = log_path;

    let env = BTreeMap::new();

    #[cfg(target_os = "linux")]
    {
        let mut env = env;
        let library = trace_library_path()?;
        env.insert(
            trace_log_env_key().to_string(),
            log_path.display().to_string(),
        );
        env.insert(
            "LD_PRELOAD".to_string(),
            merge_preload_value("LD_PRELOAD", &library, " "),
        );
    }

    Ok(env)
}

#[cfg(any(target_os = "linux", test))]
pub fn trace_library_path() -> Result<PathBuf> {
    let current_exe = std::env::current_exe().context("failed to resolve current executable")?;
    trace_library_path_from_exe(&current_exe)
}

#[cfg(any(target_os = "linux", test))]
fn trace_library_path_from_exe(current_exe: &Path) -> Result<PathBuf> {
    let file_name = trace_library_filename();
    let mut candidates = Vec::new();
    let mut seen = std::collections::BTreeSet::new();

    let mut push_candidate = |path: PathBuf| {
        if seen.insert(path.clone()) {
            candidates.push(path);
        }
    };

    if let Some(parent) = current_exe.parent() {
        push_candidate(parent.join(file_name));
        push_candidate(parent.join("deps").join(file_name));

        if let Some(grandparent) = parent.parent() {
            push_candidate(grandparent.join(file_name));
            push_candidate(grandparent.join("lib").join(file_name));
            push_candidate(grandparent.join("deps").join(file_name));
        }
    }

    for candidate in candidates {
        if candidate.is_file() {
            return candidate
                .canonicalize()
                .or_else(|_| Ok::<PathBuf, std::io::Error>(candidate))
                .context("failed to canonicalize trace library path");
        }
    }

    bail!(
        "env trace library not found; expected {} near {}",
        file_name,
        current_exe.display()
    )
}

#[cfg(any(target_os = "linux", test))]
fn trace_library_filename() -> &'static str {
    #[cfg(target_os = "macos")]
    {
        "libexplicit_env_trace.dylib"
    }

    #[cfg(target_os = "linux")]
    {
        "libexplicit_env_trace.so"
    }
}

#[cfg(any(target_os = "linux", test))]
fn merge_preload_value(key: &str, library: &Path, separator: &str) -> String {
    let value = library.display().to_string();
    match std::env::var_os(key) {
        Some(existing) if !existing.is_empty() => {
            format!("{value}{separator}{}", existing.to_string_lossy())
        }
        _ => value,
    }
}

#[cfg(test)]
mod tests {
    use super::{merge_preload_value, trace_library_path_from_exe};
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn finds_trace_library_next_to_binary() {
        let dir = tempdir().unwrap();
        let bin_dir = dir.path().join("bin");
        let lib_dir = dir.path().join("lib");
        fs::create_dir_all(&bin_dir).unwrap();
        fs::create_dir_all(&lib_dir).unwrap();

        let exe = bin_dir.join("explicit");
        fs::write(&exe, "").unwrap();
        let library = lib_dir.join(if cfg!(target_os = "macos") {
            "libexplicit_env_trace.dylib"
        } else {
            "libexplicit_env_trace.so"
        });
        fs::write(&library, "").unwrap();

        let path = trace_library_path_from_exe(&exe).unwrap();
        assert_eq!(path, library.canonicalize().unwrap());
    }

    #[test]
    fn returns_trace_library_when_no_preload_is_present() {
        let dir = tempdir().unwrap();
        let library = dir.path().join("libexplicit_env_trace.test");
        let merged = merge_preload_value("EXPLICIT_TEST_PRELOAD", &library, " ");
        assert_eq!(merged, library.display().to_string());
    }

    #[test]
    fn prepends_trace_library_to_existing_preload_value() {
        let dir = tempdir().unwrap();
        let library = dir.path().join("libexplicit_env_trace.test");
        let key = "EXPLICIT_TEST_PRELOAD_MERGE";
        unsafe {
            std::env::set_var(key, "/tmp/existing-preload");
        }
        let merged = merge_preload_value(key, &library, " ");
        unsafe {
            std::env::remove_var(key);
        }
        assert_eq!(
            merged,
            format!("{} /tmp/existing-preload", library.display())
        );
    }
}
