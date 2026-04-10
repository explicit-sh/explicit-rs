use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

pub fn host_command_paths(command: &str) -> Vec<PathBuf> {
    find_command_candidate(std::env::var_os("PATH").as_deref(), command)
        .map(|candidate| expand_command_path(&candidate))
        .unwrap_or_default()
}

pub fn preferred_command_path(command: &str) -> Option<PathBuf> {
    resolve_command_path(std::env::var_os("PATH").as_deref(), command)
}

fn expand_command_path(path: &Path) -> Vec<PathBuf> {
    let mut paths = BTreeSet::new();
    insert_path(&mut paths, path.to_path_buf());

    let canonical = fs::canonicalize(path).ok();
    if let Some(real_path) = &canonical {
        insert_path(&mut paths, real_path.clone());
    }

    for wrapper_target in wrapper_delegate_paths(path).into_iter().chain(
        canonical
            .iter()
            .flat_map(|real_path| wrapper_delegate_paths(real_path)),
    ) {
        insert_path(&mut paths, wrapper_target.clone());
        if let Ok(real_path) = fs::canonicalize(&wrapper_target) {
            insert_path(&mut paths, real_path);
        }
    }

    paths.into_iter().collect()
}

fn insert_path(paths: &mut BTreeSet<PathBuf>, path: PathBuf) {
    paths.insert(path);
}

fn find_command_candidate(path_env: Option<&OsStr>, command: &str) -> Option<PathBuf> {
    let path_env = path_env?;
    for entry in std::env::split_paths(path_env) {
        let candidate = entry.join(command);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn resolve_command_path(path_env: Option<&OsStr>, command: &str) -> Option<PathBuf> {
    let candidate = find_command_candidate(path_env, command)?;
    Some(resolve_exec_path(&candidate))
}

fn resolve_exec_path(path: &Path) -> PathBuf {
    let canonical = fs::canonicalize(path).ok();

    for wrapper_target in wrapper_delegate_paths(path).into_iter().chain(
        canonical
            .iter()
            .flat_map(|real_path| wrapper_delegate_paths(real_path)),
    ) {
        if wrapper_target.is_file() {
            return fs::canonicalize(&wrapper_target).unwrap_or(wrapper_target);
        }
    }

    canonical.unwrap_or_else(|| path.to_path_buf())
}

fn wrapper_delegate_paths(path: &Path) -> Vec<PathBuf> {
    let Ok(contents) = fs::read_to_string(path) else {
        return Vec::new();
    };
    parse_wrapper_delegate_paths(&contents)
}

fn parse_wrapper_delegate_paths(contents: &str) -> Vec<PathBuf> {
    let mut paths = BTreeSet::new();

    for line in contents.lines() {
        let trimmed = line.trim();
        let Some(rest) = trimmed.strip_prefix("for real_bin in ") else {
            continue;
        };
        let values = rest.split("; do").next().unwrap_or(rest);
        for token in values.split_whitespace() {
            let candidate = token.trim_matches(|ch| ch == '"' || ch == '\'');
            if candidate.starts_with('/') {
                paths.insert(PathBuf::from(candidate));
            }
        }
    }

    paths.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::{find_command_candidate, parse_wrapper_delegate_paths, resolve_command_path};
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use tempfile::tempdir;

    #[test]
    fn parses_wrapper_delegate_paths() {
        let contents = r#"#!/bin/bash
for real_bin in /opt/homebrew/bin/codex /usr/local/bin/codex; do
  if [ -x "$real_bin" ]; then
    exec "$real_bin" "$@"
  fi
done
"#;

        let paths = parse_wrapper_delegate_paths(contents);
        assert_eq!(
            paths,
            vec![
                PathBuf::from("/opt/homebrew/bin/codex"),
                PathBuf::from("/usr/local/bin/codex")
            ]
        );
    }

    #[test]
    fn finds_first_command_candidate_from_path_env() {
        let dir = tempdir().unwrap();
        let bin_dir = dir.path().join("bin");
        fs::create_dir_all(&bin_dir).unwrap();
        let command = bin_dir.join("demo");
        fs::write(&command, "#!/bin/sh\n").unwrap();

        let mut permissions = fs::metadata(&command).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&command, permissions).unwrap();

        let candidate = find_command_candidate(Some(bin_dir.as_os_str()), "demo");
        assert_eq!(candidate, Some(command));
    }

    #[test]
    fn preferred_command_path_uses_wrapper_delegate() {
        let dir = tempdir().unwrap();
        let wrapper_dir = dir.path().join("wrapper");
        let real_dir = dir.path().join("real");
        fs::create_dir_all(&wrapper_dir).unwrap();
        fs::create_dir_all(&real_dir).unwrap();

        let real = real_dir.join("codex");
        fs::write(&real, "#!/bin/sh\nexit 0\n").unwrap();
        let mut real_permissions = fs::metadata(&real).unwrap().permissions();
        real_permissions.set_mode(0o755);
        fs::set_permissions(&real, real_permissions).unwrap();

        let wrapper = wrapper_dir.join("codex");
        fs::write(
            &wrapper,
            format!(
                "#!/bin/sh\nfor real_bin in {}; do\n  if [ -x \"$real_bin\" ]; then\n    exec \"$real_bin\" \"$@\"\n  fi\ndone\n",
                real.display()
            ),
        )
        .unwrap();
        let mut wrapper_permissions = fs::metadata(&wrapper).unwrap().permissions();
        wrapper_permissions.set_mode(0o755);
        fs::set_permissions(&wrapper, wrapper_permissions).unwrap();

        let path_env = std::env::join_paths([wrapper_dir]).unwrap();
        let resolved = resolve_command_path(Some(path_env.as_os_str()), "codex");

        assert_eq!(resolved, Some(fs::canonicalize(real).unwrap()));
    }
}
