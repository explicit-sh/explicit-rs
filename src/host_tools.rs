use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

pub fn host_command_paths(command: &str) -> Vec<PathBuf> {
    let Some(path_env) = std::env::var_os("PATH") else {
        return Vec::new();
    };

    for entry in std::env::split_paths(&path_env) {
        let candidate = entry.join(command);
        if candidate.is_file() {
            return expand_command_path(&candidate);
        }
    }

    Vec::new()
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
    use super::parse_wrapper_delegate_paths;
    use std::path::PathBuf;

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
}
