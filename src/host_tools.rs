use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

pub fn host_command_paths(command: &str) -> Vec<PathBuf> {
    inspect_command(std::env::var_os("PATH").as_deref(), command)
        .map(|support| support.paths)
        .unwrap_or_default()
}

pub fn host_command_support_dirs(command: &str) -> Vec<PathBuf> {
    inspect_command(std::env::var_os("PATH").as_deref(), command)
        .map(|support| support.support_dirs)
        .unwrap_or_default()
}

pub fn preferred_command_path(command: &str) -> Option<PathBuf> {
    resolve_command_path(std::env::var_os("PATH").as_deref(), command)
}

#[derive(Default)]
struct HostCommandSupport {
    paths: Vec<PathBuf>,
    support_dirs: Vec<PathBuf>,
}

fn inspect_command(path_env: Option<&OsStr>, command: &str) -> Option<HostCommandSupport> {
    let candidate = find_command_candidate(path_env, command)?;
    let paths = expand_command_path(path_env, &candidate);
    let support_dirs = paths
        .iter()
        .filter_map(|path| package_root_dir(path))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    Some(HostCommandSupport {
        paths,
        support_dirs,
    })
}

fn expand_command_path(path_env: Option<&OsStr>, path: &Path) -> Vec<PathBuf> {
    let mut paths = BTreeSet::new();
    let mut queued = BTreeSet::new();
    let mut pending = vec![path.to_path_buf()];
    queued.insert(path.to_path_buf());

    while let Some(current) = pending.pop() {
        if !insert_path(&mut paths, current.clone()) {
            continue;
        }

        if let Ok(real_path) = fs::canonicalize(&current) {
            if queued.insert(real_path.clone()) {
                pending.push(real_path);
            }
        }

        for delegate in wrapper_delegate_paths(&current)
            .into_iter()
            .chain(shebang_delegate_paths(path_env, &current))
        {
            if delegate.exists() && queued.insert(delegate.clone()) {
                pending.push(delegate);
            }
        }
    }

    paths.into_iter().collect()
}

fn insert_path(paths: &mut BTreeSet<PathBuf>, path: PathBuf) -> bool {
    paths.insert(path)
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

fn shebang_delegate_paths(path_env: Option<&OsStr>, path: &Path) -> Vec<PathBuf> {
    let Some(interpreter) = shebang_interpreter_path(path_env, path) else {
        return Vec::new();
    };
    vec![interpreter]
}

fn shebang_interpreter_path(path_env: Option<&OsStr>, path: &Path) -> Option<PathBuf> {
    let mut file = fs::File::open(path).ok()?;
    let mut buf = [0u8; 256];
    let read = file.read(&mut buf).ok()?;
    if read < 2 || &buf[..2] != b"#!" {
        return None;
    }

    let header = std::str::from_utf8(&buf[..read]).ok()?;
    let line = header.lines().next()?.strip_prefix("#!")?.trim();
    if line.is_empty() {
        return None;
    }

    let tokens = line.split_whitespace().collect::<Vec<_>>();
    let interpreter = *tokens.first()?;
    if interpreter.ends_with("/env") {
        return resolve_env_shebang(path_env, &tokens[1..]);
    }

    let interpreter_path = PathBuf::from(interpreter);
    if interpreter_path.is_absolute() {
        return Some(interpreter_path);
    }

    resolve_command_path(path_env, interpreter)
}

fn resolve_env_shebang(path_env: Option<&OsStr>, args: &[&str]) -> Option<PathBuf> {
    let mut index = 0usize;
    while index < args.len() {
        let token = args[index];
        if token == "-S" {
            index += 1;
            continue;
        }
        if token.starts_with('-') {
            index += 1;
            continue;
        }
        return resolve_command_path(path_env, token);
    }
    None
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

fn package_root_dir(path: &Path) -> Option<PathBuf> {
    let components = path.components().collect::<Vec<_>>();
    let node_modules_index = components
        .iter()
        .position(|component| component.as_os_str().to_str() == Some("node_modules"))?;
    let package_index = node_modules_index + 1;
    let package_component = components.get(package_index)?;
    let package_name = package_component.as_os_str().to_str()?;

    let root_index = if package_name.starts_with('@') {
        package_index + 1
    } else {
        package_index
    };

    let mut package_root = PathBuf::new();
    for component in components.into_iter().take(root_index + 1) {
        package_root.push(component.as_os_str());
    }
    Some(package_root)
}

#[cfg(test)]
mod tests {
    use super::{
        find_command_candidate, inspect_command, parse_wrapper_delegate_paths, resolve_command_path,
    };
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

    #[test]
    fn host_command_paths_include_shebang_interpreter() {
        let dir = tempdir().unwrap();
        let bin_dir = dir.path().join("bin");
        let runtime_dir = dir.path().join("runtime");
        let package_dir = dir
            .path()
            .join("lib/node_modules/@anthropic-ai/claude-code");
        fs::create_dir_all(&bin_dir).unwrap();
        fs::create_dir_all(&runtime_dir).unwrap();
        fs::create_dir_all(&package_dir).unwrap();

        let node = runtime_dir.join("node");
        fs::write(&node, "#!/bin/sh\nexit 0\n").unwrap();
        let mut node_permissions = fs::metadata(&node).unwrap().permissions();
        node_permissions.set_mode(0o755);
        fs::set_permissions(&node, node_permissions).unwrap();

        let cli = package_dir.join("cli.js");
        fs::write(&cli, "#!/usr/bin/env node\nconsole.log('hello')\n").unwrap();
        let mut cli_permissions = fs::metadata(&cli).unwrap().permissions();
        cli_permissions.set_mode(0o755);
        fs::set_permissions(&cli, cli_permissions).unwrap();

        let command = bin_dir.join("claude");
        std::os::unix::fs::symlink(&cli, &command).unwrap();

        let path_env = std::env::join_paths([bin_dir.as_path(), runtime_dir.as_path()]).unwrap();

        let support = inspect_command(Some(path_env.as_os_str()), "claude").unwrap();
        assert!(support.paths.contains(&fs::canonicalize(&cli).unwrap()));
        assert!(support.paths.contains(&fs::canonicalize(&node).unwrap()));
    }

    #[test]
    fn host_command_support_dirs_include_npm_package_root() {
        let dir = tempdir().unwrap();
        let bin_dir = dir.path().join("bin");
        let runtime_dir = dir.path().join("runtime");
        let package_dir = dir.path().join("lib/node_modules/@openai/codex");
        fs::create_dir_all(&bin_dir).unwrap();
        fs::create_dir_all(&runtime_dir).unwrap();
        fs::create_dir_all(&package_dir).unwrap();

        let node = runtime_dir.join("node");
        fs::write(&node, "#!/bin/sh\nexit 0\n").unwrap();
        let mut node_permissions = fs::metadata(&node).unwrap().permissions();
        node_permissions.set_mode(0o755);
        fs::set_permissions(&node, node_permissions).unwrap();

        let cli = package_dir.join("cli.js");
        fs::write(&cli, "#!/usr/bin/env node\n").unwrap();
        let mut cli_permissions = fs::metadata(&cli).unwrap().permissions();
        cli_permissions.set_mode(0o755);
        fs::set_permissions(&cli, cli_permissions).unwrap();

        let command = bin_dir.join("codex");
        std::os::unix::fs::symlink(&cli, &command).unwrap();

        let path_env = std::env::join_paths([bin_dir.as_path(), runtime_dir.as_path()]).unwrap();

        let support = inspect_command(Some(path_env.as_os_str()), "codex").unwrap();
        assert!(
            support
                .support_dirs
                .contains(&fs::canonicalize(&package_dir).unwrap())
        );
    }
}
