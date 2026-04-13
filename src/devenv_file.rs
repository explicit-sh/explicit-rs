use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};
use rnix::Root;
use rnix::ast::{self, HasEntry};
use serde_yaml::{Mapping as YamlMapping, Value as YamlValue};

use crate::analysis::{
    Analysis, DetectedVersion, LanguageRequirement, RuntimeKind, ServiceRequirement, VersionKind,
};

pub const GENERATED_DEPS_FILE: &str = "explicit.generated.deps.nix";
const MANAGED_IMPORT: &str = "./explicit.generated.deps.nix";
const LEGACY_MANAGED_IMPORT: &str = "./devenv.generated.nix";

pub fn ensure_devenv_file(root: &Path) -> Result<()> {
    let path = root.join("devenv.nix");
    if !path.exists() {
        fs::write(
            &path,
            r#"{ pkgs, ... }:

{
  imports = [ ./explicit.generated.deps.nix ];

  packages = [
    pkgs.git
    pkgs.jq
    pkgs.nono
  ];

  enterShell = ''
    echo "Run explicit apply to refresh detected tools and the sandbox plan."
  '';
}
"#,
        )
        .with_context(|| format!("failed to create {}", path.display()))?;
        return Ok(());
    }

    ensure_managed_import(&path)
}

pub fn ensure_devenv_yaml(root: &Path, analysis: &crate::analysis::Analysis) -> Result<()> {
    if !analysis.requires_allow_unfree {
        return Ok(());
    }

    let path = root.join("devenv.yaml");
    let mut payload = if path.exists() {
        serde_yaml::from_str::<YamlValue>(
            &fs::read_to_string(&path)
                .with_context(|| format!("failed to read {}", path.display()))?,
        )
        .with_context(|| format!("failed to parse {}", path.display()))?
    } else {
        YamlValue::Mapping(YamlMapping::new())
    };

    if !payload.is_mapping() {
        bail!("{} must contain a top-level YAML mapping", path.display());
    }

    let root_mapping = payload
        .as_mapping_mut()
        .context("devenv.yaml is not a mapping")?;
    let nixpkgs_key = YamlValue::String("nixpkgs".to_string());
    let nixpkgs_value = root_mapping
        .entry(nixpkgs_key)
        .or_insert_with(|| YamlValue::Mapping(YamlMapping::new()));
    let nixpkgs = nixpkgs_value
        .as_mapping_mut()
        .context("devenv.yaml nixpkgs entry must be a mapping")?;
    nixpkgs.insert(
        YamlValue::String("allowUnfree".to_string()),
        YamlValue::Bool(true),
    );

    let rendered = serde_yaml::to_string(&payload)?;
    if fs::read_to_string(&path).ok().as_deref() != Some(rendered.as_str()) {
        fs::write(&path, rendered)
            .with_context(|| format!("failed to write {}", path.display()))?;
    }
    Ok(())
}

fn ensure_managed_import(path: &Path) -> Result<()> {
    let original_source =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    let source = original_source.replace(LEGACY_MANAGED_IMPORT, MANAGED_IMPORT);
    let parse = Root::parse(&source);
    if !parse.errors().is_empty() {
        bail!(
            "cannot safely update {} because it does not parse as Nix: {:?}",
            path.display(),
            parse.errors()
        );
    }

    let root = parse.tree();
    let expr = root
        .expr()
        .context("devenv.nix is missing a top-level expression")?;
    let attrset = top_level_attrset(expr)
        .context("devenv.nix must be a top-level attrset or a lambda returning one")?;

    let updated = if let Some(imports) = find_imports_entry(&attrset) {
        update_existing_imports(&source, &imports)?
    } else {
        insert_new_import(&source, &attrset)?
    };

    if updated != original_source {
        fs::write(path, updated).with_context(|| format!("failed to update {}", path.display()))?;
    }

    Ok(())
}

fn top_level_attrset(expr: ast::Expr) -> Option<ast::AttrSet> {
    match expr {
        ast::Expr::AttrSet(attrset) => Some(attrset),
        ast::Expr::Lambda(lambda) => lambda.body().and_then(|body| match body {
            ast::Expr::AttrSet(attrset) => Some(attrset),
            _ => None,
        }),
        _ => None,
    }
}

fn find_imports_entry(attrset: &ast::AttrSet) -> Option<ast::AttrpathValue> {
    attrset
        .attrpath_values()
        .find(|entry| attrpath_to_string(entry.attrpath().as_ref()).as_deref() == Some("imports"))
}

fn attrpath_to_string(attrpath: Option<&ast::Attrpath>) -> Option<String> {
    let attrpath = attrpath?;
    let mut parts = Vec::new();
    for attr in attrpath.attrs() {
        match attr {
            ast::Attr::Ident(ident) => parts.push(ident.to_string()),
            ast::Attr::Str(string) => parts.push(string.to_string()),
            ast::Attr::Dynamic(_) => return None,
        }
    }
    Some(parts.join("."))
}

fn update_existing_imports(source: &str, imports: &ast::AttrpathValue) -> Result<String> {
    let value = imports.value().context("imports entry has no value")?;
    let ast::Expr::List(list) = value else {
        bail!("cannot update devenv imports automatically because imports is not a simple list");
    };

    if list
        .items()
        .any(|item| item.to_string().trim() == MANAGED_IMPORT)
    {
        return Ok(source.to_string());
    }

    let close = list
        .r_brack_token()
        .context("imports list is missing closing bracket")?;
    let insert_at = usize::try_from(u32::from(close.text_range().start())).unwrap_or(0);
    let has_items = list.items().next().is_some();
    let needs_prefix_space = !source[..insert_at]
        .chars()
        .last()
        .is_some_and(char::is_whitespace);
    let needs_suffix_space = !source[insert_at..]
        .chars()
        .next()
        .is_some_and(char::is_whitespace);
    let insert = if has_items {
        format!(
            "{}{}{}",
            if needs_prefix_space { " " } else { "" },
            MANAGED_IMPORT,
            if needs_suffix_space { " " } else { "" }
        )
    } else {
        format!(" {} ", MANAGED_IMPORT)
    };

    let mut updated = source.to_string();
    updated.insert_str(insert_at, &insert);
    Ok(updated)
}

fn insert_new_import(source: &str, attrset: &ast::AttrSet) -> Result<String> {
    let open = attrset
        .l_curly_token()
        .context("attrset is missing opening brace")?;
    let insert_at = usize::try_from(u32::from(open.text_range().end())).unwrap_or(0);
    let mut updated = source.to_string();
    updated.insert_str(
        insert_at,
        "\n  imports = [ ./explicit.generated.deps.nix ];",
    );
    Ok(updated)
}

pub fn render_generated_nix(analysis: &Analysis) -> String {
    let mut lines = vec![
        "{ pkgs, config, ... }:".to_string(),
        String::new(),
        "{".to_string(),
        "  # Generated by explicit.".to_string(),
        format!("  # Detected markers: {}", join_or_none(&analysis.markers)),
        format!(
            "  # Detected manifests: {}",
            join_or_none(&analysis.manifests)
        ),
    ];

    if !analysis.notes.is_empty() {
        lines.extend(analysis.notes.iter().map(|note| format!("  # - {note}")));
    }

    lines.push("  packages = [".to_string());
    for package in &analysis.packages {
        lines.push(format!(
            "    # {}",
            reason_for_package(analysis, package.as_str())
        ));
        lines.push(format!("    pkgs.{package}"));
    }
    lines.push("  ];".to_string());

    for language in &analysis.detected_languages {
        lines.push(format!("  # {}", reason_for_language(analysis, *language)));
        lines.push(format!("  {}", language.devenv_option()));
    }
    for version in &analysis.detected_versions {
        for config_line in &version.config_lines {
            lines.push(format!("  # {}", reason_for_version_pin(version)));
            lines.push(format!("  {config_line}"));
        }
    }
    for service in &analysis.services {
        lines.push(format!("  # {}", reason_for_service(analysis, *service)));
        lines.push(format!("  {}", service.devenv_option()));
        for config_line in extra_service_config_lines(*service) {
            lines.push(format!("  {config_line}"));
        }
    }
    for option in &analysis.nix_options {
        lines.push(format!("  # {}", reason_for_nix_option(analysis, option)));
        lines.push(format!("  {option}"));
    }

    lines.push("}".to_string());
    lines.push(String::new());
    let source = lines.join("\n");
    format_with_nixfmt(&source).unwrap_or(source)
}

fn extra_service_config_lines(service: ServiceRequirement) -> Vec<&'static str> {
    match service {
        ServiceRequirement::Postgres => {
            vec![
                "# Prefer localhost TCP when 5432 is free while keeping the Unix socket available.",
                "services.postgres.listen_addresses = \"127.0.0.1\";",
            ]
        }
        ServiceRequirement::Mysql | ServiceRequirement::Redis => Vec::new(),
    }
}

fn join_or_none(items: &[String]) -> String {
    if items.is_empty() {
        "none".to_string()
    } else {
        items.join(", ")
    }
}

fn reason_for_package(analysis: &Analysis, package: &str) -> String {
    if let Some(reason) = first_matching_note(analysis, &package_reason_aliases(package)) {
        return reason;
    }

    match package {
        "git" => {
            "Needed by explicit for repository inspection and generated hook workflows.".to_string()
        }
        "jq" => "Needed by explicit runtime support inside generated environments.".to_string(),
        "nono" => "Needed to launch the sandboxed agent shell.".to_string(),
        "nodejs" => "Needed to run the detected JavaScript project.".to_string(),
        "pnpm" => "Needed because the project uses pnpm.".to_string(),
        "yarn" => "Needed because the project uses Yarn.".to_string(),
        "bun" => "Needed because the project uses Bun.".to_string(),
        "bundler" => "Needed because the project has a Gemfile or Bundlefile.".to_string(),
        "composer" => "Needed because the project has a composer.json.".to_string(),
        "gnumake" => "Needed because the project has a Makefile.".to_string(),
        "python3" => "Needed to run the detected Python project.".to_string(),
        "gradle" => "Needed because the project uses Gradle.".to_string(),
        "maven" => "Needed because the project uses Maven.".to_string(),
        "opentofu" => {
            "Needed because the project includes Terraform-compatible infrastructure.".to_string()
        }
        "golangci-lint" => {
            "Needed because the project has golangci-lint configuration.".to_string()
        }
        "ruff" => "Needed because the project uses Ruff.".to_string(),
        _ => format!("Added for the detected `{package}` project requirements."),
    }
}

fn reason_for_language(analysis: &Analysis, language: LanguageRequirement) -> String {
    if let Some(reason) = first_matching_note(analysis, &language_reason_aliases(language)) {
        return reason;
    }

    match language {
        LanguageRequirement::Elixir => {
            "Detected Elixir source files in the repository.".to_string()
        }
        LanguageRequirement::Go => "Detected Go source files in the repository.".to_string(),
        LanguageRequirement::Java => "Detected Java tooling in the repository.".to_string(),
        LanguageRequirement::JavaScript => {
            "Detected JavaScript or TypeScript sources in the repository.".to_string()
        }
        LanguageRequirement::Php => "Detected PHP tooling in the repository.".to_string(),
        LanguageRequirement::Python => {
            "Detected Python source files in the repository.".to_string()
        }
        LanguageRequirement::Ruby => "Detected Ruby source files in the repository.".to_string(),
        LanguageRequirement::Rust => "Detected Rust source files in the repository.".to_string(),
    }
}

fn reason_for_service(analysis: &Analysis, service: ServiceRequirement) -> String {
    if let Some(reason) = first_matching_note(analysis, &service_reason_aliases(service)) {
        return reason;
    }

    match service {
        ServiceRequirement::Mysql => {
            "Enabled because the project appears to use MySQL or MariaDB locally.".to_string()
        }
        ServiceRequirement::Postgres => {
            "Enabled because the project appears to use PostgreSQL locally.".to_string()
        }
        ServiceRequirement::Redis => {
            "Enabled because the project appears to use Redis locally.".to_string()
        }
    }
}

fn reason_for_nix_option(analysis: &Analysis, option: &str) -> String {
    if let Some(reason) = first_matching_note(analysis, &nix_option_reason_aliases(option)) {
        return reason;
    }

    if option.starts_with("android.") {
        return "Enabled because the project looks like React Native or Android-based tooling."
            .to_string();
    }

    "Enabled because the detected project requires this devenv option.".to_string()
}

fn reason_for_version_pin(version: &DetectedVersion) -> String {
    let source = &version.source;
    let label = version.runtime.display_name();
    match version.runtime {
        RuntimeKind::Nodejs => format!(
            "Pinning Node.js from {source} so the JavaScript runtime matches the project version {}.",
            version.version
        ),
        RuntimeKind::Java => format!(
            "Selecting the JDK from {source} so Java tooling matches the project version {}.",
            version.version
        ),
        RuntimeKind::Ruby => {
            if source == ".ruby-version" {
                "Respecting .ruby-version so devenv uses the same Ruby version as the project."
                    .to_string()
            } else {
                format!("Pinning Ruby from {source} to {}.", version.version)
            }
        }
        RuntimeKind::Rust => {
            if version.kind == VersionKind::ToolchainFile {
                format!(
                    "Respecting {source} so Rust uses the project's declared toolchain configuration."
                )
            } else {
                format!("Pinning Rust from {source} to {}.", version.version)
            }
        }
        _ => format!(
            "Pinning {label} from {source} so devenv matches the project version {}.",
            version.version
        ),
    }
}

fn first_matching_note(analysis: &Analysis, aliases: &[String]) -> Option<String> {
    analysis.notes.iter().find_map(|note| {
        let lower = note.to_lowercase();
        if aliases.iter().any(|alias| lower.contains(alias)) {
            Some(condense_note(note))
        } else {
            None
        }
    })
}

fn condense_note(note: &str) -> String {
    let reason = note
        .split_once("; ")
        .map(|(_, rest)| rest)
        .unwrap_or(note)
        .trim();
    let mut chars = reason.chars();
    match chars.next() {
        Some(first) => {
            let mut text = first.to_uppercase().collect::<String>();
            text.push_str(chars.as_str());
            text
        }
        None => "Added because the detected project requires it.".to_string(),
    }
}

fn package_reason_aliases(package: &str) -> Vec<String> {
    match package {
        "watchman" => vec!["watchman", "react native", "expo", "metro"],
        "postgresql" => vec![
            "postgresql",
            "postgres",
            "libpq",
            "postgrex",
            "psycopg",
            "pg",
        ],
        "mariadb-connector-c" => vec!["mariadb", "mysql", "myxql", "mysqlclient", "mysql2"],
        "pkg-config" => vec!["pkg-config", "native", "nif"],
        "libxml2" => vec!["libxml2", "xml"],
        "libxslt" => vec!["libxslt", "xslt", "xml"],
        "vips" => vec!["vips", "sharp"],
        "sqlite" => vec!["sqlite", "exqlite", "sqlite3", "rusqlite"],
        "openssl" => vec!["openssl", "prisma"],
        "libffi" => vec!["libffi", "cffi", "ffi"],
        "zlib" => vec!["zlib", "pillow", "image codec"],
        "freetype" => vec!["freetype", "pillow", "image codec"],
        "libjpeg" => vec!["libjpeg", "pillow", "image codec"],
        _ => vec![package],
    }
    .into_iter()
    .map(str::to_string)
    .collect()
}

fn language_reason_aliases(language: LanguageRequirement) -> Vec<String> {
    match language {
        LanguageRequirement::Elixir => vec!["enabling elixir"],
        LanguageRequirement::Go => vec!["enabling go"],
        LanguageRequirement::Java => vec!["enabling java", "android build"],
        LanguageRequirement::JavaScript => vec!["enabling javascript"],
        LanguageRequirement::Php => vec!["enabling php"],
        LanguageRequirement::Python => vec!["enabling python"],
        LanguageRequirement::Ruby => vec!["enabling ruby"],
        LanguageRequirement::Rust => vec!["enabling rust", "rustler", "maturin", "setuptools-rust"],
    }
    .into_iter()
    .map(str::to_string)
    .collect()
}

fn service_reason_aliases(service: ServiceRequirement) -> Vec<String> {
    match service {
        ServiceRequirement::Mysql => vec!["enabling mysql", "enabling mariadb", "mysql"],
        ServiceRequirement::Postgres => vec!["enabling postgresql", "postgresql"],
        ServiceRequirement::Redis => vec!["enabling redis", "redis"],
    }
    .into_iter()
    .map(str::to_string)
    .collect()
}

fn nix_option_reason_aliases(option: &str) -> Vec<String> {
    if option.starts_with("android.") {
        vec!["android", "react native", "expo"]
    } else {
        vec!["devenv option"]
    }
    .into_iter()
    .map(str::to_string)
    .collect()
}

fn format_with_nixfmt(source: &str) -> Option<String> {
    let mut child = match Command::new("nixfmt")
        .args(["--verify", "--filename", GENERATED_DEPS_FILE])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(child) => child,
        Err(_) => return None,
    };

    if let Some(stdin) = child.stdin.as_mut()
        && stdin.write_all(source.as_bytes()).is_err()
    {
        return None;
    }

    let output = child.wait_with_output().ok()?;
    if !output.status.success() {
        return None;
    }

    String::from_utf8(output.stdout).ok()
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::*;
    use crate::analysis::{LanguageRequirement, SandboxPlan, ServiceRequirement};

    #[test]
    fn creates_base_devenv_file_when_missing() {
        let dir = tempdir().unwrap();
        ensure_devenv_file(dir.path()).unwrap();
        let contents = fs::read_to_string(dir.path().join("devenv.nix")).unwrap();
        assert!(contents.contains("imports = [ ./explicit.generated.deps.nix ];"));
    }

    #[test]
    fn appends_managed_import_to_existing_imports_list() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("devenv.nix");
        fs::write(&path, "{ pkgs, ... }:\n{\n  imports = [ ./foo.nix ];\n}\n").unwrap();
        ensure_devenv_file(dir.path()).unwrap();
        let contents = fs::read_to_string(path).unwrap();
        assert!(contents.contains("imports = [ ./foo.nix ./explicit.generated.deps.nix ];"));
    }

    #[test]
    fn migrates_legacy_generated_import_path() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("devenv.nix");
        fs::write(
            &path,
            "{ pkgs, ... }:\n{\n  imports = [ ./devenv.generated.nix ];\n}\n",
        )
        .unwrap();
        ensure_devenv_file(dir.path()).unwrap();
        let contents = fs::read_to_string(path).unwrap();
        assert!(contents.contains("./explicit.generated.deps.nix"));
        assert!(!contents.contains("./devenv.generated.nix"));
    }

    #[test]
    fn renders_reason_comments_for_generated_entries() {
        let analysis = Analysis {
            root: "/tmp/project".into(),
            markers: vec!["mix.exs".to_string()],
            manifests: Vec::new(),
            detected_languages: vec![LanguageRequirement::Elixir, LanguageRequirement::Rust],
            detected_versions: Vec::new(),
            language_hints: Vec::new(),
            packages: vec!["git".to_string(), "postgresql".to_string()],
            services: vec![ServiceRequirement::Postgres],
            nix_options: Vec::new(),
            requires_allow_unfree: false,
            deploy_hosts: Vec::new(),
            lint_commands: Vec::new(),
            build_commands: Vec::new(),
            test_commands: Vec::new(),
            required_checks: Vec::new(),
            notes: vec![
                "Detected rustler in the Elixir dependencies; enabling Rust because Rustler-backed NIFs need a Rust toolchain.".to_string(),
                "Detected postgrex in the Elixir dependencies; adding the PostgreSQL client package and enabling PostgreSQL for local development.".to_string(),
            ],
            repository: crate::analysis::RepositoryMetadata::default(),
            sandbox_plan: SandboxPlan {
                root: "/tmp/project".into(),
                read_write_files: Vec::new(),
                read_write_dirs: Vec::new(),
                read_only_files: Vec::new(),
                read_only_dirs: Vec::new(),
                protected_write_files: Vec::new(),
                notes: Vec::new(),
            },
        };

        let rendered = render_generated_nix(&analysis);
        assert!(rendered.contains(
            "# Needed by explicit for repository inspection and generated hook workflows."
        ));
        assert!(
            rendered.contains("# Enabling Rust because Rustler-backed NIFs need a Rust toolchain.")
        );
        assert!(rendered.contains(
            "# Adding the PostgreSQL client package and enabling PostgreSQL for local development."
        ));
        assert!(rendered.contains("services.postgres.listen_addresses = \"127.0.0.1\";"));
    }
}
