use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use regex::Regex;
use serde::Deserialize;
use serde_json::Value as JsonValue;
use toml::Value as TomlValue;

use crate::analysis::{LanguageRequirement, ServiceRequirement};

const REGISTRY_TOML: &str = include_str!("../registry.toml");

#[derive(Debug, Clone, Default)]
pub(crate) struct ProjectContext {
    package_json: Option<JsonValue>,
    composer_json: Option<JsonValue>,
    pyproject: Option<TomlValue>,
    dependency_sets: BTreeMap<&'static str, BTreeSet<String>>,
}

impl ProjectContext {
    pub(crate) fn load(root: &Path) -> Result<Self> {
        let package_json = read_optional_json(root.join("package.json"))?;
        let composer_json = read_optional_json(root.join("composer.json"))?;
        let pyproject = read_optional_toml(root.join("pyproject.toml"))?;
        let dependency_sets = collect_dependency_sets(
            root,
            package_json.as_ref(),
            pyproject.as_ref(),
            composer_json.as_ref(),
        )?;

        Ok(Self {
            package_json,
            composer_json,
            pyproject,
            dependency_sets,
        })
    }

    pub(crate) fn package_json(&self) -> Option<&JsonValue> {
        self.package_json.as_ref()
    }

    pub(crate) fn composer_json(&self) -> Option<&JsonValue> {
        self.composer_json.as_ref()
    }

    pub(crate) fn pyproject(&self) -> Option<&TomlValue> {
        self.pyproject.as_ref()
    }

    pub(crate) fn dependencies(&self, ecosystem: &'static str) -> Option<&BTreeSet<String>> {
        self.dependency_sets.get(ecosystem)
    }
}

#[derive(Debug, Clone, Default)]
pub struct RegistryMatches {
    pub languages: Vec<LanguageRequirement>,
    pub packages: Vec<String>,
    pub services: Vec<ServiceRequirement>,
    pub nix_options: Vec<String>,
    pub requires_allow_unfree: bool,
    pub notes: Vec<String>,
}

#[derive(Default)]
struct RegistryAccumulator {
    languages: BTreeSet<LanguageRequirement>,
    packages: BTreeSet<String>,
    services: BTreeSet<ServiceRequirement>,
    nix_options: BTreeSet<String>,
    requires_allow_unfree: bool,
    notes: Vec<String>,
}

impl RegistryAccumulator {
    fn apply_rule(&mut self, rule: &RegistryRule) {
        for language in &rule.languages {
            self.languages.insert(*language);
        }
        for package in &rule.packages {
            self.packages.insert(package.clone());
        }
        for service in &rule.services {
            self.services.insert(*service);
        }
        for option in &rule.nix_options {
            self.nix_options.insert(option.clone());
        }
        self.requires_allow_unfree |= rule.requires_allow_unfree;
        if !rule.note.is_empty() && !self.notes.iter().any(|note| note == &rule.note) {
            self.notes.push(rule.note.clone());
        }
    }

    fn into_matches(self) -> RegistryMatches {
        RegistryMatches {
            languages: self.languages.into_iter().collect(),
            packages: self.packages.into_iter().collect(),
            services: self.services.into_iter().collect(),
            nix_options: self.nix_options.into_iter().collect(),
            requires_allow_unfree: self.requires_allow_unfree,
            notes: self.notes,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
struct RegistrySpec {
    version: u32,
    rules: Vec<RegistryRule>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RuleMatcher {
    Dependency,
    FileContains,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Confidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
struct RegistryRule {
    id: String,
    ecosystem: String,
    matcher: RuleMatcher,
    #[serde(default)]
    dependencies: Vec<String>,
    #[serde(default)]
    files: Vec<String>,
    #[serde(default)]
    contains_any: Vec<String>,
    #[serde(default)]
    packages: Vec<String>,
    #[serde(default)]
    services: Vec<ServiceRequirement>,
    #[serde(default)]
    languages: Vec<LanguageRequirement>,
    #[serde(default)]
    nix_options: Vec<String>,
    #[serde(default)]
    requires_allow_unfree: bool,
    note: String,
    confidence: Confidence,
    #[serde(default)]
    sources: Vec<String>,
}

fn parse_registry() -> Result<RegistrySpec> {
    let spec =
        toml::from_str::<RegistrySpec>(REGISTRY_TOML).context("failed to parse registry.toml")?;
    if spec.version == 0 {
        anyhow::bail!("registry.toml version must be greater than zero");
    }
    Ok(spec)
}

#[cfg(test)]
pub fn detect_registry_matches(root: &Path) -> Result<RegistryMatches> {
    let context = ProjectContext::load(root)?;
    detect_registry_matches_with_context(root, &context)
}

pub(crate) fn detect_registry_matches_with_context(
    root: &Path,
    context: &ProjectContext,
) -> Result<RegistryMatches> {
    let registry = parse_registry()?;
    let mut matches = RegistryAccumulator::default();

    for rule in &registry.rules {
        if rule_matches(rule, root, &context.dependency_sets)? {
            matches.apply_rule(rule);
        }
    }

    Ok(matches.into_matches())
}

fn collect_dependency_sets(
    root: &Path,
    package_json: Option<&JsonValue>,
    pyproject: Option<&TomlValue>,
    composer_json: Option<&JsonValue>,
) -> Result<BTreeMap<&'static str, BTreeSet<String>>> {
    let mut sets = BTreeMap::new();
    sets.insert(
        "javascript",
        package_json
            .map(collect_package_json_dependencies_from_payload)
            .unwrap_or_default(),
    );
    sets.insert(
        "python",
        collect_python_dependencies_with_pyproject(root, pyproject)?,
    );
    sets.insert("ruby", collect_ruby_dependencies(root)?);
    sets.insert("elixir", collect_mix_dependencies(root)?);
    sets.insert("rust", collect_cargo_dependencies(root)?);
    sets.insert("go", collect_go_dependencies(root)?);
    sets.insert(
        "php",
        composer_json
            .map(collect_composer_dependencies_from_payload)
            .unwrap_or_default(),
    );
    Ok(sets)
}

fn rule_matches(
    rule: &RegistryRule,
    root: &Path,
    dependency_sets: &BTreeMap<&'static str, BTreeSet<String>>,
) -> Result<bool> {
    let dependency_match = if rule.dependencies.is_empty() {
        true
    } else if let Some(dependencies) = dependency_sets.get(rule.ecosystem.as_str()) {
        rule.dependencies
            .iter()
            .any(|dependency| dependencies.contains(&dependency.to_lowercase()))
    } else {
        false
    };

    match rule.matcher {
        RuleMatcher::Dependency => Ok(dependency_match),
        RuleMatcher::FileContains => {
            if !dependency_match || rule.files.is_empty() || rule.contains_any.is_empty() {
                return Ok(false);
            }
            let patterns = rule
                .contains_any
                .iter()
                .map(|pattern| pattern.to_lowercase())
                .collect::<Vec<_>>();
            for file in &rule.files {
                let path = root.join(file);
                if !path.exists() {
                    continue;
                }
                let contents = fs::read_to_string(&path)
                    .with_context(|| format!("failed to read {}", path.display()))?;
                let haystack = contents.to_lowercase();
                if patterns.iter().any(|pattern| haystack.contains(pattern)) {
                    return Ok(true);
                }
            }
            Ok(false)
        }
    }
}

fn collect_package_json_dependencies_from_payload(payload: &JsonValue) -> BTreeSet<String> {
    let mut dependencies = BTreeSet::new();
    for field in [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ] {
        let Some(entries) = payload.get(field).and_then(JsonValue::as_object) else {
            continue;
        };
        for dependency in entries.keys() {
            dependencies.insert(dependency.to_lowercase());
        }
    }

    dependencies
}

#[cfg(test)]
pub(crate) fn collect_python_dependencies(root: &Path) -> Result<BTreeSet<String>> {
    let pyproject = read_optional_toml(root.join("pyproject.toml"))?;
    collect_python_dependencies_with_pyproject(root, pyproject.as_ref())
}

fn collect_python_dependencies_with_pyproject(
    root: &Path,
    pyproject: Option<&TomlValue>,
) -> Result<BTreeSet<String>> {
    let mut dependencies = BTreeSet::new();

    for path in python_dependency_files(root)? {
        if let Some(extension) = path.extension().and_then(|value| value.to_str())
            && (extension == "txt" || extension == "in")
        {
            let contents = fs::read_to_string(&path)
                .with_context(|| format!("failed to read {}", path.display()))?;
            for line in contents.lines() {
                if let Some(name) = normalize_requirement_name(line) {
                    dependencies.insert(name);
                }
            }
        }
    }

    if let Some(value) = pyproject {
        collect_pyproject_dependencies(value, &mut dependencies);
    }

    let uv_lock = root.join("uv.lock");
    if uv_lock.exists() {
        let contents = fs::read_to_string(&uv_lock)
            .with_context(|| format!("failed to read {}", uv_lock.display()))?;
        if let Ok(value) = toml::from_str::<TomlValue>(&contents)
            && let Some(packages) = value.get("package").and_then(TomlValue::as_array)
        {
            for package in packages {
                if let Some(name) = package.get("name").and_then(TomlValue::as_str) {
                    dependencies.insert(name.to_lowercase());
                }
            }
        }
    }

    let poetry_lock = root.join("poetry.lock");
    if poetry_lock.exists() {
        let contents = fs::read_to_string(&poetry_lock)
            .with_context(|| format!("failed to read {}", poetry_lock.display()))?;
        let regex = Regex::new(r#"(?m)^name = "([^"]+)""#)?;
        for capture in regex.captures_iter(&contents) {
            if let Some(name) = capture.get(1).map(|value| value.as_str().to_lowercase()) {
                dependencies.insert(name);
            }
        }
    }

    Ok(dependencies)
}

fn python_dependency_files(root: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();

    for candidate in [
        "requirements.txt",
        "requirements-dev.txt",
        "requirements.in",
    ] {
        let path = root.join(candidate);
        if path.exists() {
            files.push(path);
        }
    }

    let requirements_dir = root.join("requirements");
    if requirements_dir.is_dir() {
        for entry in fs::read_dir(&requirements_dir)
            .with_context(|| format!("failed to read {}", requirements_dir.display()))?
        {
            let entry = entry?;
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            if let Some(name) = path.file_name().and_then(|value| value.to_str())
                && (name.ends_with(".txt") || name.ends_with(".in"))
            {
                files.push(path);
            }
        }
    }

    Ok(files)
}

fn collect_pyproject_dependencies(value: &TomlValue, dependencies: &mut BTreeSet<String>) {
    if let Some(entries) = value
        .get("project")
        .and_then(|project| project.get("dependencies"))
        .and_then(TomlValue::as_array)
    {
        for entry in entries {
            if let Some(name) = entry.as_str().and_then(normalize_requirement_name) {
                dependencies.insert(name);
            }
        }
    }

    if let Some(optional) = value
        .get("project")
        .and_then(|project| project.get("optional-dependencies"))
        .and_then(TomlValue::as_table)
    {
        for entries in optional.values() {
            if let Some(items) = entries.as_array() {
                for entry in items {
                    if let Some(name) = entry.as_str().and_then(normalize_requirement_name) {
                        dependencies.insert(name);
                    }
                }
            }
        }
    }

    if let Some(groups) = value.get("dependency-groups").and_then(TomlValue::as_table) {
        for entries in groups.values() {
            if let Some(items) = entries.as_array() {
                for entry in items {
                    if let Some(name) = entry.as_str().and_then(normalize_requirement_name) {
                        dependencies.insert(name);
                    }
                }
            }
        }
    }

    if let Some(poetry) = value
        .get("tool")
        .and_then(|tool| tool.get("poetry"))
        .and_then(TomlValue::as_table)
    {
        collect_named_dependency_table(poetry.get("dependencies"), dependencies, &["python"]);

        if let Some(groups) = poetry.get("group").and_then(TomlValue::as_table) {
            for group in groups.values() {
                if let Some(entries) = group.get("dependencies") {
                    collect_named_dependency_table(Some(entries), dependencies, &["python"]);
                }
            }
        }
    }
}

fn collect_named_dependency_table(
    value: Option<&TomlValue>,
    dependencies: &mut BTreeSet<String>,
    excluded: &[&str],
) {
    let Some(entries) = value.and_then(TomlValue::as_table) else {
        return;
    };

    for name in entries.keys() {
        let lowered = name.to_lowercase();
        if !excluded.contains(&lowered.as_str()) {
            dependencies.insert(lowered);
        }
    }
}

fn normalize_requirement_name(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }

    let without_inline_comment = trimmed.split('#').next().unwrap_or(trimmed).trim();
    if without_inline_comment.is_empty()
        || without_inline_comment.starts_with("-r")
        || without_inline_comment.starts_with("--")
        || without_inline_comment.starts_with("git+")
        || without_inline_comment.starts_with("http://")
        || without_inline_comment.starts_with("https://")
    {
        return None;
    }

    let without_marker = without_inline_comment
        .split(';')
        .next()
        .unwrap_or(without_inline_comment)
        .trim();
    let without_direct_url = without_marker
        .split('@')
        .next()
        .unwrap_or(without_marker)
        .trim();
    let without_extras = without_direct_url
        .split('[')
        .next()
        .unwrap_or(without_direct_url)
        .trim();
    let name = without_extras
        .split([' ', '<', '>', '=', '!', '~'])
        .next()
        .unwrap_or(without_extras)
        .trim();

    if name.is_empty() {
        None
    } else {
        Some(name.to_lowercase())
    }
}

pub(crate) fn collect_ruby_dependencies(root: &Path) -> Result<BTreeSet<String>> {
    let mut dependencies = BTreeSet::new();
    let gem_pattern = Regex::new(r#"(?m)^\s*gem\s+["']([^"']+)["']"#)?;
    let lock_pattern = Regex::new(r#"(?m)^\s{2,}([A-Za-z0-9_.-]+) \("#)?;

    for candidate in ["Gemfile", "Bundlefile"] {
        let path = root.join(candidate);
        if !path.exists() {
            continue;
        }
        let contents = fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        for capture in gem_pattern.captures_iter(&contents) {
            if let Some(name) = capture.get(1) {
                dependencies.insert(name.as_str().to_lowercase());
            }
        }
    }

    let lockfile = root.join("Gemfile.lock");
    if lockfile.exists() {
        let contents = fs::read_to_string(&lockfile)
            .with_context(|| format!("failed to read {}", lockfile.display()))?;
        for capture in lock_pattern.captures_iter(&contents) {
            if let Some(name) = capture.get(1) {
                dependencies.insert(name.as_str().to_lowercase());
            }
        }
    }

    Ok(dependencies)
}

fn collect_mix_dependencies(root: &Path) -> Result<BTreeSet<String>> {
    let path = root.join("mix.exs");
    if !path.exists() {
        return Ok(BTreeSet::new());
    }

    let contents =
        fs::read_to_string(&path).with_context(|| format!("failed to read {}", path.display()))?;
    let regex = Regex::new(r#"\{\s*:([a-zA-Z0-9_]+)\s*,"#)?;
    let mut dependencies = BTreeSet::new();
    for capture in regex.captures_iter(&contents) {
        if let Some(name) = capture.get(1) {
            dependencies.insert(name.as_str().to_lowercase());
        }
    }

    Ok(dependencies)
}

fn collect_cargo_dependencies(root: &Path) -> Result<BTreeSet<String>> {
    let mut dependencies = BTreeSet::new();
    let cargo_toml = root.join("Cargo.toml");
    if cargo_toml.exists() {
        let contents = fs::read_to_string(&cargo_toml)
            .with_context(|| format!("failed to read {}", cargo_toml.display()))?;
        let value = toml::from_str::<TomlValue>(&contents)
            .with_context(|| format!("failed to parse {}", cargo_toml.display()))?;
        collect_cargo_dependency_tables(&value, &mut dependencies);
    }

    let cargo_lock = root.join("Cargo.lock");
    if cargo_lock.exists() {
        let contents = fs::read_to_string(&cargo_lock)
            .with_context(|| format!("failed to read {}", cargo_lock.display()))?;
        if let Ok(value) = toml::from_str::<TomlValue>(&contents)
            && let Some(packages) = value.get("package").and_then(TomlValue::as_array)
        {
            for package in packages {
                if let Some(name) = package.get("name").and_then(TomlValue::as_str) {
                    dependencies.insert(name.to_lowercase());
                }
            }
        }
    }

    Ok(dependencies)
}

fn collect_cargo_dependency_tables(value: &TomlValue, dependencies: &mut BTreeSet<String>) {
    for key in [
        "dependencies",
        "dev-dependencies",
        "build-dependencies",
        "workspace",
    ] {
        match key {
            "workspace" => {
                if let Some(entries) = value
                    .get("workspace")
                    .and_then(|workspace| workspace.get("dependencies"))
                    .and_then(TomlValue::as_table)
                {
                    dependencies.extend(entries.keys().map(|name| name.to_lowercase()));
                }
            }
            _ => {
                if let Some(entries) = value.get(key).and_then(TomlValue::as_table) {
                    dependencies.extend(entries.keys().map(|name| name.to_lowercase()));
                }
            }
        }
    }

    if let Some(targets) = value.get("target").and_then(TomlValue::as_table) {
        for target in targets.values() {
            if let Some(entries) = target.as_table() {
                for key in ["dependencies", "dev-dependencies", "build-dependencies"] {
                    if let Some(table) = entries.get(key).and_then(TomlValue::as_table) {
                        dependencies.extend(table.keys().map(|name| name.to_lowercase()));
                    }
                }
            }
        }
    }
}

fn collect_go_dependencies(root: &Path) -> Result<BTreeSet<String>> {
    let path = root.join("go.mod");
    if !path.exists() {
        return Ok(BTreeSet::new());
    }

    let contents =
        fs::read_to_string(&path).with_context(|| format!("failed to read {}", path.display()))?;
    let regex = Regex::new(r#"(?m)^\s*([^\s]+)\s+v[0-9]"#)?;
    let mut dependencies = BTreeSet::new();
    for capture in regex.captures_iter(&contents) {
        if let Some(name) = capture.get(1) {
            dependencies.insert(name.as_str().to_lowercase());
        }
    }

    Ok(dependencies)
}

fn collect_composer_dependencies_from_payload(payload: &JsonValue) -> BTreeSet<String> {
    let mut dependencies = BTreeSet::new();
    for field in ["require", "require-dev"] {
        let Some(entries) = payload.get(field).and_then(JsonValue::as_object) else {
            continue;
        };
        for dependency in entries.keys() {
            dependencies.insert(dependency.to_lowercase());
        }
    }

    dependencies
}

fn read_optional_json(path: PathBuf) -> Result<Option<JsonValue>> {
    if !path.exists() {
        return Ok(None);
    }
    let payload = serde_json::from_str(
        &fs::read_to_string(&path).with_context(|| format!("failed to read {}", path.display()))?,
    )
    .with_context(|| format!("failed to parse {}", path.display()))?;
    Ok(Some(payload))
}

fn read_optional_toml(path: PathBuf) -> Result<Option<TomlValue>> {
    if !path.exists() {
        return Ok(None);
    }
    let payload = toml::from_str(
        &fs::read_to_string(&path).with_context(|| format!("failed to read {}", path.display()))?,
    )
    .with_context(|| format!("failed to parse {}", path.display()))?;
    Ok(Some(payload))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::{
        Confidence, collect_cargo_dependencies, collect_composer_dependencies_from_payload,
        collect_go_dependencies, collect_mix_dependencies, collect_python_dependencies,
        collect_ruby_dependencies, detect_registry_matches, normalize_requirement_name,
        parse_registry,
    };
    use crate::analysis::{LanguageRequirement, ServiceRequirement};

    #[test]
    fn registry_toml_is_versioned_and_has_metadata() {
        let registry = parse_registry().unwrap();
        assert_eq!(registry.version, 1);
        let rule = registry
            .rules
            .iter()
            .find(|rule| rule.id == "ruby-nokogiri")
            .unwrap();
        assert_eq!(rule.confidence, Confidence::High);
        assert!(!rule.sources.is_empty());
    }

    #[test]
    fn normalizes_python_requirements() {
        assert_eq!(
            normalize_requirement_name("psycopg[binary]>=3.1 ; python_version > '3.11'"),
            Some("psycopg".to_string())
        );
        assert_eq!(
            normalize_requirement_name("Django==5.2"),
            Some("django".to_string())
        );
        assert_eq!(normalize_requirement_name("-r requirements/dev.txt"), None);
    }

    #[test]
    fn collects_python_dependencies_from_common_files() {
        let dir = tempdir().unwrap();
        fs::create_dir_all(dir.path().join("requirements")).unwrap();
        fs::write(
            dir.path().join("pyproject.toml"),
            r#"
[project]
dependencies = ["django>=5.1", "psycopg[binary]>=3.1"]

[project.optional-dependencies]
dev = ["lxml>=5.0"]
"#,
        )
        .unwrap();
        fs::write(
            dir.path().join("requirements/dev.txt"),
            "pillow>=11\nredis>=6\n",
        )
        .unwrap();

        let dependencies = collect_python_dependencies(dir.path()).unwrap();
        assert!(dependencies.contains("django"));
        assert!(dependencies.contains("psycopg"));
        assert!(dependencies.contains("lxml"));
        assert!(dependencies.contains("pillow"));
        assert!(dependencies.contains("redis"));
    }

    #[test]
    fn registry_adds_languages_packages_and_services() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("mix.exs"),
            r#"
defmodule Demo.MixProject do
  defp deps do
    [
      {:phoenix, "~> 1.7"},
      {:rustler, "~> 0.36"},
      {:postgrex, ">= 0.0.0"},
      {:redix, ">= 0.0.0"}
    ]
  end
end
"#,
        )
        .unwrap();

        let matches = detect_registry_matches(dir.path()).unwrap();
        assert!(matches.languages.contains(&LanguageRequirement::Rust));
        assert!(matches.packages.contains(&"postgresql".to_string()));
        assert!(matches.services.contains(&ServiceRequirement::Postgres));
        assert!(matches.services.contains(&ServiceRequirement::Redis));
    }

    #[test]
    fn registry_detects_file_contains_rules_for_rust_features() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("Cargo.toml"),
            r#"
[package]
name = "demo"
version = "0.1.0"
edition = "2024"

[dependencies]
openssl = "0.10"
sqlx = { version = "0.8", features = ["runtime-tokio", "postgres", "sqlite"] }
"#,
        )
        .unwrap();

        let matches = detect_registry_matches(dir.path()).unwrap();
        assert!(matches.packages.contains(&"openssl".to_string()));
        assert!(matches.packages.contains(&"postgresql".to_string()));
        assert!(matches.packages.contains(&"sqlite".to_string()));
        assert!(matches.services.contains(&ServiceRequirement::Postgres));
    }

    #[test]
    fn registry_detects_php_extensions() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("composer.json"),
            r#"{
  "require": {
    "ext-pgsql": "*",
    "ext-gd": "*",
    "ext-redis": "*"
  }
}"#,
        )
        .unwrap();

        let matches = detect_registry_matches(dir.path()).unwrap();
        assert!(matches.packages.contains(&"postgresql".to_string()));
        assert!(matches.packages.contains(&"freetype".to_string()));
        assert!(matches.packages.contains(&"libjpeg".to_string()));
        assert!(matches.packages.contains(&"libpng".to_string()));
        assert!(matches.services.contains(&ServiceRequirement::Postgres));
        assert!(matches.services.contains(&ServiceRequirement::Redis));
    }

    #[test]
    fn registry_detects_file_contains_rules_for_jvm_projects() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("build.gradle"),
            r#"
dependencies {
  implementation "org.postgresql:postgresql:42.7.5"
  implementation "io.lettuce:lettuce-core:6.5.0.RELEASE"
}
"#,
        )
        .unwrap();

        let matches = detect_registry_matches(dir.path()).unwrap();
        assert!(matches.packages.contains(&"postgresql".to_string()));
        assert!(matches.services.contains(&ServiceRequirement::Postgres));
        assert!(matches.services.contains(&ServiceRequirement::Redis));
    }

    #[test]
    fn normalizes_requirement_name_edge_cases() {
        // Comments
        assert_eq!(normalize_requirement_name("# this is a comment"), None);
        assert_eq!(normalize_requirement_name(""), None);
        // URL references
        assert_eq!(
            normalize_requirement_name("git+https://github.com/foo/bar.git"),
            None
        );
        assert_eq!(
            normalize_requirement_name("https://example.com/pkg.whl"),
            None
        );
        // With extras and markers
        assert_eq!(
            normalize_requirement_name("requests[security]>=2.28 ; python_version >= '3.8'"),
            Some("requests".to_string())
        );
        // Inline comment
        assert_eq!(
            normalize_requirement_name("flask==3.0 # web framework"),
            Some("flask".to_string())
        );
    }

    #[test]
    fn collect_ruby_dependencies_from_gemfile() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("Gemfile"),
            "gem 'rails', '~> 7.0'\ngem \"pg\", '>= 0.18'\n",
        )
        .unwrap();
        let deps = collect_ruby_dependencies(dir.path()).unwrap();
        assert!(deps.contains("rails"));
        assert!(deps.contains("pg"));
    }

    #[test]
    fn collect_ruby_dependencies_from_lockfile() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("Gemfile.lock"),
            "GEM\n  remote: https://rubygems.org/\n  specs:\n    rails (7.0.0)\n    pg (1.5.6)\n",
        )
        .unwrap();
        let deps = collect_ruby_dependencies(dir.path()).unwrap();
        assert!(deps.contains("rails"));
        assert!(deps.contains("pg"));
    }

    #[test]
    fn collect_ruby_dependencies_returns_empty_without_gemfile() {
        let dir = tempdir().unwrap();
        let deps = collect_ruby_dependencies(dir.path()).unwrap();
        assert!(deps.is_empty());
    }

    #[test]
    fn collect_mix_dependencies_from_mix_exs() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("mix.exs"),
            "defmodule Demo.MixProject do\n  defp deps do\n    [{:phoenix, \"~> 1.7\"}, {:postgrex, \">= 0.0.0\"}]\n  end\nend\n",
        )
        .unwrap();
        let deps = collect_mix_dependencies(dir.path()).unwrap();
        assert!(deps.contains("phoenix"));
        assert!(deps.contains("postgrex"));
    }

    #[test]
    fn collect_mix_dependencies_returns_empty_without_mix_exs() {
        let dir = tempdir().unwrap();
        let deps = collect_mix_dependencies(dir.path()).unwrap();
        assert!(deps.is_empty());
    }

    #[test]
    fn collect_cargo_dependencies_from_cargo_toml() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("Cargo.toml"),
            "[package]\nname = \"test\"\nversion = \"0.1.0\"\n\n[dependencies]\nreqwest = \"0.12\"\n\n[dev-dependencies]\ntempfile = \"3\"\n",
        )
        .unwrap();
        let deps = collect_cargo_dependencies(dir.path()).unwrap();
        assert!(deps.contains("reqwest"));
        assert!(deps.contains("tempfile"));
    }

    #[test]
    fn collect_cargo_dependencies_returns_empty_without_cargo_toml() {
        let dir = tempdir().unwrap();
        let deps = collect_cargo_dependencies(dir.path()).unwrap();
        assert!(deps.is_empty());
    }

    #[test]
    fn collect_go_dependencies_from_go_mod() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("go.mod"),
            "module example.com/app\n\ngo 1.21\n\nrequire (\n\tgithub.com/lib/pq v1.10.9\n\tgithub.com/redis/go-redis/v9 v9.5.1\n)\n",
        )
        .unwrap();
        let deps = collect_go_dependencies(dir.path()).unwrap();
        assert!(deps.contains("github.com/lib/pq"));
        assert!(deps.contains("github.com/redis/go-redis/v9"));
    }

    #[test]
    fn collect_go_dependencies_returns_empty_without_go_mod() {
        let dir = tempdir().unwrap();
        let deps = collect_go_dependencies(dir.path()).unwrap();
        assert!(deps.is_empty());
    }

    #[test]
    fn collect_composer_dependencies_from_payload_extracts_both_sections() {
        let payload: serde_json::Value = serde_json::json!({
            "require": {
                "ext-pgsql": "*",
                "symfony/console": "^6.0"
            },
            "require-dev": {
                "phpunit/phpunit": "^10"
            }
        });
        let deps = collect_composer_dependencies_from_payload(&payload);
        assert!(deps.contains("ext-pgsql"));
        assert!(deps.contains("symfony/console"));
        assert!(deps.contains("phpunit/phpunit"));
    }

    #[test]
    fn collect_composer_dependencies_empty_for_missing_fields() {
        let payload: serde_json::Value = serde_json::json!({});
        let deps = collect_composer_dependencies_from_payload(&payload);
        assert!(deps.is_empty());
    }
}
