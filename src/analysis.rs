use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use onefetch::cli::CliOptions;
use onefetch::info::langs::get_loc_by_language_sorted;
use onefetch_manifest::{ManifestType, get_manifests};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_yaml::Value as YamlValue;
use toml::Value as TomlValue;

use crate::host_tools::{host_command_paths, host_command_support_dirs};
use crate::registry;

pub const SUPPORT_PACKAGES: &[&str] = &["git", "jq", "nono"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LanguageRequirement {
    Elixir,
    Go,
    Java,
    JavaScript,
    Php,
    Python,
    Ruby,
    Rust,
}

impl LanguageRequirement {
    pub fn devenv_option(self) -> &'static str {
        match self {
            Self::Elixir => "languages.elixir.enable = true;",
            Self::Go => "languages.go.enable = true;",
            Self::Java => "languages.java.enable = true;",
            Self::JavaScript => "languages.javascript.enable = true;",
            Self::Php => "languages.php.enable = true;",
            Self::Python => "languages.python.enable = true;",
            Self::Ruby => "languages.ruby.enable = true;",
            Self::Rust => "languages.rust.enable = true;",
        }
    }

    pub fn default_cache_dirs(self, home: &Path) -> Vec<PathBuf> {
        match self {
            Self::Elixir => vec![home.join(".mix"), home.join(".hex")],
            Self::Go => vec![home.join("go"), home.join(".cache/go-build")],
            Self::Java => vec![home.join(".m2"), home.join(".gradle")],
            Self::JavaScript => vec![
                home.join(".npm"),
                home.join(".pnpm-store"),
                home.join(".bun"),
                home.join(".cache/yarn"),
                home.join("Library/pnpm"),
            ],
            Self::Php => vec![home.join(".composer")],
            Self::Python => vec![
                home.join(".cache/pip"),
                home.join(".cache/uv"),
                home.join(".pyenv"),
            ],
            Self::Ruby => vec![home.join(".bundle"), home.join(".gem")],
            Self::Rust => vec![home.join(".cargo")],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceRequirement {
    Mysql,
    Postgres,
    Redis,
}

impl ServiceRequirement {
    pub fn devenv_option(self) -> &'static str {
        match self {
            Self::Mysql => "services.mysql.enable = true;",
            Self::Postgres => "services.postgres.enable = true;",
            Self::Redis => "services.redis.enable = true;",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxPlan {
    pub root: PathBuf,
    #[serde(default)]
    pub read_write_files: Vec<PathBuf>,
    pub read_write_dirs: Vec<PathBuf>,
    #[serde(default)]
    pub read_only_files: Vec<PathBuf>,
    pub read_only_dirs: Vec<PathBuf>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Analysis {
    pub root: PathBuf,
    pub markers: Vec<String>,
    pub manifests: Vec<String>,
    pub detected_languages: Vec<LanguageRequirement>,
    pub language_hints: Vec<String>,
    pub packages: Vec<String>,
    pub services: Vec<ServiceRequirement>,
    pub nix_options: Vec<String>,
    pub requires_allow_unfree: bool,
    pub lint_commands: Vec<String>,
    pub build_commands: Vec<String>,
    pub test_commands: Vec<String>,
    pub notes: Vec<String>,
    pub sandbox_plan: SandboxPlan,
}

#[derive(Default)]
struct Builder {
    markers: BTreeSet<String>,
    manifests: BTreeSet<String>,
    languages: BTreeSet<LanguageRequirement>,
    language_hints: BTreeSet<String>,
    packages: BTreeSet<String>,
    services: BTreeSet<ServiceRequirement>,
    nix_options: BTreeSet<String>,
    requires_allow_unfree: bool,
    lint_commands: Vec<String>,
    build_commands: Vec<String>,
    test_commands: Vec<String>,
    notes: Vec<String>,
}

impl Builder {
    fn add_marker(&mut self, marker: impl Into<String>) {
        self.markers.insert(marker.into());
    }

    fn add_manifest(&mut self, manifest: impl Into<String>) {
        self.manifests.insert(manifest.into());
    }

    fn add_language(&mut self, language: LanguageRequirement) {
        self.languages.insert(language);
    }

    fn add_package(&mut self, package: impl Into<String>) {
        self.packages.insert(package.into());
    }

    fn add_service(&mut self, service: ServiceRequirement) {
        self.services.insert(service);
    }

    fn add_nix_option(&mut self, option: impl Into<String>) {
        self.nix_options.insert(option.into());
    }

    fn add_lint(&mut self, command: impl Into<String>) {
        let command = command.into();
        if !self.lint_commands.contains(&command) {
            self.lint_commands.push(command);
        }
    }

    fn add_build(&mut self, command: impl Into<String>) {
        let command = command.into();
        if !self.build_commands.contains(&command) {
            self.build_commands.push(command);
        }
    }

    fn add_test(&mut self, command: impl Into<String>) {
        let command = command.into();
        if !self.test_commands.contains(&command) {
            self.test_commands.push(command);
        }
    }

    fn add_note(&mut self, note: impl Into<String>) {
        let note = note.into();
        if !self.notes.contains(&note) {
            self.notes.push(note);
        }
    }
}

impl Analysis {
    pub fn analyze(root: &Path) -> Result<Self> {
        let mut builder = Builder::default();
        for package in SUPPORT_PACKAGES {
            builder.add_package(*package);
        }

        analyze_onefetch(root, &mut builder);
        analyze_manifests(root, &mut builder)?;
        analyze_common_files(root, &mut builder)?;
        analyze_compose_services(root, &mut builder)?;
        apply_registry_matches(root, &mut builder)?;

        if builder.lint_commands.is_empty()
            && builder.build_commands.is_empty()
            && builder.test_commands.is_empty()
        {
            builder.add_note(
                "No explicit lint/build/test commands were discovered, so validation hooks stay advisory until the project exposes them.",
            );
        }

        let sandbox_plan = build_sandbox_plan(root, &builder)?;

        Ok(Self {
            root: root.to_path_buf(),
            markers: builder.markers.into_iter().collect(),
            manifests: builder.manifests.into_iter().collect(),
            detected_languages: builder.languages.iter().copied().collect(),
            language_hints: builder.language_hints.into_iter().collect(),
            packages: builder.packages.into_iter().collect(),
            services: builder.services.iter().copied().collect(),
            nix_options: builder.nix_options.into_iter().collect(),
            requires_allow_unfree: builder.requires_allow_unfree,
            lint_commands: builder.lint_commands,
            build_commands: builder.build_commands,
            test_commands: builder.test_commands,
            notes: builder.notes.clone(),
            sandbox_plan,
        })
    }

    pub fn doctor_packages(&self) -> Vec<&str> {
        self.packages
            .iter()
            .map(String::as_str)
            .filter(|package| !SUPPORT_PACKAGES.contains(package))
            .collect()
    }
}

fn analyze_onefetch(root: &Path, builder: &mut Builder) {
    let cli = CliOptions::default();
    if let Some(locs) = get_loc_by_language_sorted(
        root,
        &cli.info.exclude,
        &cli.info.r#type,
        cli.info.include_hidden,
    ) {
        for (language, _) in locs {
            let display = language.to_string();
            builder.language_hints.insert(display.clone());
            let lower = display.to_lowercase();
            if lower.contains("rust") {
                builder.add_language(LanguageRequirement::Rust);
            } else if lower.contains("typescript") || lower.contains("javascript") {
                builder.add_language(LanguageRequirement::JavaScript);
            } else if lower.contains("python") {
                builder.add_language(LanguageRequirement::Python);
            } else if lower == "go" {
                builder.add_language(LanguageRequirement::Go);
            } else if lower.contains("elixir") {
                builder.add_language(LanguageRequirement::Elixir);
            } else if lower.contains("ruby") {
                builder.add_language(LanguageRequirement::Ruby);
            } else if lower.contains("php") {
                builder.add_language(LanguageRequirement::Php);
            } else if lower.contains("java") {
                builder.add_language(LanguageRequirement::Java);
            }
        }
    }
}

fn analyze_manifests(root: &Path, builder: &mut Builder) -> Result<()> {
    for manifest in get_manifests(root).context("failed to inspect manifests with onefetch")? {
        builder.add_manifest(manifest.manifest_type.to_string());
        match manifest.manifest_type {
            ManifestType::Cargo => builder.add_language(LanguageRequirement::Rust),
            ManifestType::Npm => builder.add_language(LanguageRequirement::JavaScript),
        }
    }
    Ok(())
}

fn analyze_common_files(root: &Path, builder: &mut Builder) -> Result<()> {
    let package_json = root.join("package.json");
    if package_json.exists() {
        builder.add_marker("package.json");
        builder.add_language(LanguageRequirement::JavaScript);
        builder.add_package("nodejs");
        let payload: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(&package_json).context("failed to read package.json")?,
        )
        .context("failed to parse package.json")?;
        let package_manager = payload
            .get("packageManager")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        let package_dependencies = package_json_dependencies(&payload);
        if package_dependencies.contains("react-native") {
            builder.add_marker("react-native");
        }
        if package_dependencies.contains("expo") {
            builder.add_marker("expo");
        }
        if package_manager.starts_with("pnpm@") || root.join("pnpm-lock.yaml").exists() {
            builder.add_package("pnpm");
        }
        if package_manager.starts_with("yarn@") || root.join("yarn.lock").exists() {
            builder.add_package("yarn");
        }
        if package_manager.starts_with("bun@")
            || root.join("bun.lock").exists()
            || root.join("bun.lockb").exists()
        {
            builder.add_package("bun");
        }
        let runner = if builder.packages.contains("pnpm") {
            "pnpm"
        } else if builder.packages.contains("yarn") {
            "yarn"
        } else if builder.packages.contains("bun") {
            "bun run"
        } else {
            "npm run"
        };
        let exec_runner = if builder.packages.contains("pnpm") {
            "pnpm exec"
        } else if builder.packages.contains("yarn") {
            "yarn"
        } else if builder.packages.contains("bun") {
            "bunx"
        } else {
            "npx"
        };
        if let Some(scripts) = payload
            .get("scripts")
            .and_then(serde_json::Value::as_object)
        {
            if scripts.contains_key("lint") {
                builder.add_lint(format!("{runner} lint"));
            }
            if scripts.contains_key("typecheck") && !scripts.contains_key("lint") {
                builder.add_lint(format!("{runner} typecheck"));
            }
            if scripts.contains_key("build") {
                builder.add_build(format!("{runner} build"));
            }
            let mut discovered_test_script = false;
            for (name, value) in scripts {
                if (name == "test" || name.starts_with("test:"))
                    && value
                        .as_str()
                        .map(|script| !script_is_placeholder(script))
                        .unwrap_or(false)
                {
                    builder.add_test(format!("{runner} {name}"));
                    discovered_test_script = true;
                }
            }
            if !discovered_test_script {
                for command in fallback_javascript_test_commands(&package_dependencies, exec_runner)
                {
                    builder.add_test(command);
                }
            }
        } else {
            for command in fallback_javascript_test_commands(&package_dependencies, exec_runner) {
                builder.add_test(command);
            }
        }
    }

    let cargo_toml = root.join("Cargo.toml");
    if cargo_toml.exists() {
        builder.add_marker("Cargo.toml");
        builder.add_language(LanguageRequirement::Rust);
        builder.add_build("cargo build --release");
        builder.add_lint("cargo fmt --check");
        builder.add_lint("cargo clippy --all-targets --all-features -- -D warnings");
        builder.add_test("cargo test");
    }

    if root.join("go.mod").exists() {
        builder.add_marker("go.mod");
        builder.add_language(LanguageRequirement::Go);
        builder.add_build("go build ./...");
        builder.add_test("go test ./...");
        if root.join(".golangci.yml").exists()
            || root.join(".golangci.yaml").exists()
            || root.join(".golangci.toml").exists()
        {
            builder.add_package("golangci-lint");
            builder.add_lint("golangci-lint run");
        }
    }

    if root.join("mix.exs").exists() {
        builder.add_marker("mix.exs");
        builder.add_language(LanguageRequirement::Elixir);
        builder.add_lint("mix format --check-formatted");
        builder.add_build("mix compile --warnings-as-errors");
        builder.add_test("mix test");
    }

    if root.join("Gemfile").exists() || root.join("Bundlefile").exists() {
        builder.add_marker(if root.join("Gemfile").exists() {
            "Gemfile"
        } else {
            "Bundlefile"
        });
        builder.add_language(LanguageRequirement::Ruby);
        builder.add_package("bundler");
        if root.join(".rubocop.yml").exists() {
            builder.add_lint("bundle exec rubocop");
        }
        for command in detect_ruby_test_commands(root)? {
            builder.add_test(command);
        }
    }

    if root.join("composer.json").exists() {
        builder.add_marker("composer.json");
        builder.add_language(LanguageRequirement::Php);
        builder.add_package("composer");
        let payload: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(root.join("composer.json"))
                .context("failed to read composer.json")?,
        )
        .context("failed to parse composer.json")?;
        if payload
            .get("scripts")
            .and_then(serde_json::Value::as_object)
            .and_then(|scripts| scripts.get("test"))
            .is_some()
        {
            builder.add_test("composer test");
        } else {
            let dependencies = registry::collect_composer_dependencies(root)?;
            if dependencies.contains("pestphp/pest") {
                builder.add_test("vendor/bin/pest");
            } else if dependencies.contains("phpunit/phpunit")
                || root.join("phpunit.xml").exists()
                || root.join("phpunit.xml.dist").exists()
            {
                builder.add_test("vendor/bin/phpunit");
            }
        }
    }

    if root.join("pom.xml").exists()
        || root.join("build.gradle").exists()
        || root.join("build.gradle.kts").exists()
        || root.join("gradlew").exists()
    {
        builder.add_marker("java-build");
        builder.add_language(LanguageRequirement::Java);
        if root.join("gradlew").exists() {
            builder.add_lint("./gradlew check");
            builder.add_build("./gradlew build");
            builder.add_test("./gradlew test");
        } else if root.join("build.gradle").exists() || root.join("build.gradle.kts").exists() {
            builder.add_package("gradle");
            builder.add_lint("gradle check");
            builder.add_build("gradle build");
            builder.add_test("gradle test");
        } else if root.join("pom.xml").exists() {
            builder.add_package("maven");
            builder.add_build("mvn -q -DskipTests package");
            builder.add_test("mvn test");
        }
    }

    if root.join("requirements.txt").exists()
        || root.join("pyproject.toml").exists()
        || root.join("uv.lock").exists()
        || root.join("poetry.lock").exists()
    {
        builder.add_language(LanguageRequirement::Python);
        let python_dependencies = registry::collect_python_dependencies(root)?;
        let mut has_pytest_tooling =
            root.join("pytest.ini").exists() || root.join("conftest.py").exists();
        builder.add_marker(if root.join("pyproject.toml").exists() {
            "pyproject.toml"
        } else if root.join("requirements.txt").exists() {
            "requirements.txt"
        } else if root.join("uv.lock").exists() {
            "uv.lock"
        } else {
            "poetry.lock"
        });
        builder.add_package("python3");
        if root.join("pyproject.toml").exists() {
            let pyproject = fs::read_to_string(root.join("pyproject.toml")).unwrap_or_default();
            if let Ok(value) = toml::from_str::<TomlValue>(&pyproject) {
                let tool = value.get("tool").and_then(TomlValue::as_table);
                if tool.and_then(|t| t.get("pytest")).is_some() {
                    has_pytest_tooling = true;
                }
                let dependencies = value
                    .get("project")
                    .and_then(|v| v.get("dependencies"))
                    .and_then(TomlValue::as_array)
                    .map(|deps| {
                        deps.iter()
                            .filter_map(TomlValue::as_str)
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                if tool.and_then(|t| t.get("ruff")).is_some()
                    || dependencies
                        .iter()
                        .any(|dep| dep.to_lowercase().contains("ruff"))
                {
                    builder.add_package("ruff");
                    builder.add_lint("ruff check .");
                }
            }
        }
        if has_pytest_tooling
            || python_dependencies.contains("pytest")
            || python_dependencies.contains("pytest-django")
        {
            builder.add_test("pytest");
        } else if root.join("manage.py").exists() && python_dependencies.contains("django") {
            builder.add_test("python manage.py test");
        } else if root.join("tox.ini").exists() {
            builder.add_test("tox");
        } else if root.join("tests").is_dir() {
            builder.add_test("python -m unittest discover");
        }
    }

    let makefile = root.join("Makefile");
    if makefile.exists() {
        builder.add_marker("Makefile");
        builder.add_package("gnumake");
        let targets = discover_make_targets(&makefile)?;
        if targets.contains("lint") {
            builder.add_lint("make lint");
        }
        if targets.contains("build") {
            builder.add_build("make build");
        }
        if targets.contains("test") {
            builder.add_test("make test");
        } else if targets.contains("check") {
            builder.add_test("make check");
        }
    }

    Ok(())
}

fn apply_registry_matches(root: &Path, builder: &mut Builder) -> Result<()> {
    let matches = registry::detect_registry_matches(root)?;
    for language in matches.languages {
        builder.add_language(language);
    }
    for package in matches.packages {
        builder.add_package(package);
    }
    for service in matches.services {
        builder.add_service(service);
    }
    for option in matches.nix_options {
        builder.add_nix_option(option);
    }
    builder.requires_allow_unfree |= matches.requires_allow_unfree;
    for note in matches.notes {
        builder.add_note(note);
    }
    Ok(())
}

fn analyze_compose_services(root: &Path, builder: &mut Builder) -> Result<()> {
    for candidate in [
        "docker-compose.yml",
        "docker-compose.yaml",
        "compose.yml",
        "compose.yaml",
    ] {
        let path = root.join(candidate);
        if !path.exists() {
            continue;
        }
        builder.add_marker(candidate);
        let raw =
            fs::read_to_string(&path).with_context(|| format!("failed to read {candidate}"))?;
        let doc: YamlValue =
            serde_yaml::from_str(&raw).with_context(|| format!("failed to parse {candidate}"))?;
        let Some(services) = doc.get("services").and_then(YamlValue::as_mapping) else {
            continue;
        };

        for (name, value) in services {
            let service_name = name.as_str().unwrap_or_default().to_lowercase();
            let image = value
                .get("image")
                .and_then(YamlValue::as_str)
                .unwrap_or_default()
                .to_lowercase();
            let haystack = format!("{service_name} {image}");
            if haystack.contains("postgres") || haystack.contains("postgis") {
                builder.add_service(ServiceRequirement::Postgres);
            } else if haystack.contains("redis") {
                builder.add_service(ServiceRequirement::Redis);
            } else if haystack.contains("mysql") || haystack.contains("mariadb") {
                builder.add_service(ServiceRequirement::Mysql);
            }
        }
    }
    Ok(())
}

fn discover_make_targets(path: &Path) -> Result<BTreeSet<String>> {
    let mut targets = BTreeSet::new();
    let regex = Regex::new(r"^([A-Za-z0-9_.-]+):(?:\s|$)")?;
    for line in fs::read_to_string(path)?.lines() {
        if line.starts_with('\t') || line.starts_with('#') {
            continue;
        }
        if let Some(captures) = regex.captures(line) {
            let target = captures.get(1).map(|m| m.as_str()).unwrap_or_default();
            if !target.starts_with('.') {
                targets.insert(target.to_string());
            }
        }
    }
    Ok(targets)
}

fn detect_ruby_test_commands(root: &Path) -> Result<Vec<String>> {
    let dependencies = registry::collect_ruby_dependencies(root)?;
    let has_rspec = dependencies.contains("rspec")
        || dependencies.contains("rspec-rails")
        || root.join(".rspec").exists()
        || root.join("spec").is_dir();
    if has_rspec {
        return Ok(vec!["bundle exec rspec".to_string()]);
    }

    let has_rails = dependencies.contains("rails") || root.join("bin/rails").exists();
    if has_rails && root.join("test").is_dir() {
        return Ok(vec!["bundle exec rails test".to_string()]);
    }

    if root.join("test").is_dir() && root.join("Rakefile").exists() {
        return Ok(vec!["bundle exec rake test".to_string()]);
    }

    Ok(Vec::new())
}

fn package_json_dependencies(payload: &serde_json::Value) -> BTreeSet<String> {
    let mut dependencies = BTreeSet::new();
    for field in [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ] {
        let Some(entries) = payload.get(field).and_then(serde_json::Value::as_object) else {
            continue;
        };
        for dependency in entries.keys() {
            dependencies.insert(dependency.to_lowercase());
        }
    }
    dependencies
}

fn fallback_javascript_test_commands(
    dependencies: &BTreeSet<String>,
    exec_runner: &str,
) -> Vec<String> {
    if dependencies.contains("vitest") {
        return vec![format!("{exec_runner} vitest run")];
    }
    if dependencies.contains("jest") {
        return vec![format!("{exec_runner} jest --runInBand")];
    }
    if dependencies.contains("@playwright/test") || dependencies.contains("playwright") {
        return vec![format!("{exec_runner} playwright test")];
    }
    if dependencies.contains("cypress") {
        return vec![format!("{exec_runner} cypress run")];
    }
    if dependencies.contains("ava") {
        return vec![format!("{exec_runner} ava")];
    }
    if dependencies.contains("mocha") {
        return vec![format!("{exec_runner} mocha")];
    }
    Vec::new()
}

fn script_is_placeholder(script: &str) -> bool {
    let normalized = script.to_lowercase();
    normalized.contains("no test specified")
}

fn build_sandbox_plan(root: &Path, builder: &Builder) -> Result<SandboxPlan> {
    let home = dirs::home_dir().context("failed to resolve home directory")?;
    let mut read_write_files = BTreeSet::new();
    let mut read_write_dirs = BTreeSet::new();
    let mut read_only_files = BTreeSet::new();
    let mut read_only_dirs = BTreeSet::new();

    read_write_dirs.insert(root.to_path_buf());
    read_write_dirs.insert(root.join(".devenv"));
    read_write_dirs.insert(root.join(".nono"));
    read_write_dirs.insert(root.join(".codex"));
    read_write_dirs.insert(root.join(".claude"));
    read_write_dirs.insert(home.join(".codex"));
    read_write_dirs.insert(home.join(".claude"));
    for path in platform_agent_read_write_paths(&home) {
        if path.is_file() {
            read_write_files.insert(path);
        } else {
            read_write_dirs.insert(path);
        }
    }
    for path in platform_agent_read_only_paths(&home) {
        if path.is_file() {
            read_only_files.insert(path);
        } else {
            read_only_dirs.insert(path);
        }
    }
    for path in referenced_instruction_paths(root)? {
        if path.is_file() {
            read_only_files.insert(path);
        } else {
            read_only_dirs.insert(path);
        }
    }

    for language in &builder.languages {
        for path in language.default_cache_dirs(&home) {
            read_write_dirs.insert(path);
        }
    }

    for system_dir in [
        PathBuf::from("/nix"),
        PathBuf::from("/bin"),
        PathBuf::from("/usr"),
        PathBuf::from("/etc"),
        PathBuf::from("/System"),
        PathBuf::from("/dev"),
    ] {
        read_only_dirs.insert(system_dir);
    }

    for command in ["bash", "sh", "env", "git", "devenv", "codex", "claude"] {
        for path in host_command_paths(command) {
            if let Some(parent) = path.parent() {
                read_only_dirs.insert(parent.to_path_buf());
            }
        }
        for path in host_command_support_dirs(command) {
            read_only_dirs.insert(path);
        }
    }

    if let Ok(shell) = std::env::var("SHELL") {
        if let Some(parent) = Path::new(&shell).parent() {
            read_only_dirs.insert(parent.to_path_buf());
        }
    }

    for key in [
        "TMPDIR",
        "XDG_RUNTIME_DIR",
        "XDG_CONFIG_HOME",
        "XDG_CACHE_HOME",
        "XDG_DATA_HOME",
    ] {
        if let Ok(value) = std::env::var(key) {
            let path = PathBuf::from(value);
            read_write_dirs.insert(path);
        }
    }

    if let Ok(sock) = std::env::var("SSH_AUTH_SOCK") {
        if let Some(parent) = Path::new(&sock).parent() {
            read_write_dirs.insert(parent.to_path_buf());
        }
    }
    if let Ok(address) = std::env::var("DBUS_SESSION_BUS_ADDRESS") {
        if let Some(path) = address.strip_prefix("unix:path=") {
            if let Some(parent) = Path::new(path).parent() {
                read_write_dirs.insert(parent.to_path_buf());
            }
        }
    }

    let read_write_files = read_write_files
        .into_iter()
        .filter(|path| path.exists())
        .collect::<Vec<_>>();
    let read_write_dirs = read_write_dirs
        .into_iter()
        .filter(|path| path.exists())
        .collect::<Vec<_>>();
    let read_only_files = read_only_files
        .into_iter()
        .filter(|path| path.exists())
        .collect::<Vec<_>>();
    let read_only_dirs = read_only_dirs
        .into_iter()
        .filter(|path| path.exists())
        .collect::<Vec<_>>();

    Ok(SandboxPlan {
        root: root.to_path_buf(),
        read_write_files,
        read_write_dirs,
        read_only_files,
        read_only_dirs,
        notes: builder.notes.clone(),
    })
}

fn referenced_instruction_paths(root: &Path) -> Result<Vec<PathBuf>> {
    let agents_path = root.join("AGENTS.md");
    if !agents_path.exists() {
        return Ok(Vec::new());
    }

    let content = fs::read_to_string(&agents_path)
        .with_context(|| format!("failed to read {}", agents_path.display()))?;
    let pattern = Regex::new(r#"(?m)^\s*(?:[-*]\s*)?@(?P<path>\S+)\s*$"#)?;
    let base_dir = agents_path.parent().unwrap_or(root);
    let mut paths = BTreeSet::new();

    for captures in pattern.captures_iter(&content) {
        let Some(path_match) = captures.name("path") else {
            continue;
        };
        let raw = path_match
            .as_str()
            .trim_matches(|ch| ch == '"' || ch == '\'');
        let path = PathBuf::from(raw);
        let resolved = if path.is_absolute() {
            path
        } else {
            base_dir.join(path)
        };
        paths.insert(resolved);
    }

    Ok(paths.into_iter().collect())
}

fn platform_agent_read_write_paths(home: &Path) -> Vec<PathBuf> {
    let mut paths = generic_agent_read_write_paths(home);
    paths.extend(macos_agent_read_write_paths(home));
    paths.extend(linux_agent_read_write_paths(home));
    paths
}

fn platform_agent_read_only_paths(home: &Path) -> Vec<PathBuf> {
    let mut paths = generic_agent_read_only_paths(home);
    paths.extend(macos_agent_read_only_paths(home));
    paths.extend(linux_agent_read_only_paths(home));
    paths
}

fn generic_agent_read_write_paths(home: &Path) -> Vec<PathBuf> {
    vec![
        home.join(".config"),
        home.join(".cache"),
        home.join(".local/share"),
        home.join(".config/claude"),
        home.join(".config/claude-code"),
        home.join(".config/Anthropic"),
        home.join(".config/codex"),
        home.join(".cache/claude"),
        home.join(".cache/claude-code"),
        home.join(".cache/Anthropic"),
        home.join(".cache/codex"),
        home.join(".local/share/claude"),
        home.join(".local/share/claude-code"),
        home.join(".local/share/Anthropic"),
        home.join(".local/share/codex"),
        home.join(".npm"),
        home.join(".pnpm-store"),
        home.join(".bun"),
        home.join(".local/share/pnpm"),
        home.join(".local/share/npm"),
    ]
}

fn generic_agent_read_only_paths(_home: &Path) -> Vec<PathBuf> {
    Vec::new()
}

fn macos_agent_read_write_paths(home: &Path) -> Vec<PathBuf> {
    vec![
        home.join("Library/Keychains"),
        home.join("Library/Application Support/Anthropic"),
        home.join("Library/Application Support/Claude"),
        home.join("Library/Application Support/claude-code"),
        home.join("Library/Caches/com.anthropic.claude-code"),
        home.join("Library/Caches/claude-code"),
        home.join("Library/Logs/Claude"),
        PathBuf::from("/var/run"),
        PathBuf::from("/private/var/run"),
    ]
}

fn macos_agent_read_only_paths(home: &Path) -> Vec<PathBuf> {
    vec![
        home.join("Library/Keychains/login.keychain-db"),
        home.join("Library/Keychains/metadata.keychain-db"),
        home.join("Library/Preferences"),
        PathBuf::from("/Library/Keychains/login.keychain-db"),
        PathBuf::from("/Library/Keychains/metadata.keychain-db"),
        PathBuf::from("/Library/Keychains"),
        PathBuf::from("/System/Library/Keychains"),
    ]
}

fn linux_agent_read_write_paths(_home: &Path) -> Vec<PathBuf> {
    Vec::new()
}

fn linux_agent_read_only_paths(_home: &Path) -> Vec<PathBuf> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::{
        Analysis, Builder, SUPPORT_PACKAGES, SandboxPlan, build_sandbox_plan,
        fallback_javascript_test_commands, platform_agent_read_only_paths,
        platform_agent_read_write_paths, referenced_instruction_paths, script_is_placeholder,
    };
    use std::{collections::BTreeSet, fs, path::PathBuf};
    use tempfile::tempdir;

    #[test]
    fn doctor_packages_hide_support_packages() {
        let analysis = Analysis {
            root: PathBuf::from("/tmp/project"),
            markers: Vec::new(),
            manifests: Vec::new(),
            detected_languages: Vec::new(),
            language_hints: Vec::new(),
            packages: [
                SUPPORT_PACKAGES[0].to_string(),
                SUPPORT_PACKAGES[1].to_string(),
                "nodejs".to_string(),
                "pnpm".to_string(),
            ]
            .into_iter()
            .collect(),
            services: Vec::new(),
            nix_options: Vec::new(),
            requires_allow_unfree: false,
            lint_commands: Vec::new(),
            build_commands: Vec::new(),
            test_commands: Vec::new(),
            notes: Vec::new(),
            sandbox_plan: SandboxPlan {
                root: PathBuf::from("/tmp/project"),
                read_write_files: Vec::new(),
                read_write_dirs: Vec::new(),
                read_only_files: Vec::new(),
                read_only_dirs: Vec::new(),
                notes: Vec::new(),
            },
        };

        assert_eq!(analysis.doctor_packages(), vec!["nodejs", "pnpm"]);
    }

    #[test]
    fn ignores_placeholder_test_script() {
        assert!(script_is_placeholder(
            "echo \"Error: no test specified\" && exit 1"
        ));
        assert!(!script_is_placeholder("vitest run"));
    }

    #[test]
    fn infers_javascript_fallback_test_frameworks() {
        let mut dependencies = BTreeSet::new();
        dependencies.insert("vitest".to_string());
        assert_eq!(
            fallback_javascript_test_commands(&dependencies, "pnpm exec"),
            vec!["pnpm exec vitest run".to_string()]
        );
    }

    #[test]
    fn adds_agent_support_paths() {
        let home = PathBuf::from("/Users/tester");
        let read_write = platform_agent_read_write_paths(&home);
        let read_only = platform_agent_read_only_paths(&home);
        assert!(read_write.contains(&home.join("Library/Keychains")));
        assert!(read_write.contains(&home.join(".config")));
        assert!(read_write.contains(&home.join(".npm")));
        assert!(read_write.contains(&PathBuf::from("/var/run")));
        assert!(read_only.contains(&home.join("Library/Preferences")));
        assert!(read_only.contains(&home.join("Library/Keychains/login.keychain-db")));
        assert!(read_only.contains(&home.join("Library/Keychains/metadata.keychain-db")));
        assert!(read_only.contains(&PathBuf::from("/Library/Keychains")));
    }

    #[test]
    fn resolves_referenced_instruction_paths_from_agents_file() {
        let dir = tempdir().unwrap();
        let nested = dir.path().join("docs/guide.md");
        fs::create_dir_all(nested.parent().unwrap()).unwrap();
        fs::write(&nested, "hello").unwrap();
        let absolute = dir.path().join("ABS.md");
        fs::write(&absolute, "world").unwrap();
        fs::write(
            dir.path().join("AGENTS.md"),
            format!("@docs/guide.md\n@{}\n", absolute.display()),
        )
        .unwrap();

        let paths = referenced_instruction_paths(dir.path()).unwrap();
        assert_eq!(paths, vec![absolute, nested]);
    }

    #[test]
    fn sandbox_plan_includes_referenced_instruction_files() {
        let dir = tempdir().unwrap();
        let reference = dir.path().join("instructions/extra.md");
        fs::create_dir_all(reference.parent().unwrap()).unwrap();
        fs::write(&reference, "read me").unwrap();
        fs::write(dir.path().join("AGENTS.md"), "@instructions/extra.md\n").unwrap();

        let plan = build_sandbox_plan(dir.path(), &Builder::default()).unwrap();
        assert!(plan.read_only_files.contains(&reference));
    }
}
