use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use onefetch::cli::CliOptions;
use onefetch::info::langs::get_loc_by_language_sorted;
use onefetch_manifest::{ManifestType, get_manifests};
use regex::Regex;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_yaml::Value as YamlValue;
use toml::Value as TomlValue;

use crate::host_tools::{host_command_paths, host_command_support_dirs};
use crate::registry::{self, ProjectContext};

#[path = "heuristics/elixir.rs"]
mod elixir_heuristics;
#[path = "heuristics/javascript.rs"]
mod javascript_heuristics;
#[path = "heuristics/php.rs"]
mod php_heuristics;
#[path = "heuristics/python.rs"]
mod python_heuristics;
#[path = "heuristics/ruby.rs"]
mod ruby_heuristics;

pub const SUPPORT_PACKAGES: &[&str] = &["actionlint", "git", "jq", "nono"];
const NO_COMMANDS_NOTE: &str = "No explicit lint/build/test commands were discovered, so validation hooks stay advisory until the project exposes them.";
const BROWSER_TEST_SANDBOX_NOTE: &str = "Sandbox: detected browser-driven tests; allowing browser app bundles plus writable Chrome/Chromium Crashpad directories.";
const EXPLICIT_CONFIG_FILE: &str = "explicit.toml";
const MINIMUM_COVERAGE_PERCENT: u8 = 80;
const WORKSPACE_IGNORED_DIRS: &[&str] = &[
    ".git",
    ".devenv",
    ".direnv",
    ".nono",
    ".codex",
    ".claude",
    ".terraform",
    ".venv",
    "__pycache__",
    "_build",
    "deps",
    "node_modules",
    "target",
    "dist",
    "build",
    "vendor",
];

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
            Self::Elixir => vec![
                home.join(".mix"),
                home.join(".hex"),
                home.join("Library/Caches/elixir_make"),
            ],
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
pub enum RuntimeKind {
    Elixir,
    Erlang,
    Go,
    Java,
    Nodejs,
    Php,
    Python,
    Ruby,
    Rust,
}

impl RuntimeKind {
    pub fn display_name(self) -> &'static str {
        match self {
            Self::Elixir => "elixir",
            Self::Erlang => "erlang",
            Self::Go => "go",
            Self::Java => "java",
            Self::Nodejs => "nodejs",
            Self::Php => "php",
            Self::Python => "python",
            Self::Ruby => "ruby",
            Self::Rust => "rust",
        }
    }

    pub fn eol_product_slug(self) -> &'static str {
        match self {
            Self::Elixir => "elixir",
            Self::Erlang => "erlang",
            Self::Go => "go",
            Self::Java => "",
            Self::Nodejs => "nodejs",
            Self::Php => "php",
            Self::Python => "python",
            Self::Ruby => "ruby",
            Self::Rust => "rust",
        }
    }

    pub fn cycle_from_version(self, version: &str) -> Option<String> {
        let cleaned = clean_version_value(version);
        let mut numeric_segments = cleaned
            .split(['.', '-'])
            .filter_map(|segment| {
                let digits = segment
                    .chars()
                    .take_while(|ch| ch.is_ascii_digit())
                    .collect::<String>();
                if digits.is_empty() {
                    None
                } else {
                    Some(digits)
                }
            })
            .collect::<Vec<_>>();
        if numeric_segments.is_empty() {
            return None;
        }
        match self {
            Self::Nodejs | Self::Java | Self::Erlang => numeric_segments.drain(..1).next(),
            Self::Elixir | Self::Go | Self::Php | Self::Python | Self::Ruby | Self::Rust => {
                if numeric_segments.len() == 1 {
                    Some(numeric_segments.remove(0))
                } else {
                    Some(format!("{}.{}", numeric_segments[0], numeric_segments[1]))
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VersionKind {
    Exact,
    Constraint,
    ToolchainFile,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectedVersion {
    pub runtime: RuntimeKind,
    pub version: String,
    pub source: String,
    pub kind: VersionKind,
    #[serde(default)]
    pub config_lines: Vec<String>,
}

impl DetectedVersion {
    pub fn summary(&self) -> String {
        format!(
            "{} {} ({})",
            self.runtime.display_name(),
            self.version,
            self.source
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequirementKind {
    Lint,
    Coverage,
    Starter,
}

impl RequirementKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Lint => "lint",
            Self::Coverage => "coverage",
            Self::Starter => "starter",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectRequirement {
    pub kind: RequirementKind,
    pub subject: String,
    pub summary: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationCheckKind {
    Ecto,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationCheck {
    pub kind: MigrationCheckKind,
    pub status_command: String,
    pub apply_command: String,
    pub subject: String,
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
    #[serde(default)]
    pub protected_write_files: Vec<PathBuf>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum GitHubVisibility {
    Public,
    Private,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct GitHubRepository {
    pub slug: String,
    pub visibility: GitHubVisibility,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct RepositoryMetadata {
    pub is_git_repository: bool,
    pub readme_path: Option<String>,
    pub license_path: Option<String>,
    #[serde(default)]
    pub workflow_files: Vec<String>,
    pub github: Option<GitHubRepository>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct ExplicitConfigFile {
    #[serde(default)]
    workspace: Option<WorkspaceConfig>,
    #[serde(default)]
    deploy: Option<DeployConfig>,
    #[serde(default)]
    sandbox: Option<SandboxConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct WorkspaceConfig {
    #[serde(default = "default_workspace_auto_discover")]
    auto_discover: bool,
    #[serde(default)]
    members: Vec<String>,
    #[serde(default)]
    exclude: Vec<String>,
}

impl Default for WorkspaceConfig {
    fn default() -> Self {
        Self {
            auto_discover: true,
            members: Vec::new(),
            exclude: Vec::new(),
        }
    }
}

fn default_workspace_auto_discover() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Default)]
struct DeployConfig {
    #[serde(default)]
    hosts: Vec<String>,
    #[serde(default)]
    use_ssh_agent: bool,
    #[serde(default)]
    ssh_agent_hosts: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Default)]
struct SandboxConfig {
    #[serde(default)]
    read_only_files: Vec<String>,
    #[serde(default)]
    read_only_dirs: Vec<String>,
    #[serde(default)]
    read_write_files: Vec<String>,
    #[serde(default)]
    read_write_dirs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct ConfiguredSandboxPaths {
    read_only_files: Vec<PathBuf>,
    read_only_dirs: Vec<PathBuf>,
    read_write_files: Vec<PathBuf>,
    read_write_dirs: Vec<PathBuf>,
}

impl ConfiguredSandboxPaths {
    fn is_empty(&self) -> bool {
        self.read_only_files.is_empty()
            && self.read_only_dirs.is_empty()
            && self.read_write_files.is_empty()
            && self.read_write_dirs.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WorkspaceMember {
    root: PathBuf,
    relative: PathBuf,
    reason: String,
    configured: bool,
}

#[derive(Debug, Default)]
struct WorkspaceDiscovery {
    config_present: bool,
    excludes: Vec<PathBuf>,
    members: Vec<WorkspaceMember>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DirectoryClassification {
    member_reason: Option<String>,
    continue_descending: bool,
}

impl RepositoryMetadata {
    pub fn has_readme(&self) -> bool {
        self.readme_path.is_some()
    }

    pub fn has_license(&self) -> bool {
        self.license_path.is_some()
    }

    pub fn has_workflows(&self) -> bool {
        !self.workflow_files.is_empty()
    }

    pub fn is_public_github_repository(&self) -> bool {
        self.github
            .as_ref()
            .is_some_and(|repo| repo.visibility == GitHubVisibility::Public)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Analysis {
    pub root: PathBuf,
    pub markers: Vec<String>,
    pub manifests: Vec<String>,
    #[serde(default)]
    pub install_directories: Vec<String>,
    pub detected_languages: Vec<LanguageRequirement>,
    pub detected_versions: Vec<DetectedVersion>,
    pub language_hints: Vec<String>,
    pub packages: Vec<String>,
    pub services: Vec<ServiceRequirement>,
    pub nix_options: Vec<String>,
    pub requires_allow_unfree: bool,
    #[serde(default)]
    pub deploy_hosts: Vec<String>,
    #[serde(default)]
    pub deploy_use_ssh_agent: bool,
    #[serde(default)]
    pub deploy_ssh_agent_hosts: Vec<String>,
    #[serde(default)]
    pub dev_server_commands: Vec<String>,
    pub lint_commands: Vec<String>,
    pub build_commands: Vec<String>,
    pub test_commands: Vec<String>,
    #[serde(default)]
    pub coverage_commands: Vec<String>,
    #[serde(default)]
    pub required_checks: Vec<ProjectRequirement>,
    #[serde(default)]
    pub migration_checks: Vec<MigrationCheck>,
    pub notes: Vec<String>,
    pub repository: RepositoryMetadata,
    pub sandbox_plan: SandboxPlan,
}

#[derive(Default)]
struct Builder {
    markers: BTreeSet<String>,
    manifests: BTreeSet<String>,
    install_directories: BTreeSet<String>,
    languages: BTreeSet<LanguageRequirement>,
    language_hints: BTreeSet<String>,
    packages: BTreeSet<String>,
    services: BTreeSet<ServiceRequirement>,
    nix_options: BTreeSet<String>,
    requires_allow_unfree: bool,
    dev_server_commands: Vec<String>,
    lint_commands: Vec<String>,
    build_commands: Vec<String>,
    test_commands: Vec<String>,
    coverage_commands: Vec<String>,
    required_checks: Vec<ProjectRequirement>,
    migration_checks: Vec<MigrationCheck>,
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

    fn add_install_directory(&mut self, directory: impl Into<String>) {
        self.install_directories.insert(directory.into());
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

    fn add_dev_server(&mut self, command: impl Into<String>) {
        let command = command.into();
        if !self.dev_server_commands.contains(&command) {
            self.dev_server_commands.push(command);
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

    fn add_coverage(&mut self, command: impl Into<String>) {
        let command = command.into();
        if !self.coverage_commands.contains(&command) {
            self.coverage_commands.push(command);
        }
    }

    fn add_requirement(&mut self, requirement: ProjectRequirement) {
        if !self.required_checks.contains(&requirement) {
            self.required_checks.push(requirement);
        }
    }

    fn add_migration_check(&mut self, check: MigrationCheck) {
        if !self.migration_checks.contains(&check) {
            self.migration_checks.push(check);
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
        let mut analysis = analyze_single_project(root)?;
        if !workspace_auto_discovery_enabled(root)? {
            return Ok(analysis);
        }
        let discovery = discover_workspace_members(root)?;
        if discovery.members.is_empty() {
            return Ok(analysis);
        }

        merge_workspace_members(&mut analysis, discovery)?;
        ensure_workspace_versions_are_compatible(&analysis.detected_versions)?;
        let builder = builder_from_analysis(&analysis);
        analysis.sandbox_plan = build_sandbox_plan(root, &builder)?;
        Ok(analysis)
    }

    pub fn doctor_packages(&self) -> Vec<&str> {
        self.packages
            .iter()
            .map(String::as_str)
            .filter(|package| !SUPPORT_PACKAGES.contains(package))
            .collect()
    }

    pub fn doctor_versions(&self) -> Vec<String> {
        self.detected_versions
            .iter()
            .map(DetectedVersion::summary)
            .collect()
    }
}

fn workspace_auto_discovery_enabled(root: &Path) -> Result<bool> {
    if root.join(".git").exists() {
        return Ok(true);
    }
    Ok(load_explicit_config(root)?.is_some_and(|config| config.workspace.is_some()))
}

fn analyze_single_project(root: &Path) -> Result<Analysis> {
    let mut builder = Builder::default();
    let project_context = ProjectContext::load(root)?;
    let deploy_settings = configured_deploy_settings(root)?;
    let sandbox_paths = configured_sandbox_paths(root)?;
    for package in SUPPORT_PACKAGES {
        builder.add_package(*package);
    }

    analyze_onefetch(root, &mut builder);
    analyze_manifests(root, &mut builder)?;
    analyze_common_files(root, &mut builder, &project_context)?;
    analyze_compose_services(root, &mut builder)?;
    apply_registry_matches(root, &mut builder, &project_context)?;
    let detected_versions = detect_runtime_versions(root, &builder, &project_context)?;
    let repository = detect_repository_metadata(root)?;

    if builder.lint_commands.is_empty()
        && builder.build_commands.is_empty()
        && builder.test_commands.is_empty()
    {
        builder.add_note(NO_COMMANDS_NOTE);
    }

    if !sandbox_paths.is_empty() {
        let mut entries = Vec::new();
        if !sandbox_paths.read_only_files.is_empty() {
            entries.push(format!(
                "{} read-only file override(s)",
                sandbox_paths.read_only_files.len()
            ));
        }
        if !sandbox_paths.read_only_dirs.is_empty() {
            entries.push(format!(
                "{} read-only dir override(s)",
                sandbox_paths.read_only_dirs.len()
            ));
        }
        if !sandbox_paths.read_write_files.is_empty() {
            entries.push(format!(
                "{} read-write file override(s)",
                sandbox_paths.read_write_files.len()
            ));
        }
        if !sandbox_paths.read_write_dirs.is_empty() {
            entries.push(format!(
                "{} read-write dir override(s)",
                sandbox_paths.read_write_dirs.len()
            ));
        }
        builder.add_note(format!(
            "Sandbox: loaded {} from {EXPLICIT_CONFIG_FILE}.",
            entries.join(", ")
        ));
    }
    if root.join(EXPLICIT_CONFIG_FILE).is_file() {
        builder.add_note(format!(
            "Sandbox: writes to {EXPLICIT_CONFIG_FILE} are denied inside the sandbox on macOS."
        ));
    }

    let sandbox_plan = build_sandbox_plan(root, &builder)?;

    Ok(Analysis {
        root: root.to_path_buf(),
        markers: builder.markers.into_iter().collect(),
        manifests: builder.manifests.into_iter().collect(),
        install_directories: builder.install_directories.into_iter().collect(),
        detected_languages: builder.languages.iter().copied().collect(),
        detected_versions,
        language_hints: builder.language_hints.into_iter().collect(),
        packages: builder.packages.into_iter().collect(),
        services: builder.services.iter().copied().collect(),
        nix_options: builder.nix_options.into_iter().collect(),
        requires_allow_unfree: builder.requires_allow_unfree,
        deploy_hosts: deploy_settings.hosts,
        deploy_use_ssh_agent: deploy_settings.use_ssh_agent,
        deploy_ssh_agent_hosts: deploy_settings.ssh_agent_hosts,
        dev_server_commands: builder.dev_server_commands,
        lint_commands: builder.lint_commands,
        build_commands: builder.build_commands,
        test_commands: builder.test_commands,
        coverage_commands: builder.coverage_commands,
        required_checks: builder.required_checks,
        migration_checks: builder.migration_checks,
        notes: builder.notes.clone(),
        repository,
        sandbox_plan,
    })
}

fn merge_workspace_members(analysis: &mut Analysis, discovery: WorkspaceDiscovery) -> Result<()> {
    let mut auto_discovered = 0usize;
    let mut configured = 0usize;
    let mut member_descriptions = Vec::new();

    for member in discovery.members {
        let member_analysis = analyze_single_project(&member.root)?;
        if member.configured {
            configured += 1;
        } else {
            auto_discovered += 1;
        }
        member_descriptions.push(format!(
            "{} ({})",
            display_relative_path(&member.relative),
            member.reason
        ));
        merge_member_analysis(analysis, member_analysis, &member.relative);
    }

    push_unique_string(&mut analysis.markers, "workspace".to_string());
    if discovery.config_present {
        push_unique_string(
            &mut analysis.notes,
            format!("Workspace: loaded {EXPLICIT_CONFIG_FILE}."),
        );
    }
    if !discovery.excludes.is_empty() {
        let excluded = discovery
            .excludes
            .iter()
            .map(|path| display_relative_path(path))
            .collect::<Vec<_>>()
            .join(", ");
        push_unique_string(
            &mut analysis.notes,
            format!("Workspace excludes: {excluded}."),
        );
    }

    push_unique_string(
        &mut analysis.notes,
        format!(
            "Workspace: merged {} leaf projects into the root analysis ({} auto-discovered, {} configured).",
            auto_discovered + configured,
            auto_discovered,
            configured
        ),
    );
    push_unique_string(
        &mut analysis.notes,
        format!("Workspace members: {}.", member_descriptions.join(", ")),
    );
    if !analysis.lint_commands.is_empty()
        || !analysis.build_commands.is_empty()
        || !analysis.test_commands.is_empty()
        || !analysis.coverage_commands.is_empty()
    {
        analysis.notes.retain(|note| note != NO_COMMANDS_NOTE);
    }

    Ok(())
}

fn merge_member_analysis(analysis: &mut Analysis, member: Analysis, relative: &Path) {
    merge_unique_strings(&mut analysis.markers, member.markers);
    merge_unique_strings(&mut analysis.manifests, member.manifests);
    merge_unique_strings(
        &mut analysis.install_directories,
        member
            .install_directories
            .into_iter()
            .map(|directory| prefix_workspace_path(relative, &directory))
            .collect(),
    );
    merge_unique_copy(&mut analysis.detected_languages, member.detected_languages);

    let prefixed_versions = member
        .detected_versions
        .into_iter()
        .map(|version| prefix_detected_version_source(version, relative))
        .collect::<Vec<_>>();
    merge_unique_versions(&mut analysis.detected_versions, prefixed_versions);

    merge_unique_strings(&mut analysis.language_hints, member.language_hints);
    merge_unique_strings(&mut analysis.packages, member.packages);
    merge_unique_copy(&mut analysis.services, member.services);
    merge_unique_strings(&mut analysis.nix_options, member.nix_options);
    analysis.requires_allow_unfree |= member.requires_allow_unfree;
    merge_unique_strings(
        &mut analysis.dev_server_commands,
        member
            .dev_server_commands
            .into_iter()
            .map(|command| prefix_workspace_command(relative, &command))
            .collect(),
    );
    merge_unique_strings(
        &mut analysis.lint_commands,
        member
            .lint_commands
            .into_iter()
            .map(|command| prefix_workspace_command(relative, &command))
            .collect(),
    );
    merge_unique_strings(
        &mut analysis.build_commands,
        member
            .build_commands
            .into_iter()
            .map(|command| prefix_workspace_command(relative, &command))
            .collect(),
    );
    merge_unique_strings(
        &mut analysis.test_commands,
        member
            .test_commands
            .into_iter()
            .map(|command| prefix_workspace_command(relative, &command))
            .collect(),
    );
    merge_unique_strings(
        &mut analysis.coverage_commands,
        member
            .coverage_commands
            .into_iter()
            .map(|command| prefix_workspace_command(relative, &command))
            .collect(),
    );
    merge_unique_requirements(
        &mut analysis.required_checks,
        member
            .required_checks
            .into_iter()
            .map(|requirement| prefix_requirement_subject(requirement, relative))
            .collect(),
    );
    merge_unique_migration_checks(
        &mut analysis.migration_checks,
        member
            .migration_checks
            .into_iter()
            .map(|check| prefix_migration_check(check, relative))
            .collect(),
    );
}

fn builder_from_analysis(analysis: &Analysis) -> Builder {
    let mut builder = Builder::default();
    for marker in &analysis.markers {
        builder.add_marker(marker.clone());
    }
    for manifest in &analysis.manifests {
        builder.add_manifest(manifest.clone());
    }
    for directory in &analysis.install_directories {
        builder.add_install_directory(directory.clone());
    }
    for language in &analysis.detected_languages {
        builder.add_language(*language);
    }
    builder
        .language_hints
        .extend(analysis.language_hints.iter().cloned());
    for package in &analysis.packages {
        builder.add_package(package.clone());
    }
    for service in &analysis.services {
        builder.add_service(*service);
    }
    for option in &analysis.nix_options {
        builder.add_nix_option(option.clone());
    }
    builder.requires_allow_unfree = analysis.requires_allow_unfree;
    for command in &analysis.dev_server_commands {
        builder.add_dev_server(command.clone());
    }
    for command in &analysis.lint_commands {
        builder.add_lint(command.clone());
    }
    for command in &analysis.build_commands {
        builder.add_build(command.clone());
    }
    for command in &analysis.test_commands {
        builder.add_test(command.clone());
    }
    for command in &analysis.coverage_commands {
        builder.add_coverage(command.clone());
    }
    for requirement in &analysis.required_checks {
        builder.add_requirement(requirement.clone());
    }
    for check in &analysis.migration_checks {
        builder.add_migration_check(check.clone());
    }
    for note in &analysis.notes {
        builder.add_note(note.clone());
    }
    builder
}

fn discover_workspace_members(root: &Path) -> Result<WorkspaceDiscovery> {
    let config = load_workspace_config(root)?;
    let excludes = workspace_excludes(root, config.as_ref())?;
    let mut members = BTreeMap::new();

    if let Some(config) = config.as_ref() {
        for raw_member in &config.members {
            let relative = parse_workspace_relative_path(root, raw_member, "workspace.members")?;
            let member_root = root.join(&relative);
            if !member_root.is_dir() {
                anyhow::bail!(
                    "{} lists workspace member `{}` but that directory does not exist",
                    EXPLICIT_CONFIG_FILE,
                    display_relative_path(&relative)
                );
            }
            let reason = classify_workspace_directory(&member_root)?.member_reason;
            members.insert(
                relative.clone(),
                WorkspaceMember {
                    root: member_root,
                    relative,
                    reason: reason.unwrap_or_else(|| EXPLICIT_CONFIG_FILE.to_string()),
                    configured: true,
                },
            );
        }
    }

    if config.as_ref().map(|cfg| cfg.auto_discover).unwrap_or(true) {
        walk_workspace_tree(root, root, &excludes, &mut members)?;
    }

    let mut members = members.into_values().collect::<Vec<_>>();
    members.sort_by_key(|member| member.relative.clone());

    Ok(WorkspaceDiscovery {
        config_present: config.is_some(),
        excludes,
        members,
    })
}

fn load_explicit_config(root: &Path) -> Result<Option<ExplicitConfigFile>> {
    let path = root.join(EXPLICIT_CONFIG_FILE);
    if !path.is_file() {
        return Ok(None);
    }

    let raw =
        fs::read_to_string(&path).with_context(|| format!("failed to read {}", path.display()))?;
    let parsed = toml::from_str::<ExplicitConfigFile>(&raw)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    Ok(Some(parsed))
}

fn load_workspace_config(root: &Path) -> Result<Option<WorkspaceConfig>> {
    Ok(load_explicit_config(root)?.and_then(|config| config.workspace))
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct ConfiguredDeploySettings {
    hosts: Vec<String>,
    use_ssh_agent: bool,
    ssh_agent_hosts: Vec<String>,
}

fn configured_deploy_settings(root: &Path) -> Result<ConfiguredDeploySettings> {
    let deploy = load_explicit_config(root)?
        .and_then(|config| config.deploy)
        .unwrap_or_default();
    Ok(ConfiguredDeploySettings {
        hosts: normalize_configured_hosts(deploy.hosts),
        use_ssh_agent: deploy.use_ssh_agent,
        ssh_agent_hosts: normalize_configured_hosts(deploy.ssh_agent_hosts),
    })
}

fn normalize_configured_hosts(hosts: Vec<String>) -> Vec<String> {
    hosts
        .into_iter()
        .map(|host| host.trim().to_string())
        .filter(|host| !host.is_empty())
        .collect()
}

fn configured_sandbox_paths(root: &Path) -> Result<ConfiguredSandboxPaths> {
    let Some(config) = load_explicit_config(root)? else {
        return Ok(ConfiguredSandboxPaths::default());
    };
    let Some(sandbox) = config.sandbox else {
        return Ok(ConfiguredSandboxPaths::default());
    };

    Ok(ConfiguredSandboxPaths {
        read_only_files: resolve_configured_paths(
            root,
            &sandbox.read_only_files,
            "sandbox.read_only_files",
        )?,
        read_only_dirs: resolve_configured_paths(
            root,
            &sandbox.read_only_dirs,
            "sandbox.read_only_dirs",
        )?,
        read_write_files: resolve_configured_paths(
            root,
            &sandbox.read_write_files,
            "sandbox.read_write_files",
        )?,
        read_write_dirs: resolve_configured_paths(
            root,
            &sandbox.read_write_dirs,
            "sandbox.read_write_dirs",
        )?,
    })
}

fn resolve_configured_paths(root: &Path, values: &[String], field: &str) -> Result<Vec<PathBuf>> {
    let home = dirs::home_dir().context("failed to resolve home directory")?;
    values
        .iter()
        .map(|value| resolve_configured_path(root, &home, value, field))
        .collect()
}

fn resolve_configured_path(root: &Path, home: &Path, raw: &str, field: &str) -> Result<PathBuf> {
    let raw = raw.trim();
    if raw.is_empty() {
        anyhow::bail!("{EXPLICIT_CONFIG_FILE} contains an empty `{field}` entry");
    }

    let expanded = expand_config_path_value(home, raw);
    let path = PathBuf::from(expanded);
    Ok(if path.is_absolute() {
        path
    } else {
        root.join(path)
    })
}

fn expand_config_path_value(home: &Path, raw: &str) -> String {
    if raw == "~" {
        return home.display().to_string();
    }
    if let Some(rest) = raw.strip_prefix("~/") {
        return home.join(rest).display().to_string();
    }
    if let Some(rest) = raw.strip_prefix("$HOME/") {
        return home.join(rest).display().to_string();
    }
    if let Some(rest) = raw.strip_prefix("${HOME}/") {
        return home.join(rest).display().to_string();
    }
    if raw == "$HOME" || raw == "${HOME}" {
        return home.display().to_string();
    }
    raw.to_string()
}

fn workspace_excludes(root: &Path, config: Option<&WorkspaceConfig>) -> Result<Vec<PathBuf>> {
    let mut excludes = Vec::new();
    if let Some(config) = config {
        for raw in &config.exclude {
            let path = parse_workspace_relative_path(root, raw, "workspace.exclude")?;
            if !excludes.contains(&path) {
                excludes.push(path);
            }
        }
    }

    excludes.sort();
    Ok(excludes)
}

fn parse_workspace_relative_path(root: &Path, raw: &str, field: &str) -> Result<PathBuf> {
    let path = PathBuf::from(raw);
    if path.as_os_str().is_empty() {
        anyhow::bail!("{EXPLICIT_CONFIG_FILE} contains an empty `{field}` entry");
    }

    let relative = if path.is_absolute() {
        path.strip_prefix(root).with_context(|| {
            format!(
                "{EXPLICIT_CONFIG_FILE} `{field}` entry `{}` must stay inside the workspace root {}",
                path.display(),
                root.display()
            )
        })?
        .to_path_buf()
    } else {
        path
    };

    for component in relative.components() {
        match component {
            std::path::Component::CurDir
            | std::path::Component::ParentDir
            | std::path::Component::RootDir
            | std::path::Component::Prefix(_) => {
                anyhow::bail!(
                    "{EXPLICIT_CONFIG_FILE} `{field}` entry `{}` must use a clean path relative to the workspace root",
                    raw
                );
            }
            std::path::Component::Normal(_) => {}
        }
    }

    Ok(relative)
}

fn walk_workspace_tree(
    root: &Path,
    current: &Path,
    excludes: &[PathBuf],
    members: &mut BTreeMap<PathBuf, WorkspaceMember>,
) -> Result<()> {
    for entry in
        fs::read_dir(current).with_context(|| format!("failed to read {}", current.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let Some(relative) = path.strip_prefix(root).ok().map(Path::to_path_buf) else {
            continue;
        };
        if should_ignore_workspace_dir(&relative, excludes) {
            continue;
        }

        let classification = classify_workspace_directory(&path)?;
        if let Some(reason) = classification.member_reason {
            members
                .entry(relative.clone())
                .or_insert_with(|| WorkspaceMember {
                    root: path.clone(),
                    relative: relative.clone(),
                    reason,
                    configured: false,
                });
        }

        if classification.continue_descending {
            walk_workspace_tree(root, &path, excludes, members)?;
        }
    }

    Ok(())
}

fn should_ignore_workspace_dir(relative: &Path, excludes: &[PathBuf]) -> bool {
    if relative
        .components()
        .any(|component| component.as_os_str().to_string_lossy().starts_with('.'))
    {
        return true;
    }

    if let Some(name) = relative.file_name().and_then(|value| value.to_str())
        && WORKSPACE_IGNORED_DIRS.contains(&name)
    {
        return true;
    }

    excludes
        .iter()
        .any(|excluded| relative.starts_with(excluded))
}

fn classify_workspace_directory(dir: &Path) -> Result<DirectoryClassification> {
    let package_json = dir.join("package.json");
    if package_json.is_file() {
        let continue_descending = package_json_declares_workspaces(&package_json)?
            || dir.join("pnpm-workspace.yaml").is_file();
        return Ok(DirectoryClassification {
            member_reason: Some(if continue_descending {
                "package.json#workspaces".to_string()
            } else {
                "package.json".to_string()
            }),
            continue_descending,
        });
    }

    let cargo_toml = dir.join("Cargo.toml");
    if cargo_toml.is_file() {
        let (has_package, has_workspace) = cargo_workspace_traits(&cargo_toml)?;
        if has_package || has_workspace {
            return Ok(DirectoryClassification {
                member_reason: Some(if has_workspace && !has_package {
                    "Cargo.toml#workspace".to_string()
                } else {
                    "Cargo.toml".to_string()
                }),
                continue_descending: has_workspace,
            });
        }
    }

    for (marker, reason) in [
        ("Package.swift", "Package.swift"),
        ("mix.exs", "mix.exs"),
        ("go.mod", "go.mod"),
        ("pyproject.toml", "pyproject.toml"),
        ("requirements.txt", "requirements.txt"),
        ("Gemfile", "Gemfile"),
        ("Bundlefile", "Bundlefile"),
        ("composer.json", "composer.json"),
        ("pom.xml", "pom.xml"),
        ("build.gradle", "build.gradle"),
        ("build.gradle.kts", "build.gradle.kts"),
        ("gradlew", "gradlew"),
        ("terragrunt.hcl", "terragrunt.hcl"),
    ] {
        if dir.join(marker).is_file() {
            return Ok(DirectoryClassification {
                member_reason: Some(reason.to_string()),
                continue_descending: false,
            });
        }
    }

    if directory_has_direct_terraform_files(dir)? {
        return Ok(DirectoryClassification {
            member_reason: Some("*.tf".to_string()),
            continue_descending: false,
        });
    }

    let makefile = dir.join("Makefile");
    if makefile.is_file() {
        let targets = discover_make_targets(&makefile)?;
        if ["lint", "build", "test", "check"]
            .into_iter()
            .any(|target| targets.contains(target))
        {
            return Ok(DirectoryClassification {
                member_reason: Some("Makefile".to_string()),
                continue_descending: false,
            });
        }
    }

    Ok(DirectoryClassification {
        member_reason: None,
        continue_descending: true,
    })
}

fn package_json_declares_workspaces(path: &Path) -> Result<bool> {
    let raw =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    let payload = serde_json::from_str::<serde_json::Value>(&raw)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    Ok(payload.get("workspaces").is_some())
}

fn cargo_workspace_traits(path: &Path) -> Result<(bool, bool)> {
    let raw =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    let value = toml::from_str::<TomlValue>(&raw)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    Ok((
        value.get("package").and_then(TomlValue::as_table).is_some(),
        value
            .get("workspace")
            .and_then(TomlValue::as_table)
            .is_some(),
    ))
}

fn directory_has_direct_terraform_files(dir: &Path) -> Result<bool> {
    for entry in fs::read_dir(dir).with_context(|| format!("failed to read {}", dir.display()))? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        if entry
            .path()
            .extension()
            .and_then(|value| value.to_str())
            .is_some_and(|extension| extension == "tf")
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn prefix_workspace_command(relative: &Path, command: &str) -> String {
    format!("cd {} && {command}", shell_quote(relative))
}

fn prefix_detected_version_source(
    mut version: DetectedVersion,
    relative: &Path,
) -> DetectedVersion {
    version.source = format!("{}/{}", display_relative_path(relative), version.source);
    version
}

fn prefix_requirement_subject(
    mut requirement: ProjectRequirement,
    relative: &Path,
) -> ProjectRequirement {
    requirement.subject = format!(
        "{}/{}",
        display_relative_path(relative),
        requirement.subject
    );
    requirement
}

fn prefix_migration_check(mut check: MigrationCheck, relative: &Path) -> MigrationCheck {
    check.status_command = prefix_workspace_command(relative, &check.status_command);
    check.apply_command = prefix_workspace_command(relative, &check.apply_command);
    check.subject = prefix_workspace_path(relative, &check.subject);
    check
}

fn prefix_workspace_path(relative: &Path, path: &str) -> String {
    display_relative_path(&relative.join(path))
}

fn ensure_workspace_versions_are_compatible(versions: &[DetectedVersion]) -> Result<()> {
    let mut by_runtime = BTreeMap::<RuntimeKind, Vec<&DetectedVersion>>::new();
    for version in versions {
        by_runtime.entry(version.runtime).or_default().push(version);
    }

    for (runtime, entries) in by_runtime {
        let mut unique_pins = BTreeMap::<String, Vec<&DetectedVersion>>::new();
        for entry in &entries {
            let Some(pin_key) = shared_shell_version_key(entry) else {
                continue;
            };
            unique_pins.entry(pin_key).or_default().push(*entry);
        }
        if unique_pins.len() < 2 {
            continue;
        }

        let summary = unique_pins
            .into_values()
            .flatten()
            .map(|entry| format!("{} ({})", entry.version, entry.source))
            .collect::<Vec<_>>()
            .join(", ");
        anyhow::bail!(
            "workspace requires conflicting {} versions for one shared devenv shell: {}",
            runtime.display_name(),
            summary
        );
    }

    Ok(())
}

fn shared_shell_version_key(version: &DetectedVersion) -> Option<String> {
    if version.config_lines.is_empty() {
        return None;
    }
    Some(version.config_lines.join("\n"))
}

fn merge_unique_strings(target: &mut Vec<String>, values: Vec<String>) {
    for value in values {
        push_unique_string(target, value);
    }
}

fn push_unique_string(target: &mut Vec<String>, value: String) {
    if !target.contains(&value) {
        target.push(value);
    }
}

fn merge_unique_copy<T>(target: &mut Vec<T>, values: Vec<T>)
where
    T: Copy + PartialEq,
{
    for value in values {
        if !target.contains(&value) {
            target.push(value);
        }
    }
}

fn merge_unique_versions(target: &mut Vec<DetectedVersion>, values: Vec<DetectedVersion>) {
    for value in values {
        if !target.iter().any(|current| {
            current.runtime == value.runtime
                && current.version == value.version
                && current.source == value.source
        }) {
            target.push(value);
        }
    }
    target.sort_by_key(|entry| (entry.runtime, entry.source.clone()));
}

fn merge_unique_requirements(
    target: &mut Vec<ProjectRequirement>,
    values: Vec<ProjectRequirement>,
) {
    for value in values {
        if !target.contains(&value) {
            target.push(value);
        }
    }
}

fn merge_unique_migration_checks(target: &mut Vec<MigrationCheck>, values: Vec<MigrationCheck>) {
    for value in values {
        if !target.contains(&value) {
            target.push(value);
        }
    }
}

fn display_relative_path(path: &Path) -> String {
    path.display().to_string()
}

fn shell_quote(path: &Path) -> String {
    format!("'{}'", path.display().to_string().replace('\'', "'\"'\"'"))
}

fn detect_repository_metadata(root: &Path) -> Result<RepositoryMetadata> {
    let is_git_repository = is_git_repository(root)?;
    let workflow_files = discover_workflow_files(root)?;
    let readme_path = root
        .join("README.md")
        .is_file()
        .then_some("README.md".to_string());
    let license_path = discover_license_file(root);
    let github = if is_git_repository {
        detect_github_repository(root)?
    } else {
        None
    };

    Ok(RepositoryMetadata {
        is_git_repository,
        readme_path,
        license_path,
        workflow_files,
        github,
    })
}

fn is_git_repository(root: &Path) -> Result<bool> {
    let output = match std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["rev-parse", "--is-inside-work-tree"])
        .output()
    {
        Ok(output) => output,
        Err(_) => return Ok(false),
    };
    Ok(output.status.success()
        && String::from_utf8_lossy(&output.stdout)
            .trim()
            .eq_ignore_ascii_case("true"))
}

fn discover_license_file(root: &Path) -> Option<String> {
    for candidate in [
        "LICENSE",
        "LICENSE.md",
        "LICENSE.txt",
        "LICENSE-MIT",
        "LICENSE-APACHE",
        "LICENCE",
        "LICENCE.md",
        "COPYING",
        "UNLICENSE",
    ] {
        if root.join(candidate).is_file() {
            return Some(candidate.to_string());
        }
    }
    None
}

fn discover_workflow_files(root: &Path) -> Result<Vec<String>> {
    let workflows_dir = root.join(".github/workflows");
    if !workflows_dir.is_dir() {
        return Ok(Vec::new());
    }

    let mut files = Vec::new();
    for entry in fs::read_dir(&workflows_dir)
        .with_context(|| format!("failed to read {}", workflows_dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Some(extension) = path.extension().and_then(|value| value.to_str()) else {
            continue;
        };
        if !matches!(extension, "yml" | "yaml") {
            continue;
        }
        let relative = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .display()
            .to_string();
        files.push(relative);
    }
    files.sort();
    Ok(files)
}

fn detect_github_repository(root: &Path) -> Result<Option<GitHubRepository>> {
    for remote in git_remote_names(root)? {
        let Some(url) = git_remote_url(root, &remote)? else {
            continue;
        };
        let Some(slug) = parse_github_slug(&url) else {
            continue;
        };
        return Ok(Some(GitHubRepository {
            visibility: github_visibility(&slug),
            slug,
        }));
    }
    Ok(None)
}

fn git_remote_names(root: &Path) -> Result<Vec<String>> {
    let output = match std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .arg("remote")
        .output()
    {
        Ok(output) => output,
        Err(_) => return Ok(Vec::new()),
    };
    if !output.status.success() {
        return Ok(Vec::new());
    }

    let mut remotes = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>();
    remotes.sort_by_key(|name| if name == "origin" { 0 } else { 1 });
    Ok(remotes)
}

fn git_remote_url(root: &Path, remote: &str) -> Result<Option<String>> {
    let output = match std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["remote", "get-url", remote])
        .output()
    {
        Ok(output) => output,
        Err(_) => return Ok(None),
    };
    if !output.status.success() {
        return Ok(None);
    }
    let url = String::from_utf8_lossy(&output.stdout).trim().to_string();
    Ok((!url.is_empty()).then_some(url))
}

fn parse_github_slug(remote_url: &str) -> Option<String> {
    let trimmed = remote_url.trim().trim_end_matches('/');
    let without_git = trimmed.strip_suffix(".git").unwrap_or(trimmed);

    for prefix in [
        "https://github.com/",
        "http://github.com/",
        "ssh://git@github.com/",
        "git@github.com:",
    ] {
        if let Some(rest) = without_git.strip_prefix(prefix) {
            let mut parts = rest.split('/').filter(|part| !part.is_empty());
            let owner = parts.next()?;
            let repo = parts.next()?;
            if parts.next().is_none() {
                return Some(format!("{owner}/{repo}"));
            }
        }
    }

    None
}

fn github_visibility(slug: &str) -> GitHubVisibility {
    #[derive(Deserialize)]
    struct GitHubRepoApi {
        private: bool,
    }

    let client = match Client::builder()
        .user_agent(format!("explicit/{}", env!("CARGO_PKG_VERSION")))
        .timeout(std::time::Duration::from_secs(4))
        .build()
    {
        Ok(client) => client,
        Err(_) => return GitHubVisibility::Unknown,
    };

    let mut request = client.get(format!("https://api.github.com/repos/{slug}"));
    if let Some(token) = std::env::var("GITHUB_TOKEN")
        .ok()
        .or_else(|| std::env::var("GH_TOKEN").ok())
    {
        request = request.bearer_auth(token);
    }

    let response = match request.send() {
        Ok(response) => response,
        Err(_) => return GitHubVisibility::Unknown,
    };

    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return GitHubVisibility::Unknown;
    }
    if !response.status().is_success() {
        return GitHubVisibility::Unknown;
    }

    match response.json::<GitHubRepoApi>() {
        Ok(payload) if payload.private => GitHubVisibility::Private,
        Ok(_) => GitHubVisibility::Public,
        Err(_) => GitHubVisibility::Unknown,
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

fn analyze_common_files(
    root: &Path,
    builder: &mut Builder,
    context: &ProjectContext,
) -> Result<()> {
    javascript_heuristics::analyze(root, builder, context)?;

    let cargo_toml = root.join("Cargo.toml");
    if cargo_toml.exists() {
        builder.add_marker("Cargo.toml");
        builder.add_language(LanguageRequirement::Rust);
        builder.add_package("cargo-llvm-cov");
        builder.add_build("cargo build --release");
        builder.add_lint("cargo fmt --check");
        builder.add_lint("cargo clippy --all-targets --all-features -- -D warnings");
        builder.add_test("cargo test");
        builder.add_coverage(format!(
            "cargo llvm-cov --workspace --all-features --fail-under-lines {MINIMUM_COVERAGE_PERCENT} --summary-only"
        ));
    }

    let package_swift = root.join("Package.swift");
    if package_swift.is_file() {
        builder.add_marker("Package.swift");
        builder.add_package("swift");
        builder.add_build("swift build --disable-sandbox");
        builder.add_test("swift test --disable-sandbox");
        if package_swift_declares_macos_app(&package_swift)? {
            builder.add_note(
                "Detected a SwiftPM macOS app; adding the Swift toolchain plus macOS app install/build access. Xcode and Command Line Tools stay host-level dependencies.",
            );
        } else {
            builder
                .add_note("Detected a Swift Package Manager project; adding the Swift toolchain.");
        }
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

    elixir_heuristics::analyze(root, builder, context)?;
    ruby_heuristics::analyze(root, builder, context)?;
    php_heuristics::analyze(root, builder, context)?;

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

    python_heuristics::analyze(root, builder, context)?;

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

    if root.join("terragrunt.hcl").is_file() {
        builder.add_marker("terragrunt.hcl");
        builder.add_package("terragrunt");
        builder.add_lint("terragrunt hclfmt --check");
    } else if directory_has_direct_terraform_files(root)? {
        builder.add_marker("terraform");
        builder.add_package("opentofu");
        builder.add_lint("tofu fmt -check -recursive");
    }

    if project_uses_browser_tests(context) {
        builder.add_note(BROWSER_TEST_SANDBOX_NOTE);
    }

    Ok(())
}

fn project_uses_browser_tests(context: &ProjectContext) -> bool {
    has_any_dependency(
        context.dependencies("javascript"),
        &[
            "@playwright/test",
            "playwright",
            "cypress",
            "puppeteer",
            "puppeteer-core",
            "selenium-webdriver",
            "webdriverio",
            "@wdio/cli",
            "@wdio/local-runner",
            "nightwatch",
            "testcafe",
            "@web/test-runner",
            "web-test-runner",
        ],
    ) || has_any_dependency(context.dependencies("elixir"), &["wallaby", "hound"])
        || package_json_scripts_use_browser_tests(context.package_json())
}

fn has_any_dependency(dependencies: Option<&BTreeSet<String>>, expected: &[&str]) -> bool {
    let Some(dependencies) = dependencies else {
        return false;
    };
    expected.iter().any(|name| dependencies.contains(*name))
}

fn package_json_scripts_use_browser_tests(payload: Option<&serde_json::Value>) -> bool {
    let Some(scripts) = payload
        .and_then(|value| value.get("scripts"))
        .and_then(serde_json::Value::as_object)
    else {
        return false;
    };

    scripts.values().any(|value| {
        let Some(script) = value.as_str() else {
            return false;
        };
        let normalized = script.to_lowercase();
        normalized.contains("playwright")
            || normalized.contains("cypress")
            || normalized.contains("puppeteer")
            || normalized.contains("selenium")
            || normalized.contains("webdriverio")
            || normalized.contains("testcafe")
            || normalized.contains("nightwatch")
    })
}

fn apply_registry_matches(
    root: &Path,
    builder: &mut Builder,
    context: &ProjectContext,
) -> Result<()> {
    let matches = registry::detect_registry_matches_with_context(root, context)?;
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

fn detect_runtime_versions(
    root: &Path,
    builder: &Builder,
    context: &ProjectContext,
) -> Result<Vec<DetectedVersion>> {
    let tool_versions = parse_tool_versions(root)?;
    let mise_tools = parse_mise_tools(root)?;
    let mut detected = Vec::new();

    if (root.join("package.json").exists()
        || builder.languages.contains(&LanguageRequirement::JavaScript))
        && let Some(version) =
            detect_nodejs_version(root, &tool_versions, &mise_tools, context.package_json())?
    {
        detected.push(version);
    }

    if (root.join("Gemfile").exists()
        || root.join("Bundlefile").exists()
        || builder.languages.contains(&LanguageRequirement::Ruby))
        && let Some(version) = detect_ruby_version(root, &tool_versions, &mise_tools)?
    {
        detected.push(version);
    }

    if (root.join("pyproject.toml").exists()
        || root.join("requirements.txt").exists()
        || root.join("uv.lock").exists()
        || root.join("poetry.lock").exists()
        || builder.languages.contains(&LanguageRequirement::Python))
        && let Some(version) =
            detect_python_version(root, &tool_versions, &mise_tools, context.pyproject())?
    {
        detected.push(version);
    }

    if (root.join("go.mod").exists() || builder.languages.contains(&LanguageRequirement::Go))
        && let Some(version) = detect_go_version(root, &tool_versions, &mise_tools)?
    {
        detected.push(version);
    }

    if (root.join("Cargo.toml").exists() || builder.languages.contains(&LanguageRequirement::Rust))
        && let Some(version) = detect_rust_version(root, &tool_versions, &mise_tools)?
    {
        detected.push(version);
    }

    if (root.join("composer.json").exists()
        || builder.languages.contains(&LanguageRequirement::Php))
        && let Some(version) =
            detect_php_version(root, &tool_versions, &mise_tools, context.composer_json())?
    {
        detected.push(version);
    }

    if root.join("mix.exs").exists() || builder.languages.contains(&LanguageRequirement::Elixir) {
        if let Some(version) = detect_elixir_version(root, &tool_versions, &mise_tools)? {
            detected.push(version);
        }
        if let Some(version) = detect_erlang_version(root, &tool_versions, &mise_tools)? {
            detected.push(version);
        }
    }

    if (root.join("pom.xml").exists()
        || root.join("build.gradle").exists()
        || root.join("build.gradle.kts").exists()
        || root.join("gradlew").exists()
        || builder.languages.contains(&LanguageRequirement::Java))
        && let Some(version) = detect_java_version(root, &tool_versions, &mise_tools)?
    {
        detected.push(version);
    }

    detected.sort_by_key(|entry| (entry.runtime, entry.source.clone()));
    Ok(detected)
}

fn detect_nodejs_version(
    root: &Path,
    tool_versions: &BTreeMap<String, String>,
    mise_tools: &BTreeMap<String, String>,
    package_json: Option<&serde_json::Value>,
) -> Result<Option<DetectedVersion>> {
    if let Some(version) = read_version_file(root.join(".node-version"))? {
        return Ok(Some(DetectedVersion {
            runtime: RuntimeKind::Nodejs,
            version: version.clone(),
            source: ".node-version".to_string(),
            kind: numeric_version_kind(&version),
            config_lines: nodejs_config_lines(&version),
        }));
    }
    if let Some(version) = read_version_file(root.join(".nvmrc"))? {
        return Ok(Some(DetectedVersion {
            runtime: RuntimeKind::Nodejs,
            version: version.clone(),
            source: ".nvmrc".to_string(),
            kind: numeric_version_kind(&version),
            config_lines: nodejs_config_lines(&version),
        }));
    }
    if let Some(version) = tool_version(tool_versions, &["nodejs", "node"]) {
        return Ok(Some(DetectedVersion {
            runtime: RuntimeKind::Nodejs,
            version: version.clone(),
            source: ".tool-versions".to_string(),
            kind: numeric_version_kind(&version),
            config_lines: nodejs_config_lines(&version),
        }));
    }
    if let Some(version) = tool_version(mise_tools, &["nodejs", "node"]) {
        return Ok(Some(DetectedVersion {
            runtime: RuntimeKind::Nodejs,
            version: version.clone(),
            source: "mise.toml".to_string(),
            kind: numeric_version_kind(&version),
            config_lines: nodejs_config_lines(&version),
        }));
    }

    if let Some(payload) = package_json
        && let Some(version) = payload
            .get("engines")
            .and_then(|engines| engines.get("node"))
            .and_then(serde_json::Value::as_str)
            .map(clean_version_value)
            .filter(|value| !value.is_empty())
    {
        return Ok(Some(DetectedVersion {
            runtime: RuntimeKind::Nodejs,
            version,
            source: "package.json#engines.node".to_string(),
            kind: VersionKind::Constraint,
            config_lines: Vec::new(),
        }));
    }

    Ok(None)
}

fn detect_ruby_version(
    root: &Path,
    tool_versions: &BTreeMap<String, String>,
    mise_tools: &BTreeMap<String, String>,
) -> Result<Option<DetectedVersion>> {
    if let Some(version) = read_version_file(root.join(".ruby-version"))? {
        return Ok(Some(DetectedVersion {
            runtime: RuntimeKind::Ruby,
            version,
            source: ".ruby-version".to_string(),
            kind: VersionKind::Exact,
            config_lines: vec!["languages.ruby.versionFile = ./.ruby-version;".to_string()],
        }));
    }
    if let Some(version) = tool_version(tool_versions, &["ruby"]) {
        return Ok(Some(simple_version_pin(
            RuntimeKind::Ruby,
            version,
            ".tool-versions",
            "languages.ruby.version",
        )));
    }
    if let Some(version) = tool_version(mise_tools, &["ruby"]) {
        return Ok(Some(simple_version_pin(
            RuntimeKind::Ruby,
            version,
            "mise.toml",
            "languages.ruby.version",
        )));
    }

    let gemfile = root.join("Gemfile");
    if gemfile.exists() {
        let contents = fs::read_to_string(&gemfile)
            .with_context(|| format!("failed to read {}", gemfile.display()))?;
        let ruby_directive = Regex::new(r#"(?m)^\s*ruby\s+["']([^"']+)["']"#)?;
        if let Some(version) = ruby_directive
            .captures(&contents)
            .and_then(|captures| captures.get(1))
            .map(|value| clean_version_value(value.as_str()))
            .filter(|value| !value.is_empty())
        {
            return Ok(Some(DetectedVersion {
                runtime: RuntimeKind::Ruby,
                version,
                source: "Gemfile#ruby".to_string(),
                kind: VersionKind::Constraint,
                config_lines: Vec::new(),
            }));
        }
    }

    Ok(None)
}

fn detect_python_version(
    root: &Path,
    tool_versions: &BTreeMap<String, String>,
    mise_tools: &BTreeMap<String, String>,
    pyproject: Option<&TomlValue>,
) -> Result<Option<DetectedVersion>> {
    if let Some(version) = read_version_file(root.join(".python-version"))? {
        return Ok(Some(simple_version_pin(
            RuntimeKind::Python,
            version,
            ".python-version",
            "languages.python.version",
        )));
    }
    if let Some(version) = tool_version(tool_versions, &["python"]) {
        return Ok(Some(simple_version_pin(
            RuntimeKind::Python,
            version,
            ".tool-versions",
            "languages.python.version",
        )));
    }
    if let Some(version) = tool_version(mise_tools, &["python"]) {
        return Ok(Some(simple_version_pin(
            RuntimeKind::Python,
            version,
            "mise.toml",
            "languages.python.version",
        )));
    }
    let runtime_txt = root.join("runtime.txt");
    if runtime_txt.exists()
        && let Some(version) = read_version_file(&runtime_txt)?
            .map(|value| value.trim_start_matches("python-").to_string())
            .filter(|value| !value.is_empty())
    {
        return Ok(Some(simple_version_pin(
            RuntimeKind::Python,
            version,
            "runtime.txt",
            "languages.python.version",
        )));
    }

    if let Some(value) = pyproject
        && let Some(version) = value
            .get("project")
            .and_then(|project| project.get("requires-python"))
            .and_then(TomlValue::as_str)
            .map(clean_version_value)
            .filter(|value| !value.is_empty())
    {
        return Ok(Some(DetectedVersion {
            runtime: RuntimeKind::Python,
            version,
            source: "pyproject.toml#project.requires-python".to_string(),
            kind: VersionKind::Constraint,
            config_lines: Vec::new(),
        }));
    }

    Ok(None)
}

fn detect_go_version(
    root: &Path,
    tool_versions: &BTreeMap<String, String>,
    mise_tools: &BTreeMap<String, String>,
) -> Result<Option<DetectedVersion>> {
    if let Some(version) = read_version_file(root.join(".go-version"))? {
        return Ok(Some(simple_version_pin(
            RuntimeKind::Go,
            version,
            ".go-version",
            "languages.go.version",
        )));
    }

    let go_mod = root.join("go.mod");
    if go_mod.exists() {
        let contents = fs::read_to_string(&go_mod)
            .with_context(|| format!("failed to read {}", go_mod.display()))?;
        let toolchain = Regex::new(r"(?m)^toolchain\s+go([0-9][^\s]*)\s*$")?;
        if let Some(version) = toolchain
            .captures(&contents)
            .and_then(|captures| captures.get(1))
            .map(|value| clean_version_value(value.as_str()))
            .filter(|value| !value.is_empty())
        {
            return Ok(Some(simple_version_pin(
                RuntimeKind::Go,
                version,
                "go.mod#toolchain",
                "languages.go.version",
            )));
        }
        let go_directive = Regex::new(r"(?m)^go\s+([0-9][^\s]*)\s*$")?;
        if let Some(version) = go_directive
            .captures(&contents)
            .and_then(|captures| captures.get(1))
            .map(|value| clean_version_value(value.as_str()))
            .filter(|value| !value.is_empty())
        {
            return Ok(Some(simple_version_pin(
                RuntimeKind::Go,
                version,
                "go.mod#go",
                "languages.go.version",
            )));
        }
    }

    if let Some(version) = tool_version(tool_versions, &["golang", "go"]) {
        return Ok(Some(simple_version_pin(
            RuntimeKind::Go,
            version,
            ".tool-versions",
            "languages.go.version",
        )));
    }
    if let Some(version) = tool_version(mise_tools, &["golang", "go"]) {
        return Ok(Some(simple_version_pin(
            RuntimeKind::Go,
            version,
            "mise.toml",
            "languages.go.version",
        )));
    }

    Ok(None)
}

fn detect_rust_version(
    root: &Path,
    tool_versions: &BTreeMap<String, String>,
    mise_tools: &BTreeMap<String, String>,
) -> Result<Option<DetectedVersion>> {
    let toolchain_toml = root.join("rust-toolchain.toml");
    if toolchain_toml.exists() {
        let contents = fs::read_to_string(&toolchain_toml)
            .with_context(|| format!("failed to read {}", toolchain_toml.display()))?;
        let value = toml::from_str::<TomlValue>(&contents)
            .with_context(|| format!("failed to parse {}", toolchain_toml.display()))?;
        let channel = value
            .get("toolchain")
            .and_then(|toolchain| toolchain.get("channel"))
            .and_then(TomlValue::as_str)
            .map(clean_version_value)
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "configured in rust-toolchain.toml".to_string());
        return Ok(Some(DetectedVersion {
            runtime: RuntimeKind::Rust,
            version: channel,
            source: "rust-toolchain.toml".to_string(),
            kind: VersionKind::ToolchainFile,
            config_lines: vec!["languages.rust.toolchainFile = ./rust-toolchain.toml;".to_string()],
        }));
    }

    let toolchain = root.join("rust-toolchain");
    if toolchain.exists()
        && let Some(channel) = read_version_file(&toolchain)?.filter(|value| !value.is_empty())
    {
        return Ok(Some(DetectedVersion {
            runtime: RuntimeKind::Rust,
            version: channel,
            source: "rust-toolchain".to_string(),
            kind: VersionKind::ToolchainFile,
            config_lines: vec!["languages.rust.toolchainFile = ./rust-toolchain;".to_string()],
        }));
    }

    if let Some(version) = tool_version(tool_versions, &["rust"]) {
        return Ok(Some(DetectedVersion {
            runtime: RuntimeKind::Rust,
            version: version.clone(),
            source: ".tool-versions".to_string(),
            kind: numeric_version_kind(&version),
            config_lines: rust_config_lines(&version),
        }));
    }
    if let Some(version) = tool_version(mise_tools, &["rust"]) {
        return Ok(Some(DetectedVersion {
            runtime: RuntimeKind::Rust,
            version: version.clone(),
            source: "mise.toml".to_string(),
            kind: numeric_version_kind(&version),
            config_lines: rust_config_lines(&version),
        }));
    }

    let cargo_toml = root.join("Cargo.toml");
    if cargo_toml.exists() {
        let contents = fs::read_to_string(&cargo_toml)
            .with_context(|| format!("failed to read {}", cargo_toml.display()))?;
        let value = toml::from_str::<TomlValue>(&contents)
            .with_context(|| format!("failed to parse {}", cargo_toml.display()))?;
        if let Some(version) = value
            .get("package")
            .and_then(|package| package.get("rust-version"))
            .and_then(TomlValue::as_str)
            .map(clean_version_value)
            .filter(|value| !value.is_empty())
        {
            return Ok(Some(DetectedVersion {
                runtime: RuntimeKind::Rust,
                version,
                source: "Cargo.toml#package.rust-version".to_string(),
                kind: VersionKind::Constraint,
                config_lines: Vec::new(),
            }));
        }
    }

    Ok(None)
}

fn detect_php_version(
    root: &Path,
    tool_versions: &BTreeMap<String, String>,
    mise_tools: &BTreeMap<String, String>,
    composer_json: Option<&serde_json::Value>,
) -> Result<Option<DetectedVersion>> {
    if let Some(version) = read_version_file(root.join(".php-version"))? {
        return Ok(Some(simple_version_pin(
            RuntimeKind::Php,
            version,
            ".php-version",
            "languages.php.version",
        )));
    }
    if let Some(version) = tool_version(tool_versions, &["php"]) {
        return Ok(Some(simple_version_pin(
            RuntimeKind::Php,
            version,
            ".tool-versions",
            "languages.php.version",
        )));
    }
    if let Some(version) = tool_version(mise_tools, &["php"]) {
        return Ok(Some(simple_version_pin(
            RuntimeKind::Php,
            version,
            "mise.toml",
            "languages.php.version",
        )));
    }

    if let Some(payload) = composer_json {
        if let Some(version) = payload
            .get("config")
            .and_then(|config| config.get("platform"))
            .and_then(|platform| platform.get("php"))
            .and_then(serde_json::Value::as_str)
            .map(clean_version_value)
            .filter(|value| !value.is_empty())
        {
            let kind = numeric_version_kind(&version);
            return Ok(Some(DetectedVersion {
                runtime: RuntimeKind::Php,
                version: version.clone(),
                source: "composer.json#config.platform.php".to_string(),
                kind,
                config_lines: if kind == VersionKind::Exact {
                    vec![format!(r#"languages.php.version = "{version}";"#)]
                } else {
                    Vec::new()
                },
            }));
        }
        if let Some(version) = payload
            .get("require")
            .and_then(|require| require.get("php"))
            .and_then(serde_json::Value::as_str)
            .map(clean_version_value)
            .filter(|value| !value.is_empty())
        {
            return Ok(Some(DetectedVersion {
                runtime: RuntimeKind::Php,
                version,
                source: "composer.json#require.php".to_string(),
                kind: VersionKind::Constraint,
                config_lines: Vec::new(),
            }));
        }
    }

    Ok(None)
}

fn detect_elixir_version(
    root: &Path,
    tool_versions: &BTreeMap<String, String>,
    mise_tools: &BTreeMap<String, String>,
) -> Result<Option<DetectedVersion>> {
    if let Some(version) = tool_version(tool_versions, &["elixir"]) {
        return Ok(Some(DetectedVersion {
            runtime: RuntimeKind::Elixir,
            version,
            source: ".tool-versions".to_string(),
            kind: VersionKind::Exact,
            config_lines: Vec::new(),
        }));
    }
    if let Some(version) = tool_version(mise_tools, &["elixir"]) {
        return Ok(Some(DetectedVersion {
            runtime: RuntimeKind::Elixir,
            version,
            source: "mise.toml".to_string(),
            kind: VersionKind::Exact,
            config_lines: Vec::new(),
        }));
    }

    let mix_exs = root.join("mix.exs");
    if mix_exs.exists() {
        let contents = fs::read_to_string(&mix_exs)
            .with_context(|| format!("failed to read {}", mix_exs.display()))?;
        let elixir_requirement = Regex::new(r#"elixir:\s*["']([^"']+)["']"#)?;
        if let Some(version) = elixir_requirement
            .captures(&contents)
            .and_then(|captures| captures.get(1))
            .map(|value| clean_version_value(value.as_str()))
            .filter(|value| !value.is_empty())
        {
            return Ok(Some(DetectedVersion {
                runtime: RuntimeKind::Elixir,
                version,
                source: "mix.exs#elixir".to_string(),
                kind: VersionKind::Constraint,
                config_lines: Vec::new(),
            }));
        }
    }

    Ok(None)
}

fn detect_erlang_version(
    _root: &Path,
    tool_versions: &BTreeMap<String, String>,
    mise_tools: &BTreeMap<String, String>,
) -> Result<Option<DetectedVersion>> {
    if let Some(version) = tool_version(tool_versions, &["erlang", "otp"]) {
        return Ok(Some(DetectedVersion {
            runtime: RuntimeKind::Erlang,
            version,
            source: ".tool-versions".to_string(),
            kind: VersionKind::Exact,
            config_lines: Vec::new(),
        }));
    }
    if let Some(version) = tool_version(mise_tools, &["erlang", "otp"]) {
        return Ok(Some(DetectedVersion {
            runtime: RuntimeKind::Erlang,
            version,
            source: "mise.toml".to_string(),
            kind: VersionKind::Exact,
            config_lines: Vec::new(),
        }));
    }
    Ok(None)
}

fn detect_java_version(
    root: &Path,
    tool_versions: &BTreeMap<String, String>,
    mise_tools: &BTreeMap<String, String>,
) -> Result<Option<DetectedVersion>> {
    if let Some(version) = read_version_file(root.join(".java-version"))? {
        return Ok(Some(DetectedVersion {
            runtime: RuntimeKind::Java,
            version: version.clone(),
            source: ".java-version".to_string(),
            kind: numeric_version_kind(&version),
            config_lines: java_config_lines(&version),
        }));
    }

    let sdkman = root.join(".sdkmanrc");
    if sdkman.exists() {
        let contents = fs::read_to_string(&sdkman)
            .with_context(|| format!("failed to read {}", sdkman.display()))?;
        for line in contents.lines() {
            let trimmed = line.trim();
            if let Some(value) = trimmed.strip_prefix("java=") {
                let version = clean_version_value(value);
                if !version.is_empty() {
                    return Ok(Some(DetectedVersion {
                        runtime: RuntimeKind::Java,
                        version: version.clone(),
                        source: ".sdkmanrc".to_string(),
                        kind: numeric_version_kind(&version),
                        config_lines: java_config_lines(&version),
                    }));
                }
            }
        }
    }

    if let Some(version) = tool_version(tool_versions, &["java"]) {
        return Ok(Some(DetectedVersion {
            runtime: RuntimeKind::Java,
            version: version.clone(),
            source: ".tool-versions".to_string(),
            kind: numeric_version_kind(&version),
            config_lines: java_config_lines(&version),
        }));
    }
    if let Some(version) = tool_version(mise_tools, &["java"]) {
        return Ok(Some(DetectedVersion {
            runtime: RuntimeKind::Java,
            version: version.clone(),
            source: "mise.toml".to_string(),
            kind: numeric_version_kind(&version),
            config_lines: java_config_lines(&version),
        }));
    }

    Ok(None)
}

fn parse_tool_versions(root: &Path) -> Result<BTreeMap<String, String>> {
    let path = root.join(".tool-versions");
    if !path.exists() {
        return Ok(BTreeMap::new());
    }
    let contents =
        fs::read_to_string(&path).with_context(|| format!("failed to read {}", path.display()))?;
    let mut tools = BTreeMap::new();
    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let mut parts = trimmed.split_whitespace();
        let Some(tool) = parts.next() else {
            continue;
        };
        let Some(version) = parts.next() else {
            continue;
        };
        let version = clean_version_value(version);
        if !version.is_empty() {
            tools.insert(tool.to_lowercase(), version);
        }
    }
    Ok(tools)
}

fn parse_mise_tools(root: &Path) -> Result<BTreeMap<String, String>> {
    for candidate in [".mise.toml", "mise.toml"] {
        let path = root.join(candidate);
        if !path.exists() {
            continue;
        }
        let contents = fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        let value = toml::from_str::<TomlValue>(&contents)
            .with_context(|| format!("failed to parse {}", path.display()))?;
        let mut tools = BTreeMap::new();
        if let Some(entries) = value.get("tools").and_then(TomlValue::as_table) {
            for (tool, value) in entries {
                if let Some(version) = toml_tool_version(value) {
                    tools.insert(tool.to_lowercase(), version);
                }
            }
        }
        return Ok(tools);
    }
    Ok(BTreeMap::new())
}

fn toml_tool_version(value: &TomlValue) -> Option<String> {
    if let Some(version) = value.as_str() {
        let version = clean_version_value(version);
        return (!version.is_empty()).then_some(version);
    }
    if let Some(table) = value.as_table() {
        if let Some(version) = table.get("version").and_then(TomlValue::as_str) {
            let version = clean_version_value(version);
            return (!version.is_empty()).then_some(version);
        }
        if let Some(versions) = table.get("versions").and_then(TomlValue::as_array) {
            return versions
                .iter()
                .find_map(TomlValue::as_str)
                .map(clean_version_value)
                .filter(|version| !version.is_empty());
        }
    }
    if let Some(array) = value.as_array() {
        return array
            .iter()
            .find_map(TomlValue::as_str)
            .map(clean_version_value)
            .filter(|version| !version.is_empty());
    }
    None
}

fn tool_version(tools: &BTreeMap<String, String>, names: &[&str]) -> Option<String> {
    names
        .iter()
        .find_map(|name| tools.get(*name))
        .map(ToOwned::to_owned)
}

fn read_version_file(path: impl AsRef<Path>) -> Result<Option<String>> {
    let path = path.as_ref();
    if !path.exists() {
        return Ok(None);
    }
    let contents =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    Ok(contents
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty() && !line.starts_with('#'))
        .map(clean_version_value)
        .filter(|value| !value.is_empty()))
}

fn clean_version_value(raw: &str) -> String {
    let trimmed = raw
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .split('#')
        .next()
        .unwrap_or_default()
        .trim();
    trimmed
        .trim_start_matches("ruby-")
        .trim_start_matches("python-")
        .trim_start_matches('v')
        .trim()
        .to_string()
}

fn numeric_version_kind(version: &str) -> VersionKind {
    if version.chars().next().is_some_and(|ch| ch.is_ascii_digit()) {
        VersionKind::Exact
    } else {
        VersionKind::Constraint
    }
}

fn simple_version_pin(
    runtime: RuntimeKind,
    version: String,
    source: &str,
    option: &str,
) -> DetectedVersion {
    let kind = numeric_version_kind(&version);
    DetectedVersion {
        runtime,
        version: version.clone(),
        source: source.to_string(),
        kind,
        config_lines: if kind == VersionKind::Exact {
            vec![format!(r#"{option} = "{version}";"#)]
        } else {
            Vec::new()
        },
    }
}

fn nodejs_config_lines(version: &str) -> Vec<String> {
    major_version(version)
        .map(|major| {
            vec![format!(
                r#"languages.javascript.package = let attr = "nodejs_{major}"; in if builtins.hasAttr attr pkgs then builtins.getAttr attr pkgs else pkgs.nodejs;"#
            )]
        })
        .unwrap_or_default()
}

fn java_config_lines(version: &str) -> Vec<String> {
    major_version(version)
        .map(|major| {
            vec![format!(
                r#"languages.java.jdk.package = let attr = "jdk{major}"; in if builtins.hasAttr attr pkgs then builtins.getAttr attr pkgs else pkgs.jdk;"#
            )]
        })
        .unwrap_or_default()
}

fn rust_config_lines(version: &str) -> Vec<String> {
    if version.eq_ignore_ascii_case("stable")
        || version.eq_ignore_ascii_case("beta")
        || version.eq_ignore_ascii_case("nightly")
    {
        return vec![format!(
            r#"languages.rust.channel = "{}";"#,
            version.to_lowercase()
        )];
    }
    if version.chars().next().is_some_and(|ch| ch.is_ascii_digit()) {
        return vec![
            r#"languages.rust.channel = "stable";"#.to_string(),
            format!(r#"languages.rust.version = "{version}";"#),
        ];
    }
    Vec::new()
}

fn major_version(version: &str) -> Option<String> {
    let cleaned = clean_version_value(version);
    let digits = cleaned
        .chars()
        .skip_while(|ch| !ch.is_ascii_digit())
        .take_while(|ch| ch.is_ascii_digit())
        .collect::<String>();
    (!digits.is_empty()).then_some(digits)
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

fn detect_ruby_test_commands(
    root: &Path,
    dependencies: Option<&BTreeSet<String>>,
) -> Result<Vec<String>> {
    let dependencies = dependencies.cloned().unwrap_or_else(BTreeSet::new);
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

fn detect_phoenix_starter_page_requirement(
    root: &Path,
    dependencies: &BTreeSet<String>,
) -> Result<Option<ProjectRequirement>> {
    if !dependencies.contains("phoenix") {
        return Ok(None);
    }

    let Some(router_path) = find_first_relative_file(root, &|relative, _| {
        let normalized = relative.to_string_lossy().replace('\\', "/");
        normalized.starts_with("lib/") && normalized.ends_with("/router.ex")
    })?
    else {
        return Ok(None);
    };
    let router_contents = fs::read_to_string(root.join(&router_path))
        .with_context(|| format!("failed to read {}", root.join(&router_path).display()))?;
    let Some(action) = phoenix_default_home_action(&router_contents) else {
        return Ok(None);
    };

    let Some(template_path) = find_first_relative_file(root, &|relative, _| {
        let normalized = relative.to_string_lossy().replace('\\', "/");
        normalized.starts_with("lib/")
            && (normalized.contains("/page_html/") || normalized.contains("/templates/page/"))
    })?
    else {
        return Ok(None);
    };

    let template_file_name = template_path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default();
    if !matches!(
        (action, template_file_name),
        ("home", "home.html.heex")
            | ("home", "home.html.eex")
            | ("index", "index.html.heex")
            | ("index", "index.html.eex")
    ) {
        return Ok(None);
    }

    let template_contents = fs::read_to_string(root.join(&template_path))
        .with_context(|| format!("failed to read {}", root.join(&template_path).display()))?;
    if !looks_like_default_phoenix_home_page(&template_contents) {
        return Ok(None);
    }

    Ok(Some(ProjectRequirement {
        kind: RequirementKind::Starter,
        subject: display_relative_path(&template_path),
        summary: "Phoenix projects must replace the default getting started home page before using the generated stop hook.".to_string(),
    }))
}

fn detect_rails_starter_page_requirement(
    root: &Path,
    dependencies: &BTreeSet<String>,
) -> Result<Option<ProjectRequirement>> {
    let has_rails = dependencies.contains("rails") || root.join("bin/rails").exists();
    if !has_rails || rails_project_is_api_only(root)? {
        return Ok(None);
    }

    let routes_path = root.join("config/routes.rb");
    if !routes_path.is_file() {
        return Ok(None);
    }
    let routes = fs::read_to_string(&routes_path)
        .with_context(|| format!("failed to read {}", routes_path.display()))?;
    if rails_routes_define_root(&routes) {
        return Ok(None);
    }

    Ok(Some(ProjectRequirement {
        kind: RequirementKind::Starter,
        subject: "config/routes.rb".to_string(),
        summary: "Rails projects must replace the generated getting started page by defining a real root route.".to_string(),
    }))
}

fn detect_elixir_coverage_requirement(root: &Path) -> Result<Option<ProjectRequirement>> {
    let mix_exs = root.join("mix.exs");
    let contents = fs::read_to_string(&mix_exs)
        .with_context(|| format!("failed to read {}", mix_exs.display()))?;
    let Some(config) = extract_elixir_test_coverage_config(&contents) else {
        return Ok(None);
    };

    if elixir_coverage_summary_is_disabled(config) {
        return Ok(Some(ProjectRequirement {
            kind: RequirementKind::Coverage,
            subject: "mix.exs#test_coverage".to_string(),
            summary: format!(
                "Elixir projects must keep `mix test --cover` coverage enforcement enabled with a summary threshold of at least {MINIMUM_COVERAGE_PERCENT}%."
            ),
        }));
    }

    let Some(threshold) = elixir_coverage_threshold(config) else {
        return Ok(None);
    };
    if threshold >= f32::from(MINIMUM_COVERAGE_PERCENT) {
        return Ok(None);
    }

    Ok(Some(ProjectRequirement {
        kind: RequirementKind::Coverage,
        subject: "mix.exs#test_coverage".to_string(),
        summary: format!(
            "Elixir projects must enforce at least {MINIMUM_COVERAGE_PERCENT}% test coverage; `mix.exs` configures {threshold:.1}%."
        ),
    }))
}

fn extract_elixir_test_coverage_config(contents: &str) -> Option<&str> {
    let start = contents.find("test_coverage:")?;
    let body = &contents[start..];
    let open = body.find('[')?;
    let mut depth = 0usize;
    let mut end_offset = None;
    for (index, ch) in body[open..].char_indices() {
        match ch {
            '[' => depth += 1,
            ']' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    end_offset = Some(open + index + ch.len_utf8());
                    break;
                }
            }
            _ => {}
        }
    }
    end_offset.map(|end| &body[..end])
}

fn elixir_coverage_summary_is_disabled(config: &str) -> bool {
    Regex::new(r#"summary\s*:\s*false\b"#)
        .ok()
        .is_some_and(|regex| regex.is_match(config))
}

fn elixir_coverage_threshold(config: &str) -> Option<f32> {
    let regex = Regex::new(r#"threshold\s*:\s*(\d+(?:\.\d+)?)"#).ok()?;
    let captures = regex.captures(config)?;
    captures.get(1)?.as_str().parse::<f32>().ok()
}

fn phoenix_default_home_action(router_contents: &str) -> Option<&'static str> {
    let regex = Regex::new(r#"get\s+["']/["']\s*,\s*PageController\s*,\s*:(home|index)\b"#).ok()?;
    for line in router_contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some(captures) = regex.captures(line) else {
            continue;
        };
        let action = captures.get(1)?.as_str();
        return match action {
            "home" => Some("home"),
            "index" => Some("index"),
            _ => None,
        };
    }
    None
}

fn looks_like_default_phoenix_home_page(contents: &str) -> bool {
    let normalized = contents.to_lowercase();
    (normalized.contains("peace of mind from prototype to production")
        && normalized
            .contains("a productive framework that does not compromise speed or maintainability"))
        || (normalized.contains("welcome to phoenix!") && normalized.contains("phoenix framework"))
}

fn rails_project_is_api_only(root: &Path) -> Result<bool> {
    let application_path = root.join("config/application.rb");
    if application_path.is_file() {
        let contents = fs::read_to_string(&application_path)
            .with_context(|| format!("failed to read {}", application_path.display()))?;
        if contents.contains("config.api_only = true") {
            return Ok(true);
        }
    }

    let application_controller = root.join("app/controllers/application_controller.rb");
    if application_controller.is_file() {
        let contents = fs::read_to_string(&application_controller)
            .with_context(|| format!("failed to read {}", application_controller.display()))?;
        if contents.contains("ActionController::API") {
            return Ok(true);
        }
    }

    Ok(false)
}

fn rails_routes_define_root(routes: &str) -> bool {
    let regex = Regex::new(r#"\broot\s+(?:["'][^"']+["']|to:\s*["'][^"']+["'])"#)
        .expect("root route regex must compile");
    routes.lines().any(|line| {
        let line = line.trim();
        !line.is_empty() && !line.starts_with('#') && regex.is_match(line)
    })
}

fn find_first_relative_file(
    start: &Path,
    predicate: &dyn Fn(&Path, &Path) -> bool,
) -> Result<Option<PathBuf>> {
    if !start.is_dir() {
        return Ok(None);
    }
    find_first_relative_file_impl(start, start, predicate)
}

fn find_first_relative_file_impl(
    base: &Path,
    current: &Path,
    predicate: &dyn Fn(&Path, &Path) -> bool,
) -> Result<Option<PathBuf>> {
    let mut entries = fs::read_dir(current)
        .with_context(|| format!("failed to read {}", current.display()))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.path());

    for entry in entries {
        let path = entry.path();
        let relative = path.strip_prefix(base).unwrap_or(&path);
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            if let Some(found) = find_first_relative_file_impl(base, &path, predicate)? {
                return Ok(Some(found));
            }
            continue;
        }
        if file_type.is_file() && predicate(relative, &path) {
            return Ok(Some(relative.to_path_buf()));
        }
    }

    Ok(None)
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

fn detect_javascript_dev_server_command(
    dependencies: &BTreeSet<String>,
    scripts: &serde_json::Map<String, serde_json::Value>,
    runner: &str,
) -> Option<String> {
    let dev_script = scripts.get("dev")?.as_str()?;
    if script_is_placeholder(dev_script) {
        return None;
    }

    let known_dev_server = [
        "next",
        "vite",
        "nuxt",
        "astro",
        "@remix-run/dev",
        "@sveltejs/kit",
        "@angular/cli",
    ]
    .into_iter()
    .any(|dependency| dependencies.contains(dependency));

    if known_dev_server {
        return Some(format!("{runner} dev"));
    }

    None
}

fn script_is_placeholder(script: &str) -> bool {
    let normalized = script.to_lowercase();
    normalized.contains("no test specified")
}

fn script_is_verification_ready(name: &str, script: &str) -> bool {
    if script_is_placeholder(script) {
        return false;
    }

    let normalized_name = name.to_lowercase();
    let normalized_script = script.to_lowercase();

    if normalized_name.contains("debug")
        || normalized_name.contains("watch")
        || normalized_name.contains("inspect")
    {
        return false;
    }

    if normalized_script.contains("--inspect")
        || normalized_script.contains("--inspect-brk")
        || normalized_script.contains("--watch")
        || normalized_script.contains("--watchall")
        || normalized_script.contains("cypress open")
        || normalized_script.contains("playwright test --ui")
        || normalized_script.contains("vitest --ui")
    {
        return false;
    }

    true
}

fn build_sandbox_plan(root: &Path, builder: &Builder) -> Result<SandboxPlan> {
    let home = dirs::home_dir().context("failed to resolve home directory")?;
    let configured_paths = configured_sandbox_paths(root)?;
    let mut read_write_files = BTreeSet::new();
    let mut read_write_dirs = BTreeSet::new();
    let mut read_only_files = BTreeSet::new();
    let mut read_only_dirs = BTreeSet::new();
    let mut protected_write_files = BTreeSet::new();

    read_write_dirs.insert(root.to_path_buf());
    read_write_dirs.insert(root.join(".devenv"));
    read_write_dirs.insert(root.join(".nono"));
    read_write_dirs.insert(root.join(".codex"));
    read_write_dirs.insert(root.join(".claude"));
    read_write_dirs.insert(home.join(".codex"));
    read_write_dirs.insert(home.join(".claude"));
    if let Some(parent) = root.parent() {
        insert_path_with_realpath(&mut read_only_dirs, parent.to_path_buf());
    }
    for path in platform_agent_read_write_paths(&home) {
        if path.is_file() {
            read_write_files.insert(path);
        } else {
            read_write_dirs.insert(path);
        }
    }
    for path in platform_agent_read_only_paths(&home) {
        insert_read_only_path_with_realpath(&mut read_only_files, &mut read_only_dirs, path);
    }
    for path in referenced_instruction_paths(root)? {
        if path.is_file() {
            read_only_files.insert(path);
        } else {
            read_only_dirs.insert(path);
        }
    }

    for path in standard_device_read_write_paths() {
        read_write_files.insert(path);
    }

    for path in standard_temp_read_write_paths() {
        insert_path_with_realpath(&mut read_write_dirs, path);
    }

    for language in &builder.languages {
        for path in language.default_cache_dirs(&home) {
            read_write_dirs.insert(path);
        }
    }

    if builder.markers.contains("Package.swift") {
        for path in macos_swift_read_write_paths(&home) {
            if path.is_file() {
                read_write_files.insert(path);
            } else {
                insert_path_with_realpath(&mut read_write_dirs, path);
            }
        }
        for path in macos_swift_read_only_paths() {
            if path.is_file() {
                read_only_files.insert(path);
            } else {
                read_only_dirs.insert(path);
            }
        }
    }

    if builder
        .notes
        .iter()
        .any(|note| note == BROWSER_TEST_SANDBOX_NOTE)
    {
        for path in macos_browser_test_read_write_paths(&home) {
            if path.is_file() {
                read_write_files.insert(path);
            } else {
                insert_path_with_realpath(&mut read_write_dirs, path);
            }
        }
        for path in macos_browser_test_read_only_paths() {
            insert_read_only_path_with_realpath(&mut read_only_files, &mut read_only_dirs, path);
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

    let mut host_commands = vec![
        "bash", "sh", "env", "git", "devenv", "codex", "claude", "gemini",
    ];
    if builder.markers.contains("Package.swift") {
        host_commands.extend([
            "swift",
            "xcrun",
            "xcodebuild",
            "open",
            "osascript",
            "hdiutil",
            "installer",
            "pkgutil",
            "ditto",
            "codesign",
            "spctl",
            "mas",
        ]);
    }

    for command in host_commands {
        for path in host_command_paths(command) {
            if let Some(parent) = path.parent() {
                read_only_dirs.insert(parent.to_path_buf());
            }
        }
        for path in host_command_support_dirs(command) {
            read_only_dirs.insert(path);
        }
    }

    if let Ok(shell) = std::env::var("SHELL")
        && let Some(parent) = Path::new(&shell).parent()
    {
        read_only_dirs.insert(parent.to_path_buf());
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
            insert_path_with_realpath(&mut read_write_dirs, path);
        }
    }

    if let Ok(address) = std::env::var("DBUS_SESSION_BUS_ADDRESS")
        && let Some(path) = address.strip_prefix("unix:path=")
        && let Some(parent) = Path::new(path).parent()
    {
        insert_path_with_realpath(&mut read_write_dirs, parent.to_path_buf());
    }

    for path in configured_paths.read_write_files {
        read_write_files.insert(path);
    }
    for path in configured_paths.read_write_dirs {
        read_write_dirs.insert(path);
    }
    for path in configured_paths.read_only_files {
        read_only_files.insert(path);
    }
    for path in configured_paths.read_only_dirs {
        read_only_dirs.insert(path);
    }
    let explicit_config = root.join(EXPLICIT_CONFIG_FILE);
    if explicit_config.is_file() {
        read_write_files.remove(&explicit_config);
        read_only_files.insert(explicit_config.clone());
        protected_write_files.insert(explicit_config);
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
    let protected_write_files = protected_write_files
        .into_iter()
        .filter(|path| path.exists())
        .collect::<Vec<_>>();

    Ok(SandboxPlan {
        root: root.to_path_buf(),
        read_write_files,
        read_write_dirs,
        read_only_files,
        read_only_dirs,
        protected_write_files,
        notes: builder.notes.clone(),
    })
}

fn standard_device_read_write_paths() -> Vec<PathBuf> {
    vec![
        PathBuf::from("/dev/null"),
        PathBuf::from("/dev/tty"),
        PathBuf::from("/dev/stdin"),
        PathBuf::from("/dev/stdout"),
        PathBuf::from("/dev/stderr"),
    ]
}

fn standard_temp_read_write_paths() -> Vec<PathBuf> {
    vec![
        PathBuf::from("/tmp"),
        PathBuf::from("/private/tmp"),
        PathBuf::from("/var/folders"),
        PathBuf::from("/private/var/folders"),
    ]
}

fn macos_swift_read_write_paths(home: &Path) -> Vec<PathBuf> {
    vec![
        home.join("Applications"),
        home.join("Downloads"),
        home.join("Library/Caches/Homebrew"),
        home.join("Library/Caches/org.swift.swiftpm"),
        home.join("Library/org.swift.swiftpm"),
        home.join("Library/Developer"),
    ]
}

fn macos_swift_read_only_paths() -> Vec<PathBuf> {
    let mut paths = vec![
        PathBuf::from("/Applications"),
        PathBuf::from("/Library/Developer"),
        PathBuf::from("/Library/Frameworks"),
    ];
    if let Some(developer_dir) = std::process::Command::new("xcode-select")
        .arg("-p")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|stdout| stdout.trim().to_string())
        .filter(|stdout| !stdout.is_empty())
    {
        paths.push(PathBuf::from(developer_dir));
    }
    paths
}

fn package_swift_declares_macos_app(path: &Path) -> Result<bool> {
    let contents =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    let normalized = contents.replace(char::is_whitespace, "");
    Ok(normalized.contains("platforms:[.macOS(")
        || normalized.contains("platforms:[.macos(")
        || normalized.contains("importSwiftUI")
        || normalized.contains("importAppKit"))
}

fn insert_path_with_realpath(paths: &mut BTreeSet<PathBuf>, path: PathBuf) {
    paths.insert(path.clone());
    if let Ok(real_path) = fs::canonicalize(&path) {
        paths.insert(real_path);
    }
}

fn insert_read_only_path_with_realpath(
    files: &mut BTreeSet<PathBuf>,
    dirs: &mut BTreeSet<PathBuf>,
    path: PathBuf,
) {
    let metadata = fs::symlink_metadata(&path).ok();
    if metadata
        .as_ref()
        .is_some_and(|metadata| metadata.file_type().is_symlink())
        && let Ok(real_path) = fs::canonicalize(&path)
    {
        insert_read_only_path_with_realpath(files, dirs, real_path);
    }

    if path.is_file() {
        files.insert(path);
    } else {
        dirs.insert(path);
    }
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
        home.join(".gemini"),
        home.join(".config/claude"),
        home.join(".config/claude-code"),
        home.join(".config/Anthropic"),
        home.join(".config/codex"),
        home.join(".config/gemini"),
        home.join(".cache/claude"),
        home.join(".cache/claude-code"),
        home.join(".cache/Anthropic"),
        home.join(".cache/codex"),
        home.join(".cache/gemini"),
        home.join(".cache/nix"),
        home.join(".local/share/claude"),
        home.join(".local/share/claude-code"),
        home.join(".local/share/Anthropic"),
        home.join(".local/share/codex"),
        home.join(".local/share/gemini"),
        home.join(".npm"),
        home.join(".pnpm-store"),
        home.join(".bun"),
        home.join(".local/share/pnpm"),
        home.join(".local/share/npm"),
    ]
}

fn generic_agent_read_only_paths(home: &Path) -> Vec<PathBuf> {
    vec![
        home.join(".agents"),
        home.join(".profile"),
        home.join(".bash_profile"),
        home.join(".bash_login"),
        home.join(".bashrc"),
        home.join(".zprofile"),
        home.join(".zshrc"),
        home.join(".zshenv"),
        home.join(".gitconfig"),
        home.join(".gitignore"),
        home.join(".gitignore_global"),
        home.join(".config/git"),
    ]
}

fn macos_agent_read_write_paths(home: &Path) -> Vec<PathBuf> {
    vec![
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
        home.join("Library/Preferences"),
        PathBuf::from("/etc/ssl/cert.pem"),
        PathBuf::from("/etc/ssl/certs/ca-certificates.crt"),
        PathBuf::from("/Library/Keychains"),
        PathBuf::from("/System/Library/Keychains"),
        PathBuf::from("/var/select"),
        PathBuf::from("/private/var/select"),
    ]
}

fn linux_agent_read_write_paths(_home: &Path) -> Vec<PathBuf> {
    Vec::new()
}

fn macos_browser_test_read_only_paths() -> Vec<PathBuf> {
    vec![
        PathBuf::from("/Applications/Google Chrome.app"),
        PathBuf::from("/Applications/Google Chrome for Testing.app"),
        PathBuf::from("/Applications/Chromium.app"),
    ]
}

fn macos_browser_test_read_write_paths(home: &Path) -> Vec<PathBuf> {
    vec![
        home.join("Library/Application Support/Google/Chrome/Crashpad"),
        home.join("Library/Application Support/Google/Chrome for Testing/Crashpad"),
        home.join("Library/Application Support/Chromium/Crashpad"),
    ]
}

fn linux_agent_read_only_paths(_home: &Path) -> Vec<PathBuf> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::{
        Analysis, BROWSER_TEST_SANDBOX_NOTE, Builder, EXPLICIT_CONFIG_FILE, LanguageRequirement,
        MINIMUM_COVERAGE_PERCENT, NO_COMMANDS_NOTE, RepositoryMetadata, RequirementKind,
        RuntimeKind, SUPPORT_PACKAGES, SandboxPlan, build_sandbox_plan, configured_sandbox_paths,
        expand_config_path_value, fallback_javascript_test_commands, insert_path_with_realpath,
        insert_read_only_path_with_realpath, macos_browser_test_read_only_paths,
        macos_browser_test_read_write_paths, platform_agent_read_only_paths,
        platform_agent_read_write_paths, referenced_instruction_paths, script_is_placeholder,
        script_is_verification_ready, standard_device_read_write_paths,
        standard_temp_read_write_paths,
    };
    use std::{collections::BTreeSet, fs, os::unix::fs::symlink, path::PathBuf};
    use tempfile::tempdir;

    #[test]
    fn doctor_packages_hide_support_packages() {
        let analysis = Analysis {
            root: PathBuf::from("/tmp/project"),
            markers: Vec::new(),
            manifests: Vec::new(),
            install_directories: Vec::new(),
            detected_languages: Vec::new(),
            detected_versions: Vec::new(),
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
            deploy_hosts: Vec::new(),
            deploy_use_ssh_agent: false,
            deploy_ssh_agent_hosts: Vec::new(),
            dev_server_commands: Vec::new(),
            lint_commands: Vec::new(),
            build_commands: Vec::new(),
            test_commands: Vec::new(),
            coverage_commands: Vec::new(),
            required_checks: Vec::new(),
            migration_checks: Vec::new(),
            notes: Vec::new(),
            repository: RepositoryMetadata::default(),
            sandbox_plan: SandboxPlan {
                root: PathBuf::from("/tmp/project"),
                read_write_files: Vec::new(),
                read_write_dirs: Vec::new(),
                read_only_files: Vec::new(),
                read_only_dirs: Vec::new(),
                protected_write_files: Vec::new(),
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
    fn ignores_non_verification_test_scripts() {
        assert!(!script_is_verification_ready(
            "test:debug",
            "node --inspect-brk node_modules/jest/bin/jest.js --runInBand"
        ));
        assert!(!script_is_verification_ready(
            "test:watch",
            "vitest --watch"
        ));
        assert!(script_is_verification_ready("test", "npx jest"));
        assert!(script_is_verification_ready("test:unit", "vitest run"));
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
    fn nextjs_projects_add_dev_server_command() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{
  "name": "web",
  "dependencies": {
    "next": "15.0.0"
  },
  "scripts": {
    "dev": "next dev",
    "build": "next build",
    "lint": "next lint"
  }
}"#,
        )
        .unwrap();

        let analysis = Analysis::analyze(dir.path()).unwrap();
        assert_eq!(
            analysis.dev_server_commands,
            vec!["npm run dev".to_string()]
        );
    }

    #[test]
    fn analysis_skips_debug_test_scripts() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{
                "name":"demo",
                "scripts":{
                    "test":"npx jest",
                    "test:debug":"node --inspect-brk node_modules/jest/bin/jest.js --runInBand"
                }
            }"#,
        )
        .unwrap();
        fs::write(dir.path().join("yarn.lock"), "").unwrap();

        let analysis = Analysis::analyze(dir.path()).unwrap();
        assert_eq!(analysis.test_commands, vec!["yarn test".to_string()]);
    }

    #[test]
    fn adds_agent_support_paths() {
        let home = PathBuf::from("/Users/tester");
        let read_write = platform_agent_read_write_paths(&home);
        let read_only = platform_agent_read_only_paths(&home);
        assert!(read_write.contains(&home.join(".config/codex")));
        assert!(read_write.contains(&home.join(".gemini")));
        assert!(read_write.contains(&home.join(".config/gemini")));
        assert!(read_write.contains(&home.join(".cache/codex")));
        assert!(read_write.contains(&home.join(".cache/gemini")));
        assert!(read_write.contains(&home.join(".cache/nix")));
        assert!(read_write.contains(&home.join(".local/share/codex")));
        assert!(read_write.contains(&home.join(".local/share/gemini")));
        assert!(read_write.contains(&home.join(".npm")));
        assert!(read_write.contains(&PathBuf::from("/var/run")));
        assert!(read_only.contains(&home.join(".gitconfig")));
        assert!(read_only.contains(&home.join(".agents")));
        assert!(read_only.contains(&home.join(".profile")));
        assert!(read_only.contains(&home.join(".zshrc")));
        assert!(read_only.contains(&home.join(".config/git")));
        assert!(read_only.contains(&home.join("Library/Preferences")));
        assert!(read_only.contains(&PathBuf::from("/etc/ssl/cert.pem")));
        assert!(read_only.contains(&PathBuf::from("/etc/ssl/certs/ca-certificates.crt")));
        assert!(read_only.contains(&PathBuf::from("/Library/Keychains")));
        assert!(read_only.contains(&PathBuf::from("/var/select")));
        assert!(read_only.contains(&PathBuf::from("/private/var/select")));
    }

    #[test]
    fn browser_test_paths_include_google_chrome() {
        let paths = macos_browser_test_read_only_paths();
        assert!(paths.contains(&PathBuf::from("/Applications/Google Chrome.app")));
    }

    #[test]
    fn browser_test_paths_include_chrome_crashpad() {
        let home = PathBuf::from("/Users/tester");
        let paths = macos_browser_test_read_write_paths(&home);
        assert!(paths.contains(&home.join("Library/Application Support/Google/Chrome/Crashpad")));
    }

    #[test]
    fn read_only_path_helper_adds_symlink_realpath_target() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("ca-certificates.crt");
        fs::write(&target, "demo").unwrap();
        let link = dir.path().join("cert.pem");
        symlink(&target, &link).unwrap();

        let mut files = BTreeSet::new();
        let mut dirs = BTreeSet::new();
        insert_read_only_path_with_realpath(&mut files, &mut dirs, link.clone());

        let canonical_target = fs::canonicalize(&target).unwrap();
        assert!(files.contains(&link));
        assert!(files.contains(&canonical_target));
        assert!(dirs.is_empty());
    }

    #[test]
    fn playwright_projects_gain_browser_app_access_note() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{
  "name": "browser-tests",
  "devDependencies": {
    "@playwright/test": "^1.50.0"
  }
}"#,
        )
        .unwrap();

        let analysis = Analysis::analyze(dir.path()).unwrap();
        assert!(
            analysis
                .notes
                .iter()
                .any(|note| note == BROWSER_TEST_SANDBOX_NOTE)
        );
    }

    #[test]
    fn wallaby_projects_gain_browser_app_access_note() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("mix.exs"),
            r#"defmodule Demo.MixProject do
  use Mix.Project

  def project do
    [
      app: :demo,
      version: "0.1.0",
      elixir: "~> 1.17",
      deps: deps()
    ]
  end

  def application do
    [extra_applications: [:logger]]
  end

  defp deps do
    [
      {:wallaby, "~> 0.30", only: :test}
    ]
  end
end
"#,
        )
        .unwrap();

        let analysis = Analysis::analyze(dir.path()).unwrap();
        assert!(
            analysis
                .notes
                .iter()
                .any(|note| note == BROWSER_TEST_SANDBOX_NOTE)
        );
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

    #[test]
    fn includes_standard_device_nodes_in_read_write_files() {
        let device_paths = standard_device_read_write_paths();
        assert!(device_paths.contains(&PathBuf::from("/dev/null")));

        let dir = tempdir().unwrap();
        let plan = build_sandbox_plan(dir.path(), &Builder::default()).unwrap();
        assert!(plan.read_write_files.contains(&PathBuf::from("/dev/null")));
    }

    #[test]
    fn includes_tmp_in_default_read_write_paths() {
        let temp_paths = standard_temp_read_write_paths();
        assert!(temp_paths.contains(&PathBuf::from("/tmp")));
        assert!(temp_paths.contains(&PathBuf::from("/private/tmp")));
        assert!(temp_paths.contains(&PathBuf::from("/var/folders")));
        assert!(temp_paths.contains(&PathBuf::from("/private/var/folders")));

        let dir = tempdir().unwrap();
        let plan = build_sandbox_plan(dir.path(), &Builder::default()).unwrap();
        assert!(plan.read_write_dirs.contains(&PathBuf::from("/tmp")));
    }

    #[test]
    fn sandbox_plan_includes_repo_parent_for_sibling_discovery() {
        let dir = tempdir().unwrap();
        let repo = dir.path().join("repo");
        fs::create_dir_all(&repo).unwrap();

        let plan = build_sandbox_plan(&repo, &Builder::default()).unwrap();
        assert!(plan.read_only_dirs.contains(&dir.path().to_path_buf()));
    }

    #[test]
    fn swiftpm_projects_gain_macos_app_access_paths() {
        let home = dirs::home_dir().expect("expected home dir");
        let applications = home.join("Applications");
        fs::create_dir_all(&applications).unwrap();

        let dir = tempdir().unwrap();
        fs::create_dir_all(dir.path().join("Sources")).unwrap();
        fs::write(
            dir.path().join("Package.swift"),
            r#"// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "Demo",
    platforms: [.macOS(.v14)],
    products: [.executable(name: "Demo", targets: ["Demo"])],
    targets: [.executableTarget(name: "Demo", path: "Sources")]
)
"#,
        )
        .unwrap();

        let analysis = Analysis::analyze(dir.path()).unwrap();
        assert!(analysis.packages.contains(&"swift".to_string()));
        assert!(
            analysis
                .notes
                .iter()
                .any(|note| note.contains("SwiftPM macOS app"))
        );
        assert!(
            analysis
                .sandbox_plan
                .read_write_dirs
                .contains(&applications)
        );
    }

    #[test]
    fn insert_path_with_realpath_keeps_both_aliases() {
        let dir = tempdir().unwrap();
        let real_dir = dir.path().join("real");
        fs::create_dir_all(&real_dir).unwrap();
        let alias_dir = dir.path().join("alias");
        std::os::unix::fs::symlink(&real_dir, &alias_dir).unwrap();

        let mut paths = BTreeSet::new();
        insert_path_with_realpath(&mut paths, alias_dir.clone());

        assert!(paths.contains(&alias_dir));
        assert!(paths.contains(&fs::canonicalize(&alias_dir).unwrap()));
    }

    #[test]
    fn elixir_default_cache_dirs_include_elixir_make_cache() {
        let home = PathBuf::from("/tmp/home");
        let dirs = LanguageRequirement::Elixir.default_cache_dirs(&home);
        assert!(dirs.contains(&home.join(".mix")));
        assert!(dirs.contains(&home.join(".hex")));
        assert!(dirs.contains(&home.join("Library/Caches/elixir_make")));
    }

    #[test]
    fn expands_config_path_home_prefixes() {
        let home = PathBuf::from("/Users/tester");
        assert_eq!(
            expand_config_path_value(&home, "$HOME/.config/sops/age/key.txt"),
            "/Users/tester/.config/sops/age/key.txt"
        );
        assert_eq!(
            expand_config_path_value(&home, "${HOME}/.config/sops/age/key.txt"),
            "/Users/tester/.config/sops/age/key.txt"
        );
        assert_eq!(
            expand_config_path_value(&home, "~/.config/sops/age/key.txt"),
            "/Users/tester/.config/sops/age/key.txt"
        );
    }

    #[test]
    fn sandbox_config_adds_read_only_files_and_root_relative_dirs() {
        let dir = tempdir().unwrap();
        let key_dir = dir.path().join("keys");
        let cache_dir = dir.path().join("runtime-cache");
        fs::create_dir_all(&key_dir).unwrap();
        fs::create_dir_all(&cache_dir).unwrap();
        let key_file = key_dir.join("deploy.age");
        fs::write(&key_file, "secret").unwrap();
        fs::write(
            dir.path().join(EXPLICIT_CONFIG_FILE),
            r#"[sandbox]
read_only_files = ["keys/deploy.age"]
read_write_dirs = ["runtime-cache"]
"#,
        )
        .unwrap();

        let configured = configured_sandbox_paths(dir.path()).unwrap();
        assert_eq!(configured.read_only_files, vec![key_file.clone()]);
        assert_eq!(configured.read_write_dirs, vec![cache_dir.clone()]);

        let analysis = Analysis::analyze(dir.path()).unwrap();
        assert!(analysis.sandbox_plan.read_only_files.contains(&key_file));
        assert!(analysis.sandbox_plan.read_write_dirs.contains(&cache_dir));
        assert!(analysis.notes.iter().any(|note| {
            note == &format!(
                "Sandbox: loaded 1 read-only file override(s), 1 read-write dir override(s) from {EXPLICIT_CONFIG_FILE}."
            )
        }));
    }

    #[test]
    fn sandbox_plan_protects_explicit_toml_from_writes() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join(EXPLICIT_CONFIG_FILE), "[sandbox]\n").unwrap();

        let analysis = Analysis::analyze(dir.path()).unwrap();
        assert!(
            analysis
                .sandbox_plan
                .read_only_files
                .contains(&dir.path().join(EXPLICIT_CONFIG_FILE))
        );
        assert!(
            analysis
                .sandbox_plan
                .protected_write_files
                .contains(&dir.path().join(EXPLICIT_CONFIG_FILE))
        );
        assert!(analysis.notes.iter().any(|note| {
            note == &format!(
                "Sandbox: writes to {EXPLICIT_CONFIG_FILE} are denied inside the sandbox on macOS."
            )
        }));
    }

    #[test]
    fn detects_node_version_from_dedicated_file() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"name":"demo","scripts":{"test":"vitest run"}}"#,
        )
        .unwrap();
        fs::write(dir.path().join(".node-version"), "20.18.0\n").unwrap();

        let analysis = Analysis::analyze(dir.path()).unwrap();
        assert!(
            analysis
                .detected_languages
                .contains(&LanguageRequirement::JavaScript)
        );
        assert!(analysis.detected_versions.iter().any(|version| {
            version.runtime == RuntimeKind::Nodejs
                && version.version == "20.18.0"
                && version.source == ".node-version"
                && version
                    .config_lines
                    .iter()
                    .any(|line| line.contains("nodejs_20"))
        }));
    }

    #[test]
    fn detects_rust_toolchain_file_as_pin() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("Cargo.toml"),
            "[package]\nname = \"demo\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .unwrap();
        fs::write(
            dir.path().join("rust-toolchain.toml"),
            "[toolchain]\nchannel = \"1.84.0\"\n",
        )
        .unwrap();

        let analysis = Analysis::analyze(dir.path()).unwrap();
        assert!(analysis.detected_versions.iter().any(|version| {
            version.runtime == RuntimeKind::Rust
                && version.source == "rust-toolchain.toml"
                && version.config_lines
                    == vec!["languages.rust.toolchainFile = ./rust-toolchain.toml;"]
        }));
    }

    #[test]
    fn detects_tool_versions_for_elixir_and_erlang() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("mix.exs"),
            "defmodule Demo.MixProject do end\n",
        )
        .unwrap();
        fs::write(
            dir.path().join(".tool-versions"),
            "elixir 1.17.3-otp-27\nerlang 27.3.4.10\n",
        )
        .unwrap();

        let analysis = Analysis::analyze(dir.path()).unwrap();
        assert!(analysis.detected_versions.iter().any(|version| {
            version.runtime == RuntimeKind::Elixir
                && version.version == "1.17.3-otp-27"
                && version.source == ".tool-versions"
        }));
        assert!(analysis.detected_versions.iter().any(|version| {
            version.runtime == RuntimeKind::Erlang
                && version.version == "27.3.4.10"
                && version.source == ".tool-versions"
        }));
    }

    #[test]
    fn detects_java_version_from_java_version_file() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("pom.xml"), "<project></project>\n").unwrap();
        fs::write(dir.path().join(".java-version"), "21.0.2-tem\n").unwrap();

        let analysis = Analysis::analyze(dir.path()).unwrap();
        assert!(analysis.detected_versions.iter().any(|version| {
            version.runtime == RuntimeKind::Java
                && version.version == "21.0.2-tem"
                && version
                    .config_lines
                    .iter()
                    .any(|line| line.contains("jdk21"))
        }));
    }

    #[test]
    fn auto_discovers_workspace_members_and_prefixes_commands() {
        let dir = tempdir().unwrap();
        fs::create_dir(dir.path().join(".git")).unwrap();
        let services = dir.path().join("services/api");
        let mobile = dir.path().join("apps/mobile");
        fs::create_dir_all(&services).unwrap();
        fs::create_dir_all(&mobile).unwrap();
        fs::write(
            services.join("Makefile"),
            "lint:\n\t@echo lint\ncheck:\n\t@echo test\n",
        )
        .unwrap();
        fs::write(
            mobile.join("package.json"),
            r#"{
  "name": "mobile",
  "packageManager": "yarn@4.0.0",
  "scripts": {
    "lint": "eslint .",
    "test": "jest"
  }
}"#,
        )
        .unwrap();
        fs::write(mobile.join("yarn.lock"), "").unwrap();

        let analysis = Analysis::analyze(dir.path()).unwrap();
        assert!(
            analysis
                .lint_commands
                .contains(&"cd 'services/api' && make lint".to_string())
        );
        assert!(
            analysis
                .test_commands
                .contains(&"cd 'services/api' && make check".to_string())
        );
        assert!(
            analysis
                .lint_commands
                .contains(&"cd 'apps/mobile' && yarn lint".to_string())
        );
        assert!(
            analysis
                .test_commands
                .contains(&"cd 'apps/mobile' && yarn test".to_string())
        );
        assert!(
            analysis
                .install_directories
                .contains(&"apps/mobile/node_modules".to_string())
        );
        assert!(analysis.notes.iter().any(|note| {
            note == "Workspace: merged 2 leaf projects into the root analysis (2 auto-discovered, 0 configured)."
        }));
        assert!(
            analysis
                .notes
                .iter()
                .any(|note| note.contains("services/api (Makefile)"))
        );
        assert!(
            analysis
                .notes
                .iter()
                .any(|note| note.contains("apps/mobile (package.json)"))
        );
        assert!(!analysis.notes.iter().any(|note| note == NO_COMMANDS_NOTE));
    }

    #[test]
    fn auto_discovers_swiftpm_workspace_members() {
        let dir = tempdir().unwrap();
        fs::create_dir(dir.path().join(".git")).unwrap();
        let app = dir.path().join("apps/macos-client");
        fs::create_dir_all(app.join("Sources")).unwrap();
        fs::write(
            app.join("Package.swift"),
            r#"// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "MacClient",
    platforms: [.macOS(.v14)],
    products: [
        .executable(name: "MacClient", targets: ["MacClient"])
    ],
    targets: [
        .executableTarget(name: "MacClient", path: "Sources")
    ]
)
"#,
        )
        .unwrap();

        let analysis = Analysis::analyze(dir.path()).unwrap();
        assert!(
            analysis
                .build_commands
                .contains(&"cd 'apps/macos-client' && swift build --disable-sandbox".to_string())
        );
        assert!(
            analysis
                .test_commands
                .contains(&"cd 'apps/macos-client' && swift test --disable-sandbox".to_string())
        );
        assert!(analysis.packages.contains(&"swift".to_string()));
        assert!(
            analysis
                .notes
                .iter()
                .any(|note| note.contains("apps/macos-client (Package.swift)"))
        );
    }

    #[test]
    fn detects_package_install_directories_for_supported_package_managers() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"name":"demo","scripts":{"test":"vitest run"}}"#,
        )
        .unwrap();
        fs::write(
            dir.path().join("mix.exs"),
            "defmodule Demo.MixProject do end\n",
        )
        .unwrap();
        fs::write(
            dir.path().join("composer.json"),
            r#"{"name":"demo/app","require-dev":{"phpunit/phpunit":"^11.0"}}"#,
        )
        .unwrap();

        let analysis = Analysis::analyze(dir.path()).unwrap();
        assert!(
            analysis
                .install_directories
                .contains(&"node_modules".to_string())
        );
        assert!(analysis.install_directories.contains(&"deps".to_string()));
        assert!(analysis.install_directories.contains(&"vendor".to_string()));
    }

    #[test]
    fn workspace_config_can_exclude_and_add_members() {
        let dir = tempdir().unwrap();
        let service = dir.path().join("services/api");
        let ignored = dir.path().join("examples/demo");
        let configured = dir.path().join("tools/custom");
        fs::create_dir_all(&service).unwrap();
        fs::create_dir_all(&ignored).unwrap();
        fs::create_dir_all(&configured).unwrap();
        fs::write(service.join("Makefile"), "lint:\n\t@echo lint\n").unwrap();
        fs::write(ignored.join("Makefile"), "lint:\n\t@echo ignored\n").unwrap();
        fs::write(configured.join("Makefile"), "test:\n\t@echo configured\n").unwrap();
        fs::write(
            dir.path().join(EXPLICIT_CONFIG_FILE),
            r#"[workspace]
exclude = ["examples"]
members = ["tools/custom"]
"#,
        )
        .unwrap();

        let analysis = Analysis::analyze(dir.path()).unwrap();
        assert!(
            analysis
                .lint_commands
                .contains(&"cd 'services/api' && make lint".to_string())
        );
        assert!(
            analysis
                .test_commands
                .contains(&"cd 'tools/custom' && make test".to_string())
        );
        assert!(
            !analysis
                .lint_commands
                .iter()
                .any(|command| command.contains("examples/demo"))
        );
        assert!(
            analysis
                .notes
                .iter()
                .any(|note| note == &format!("Workspace: loaded {EXPLICIT_CONFIG_FILE}."))
        );
        assert!(
            analysis
                .notes
                .iter()
                .any(|note| note == "Workspace excludes: examples.")
        );
    }

    #[test]
    fn deploy_hosts_load_from_explicit_toml() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("mix.exs"),
            "defmodule Demo.MixProject do end\n",
        )
        .unwrap();
        fs::write(
            dir.path().join(EXPLICIT_CONFIG_FILE),
            r#"[deploy]
hosts = ["prod.example.com", "ssh://git@deploy.example.com:2222/app"]
"#,
        )
        .unwrap();

        let analysis = Analysis::analyze(dir.path()).unwrap();
        assert_eq!(
            analysis.deploy_hosts,
            vec![
                "prod.example.com".to_string(),
                "ssh://git@deploy.example.com:2222/app".to_string()
            ]
        );
        assert!(!analysis.deploy_use_ssh_agent);
        assert!(analysis.deploy_ssh_agent_hosts.is_empty());
        assert!(!analysis.markers.contains(&"workspace".to_string()));
    }

    #[test]
    fn deploy_ssh_agent_settings_load_from_explicit_toml() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("mix.exs"),
            "defmodule Demo.MixProject do end\n",
        )
        .unwrap();
        fs::write(
            dir.path().join(EXPLICIT_CONFIG_FILE),
            r#"[deploy]
hosts = ["prod.example.com"]
use_ssh_agent = true
ssh_agent_hosts = ["prod.example.com", "github.com"]
"#,
        )
        .unwrap();

        let analysis = Analysis::analyze(dir.path()).unwrap();
        assert!(analysis.deploy_use_ssh_agent);
        assert_eq!(
            analysis.deploy_ssh_agent_hosts,
            vec!["prod.example.com".to_string(), "github.com".to_string()]
        );
    }

    #[test]
    fn deploy_only_explicit_toml_does_not_enable_workspace_discovery() {
        let dir = tempdir().unwrap();
        let nested = dir.path().join("deps/child");
        fs::create_dir_all(&nested).unwrap();
        fs::write(
            dir.path().join("mix.exs"),
            "defmodule Demo.MixProject do end\n",
        )
        .unwrap();
        fs::write(nested.join("package.json"), r#"{"name":"child"}"#).unwrap();
        fs::write(
            dir.path().join(EXPLICIT_CONFIG_FILE),
            r#"[deploy]
hosts = ["prod.example.com"]
"#,
        )
        .unwrap();

        let analysis = Analysis::analyze(dir.path()).unwrap();
        assert!(!analysis.markers.contains(&"workspace".to_string()));
        assert!(
            analysis
                .deploy_hosts
                .contains(&"prod.example.com".to_string())
        );
    }

    #[test]
    fn auto_discovers_terraform_leafs() {
        let dir = tempdir().unwrap();
        fs::create_dir(dir.path().join(".git")).unwrap();
        let infra = dir.path().join("infra/networking");
        fs::create_dir_all(&infra).unwrap();
        fs::write(
            infra.join("main.tf"),
            "terraform {\n  required_version = \">= 1.6.0\"\n}\n",
        )
        .unwrap();

        let analysis = Analysis::analyze(dir.path()).unwrap();
        assert!(analysis.packages.contains(&"opentofu".to_string()));
        assert!(
            analysis
                .lint_commands
                .contains(&"cd 'infra/networking' && tofu fmt -check -recursive".to_string())
        );
    }

    #[test]
    fn rust_projects_add_coverage_command_and_package() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("Cargo.toml"),
            r#"[package]
name = "demo"
version = "0.1.0"
edition = "2021"
"#,
        )
        .unwrap();

        let analysis = Analysis::analyze(dir.path()).unwrap();
        assert!(analysis.packages.contains(&"cargo-llvm-cov".to_string()));
        assert!(
            analysis
                .coverage_commands
                .contains(&format!(
                    "cargo llvm-cov --workspace --all-features --fail-under-lines {MINIMUM_COVERAGE_PERCENT} --summary-only"
                ))
        );
    }

    #[test]
    fn elixir_projects_add_credo_and_coverage_commands_when_missing() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("mix.exs"),
            r#"defmodule Demo.MixProject do
  use Mix.Project

  def project do
    [app: :demo, version: "0.1.0", elixir: "~> 1.15"]
  end
end
"#,
        )
        .unwrap();

        let analysis = Analysis::analyze(dir.path()).unwrap();
        assert!(
            analysis
                .lint_commands
                .contains(&"mix format --check-formatted".to_string())
        );
        assert!(
            analysis
                .lint_commands
                .contains(&"mix credo --strict".to_string())
        );
        assert!(
            analysis
                .coverage_commands
                .contains(&"mix test --cover".to_string())
        );
        assert_eq!(analysis.required_checks.len(), 1);
        assert_eq!(analysis.required_checks[0].subject, "mix.exs");
        assert!(analysis.required_checks[0].summary.contains("Credo"));
    }

    #[test]
    fn elixir_projects_with_credo_clear_lint_requirement() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("mix.exs"),
            r#"defmodule Demo.MixProject do
  use Mix.Project

  def project do
    [app: :demo, version: "0.1.0", elixir: "~> 1.15"]
  end

  defp deps do
    [
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false}
    ]
  end
end
"#,
        )
        .unwrap();

        let analysis = Analysis::analyze(dir.path()).unwrap();
        assert!(
            analysis
                .lint_commands
                .contains(&"mix credo --strict".to_string())
        );
        assert!(
            analysis
                .coverage_commands
                .contains(&"mix test --cover".to_string())
        );
        assert!(analysis.required_checks.is_empty());
    }

    #[test]
    fn elixir_projects_require_coverage_threshold_when_summary_is_disabled() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("mix.exs"),
            r#"defmodule Demo.MixProject do
  use Mix.Project

  def project do
    [
      app: :demo,
      version: "0.1.0",
      elixir: "~> 1.15",
      test_coverage: [summary: false]
    ]
  end

  defp deps do
    [
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false}
    ]
  end
end
"#,
        )
        .unwrap();

        let analysis = Analysis::analyze(dir.path()).unwrap();
        let requirement = analysis
            .required_checks
            .iter()
            .find(|requirement| requirement.kind == RequirementKind::Coverage)
            .expect("expected coverage requirement");
        assert_eq!(requirement.subject, "mix.exs#test_coverage");
        assert!(requirement.summary.contains("mix test --cover"));
    }

    #[test]
    fn elixir_projects_require_coverage_threshold_when_below_minimum() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("mix.exs"),
            r#"defmodule Demo.MixProject do
  use Mix.Project

  def project do
    [
      app: :demo,
      version: "0.1.0",
      elixir: "~> 1.15",
      test_coverage: [summary: [threshold: 75]]
    ]
  end

  defp deps do
    [
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false}
    ]
  end
end
"#,
        )
        .unwrap();

        let analysis = Analysis::analyze(dir.path()).unwrap();
        let requirement = analysis
            .required_checks
            .iter()
            .find(|requirement| requirement.kind == RequirementKind::Coverage)
            .expect("expected coverage requirement");
        assert!(requirement.summary.contains("80%"));
        assert!(requirement.summary.contains("75.0%"));
    }

    #[test]
    fn elixir_projects_accept_default_or_stronger_coverage_thresholds() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("mix.exs"),
            r#"defmodule Demo.MixProject do
  use Mix.Project

  def project do
    [
      app: :demo,
      version: "0.1.0",
      elixir: "~> 1.15",
      test_coverage: [summary: [threshold: 85]]
    ]
  end

  defp deps do
    [
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false}
    ]
  end
end
"#,
        )
        .unwrap();

        let analysis = Analysis::analyze(dir.path()).unwrap();
        assert!(
            !analysis
                .required_checks
                .iter()
                .any(|requirement| requirement.kind == RequirementKind::Coverage)
        );
    }

    #[test]
    fn phoenix_projects_require_replacing_default_home_page() {
        let dir = tempdir().unwrap();
        fs::create_dir_all(dir.path().join("lib/demo_web/controllers/page_html")).unwrap();
        fs::write(
            dir.path().join("mix.exs"),
            r#"defmodule Demo.MixProject do
  use Mix.Project

  def project do
    [app: :demo, version: "0.1.0", elixir: "~> 1.15"]
  end

  defp deps do
    [
      {:phoenix, "~> 1.7"},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false}
    ]
  end
end
"#,
        )
        .unwrap();
        fs::write(
            dir.path().join("lib/demo_web/router.ex"),
            r#"defmodule DemoWeb.Router do
  use DemoWeb, :router

  scope "/", DemoWeb do
    pipe_through :browser
    get "/", PageController, :home
  end
end
"#,
        )
        .unwrap();
        fs::write(
            dir.path()
                .join("lib/demo_web/controllers/page_html/home.html.heex"),
            r#"<section>
  <h1>Peace of mind from prototype to production</h1>
  <p>A productive framework that does not compromise speed or maintainability.</p>
</section>
"#,
        )
        .unwrap();

        let analysis = Analysis::analyze(dir.path()).unwrap();
        let requirement = analysis
            .required_checks
            .iter()
            .find(|requirement| requirement.kind == RequirementKind::Starter)
            .expect("expected starter requirement");
        assert_eq!(
            requirement.subject,
            "lib/demo_web/controllers/page_html/home.html.heex"
        );
        assert!(
            requirement
                .summary
                .contains("Phoenix projects must replace")
        );
        assert!(analysis.markers.contains(&"phoenix".to_string()));
        assert_eq!(
            analysis.dev_server_commands,
            vec!["mix phx.server".to_string()]
        );
    }

    #[test]
    fn phoenix_projects_with_custom_home_page_clear_starter_requirement() {
        let dir = tempdir().unwrap();
        fs::create_dir_all(dir.path().join("lib/demo_web/controllers/page_html")).unwrap();
        fs::write(
            dir.path().join("mix.exs"),
            r#"defmodule Demo.MixProject do
  use Mix.Project

  def project do
    [app: :demo, version: "0.1.0", elixir: "~> 1.15"]
  end

  defp deps do
    [
      {:phoenix, "~> 1.7"},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false}
    ]
  end
end
"#,
        )
        .unwrap();
        fs::write(
            dir.path().join("lib/demo_web/router.ex"),
            r#"defmodule DemoWeb.Router do
  use DemoWeb, :router

  scope "/", DemoWeb do
    pipe_through :browser
    get "/", PageController, :home
  end
end
"#,
        )
        .unwrap();
        fs::write(
            dir.path()
                .join("lib/demo_web/controllers/page_html/home.html.heex"),
            "<h1>Custom storefront</h1>\n",
        )
        .unwrap();

        let analysis = Analysis::analyze(dir.path()).unwrap();
        assert!(
            !analysis
                .required_checks
                .iter()
                .any(|requirement| requirement.kind == RequirementKind::Starter)
        );
        assert_eq!(
            analysis.dev_server_commands,
            vec!["mix phx.server".to_string()]
        );
    }

    #[test]
    fn rails_projects_require_real_root_route() {
        let dir = tempdir().unwrap();
        fs::create_dir_all(dir.path().join("config")).unwrap();
        fs::create_dir_all(dir.path().join("app/controllers")).unwrap();
        fs::write(
            dir.path().join("Gemfile"),
            "source \"https://rubygems.org\"\ngem \"rails\"\n",
        )
        .unwrap();
        fs::write(
            dir.path().join("config/routes.rb"),
            "Rails.application.routes.draw do\n  # root \"posts#index\"\nend\n",
        )
        .unwrap();
        fs::write(
            dir.path().join("app/controllers/application_controller.rb"),
            "class ApplicationController < ActionController::Base\nend\n",
        )
        .unwrap();

        let analysis = Analysis::analyze(dir.path()).unwrap();
        let requirement = analysis
            .required_checks
            .iter()
            .find(|requirement| requirement.kind == RequirementKind::Starter)
            .expect("expected starter requirement");
        assert_eq!(requirement.subject, "config/routes.rb");
        assert!(requirement.summary.contains("real root route"));
        assert!(analysis.markers.contains(&"rails".to_string()));
        assert_eq!(
            analysis.dev_server_commands,
            vec!["bin/rails server".to_string()]
        );
    }

    #[test]
    fn rails_projects_with_root_route_clear_starter_requirement() {
        let dir = tempdir().unwrap();
        fs::create_dir_all(dir.path().join("config")).unwrap();
        fs::create_dir_all(dir.path().join("app/controllers")).unwrap();
        fs::write(
            dir.path().join("Gemfile"),
            "source \"https://rubygems.org\"\ngem \"rails\"\n",
        )
        .unwrap();
        fs::write(
            dir.path().join("config/routes.rb"),
            "Rails.application.routes.draw do\n  root \"home#index\"\nend\n",
        )
        .unwrap();
        fs::write(
            dir.path().join("app/controllers/application_controller.rb"),
            "class ApplicationController < ActionController::Base\nend\n",
        )
        .unwrap();

        let analysis = Analysis::analyze(dir.path()).unwrap();
        assert!(
            !analysis
                .required_checks
                .iter()
                .any(|requirement| requirement.kind == RequirementKind::Starter)
        );
        assert_eq!(
            analysis.dev_server_commands,
            vec!["bin/rails server".to_string()]
        );
    }

    #[test]
    fn workspace_conflicting_runtime_versions_fail_analysis() {
        let dir = tempdir().unwrap();
        fs::create_dir(dir.path().join(".git")).unwrap();
        let api = dir.path().join("services/api");
        let mobile = dir.path().join("apps/mobile");
        fs::create_dir_all(&api).unwrap();
        fs::create_dir_all(&mobile).unwrap();
        fs::write(api.join("package.json"), r#"{"name":"api"}"#).unwrap();
        fs::write(api.join(".node-version"), "18.19.1\n").unwrap();
        fs::write(mobile.join("package.json"), r#"{"name":"mobile"}"#).unwrap();
        fs::write(mobile.join(".node-version"), "20.11.1\n").unwrap();

        let err = Analysis::analyze(dir.path()).unwrap_err().to_string();
        assert!(err.contains("conflicting nodejs versions"));
        assert!(err.contains("18.19.1 (services/api/.node-version)"));
        assert!(err.contains("20.11.1 (apps/mobile/.node-version)"));
    }

    #[test]
    fn workspace_discovery_skips_leaf_dependency_dirs() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("services/stuffix");
        let deps = root.join("deps/phoenix");
        fs::create_dir_all(&deps).unwrap();
        fs::write(
            root.join("mix.exs"),
            r#"defmodule Stuffix.MixProject do
  use Mix.Project

  def project do
    [app: :stuffix, version: "0.1.0", elixir: "~> 1.15"]
  end
end
"#,
        )
        .unwrap();
        fs::write(
            deps.join("mix.exs"),
            r#"defmodule Phoenix.MixProject do
  use Mix.Project

  def project do
    [app: :phoenix, version: "0.1.0", elixir: "~> 1.11"]
  end
end
"#,
        )
        .unwrap();

        let analysis = Analysis::analyze(&root).unwrap();
        assert!(!analysis.markers.contains(&"workspace".to_string()));
        assert_eq!(analysis.detected_versions.len(), 1);
        assert_eq!(analysis.detected_versions[0].version, "~> 1.15");
        assert_eq!(analysis.detected_versions[0].source, "mix.exs#elixir");
    }

    #[test]
    fn workspace_constraint_versions_without_shared_pin_do_not_conflict() {
        let dir = tempdir().unwrap();
        fs::create_dir(dir.path().join(".git")).unwrap();
        let api = dir.path().join("services/api");
        let worker = dir.path().join("services/worker");
        fs::create_dir_all(&api).unwrap();
        fs::create_dir_all(&worker).unwrap();
        fs::write(
            api.join("mix.exs"),
            r#"defmodule Api.MixProject do
  use Mix.Project

  def project do
    [app: :api, version: "0.1.0", elixir: "~> 1.15"]
  end
end
"#,
        )
        .unwrap();
        fs::write(
            worker.join("mix.exs"),
            r#"defmodule Worker.MixProject do
  use Mix.Project

  def project do
    [app: :worker, version: "0.1.0", elixir: "~> 1.18"]
  end
end
"#,
        )
        .unwrap();

        let analysis = Analysis::analyze(dir.path()).unwrap();
        assert!(analysis.markers.contains(&"workspace".to_string()));
        assert!(
            analysis
                .notes
                .iter()
                .any(|note| note.contains("services/api (mix.exs)"))
        );
        assert!(
            analysis
                .notes
                .iter()
                .any(|note| note.contains("services/worker (mix.exs)"))
        );
    }

    #[test]
    fn workspace_same_node_major_versions_share_shell_pin() {
        let dir = tempdir().unwrap();
        fs::create_dir(dir.path().join(".git")).unwrap();
        let api = dir.path().join("services/api");
        let mobile = dir.path().join("apps/mobile");
        fs::create_dir_all(&api).unwrap();
        fs::create_dir_all(&mobile).unwrap();
        fs::write(api.join("package.json"), r#"{"name":"api"}"#).unwrap();
        fs::write(api.join(".node-version"), "18.19.1\n").unwrap();
        fs::write(mobile.join("package.json"), r#"{"name":"mobile"}"#).unwrap();
        fs::write(mobile.join(".node-version"), "18.20.2\n").unwrap();

        let analysis = Analysis::analyze(dir.path()).unwrap();
        assert!(
            analysis
                .detected_versions
                .iter()
                .any(|version| version.source == "services/api/.node-version")
        );
        assert!(
            analysis
                .detected_versions
                .iter()
                .any(|version| version.source == "apps/mobile/.node-version")
        );
    }
}
