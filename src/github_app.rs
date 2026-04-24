use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use reqwest::blocking::Client;
use reqwest::header::{ACCEPT, AUTHORIZATION, HeaderMap, HeaderValue, USER_AGENT};
use serde::{Deserialize, Serialize};

use crate::analysis::Analysis;

const XDG_CONFIG_FILE: &str = "config.toml";
const GITHUB_API_ACCEPT: &str = "application/vnd.github+json";
const GITHUB_API_VERSION: &str = "2022-11-28";

#[derive(Debug, Clone, Deserialize, Default)]
struct ExplicitConfigFile {
    #[serde(default)]
    github_app: Option<GitHubAppConfig>,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct GitHubAppConfig {
    #[serde(default)]
    enabled: Option<bool>,
    app_id: Option<u64>,
    installation_id: Option<u64>,
    private_key_file: Option<String>,
    base_url: Option<String>,
    #[serde(default)]
    extra_repositories: Vec<String>,
}

#[derive(Debug, Serialize)]
struct GitHubAppClaims {
    iat: u64,
    exp: u64,
    iss: String,
}

#[derive(Debug, Deserialize)]
struct InstallationResponse {
    id: u64,
}

#[derive(Debug, Deserialize)]
struct AccessTokenResponse {
    token: String,
}

#[derive(Debug, Serialize)]
struct AccessTokenRequest<'a> {
    repositories: &'a [String],
}

pub fn sandbox_env(root: &Path, analysis: &Analysis) -> Result<BTreeMap<String, String>> {
    let Some((config, config_dir)) = load_config()? else {
        return Ok(BTreeMap::new());
    };
    if !config.enabled.unwrap_or(true) {
        return Ok(BTreeMap::new());
    }

    let app_id = config
        .app_id
        .context("github_app.app_id is required when github_app.enabled = true")?;
    let private_key_path = resolve_config_path(
        &config_dir,
        config
            .private_key_file
            .as_deref()
            .context("github_app.private_key_file is required when github_app.enabled = true")?,
    )?;
    let private_key = fs::read(&private_key_path)
        .with_context(|| format!("failed to read {}", private_key_path.display()))?;
    let base_url = config
        .base_url
        .as_deref()
        .unwrap_or("https://api.github.com")
        .trim_end_matches('/')
        .to_string();

    let allowed_repositories =
        allowed_repository_names(root, analysis, config.extra_repositories.as_slice())?;
    if allowed_repositories.is_empty() {
        return Ok(BTreeMap::new());
    }

    let app_jwt = mint_app_jwt(app_id, &private_key)?;
    let installation_id = if let Some(id) = config.installation_id {
        id
    } else {
        let slug = analysis
            .repository
            .github
            .as_ref()
            .map(|repo| repo.slug.as_str())
            .filter(|slug| !slug.trim().is_empty())
            .context(
                "github_app.installation_id is required when the current repository has no GitHub remote slug",
            )?;
        lookup_installation_id(&base_url, &app_jwt, slug)?
    };
    let token =
        mint_installation_token(&base_url, &app_jwt, installation_id, &allowed_repositories)?;

    let mut env = BTreeMap::new();
    env.insert("GH_TOKEN".to_string(), token.clone());
    env.insert("GITHUB_TOKEN".to_string(), token);
    env.insert("GH_PROMPT_DISABLED".to_string(), "1".to_string());
    Ok(env)
}

pub fn print_setup_instructions() -> Result<()> {
    let config_path = xdg_config_file_path()?;
    println!(
        "\
Create GitHub App in GitHub web UI.

Personal account:
- https://github.com/settings/apps/new

Organization:
- https://github.com/organizations/<org>/settings/apps/new

Recommended setup:
- disable webhooks unless you need them
- permissions: repository metadata read-only
- permissions: pull requests read/write if agents create PRs
- permissions: contents read/write if agents push branches through app token
- install app only on target repo or target org repos

After creating app:
1. note App ID
2. generate private key PEM
3. install app on repo
4. optionally note installation ID

User config path:
- {config}

Example config:
[github_app]
app_id = 123456
private_key_file = \"github-app.pem\"

# optional
installation_id = 7890123
base_url = \"https://api.github.com\"
extra_repositories = [\"my-org/shared-submodule\"]

Notes:
- relative private_key_file paths resolve from XDG config dir
- config auto-activates when file exists
- set enabled = false to keep file present but disable token minting
",
        config = config_path.display()
    );
    Ok(())
}

fn load_config() -> Result<Option<(GitHubAppConfig, PathBuf)>> {
    let path = xdg_config_file_path()?;
    if !path.is_file() {
        return Ok(None);
    }
    let raw =
        fs::read_to_string(&path).with_context(|| format!("failed to read {}", path.display()))?;
    let parsed = toml::from_str::<ExplicitConfigFile>(&raw)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    Ok(parsed.github_app.map(|config| {
        (
            config,
            path.parent().unwrap_or(Path::new("/")).to_path_buf(),
        )
    }))
}

fn xdg_config_file_path() -> Result<PathBuf> {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(|| dirs::home_dir().map(|home| home.join(".config")))
        .context("failed to resolve XDG config directory")?;
    Ok(base.join("explicit").join(XDG_CONFIG_FILE))
}

fn resolve_config_path(config_dir: &Path, raw: &str) -> Result<PathBuf> {
    let home = dirs::home_dir().context("failed to resolve home directory")?;
    let path = if raw == "~" {
        home
    } else if let Some(suffix) = raw.strip_prefix("~/") {
        home.join(suffix)
    } else {
        let path = PathBuf::from(raw);
        if path.is_absolute() {
            path
        } else {
            config_dir.join(path)
        }
    };
    Ok(path)
}

fn allowed_repository_names(
    root: &Path,
    analysis: &Analysis,
    extra_repositories: &[String],
) -> Result<Vec<String>> {
    let mut slugs = BTreeSet::new();
    if let Some(github) = &analysis.repository.github
        && !github.slug.trim().is_empty()
    {
        slugs.insert(github.slug.clone());
    }
    slugs.extend(github_submodule_slugs(root)?);
    slugs.extend(
        extra_repositories
            .iter()
            .map(|slug| slug.trim().to_string())
            .filter(|slug| !slug.is_empty()),
    );

    let root_owner = analysis
        .repository
        .github
        .as_ref()
        .and_then(|repo| repo.slug.split('/').next())
        .map(str::to_string);
    let names = slugs
        .into_iter()
        .filter_map(|slug| {
            let (owner, name) = split_slug(&slug)?;
            if root_owner
                .as_deref()
                .is_none_or(|expected| expected == owner)
            {
                Some(name.to_string())
            } else {
                None
            }
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    Ok(names)
}

fn github_submodule_slugs(root: &Path) -> Result<Vec<String>> {
    let path = root.join(".gitmodules");
    if !path.is_file() {
        return Ok(Vec::new());
    }
    let raw =
        fs::read_to_string(&path).with_context(|| format!("failed to read {}", path.display()))?;
    let value = raw.parse::<toml::Table>().ok();
    let mut slugs = BTreeSet::new();

    if let Some(table) = value {
        for (key, section) in table {
            if !key.starts_with("submodule ") {
                continue;
            }
            let Some(url) = section.get("url").and_then(|value| value.as_str()) else {
                continue;
            };
            if let Some(slug) = parse_github_slug(url) {
                slugs.insert(slug);
            }
        }
    } else {
        for line in raw.lines() {
            let trimmed = line.trim();
            let Some(url) = trimmed.strip_prefix("url =") else {
                continue;
            };
            if let Some(slug) = parse_github_slug(url.trim()) {
                slugs.insert(slug);
            }
        }
    }

    Ok(slugs.into_iter().collect())
}

fn parse_github_slug(remote_url: &str) -> Option<String> {
    let trimmed = remote_url.trim().trim_end_matches(".git");
    for prefix in [
        "https://github.com/",
        "http://github.com/",
        "ssh://git@github.com/",
        "git@github.com:",
    ] {
        if let Some(rest) = trimmed.strip_prefix(prefix) {
            let slug = rest.trim_matches('/');
            if split_slug(slug).is_some() {
                return Some(slug.to_string());
            }
        }
    }
    None
}

fn split_slug(slug: &str) -> Option<(&str, &str)> {
    let (owner, name) = slug.split_once('/')?;
    if owner.is_empty() || name.is_empty() {
        return None;
    }
    Some((owner, name))
}

fn mint_app_jwt(app_id: u64, private_key: &[u8]) -> Result<String> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock before unix epoch")?
        .as_secs();
    let claims = GitHubAppClaims {
        iat: now.saturating_sub(60),
        exp: now + 9 * 60,
        iss: app_id.to_string(),
    };
    let mut header = Header::new(Algorithm::RS256);
    header.typ = Some("JWT".to_string());
    let key = EncodingKey::from_rsa_pem(private_key)
        .context("failed to parse GitHub App private key PEM")?;
    encode(&header, &claims, &key).context("failed to encode GitHub App JWT")
}

fn lookup_installation_id(base_url: &str, jwt: &str, slug: &str) -> Result<u64> {
    let client = github_client(jwt)?;
    let response = client
        .get(format!("{base_url}/repos/{slug}/installation"))
        .header("X-GitHub-Api-Version", GITHUB_API_VERSION)
        .send()
        .with_context(|| format!("failed to look up GitHub App installation for {slug}"))?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().unwrap_or_default();
        bail!(
            "GitHub App installation lookup failed for {slug}: {status} {}",
            body.trim()
        );
    }
    let payload = response
        .json::<InstallationResponse>()
        .context("failed to decode installation lookup response")?;
    Ok(payload.id)
}

fn mint_installation_token(
    base_url: &str,
    jwt: &str,
    installation_id: u64,
    repositories: &[String],
) -> Result<String> {
    let client = github_client(jwt)?;
    let response = client
        .post(format!(
            "{base_url}/app/installations/{installation_id}/access_tokens"
        ))
        .header("X-GitHub-Api-Version", GITHUB_API_VERSION)
        .json(&AccessTokenRequest { repositories })
        .send()
        .with_context(|| {
            format!("failed to mint GitHub App installation token for {installation_id}")
        })?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().unwrap_or_default();
        bail!(
            "GitHub App installation token mint failed for {installation_id}: {status} {}",
            body.trim()
        );
    }
    let payload = response
        .json::<AccessTokenResponse>()
        .context("failed to decode installation token response")?;
    Ok(payload.token)
}

fn github_client(jwt: &str) -> Result<Client> {
    let mut headers = HeaderMap::new();
    headers.insert(USER_AGENT, HeaderValue::from_static("explicit/0.1.0"));
    headers.insert(ACCEPT, HeaderValue::from_static(GITHUB_API_ACCEPT));
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {jwt}"))
            .context("failed to build GitHub authorization header")?,
    );
    Client::builder()
        .default_headers(headers)
        .build()
        .context("failed to build GitHub App HTTP client")
}

#[cfg(test)]
mod tests {
    use super::{
        allowed_repository_names, github_submodule_slugs, load_config, parse_github_slug,
        resolve_config_path, split_slug, xdg_config_file_path,
    };
    use crate::analysis::{
        Analysis, GitHubRepository, GitHubVisibility, RepositoryMetadata, SandboxPlan,
    };
    use std::path::PathBuf;
    use tempfile::tempdir;

    fn analysis_for_slug(slug: &str) -> Analysis {
        Analysis {
            root: PathBuf::from("/tmp/project"),
            markers: Vec::new(),
            manifests: Vec::new(),
            install_directories: Vec::new(),
            detected_languages: Vec::new(),
            detected_versions: Vec::new(),
            language_hints: Vec::new(),
            packages: Vec::new(),
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
            repository: RepositoryMetadata {
                github: Some(GitHubRepository {
                    slug: slug.to_string(),
                    visibility: GitHubVisibility::Private,
                }),
                ..RepositoryMetadata::default()
            },
            sandbox_plan: SandboxPlan {
                root: PathBuf::from("/tmp/project"),
                read_write_files: Vec::new(),
                read_write_dirs: Vec::new(),
                read_only_files: Vec::new(),
                read_only_dirs: Vec::new(),
                protected_write_files: Vec::new(),
                notes: Vec::new(),
            },
        }
    }

    #[test]
    fn parses_common_github_remote_forms() {
        assert_eq!(
            parse_github_slug("git@github.com:owner/repo.git").as_deref(),
            Some("owner/repo")
        );
        assert_eq!(
            parse_github_slug("https://github.com/owner/repo").as_deref(),
            Some("owner/repo")
        );
        assert_eq!(parse_github_slug("https://example.com/demo"), None);
    }

    #[test]
    fn allowed_repository_names_include_same_owner_submodules_only() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join(".gitmodules"),
            r#"
[submodule "a"]
    path = deps/a
    url = git@github.com:example/sub-a.git
[submodule "b"]
    path = deps/b
    url = git@github.com:other/sub-b.git
"#,
        )
        .unwrap();

        let names = allowed_repository_names(
            dir.path(),
            &analysis_for_slug("example/root"),
            &["example/manual-extra".to_string()],
        )
        .unwrap();
        assert_eq!(
            names,
            vec![
                "manual-extra".to_string(),
                "root".to_string(),
                "sub-a".to_string()
            ]
        );
    }

    #[test]
    fn split_slug_returns_owner_and_name() {
        assert_eq!(split_slug("owner/repo"), Some(("owner", "repo")));
    }

    #[test]
    fn split_slug_returns_none_for_no_slash() {
        assert_eq!(split_slug("no-slash"), None);
    }

    #[test]
    fn split_slug_returns_none_for_empty_owner() {
        assert_eq!(split_slug("/repo"), None);
    }

    #[test]
    fn split_slug_returns_none_for_empty_name() {
        assert_eq!(split_slug("owner/"), None);
    }

    #[test]
    fn parse_github_slug_handles_ssh_colon_form() {
        assert_eq!(
            parse_github_slug("git@github.com:owner/repo.git").as_deref(),
            Some("owner/repo")
        );
    }

    #[test]
    fn parse_github_slug_handles_https_form() {
        assert_eq!(
            parse_github_slug("https://github.com/owner/repo").as_deref(),
            Some("owner/repo")
        );
    }

    #[test]
    fn parse_github_slug_handles_http_form() {
        assert_eq!(
            parse_github_slug("http://github.com/owner/repo.git").as_deref(),
            Some("owner/repo")
        );
    }

    #[test]
    fn parse_github_slug_handles_ssh_url_form() {
        assert_eq!(
            parse_github_slug("ssh://git@github.com/owner/repo.git").as_deref(),
            Some("owner/repo")
        );
    }

    #[test]
    fn parse_github_slug_returns_none_for_non_github_url() {
        assert_eq!(parse_github_slug("https://gitlab.com/owner/repo"), None);
    }

    #[test]
    fn resolve_config_path_absolute_passes_through() {
        let result =
            resolve_config_path(PathBuf::from("/config").as_path(), "/absolute/key.pem").unwrap();
        assert_eq!(result, PathBuf::from("/absolute/key.pem"));
    }

    #[test]
    fn resolve_config_path_relative_joins_to_config_dir() {
        let result =
            resolve_config_path(PathBuf::from("/config").as_path(), "relative/key.pem").unwrap();
        assert_eq!(result, PathBuf::from("/config/relative/key.pem"));
    }

    #[test]
    fn resolve_config_path_tilde_slash_resolves_to_home() {
        let result = resolve_config_path(PathBuf::from("/config").as_path(), "~/key.pem").unwrap();
        let home = dirs::home_dir().unwrap();
        assert_eq!(result, home.join("key.pem"));
    }

    #[test]
    fn resolve_config_path_bare_tilde_resolves_to_home() {
        let result = resolve_config_path(PathBuf::from("/config").as_path(), "~").unwrap();
        let home = dirs::home_dir().unwrap();
        assert_eq!(result, home);
    }

    #[test]
    fn xdg_config_file_path_uses_xdg_config_home_env() {
        let dir = tempdir().unwrap();
        // Safety: test-only env manipulation.
        unsafe { std::env::set_var("XDG_CONFIG_HOME", dir.path().as_os_str()) };
        let path = xdg_config_file_path().unwrap();
        assert_eq!(path, dir.path().join("explicit/config.toml"));
        unsafe { std::env::remove_var("XDG_CONFIG_HOME") };
    }

    #[test]
    fn github_submodule_slugs_parses_gitmodules() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join(".gitmodules"),
            "[submodule \"deps/a\"]\n    path = deps/a\n    url = git@github.com:owner/repo-a.git\n[submodule \"deps/b\"]\n    path = deps/b\n    url = https://github.com/owner/repo-b.git\n",
        )
        .unwrap();
        let slugs = github_submodule_slugs(dir.path()).unwrap();
        assert!(slugs.contains(&"owner/repo-a".to_string()));
        assert!(slugs.contains(&"owner/repo-b".to_string()));
    }

    #[test]
    fn github_submodule_slugs_returns_empty_when_no_file() {
        let dir = tempdir().unwrap();
        let slugs = github_submodule_slugs(dir.path()).unwrap();
        assert!(slugs.is_empty());
    }

    #[test]
    fn github_submodule_slugs_skips_non_github_urls() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join(".gitmodules"),
            "[submodule \"deps/x\"]\n    path = deps/x\n    url = https://gitlab.com/owner/repo.git\n",
        )
        .unwrap();
        let slugs = github_submodule_slugs(dir.path()).unwrap();
        assert!(slugs.is_empty());
    }

    #[test]
    fn load_config_returns_none_when_no_config_file() {
        let dir = tempdir().unwrap();
        // Safety: test-only env manipulation.
        unsafe { std::env::set_var("XDG_CONFIG_HOME", dir.path().as_os_str()) };
        let result = load_config().unwrap();
        assert!(result.is_none());
        unsafe { std::env::remove_var("XDG_CONFIG_HOME") };
    }

    #[test]
    fn load_config_returns_config_when_file_present() {
        let dir = tempdir().unwrap();
        let explicit_dir = dir.path().join("explicit");
        std::fs::create_dir_all(&explicit_dir).unwrap();
        std::fs::write(
            explicit_dir.join("config.toml"),
            "[github_app]\napp_id = 123456\nprivate_key_file = \"app.pem\"\n",
        )
        .unwrap();
        // Safety: test-only env manipulation.
        unsafe { std::env::set_var("XDG_CONFIG_HOME", dir.path().as_os_str()) };
        let result = load_config().unwrap();
        assert!(result.is_some());
        let (config, config_dir) = result.unwrap();
        assert_eq!(config.app_id, Some(123456));
        assert_eq!(config_dir, explicit_dir);
        unsafe { std::env::remove_var("XDG_CONFIG_HOME") };
    }

    #[test]
    fn load_config_returns_none_when_no_github_app_section() {
        let dir = tempdir().unwrap();
        let explicit_dir = dir.path().join("explicit");
        std::fs::create_dir_all(&explicit_dir).unwrap();
        std::fs::write(explicit_dir.join("config.toml"), "# no github_app\n").unwrap();
        // Safety: test-only env manipulation.
        unsafe { std::env::set_var("XDG_CONFIG_HOME", dir.path().as_os_str()) };
        let result = load_config().unwrap();
        assert!(result.is_none());
        unsafe { std::env::remove_var("XDG_CONFIG_HOME") };
    }

    #[test]
    fn parse_github_slug_returns_none_for_prefix_without_valid_owner_repo() {
        // Prefix matches but no slash separating owner from repo.
        assert_eq!(parse_github_slug("https://github.com/onlyowner"), None);
        assert_eq!(parse_github_slug("git@github.com:onlyowner.git"), None);
        assert_eq!(parse_github_slug("https://gitlab.com/owner/repo"), None);
    }

    #[test]
    fn github_submodule_slugs_reads_toml_format_gitmodules() {
        let dir = tempdir().unwrap();
        // A .gitmodules file that parses as valid TOML (using quoted submodule key).
        std::fs::write(
            dir.path().join(".gitmodules"),
            "\"submodule foo\" = {url = \"https://github.com/owner/toml-repo.git\"}\n",
        )
        .unwrap();
        let slugs = github_submodule_slugs(dir.path()).unwrap();
        assert!(
            slugs.contains(&"owner/toml-repo".to_string()),
            "expected owner/toml-repo, got {slugs:?}"
        );
    }

    #[test]
    fn print_setup_instructions_succeeds_without_panicking() {
        let dir = tempdir().unwrap();
        let explicit_dir = dir.path().join("explicit");
        std::fs::create_dir_all(&explicit_dir).unwrap();
        // Safety: test-only env manipulation.
        unsafe { std::env::set_var("XDG_CONFIG_HOME", dir.path().as_os_str()) };
        let result = super::print_setup_instructions();
        unsafe { std::env::remove_var("XDG_CONFIG_HOME") };
        assert!(result.is_ok());
    }

    #[test]
    fn resolve_config_path_handles_tilde_prefix() {
        let home = dirs::home_dir().unwrap();
        let config_dir = std::path::Path::new("/some/config");

        let result = resolve_config_path(config_dir, "~/keys/app.pem").unwrap();
        assert_eq!(result, home.join("keys/app.pem"));
    }

    #[test]
    fn resolve_config_path_handles_bare_tilde() {
        let home = dirs::home_dir().unwrap();
        let config_dir = std::path::Path::new("/some/config");
        let result = resolve_config_path(config_dir, "~").unwrap();
        assert_eq!(result, home);
    }

    #[test]
    fn resolve_config_path_handles_absolute_path() {
        let config_dir = std::path::Path::new("/some/config");
        let result = resolve_config_path(config_dir, "/etc/keys/app.pem").unwrap();
        assert_eq!(result, std::path::PathBuf::from("/etc/keys/app.pem"));
    }

    #[test]
    fn resolve_config_path_handles_relative_path() {
        let config_dir = std::path::Path::new("/home/user/.config/explicit");
        let result = resolve_config_path(config_dir, "keys/app.pem").unwrap();
        assert_eq!(
            result,
            std::path::PathBuf::from("/home/user/.config/explicit/keys/app.pem")
        );
    }
}
