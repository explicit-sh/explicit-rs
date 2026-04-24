use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result, bail};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};

use crate::analysis::DetectedVersion;

const EOL_DB_TOML: &str = include_str!("../eol_db.toml");
const REMOTE_CACHE_TTL: Duration = Duration::from_secs(60 * 60 * 24);
static EMBEDDED_DB: OnceLock<EolDatabase> = OnceLock::new();
static HTTP_CLIENT: OnceLock<Client> = OnceLock::new();
static REMOTE_PRODUCTS: OnceLock<Mutex<BTreeMap<String, ProductSnapshot>>> = OnceLock::new();

#[derive(Debug, Deserialize)]
struct EolDatabase {
    products: Vec<ProductSnapshot>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct ProductSnapshot {
    slug: String,
    label: String,
    cycles: Vec<CycleSnapshot>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct CycleSnapshot {
    name: String,
    is_eol: bool,
    is_maintained: bool,
    eol_from: Option<String>,
    latest: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct ApiDocument {
    result: ProductResult,
}

#[derive(Debug, Deserialize, Serialize)]
struct ProductResult {
    label: String,
    releases: Vec<ApiRelease>,
}

#[derive(Debug, Deserialize, Serialize)]
struct ApiRelease {
    name: String,
    #[serde(rename = "isEol")]
    is_eol: bool,
    #[serde(rename = "isMaintained")]
    is_maintained: bool,
    #[serde(rename = "eolFrom")]
    eol_from: Option<String>,
    latest: Option<ApiLatest>,
}

#[derive(Debug, Deserialize, Serialize)]
struct ApiLatest {
    name: String,
}

#[derive(Debug, Clone)]
struct ResolvedStatus {
    label: String,
    cycle: String,
    is_eol: bool,
    eol_from: Option<String>,
    latest: Option<String>,
    source: &'static str,
}

pub fn ensure_supported_runtime_versions(
    versions: &[DetectedVersion],
    allow_end_of_life: bool,
) -> Result<()> {
    let mut failures = Vec::new();
    for version in versions {
        if version.runtime.eol_product_slug().is_empty() {
            continue;
        }
        let Some(status) = resolve_status(version)? else {
            continue;
        };
        if status.is_eol {
            failures.push(format_failure(version, &status));
        }
    }

    if failures.is_empty() {
        return Ok(());
    }

    if allow_end_of_life {
        eprintln!("Warning: end-of-life runtimes detected:");
        for failure in &failures {
            eprintln!("  - {failure}");
        }
        eprintln!("Continuing because --dangerously-use-end-of-life-versions was provided.");
        return Ok(());
    }

    let mut message = String::from("End-of-life runtimes detected:\n");
    for failure in &failures {
        message.push_str("  - ");
        message.push_str(failure);
        message.push('\n');
    }
    message.push_str(
        "Re-run with --dangerously-use-end-of-life-versions if you want to continue anyway.",
    );
    bail!(message);
}

fn format_failure(version: &DetectedVersion, status: &ResolvedStatus) -> String {
    let eol_from = status.eol_from.as_deref().unwrap_or("an unknown date");
    let latest = status.latest.as_deref().unwrap_or("unknown");
    format!(
        "{} {} from {} is end-of-life in cycle {} (EOL {}). Latest known release in that cycle: {}. Data source: {}.",
        status.label,
        version.version,
        version.source,
        status.cycle,
        eol_from,
        latest,
        status.source
    )
}

fn resolve_status(version: &DetectedVersion) -> Result<Option<ResolvedStatus>> {
    let slug = version.runtime.eol_product_slug();
    if slug.is_empty() {
        return Ok(None);
    }
    let Some(cycle) = version.runtime.cycle_from_version(&version.version) else {
        return Ok(None);
    };

    let db = parse_embedded_db();
    if let Some(status) =
        find_cycle(&db.products, slug, &cycle).map(|cycle_snapshot| ResolvedStatus {
            label: product_label(&db.products, slug)
                .unwrap_or_else(|| version.runtime.display_name().to_string()),
            cycle: cycle.to_string(),
            is_eol: cycle_snapshot.is_eol,
            eol_from: cycle_snapshot.eol_from.clone(),
            latest: cycle_snapshot.latest.clone(),
            source: "embedded endoflife.date snapshot",
        })
    {
        return Ok(Some(status));
    }

    let remote = fetch_remote_product(slug)?;
    Ok(
        find_cycle(std::slice::from_ref(&remote), slug, &cycle).map(|cycle_snapshot| {
            ResolvedStatus {
                label: remote.label.clone(),
                cycle,
                is_eol: cycle_snapshot.is_eol,
                eol_from: cycle_snapshot.eol_from.clone(),
                latest: cycle_snapshot.latest.clone(),
                source: "live endoflife.date API",
            }
        }),
    )
}

fn parse_embedded_db() -> &'static EolDatabase {
    EMBEDDED_DB.get_or_init(|| {
        toml::from_str(EOL_DB_TOML).expect("embedded end-of-life database must parse")
    })
}

fn find_cycle<'a>(
    products: &'a [ProductSnapshot],
    slug: &str,
    cycle: &str,
) -> Option<&'a CycleSnapshot> {
    products
        .iter()
        .find(|product| product.slug == slug)
        .and_then(|product| product.cycles.iter().find(|entry| entry.name == cycle))
}

fn product_label(products: &[ProductSnapshot], slug: &str) -> Option<String> {
    products
        .iter()
        .find(|product| product.slug == slug)
        .map(|product| product.label.clone())
}

fn fetch_remote_product(slug: &str) -> Result<ProductSnapshot> {
    if let Some(snapshot) = remote_product_cache()
        .lock()
        .expect("remote product cache mutex poisoned")
        .get(slug)
        .cloned()
    {
        return Ok(snapshot);
    }

    if let Some(cached) = read_cached_product(slug)? {
        remote_product_cache()
            .lock()
            .expect("remote product cache mutex poisoned")
            .insert(slug.to_string(), cached.clone());
        return Ok(cached);
    }

    let url = format!("https://endoflife.date/api/v1/products/{slug}/");
    let response = eol_client()
        .get(&url)
        .send()
        .with_context(|| format!("failed to query {url}"))?
        .error_for_status()
        .with_context(|| format!("endoflife.date returned an error for {slug}"))?;
    let document = response
        .json::<ApiDocument>()
        .with_context(|| format!("failed to decode endoflife.date payload for {slug}"))?;
    let snapshot = ProductSnapshot {
        slug: slug.to_string(),
        label: document.result.label,
        cycles: document
            .result
            .releases
            .into_iter()
            .map(|release| CycleSnapshot {
                name: release.name,
                is_eol: release.is_eol,
                is_maintained: release.is_maintained,
                eol_from: release.eol_from,
                latest: release.latest.map(|latest| latest.name),
            })
            .collect(),
    };
    write_cached_product(slug, &snapshot)?;
    remote_product_cache()
        .lock()
        .expect("remote product cache mutex poisoned")
        .insert(slug.to_string(), snapshot.clone());
    Ok(snapshot)
}

fn read_cached_product(slug: &str) -> Result<Option<ProductSnapshot>> {
    let path = remote_cache_path(slug)?;
    if !path.exists() || cache_is_stale(&path)? {
        return Ok(None);
    }
    let payload =
        fs::read_to_string(&path).with_context(|| format!("failed to read {}", path.display()))?;
    let snapshot = serde_json::from_str::<ProductSnapshot>(&payload)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    Ok(Some(snapshot))
}

fn write_cached_product(slug: &str, snapshot: &ProductSnapshot) -> Result<()> {
    let path = remote_cache_path(slug)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    fs::write(&path, serde_json::to_vec_pretty(snapshot)?)
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

fn remote_cache_path(slug: &str) -> Result<PathBuf> {
    let root = dirs::cache_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("explicit/endoflife");
    Ok(root.join(format!("{slug}.json")))
}

fn cache_is_stale(path: &Path) -> Result<bool> {
    let modified = fs::metadata(path)
        .with_context(|| format!("failed to read metadata for {}", path.display()))?
        .modified()
        .with_context(|| format!("failed to read modified time for {}", path.display()))?;
    let age = SystemTime::now()
        .duration_since(modified)
        .unwrap_or_else(|_| Duration::from_secs(0));
    Ok(age > REMOTE_CACHE_TTL)
}

fn eol_client() -> &'static Client {
    HTTP_CLIENT.get_or_init(|| {
        Client::builder()
            .timeout(Duration::from_secs(3))
            .build()
            .expect("endoflife.date client must build")
    })
}

fn remote_product_cache() -> &'static Mutex<BTreeMap<String, ProductSnapshot>> {
    REMOTE_PRODUCTS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

#[cfg(test)]
mod tests {
    use super::{
        ApiDocument, CycleSnapshot, EOL_DB_TOML, ProductSnapshot, ResolvedStatus, cache_is_stale,
        ensure_supported_runtime_versions, find_cycle, format_failure, parse_embedded_db,
        product_label, read_cached_product, remote_cache_path, write_cached_product,
    };
    use crate::analysis::{DetectedVersion, RuntimeKind, VersionKind};

    #[test]
    fn embedded_database_loads() {
        let db = parse_embedded_db();
        assert!(db.products.iter().any(|product| product.slug == "nodejs"));
    }

    #[test]
    fn api_payload_maps_to_cycle_snapshot_shape() {
        let payload = r#"{
          "result": {
            "label": "Node.js",
            "releases": [
              {
                "name": "20",
                "isEol": false,
                "isMaintained": true,
                "eolFrom": "2026-04-30",
                "latest": { "name": "20.20.2" }
              }
            ]
          }
        }"#;
        let parsed = serde_json::from_str::<ApiDocument>(payload).unwrap();
        assert_eq!(parsed.result.releases[0].name, "20");
        assert_eq!(
            parsed.result.releases[0].latest.as_ref().unwrap().name,
            "20.20.2"
        );
    }

    #[test]
    fn cycle_extraction_matches_embedded_node_lts_versions() {
        let version = DetectedVersion {
            runtime: RuntimeKind::Nodejs,
            version: "20.18.0".to_string(),
            source: ".node-version".to_string(),
            kind: VersionKind::Exact,
            config_lines: Vec::new(),
        };
        assert_eq!(
            version
                .runtime
                .cycle_from_version(&version.version)
                .as_deref(),
            Some("20")
        );
    }

    #[test]
    fn embedded_db_toml_is_not_empty() {
        assert!(EOL_DB_TOML.contains("nodejs"));
    }

    #[test]
    fn rejects_end_of_life_versions_from_embedded_db() {
        let result = ensure_supported_runtime_versions(
            &[DetectedVersion {
                runtime: RuntimeKind::Nodejs,
                version: "16.20.2".to_string(),
                source: ".node-version".to_string(),
                kind: VersionKind::Exact,
                config_lines: Vec::new(),
            }],
            false,
        );
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("dangerously-use-end-of-life-versions")
        );
    }

    #[test]
    fn allows_unmapped_versions_without_error() {
        let result = ensure_supported_runtime_versions(
            &[DetectedVersion {
                runtime: RuntimeKind::Elixir,
                version: "~> 1.15".to_string(),
                source: "services/stuffix/mix.exs#elixir".to_string(),
                kind: VersionKind::Constraint,
                config_lines: Vec::new(),
            }],
            false,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn warns_but_continues_for_eol_versions_with_allow_flag() {
        let result = ensure_supported_runtime_versions(
            &[DetectedVersion {
                runtime: RuntimeKind::Nodejs,
                version: "16.20.2".to_string(),
                source: ".node-version".to_string(),
                kind: VersionKind::Exact,
                config_lines: Vec::new(),
            }],
            true,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn find_cycle_returns_matching_cycle() {
        let products = vec![ProductSnapshot {
            slug: "nodejs".to_string(),
            label: "Node.js".to_string(),
            cycles: vec![CycleSnapshot {
                name: "20".to_string(),
                is_eol: false,
                is_maintained: true,
                eol_from: Some("2026-04-30".to_string()),
                latest: Some("20.18.0".to_string()),
            }],
        }];
        let cycle = find_cycle(&products, "nodejs", "20");
        assert!(cycle.is_some());
        assert_eq!(cycle.unwrap().name, "20");
        assert!(!cycle.unwrap().is_eol);
    }

    #[test]
    fn find_cycle_returns_none_for_unknown_product() {
        let db = parse_embedded_db();
        assert!(find_cycle(&db.products, "nonexistent-product-xyz", "1").is_none());
    }

    #[test]
    fn find_cycle_returns_none_for_unknown_cycle() {
        let db = parse_embedded_db();
        assert!(find_cycle(&db.products, "nodejs", "999").is_none());
    }

    #[test]
    fn product_label_returns_label_for_known_product() {
        let db = parse_embedded_db();
        let label = product_label(&db.products, "nodejs");
        assert!(label.is_some());
        assert!(!label.unwrap().is_empty());
    }

    #[test]
    fn product_label_returns_none_for_unknown() {
        let db = parse_embedded_db();
        assert!(product_label(&db.products, "xyz-unknown-product-99999").is_none());
    }

    #[test]
    fn format_failure_includes_version_info() {
        let version = DetectedVersion {
            runtime: RuntimeKind::Nodejs,
            version: "16.20.0".to_string(),
            source: ".node-version".to_string(),
            kind: VersionKind::Exact,
            config_lines: Vec::new(),
        };
        let status = ResolvedStatus {
            label: "Node.js".to_string(),
            cycle: "16".to_string(),
            is_eol: true,
            eol_from: Some("2023-09-11".to_string()),
            latest: Some("16.20.2".to_string()),
            source: "embedded endoflife.date snapshot",
        };
        let msg = format_failure(&version, &status);
        assert!(msg.contains("Node.js"));
        assert!(msg.contains("16.20.0"));
        assert!(msg.contains("2023-09-11"));
        assert!(msg.contains("embedded endoflife.date snapshot"));
    }

    #[test]
    fn format_failure_handles_missing_optional_fields() {
        let version = DetectedVersion {
            runtime: RuntimeKind::Nodejs,
            version: "14.0.0".to_string(),
            source: ".nvmrc".to_string(),
            kind: VersionKind::Exact,
            config_lines: Vec::new(),
        };
        let status = ResolvedStatus {
            label: "Node.js".to_string(),
            cycle: "14".to_string(),
            is_eol: true,
            eol_from: None,
            latest: None,
            source: "live endoflife.date API",
        };
        let msg = format_failure(&version, &status);
        assert!(msg.contains("an unknown date"));
        assert!(msg.contains("unknown"));
    }

    #[test]
    fn cache_is_stale_returns_false_for_freshly_written_file() {
        use std::fs;
        use tempfile::tempdir;
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.json");
        fs::write(&path, b"{}").unwrap();
        let stale = cache_is_stale(&path).unwrap();
        assert!(!stale, "freshly written file should not be stale");
    }

    #[test]
    fn write_and_read_cached_product_round_trip() {
        use tempfile::tempdir;
        // Override cache dir via DIRS_CACHE_DIR isn't available, so we use
        // `dirs::cache_dir` which reads XDG_CACHE_HOME on Linux/macOS.
        // On macOS `dirs::cache_dir()` uses ~/Library/Caches (not XDG).
        // We can't easily override it, so instead we use XDG_CACHE_HOME which
        // the dirs crate respects when set.
        let dir = tempdir().unwrap();
        // Safety: test-only env manipulation.
        unsafe { std::env::set_var("XDG_CACHE_HOME", dir.path()) };
        let snapshot = ProductSnapshot {
            slug: "test-slug-xyz".to_string(),
            label: "TestProduct".to_string(),
            cycles: vec![CycleSnapshot {
                name: "1".to_string(),
                is_eol: false,
                is_maintained: true,
                eol_from: None,
                latest: Some("1.2.3".to_string()),
            }],
        };
        write_cached_product("test-slug-xyz", &snapshot).unwrap();
        let path = remote_cache_path("test-slug-xyz").unwrap();
        assert!(path.exists());
        let loaded = read_cached_product("test-slug-xyz").unwrap();
        unsafe { std::env::remove_var("XDG_CACHE_HOME") };
        let loaded = loaded.expect("cached product should be readable");
        assert_eq!(loaded.slug, "test-slug-xyz");
        assert_eq!(loaded.label, "TestProduct");
        assert_eq!(loaded.cycles[0].latest, Some("1.2.3".to_string()));
    }

    #[test]
    fn read_cached_product_returns_none_when_absent() {
        use tempfile::tempdir;
        let dir = tempdir().unwrap();
        unsafe { std::env::set_var("XDG_CACHE_HOME", dir.path()) };
        let result = read_cached_product("no-such-product-xyz123").unwrap();
        unsafe { std::env::remove_var("XDG_CACHE_HOME") };
        assert!(result.is_none());
    }
}
