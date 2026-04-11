use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result, bail};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};

use crate::analysis::DetectedVersion;

const EOL_DB_TOML: &str = include_str!("../eol_db.toml");
const REMOTE_CACHE_TTL: Duration = Duration::from_secs(60 * 60 * 24);

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

    let db = parse_embedded_db()?;
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

fn parse_embedded_db() -> Result<EolDatabase> {
    toml::from_str(EOL_DB_TOML).context("failed to parse embedded end-of-life database")
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
    if let Some(cached) = read_cached_product(slug)? {
        return Ok(cached);
    }

    let url = format!("https://endoflife.date/api/v1/products/{slug}/");
    let client = Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .context("failed to build endoflife.date client")?;
    let response = client
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

#[cfg(test)]
mod tests {
    use super::{ApiDocument, EOL_DB_TOML, ensure_supported_runtime_versions, parse_embedded_db};
    use crate::analysis::{DetectedVersion, RuntimeKind, VersionKind};

    #[test]
    fn embedded_database_loads() {
        let db = parse_embedded_db().unwrap();
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
}
