use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::Deserialize;

#[derive(Debug, Deserialize, Default)]
struct CodexConfig {
    #[serde(default)]
    mcp_servers: BTreeMap<String, McpServerConfig>,
}

#[derive(Debug, Deserialize, Default)]
struct McpServerConfig {
    #[serde(default)]
    env_http_headers: BTreeMap<String, String>,
}

pub fn sandbox_env() -> Result<BTreeMap<String, String>> {
    let Some(config_path) = config_path() else {
        return Ok(BTreeMap::new());
    };
    if !config_path.is_file() {
        return Ok(BTreeMap::new());
    }

    let raw = fs::read_to_string(&config_path)
        .with_context(|| format!("failed to read {}", config_path.display()))?;
    let parsed: CodexConfig = toml::from_str(&raw)
        .with_context(|| format!("failed to parse {}", config_path.display()))?;

    let mut env = BTreeMap::new();
    for server in parsed.mcp_servers.values() {
        for variable_name in server.env_http_headers.values() {
            let name = variable_name.trim();
            if name.is_empty() {
                continue;
            }
            if let Ok(value) = std::env::var(name) {
                env.entry(name.to_string()).or_insert(value);
            }
        }
    }
    Ok(env)
}

fn config_path() -> Option<PathBuf> {
    let home = dirs::home_dir()?;
    Some(home.join(".codex/config.toml"))
}

#[cfg(test)]
mod tests {
    use super::CodexConfig;

    #[test]
    fn parses_mcp_header_environment_variable_names() {
        let parsed: CodexConfig = toml::from_str(
            r#"
[mcp_servers.context7]
transport = "streamable_http"
url = "https://mcp.context7.com/mcp"

[mcp_servers.context7.env_http_headers]
CONTEXT7_API_KEY = "CONTEXT7_API_KEY"

[mcp_servers.other]
transport = "streamable_http"
url = "https://example.test/mcp"

[mcp_servers.other.env_http_headers]
X_FOO = "OTHER_TOKEN"
"#,
        )
        .unwrap();

        let collected = parsed
            .mcp_servers
            .values()
            .flat_map(|server| server.env_http_headers.values().cloned())
            .collect::<Vec<_>>();
        assert!(collected.contains(&"CONTEXT7_API_KEY".to_string()));
        assert!(collected.contains(&"OTHER_TOKEN".to_string()));
    }
}
