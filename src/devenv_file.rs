use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};
use rnix::Root;
use rnix::ast::{self, HasEntry};
use serde_yaml::{Mapping as YamlMapping, Value as YamlValue};

const MANAGED_IMPORT: &str = "./devenv.generated.nix";

pub fn ensure_devenv_file(root: &Path) -> Result<()> {
    let path = root.join("devenv.nix");
    if !path.exists() {
        fs::write(
            &path,
            r#"{ pkgs, ... }:

{
  imports = [ ./devenv.generated.nix ];

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

    fs::write(&path, serde_yaml::to_string(&payload)?)
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

fn ensure_managed_import(path: &Path) -> Result<()> {
    let source =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
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

    if updated != source {
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
    updated.insert_str(insert_at, "\n  imports = [ ./devenv.generated.nix ];");
    Ok(updated)
}

pub fn render_generated_nix(analysis: &crate::analysis::Analysis) -> String {
    let mut lines = vec![
        "{ pkgs, ... }:".to_string(),
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

    let packages = analysis
        .packages
        .iter()
        .map(|package| format!("pkgs.{package}"))
        .collect::<Vec<_>>();
    lines.push(format!("  packages = [ {} ];", packages.join(" ")));

    for language in &analysis.detected_languages {
        lines.push(format!("  {}", language.devenv_option()));
    }
    for service in &analysis.services {
        lines.push(format!("  {}", service.devenv_option()));
    }
    for option in &analysis.nix_options {
        lines.push(format!("  {option}"));
    }

    lines.push("}".to_string());
    lines.push(String::new());
    lines.join("\n")
}

fn join_or_none(items: &[String]) -> String {
    if items.is_empty() {
        "none".to_string()
    } else {
        items.join(", ")
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn creates_base_devenv_file_when_missing() {
        let dir = tempdir().unwrap();
        ensure_devenv_file(dir.path()).unwrap();
        let contents = fs::read_to_string(dir.path().join("devenv.nix")).unwrap();
        assert!(contents.contains("imports = [ ./devenv.generated.nix ];"));
    }

    #[test]
    fn appends_managed_import_to_existing_imports_list() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("devenv.nix");
        fs::write(&path, "{ pkgs, ... }:\n{\n  imports = [ ./foo.nix ];\n}\n").unwrap();
        ensure_devenv_file(dir.path()).unwrap();
        let contents = fs::read_to_string(path).unwrap();
        assert!(contents.contains("imports = [ ./foo.nix ./devenv.generated.nix ];"));
    }
}
