use std::path::Path;

use anyhow::Result;
use toml::Value as TomlValue;

use super::{Builder, ProjectContext};

pub(super) fn analyze(root: &Path, builder: &mut Builder, context: &ProjectContext) -> Result<()> {
    if !root.join("requirements.txt").exists()
        && !root.join("pyproject.toml").exists()
        && !root.join("uv.lock").exists()
        && !root.join("poetry.lock").exists()
    {
        return Ok(());
    }

    builder.add_language(super::LanguageRequirement::Python);
    let python_dependencies = context.dependencies("python").cloned().unwrap_or_default();
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
    if let Some(value) = context.pyproject() {
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
    if root.join("manage.py").is_file() && python_dependencies.contains("django") {
        builder.add_dev_server("python manage.py runserver");
    }

    Ok(())
}
