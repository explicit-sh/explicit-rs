use std::path::Path;

use anyhow::Result;

use super::{
    Builder, ProjectContext, detect_javascript_dev_server_command,
    fallback_javascript_test_commands, script_is_verification_ready,
};

pub(super) fn analyze(root: &Path, builder: &mut Builder, context: &ProjectContext) -> Result<()> {
    let Some(payload) = context.package_json() else {
        return Ok(());
    };

    builder.add_marker("package.json");
    builder.add_install_directory("node_modules");
    builder.add_language(super::LanguageRequirement::JavaScript);
    builder.add_package("nodejs");
    let package_manager = payload
        .get("packageManager")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    let package_dependencies = context
        .dependencies("javascript")
        .cloned()
        .unwrap_or_default();
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
        if let Some(command) =
            detect_javascript_dev_server_command(&package_dependencies, scripts, runner)
        {
            builder.add_dev_server(command);
        }
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
                    .map(|script| script_is_verification_ready(name, script))
                    .unwrap_or(false)
            {
                builder.add_test(format!("{runner} {name}"));
                discovered_test_script = true;
            }
        }
        if !discovered_test_script {
            for command in fallback_javascript_test_commands(&package_dependencies, exec_runner) {
                builder.add_test(command);
            }
        }
    } else {
        for command in fallback_javascript_test_commands(&package_dependencies, exec_runner) {
            builder.add_test(command);
        }
    }

    Ok(())
}
