use std::path::Path;

use anyhow::Result;

use super::{
    Builder, ProjectContext, detect_rails_starter_page_requirement, detect_ruby_test_commands,
};

pub(super) fn analyze(root: &Path, builder: &mut Builder, context: &ProjectContext) -> Result<()> {
    if !root.join("Gemfile").exists() && !root.join("Bundlefile").exists() {
        return Ok(());
    }

    let ruby_dependencies = context.dependencies("ruby").cloned().unwrap_or_default();
    builder.add_marker(if root.join("Gemfile").exists() {
        "Gemfile"
    } else {
        "Bundlefile"
    });
    builder.add_language(super::LanguageRequirement::Ruby);
    builder.add_package("bundler");
    if ruby_dependencies.contains("rails") || root.join("bin/rails").exists() {
        builder.add_marker("rails");
        builder.add_dev_server("bin/rails server");
    }
    if root.join(".rubocop.yml").exists() {
        builder.add_lint("bundle exec rubocop");
    }
    for command in detect_ruby_test_commands(root, Some(&ruby_dependencies))? {
        builder.add_test(command);
    }
    if let Some(requirement) = detect_rails_starter_page_requirement(root, &ruby_dependencies)? {
        builder.add_requirement(requirement);
    }

    Ok(())
}
