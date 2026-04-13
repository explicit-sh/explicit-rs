use std::path::Path;

use anyhow::Result;

use super::{Builder, ProjectContext};

pub(super) fn analyze(root: &Path, builder: &mut Builder, context: &ProjectContext) -> Result<()> {
    let Some(payload) = context.composer_json() else {
        return Ok(());
    };

    builder.add_marker("composer.json");
    builder.add_install_directory("vendor");
    builder.add_language(super::LanguageRequirement::Php);
    builder.add_package("composer");
    if payload
        .get("scripts")
        .and_then(serde_json::Value::as_object)
        .and_then(|scripts| scripts.get("test"))
        .is_some()
    {
        builder.add_test("composer test");
    } else {
        let dependencies = context.dependencies("php").cloned().unwrap_or_default();
        if dependencies.contains("laravel/framework") && root.join("artisan").is_file() {
            builder.add_dev_server("php artisan serve");
        }
        if dependencies.contains("pestphp/pest") {
            builder.add_test("vendor/bin/pest");
        } else if dependencies.contains("phpunit/phpunit")
            || root.join("phpunit.xml").exists()
            || root.join("phpunit.xml.dist").exists()
        {
            builder.add_test("vendor/bin/phpunit");
        }
    }

    Ok(())
}
