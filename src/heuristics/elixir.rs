use std::path::Path;

use anyhow::Result;

use super::{
    Builder, MigrationCheck, MigrationCheckKind, ProjectContext, ProjectRequirement,
    RequirementKind, detect_elixir_coverage_requirement, detect_phoenix_starter_page_requirement,
};

pub(super) fn analyze(root: &Path, builder: &mut Builder, context: &ProjectContext) -> Result<()> {
    if !root.join("mix.exs").exists() {
        return Ok(());
    }

    let elixir_dependencies = context.dependencies("elixir").cloned().unwrap_or_default();
    builder.add_marker("mix.exs");
    builder.add_install_directory("deps");
    builder.add_language(super::LanguageRequirement::Elixir);
    if elixir_dependencies.contains("phoenix") {
        builder.add_marker("phoenix");
        builder.add_dev_server("mix phx.server");
    }
    builder.add_lint("mix format --check-formatted");
    builder.add_lint("mix credo --strict");
    builder.add_build("mix compile --warnings-as-errors");
    builder.add_test("mix test");
    builder.add_coverage("mix test --cover");
    builder.add_migration_check(MigrationCheck {
        kind: MigrationCheckKind::Ecto,
        status_command: "mix ecto.migrations".to_string(),
        apply_command: "mix ecto.migrate".to_string(),
        subject: "mix.exs#migrations".to_string(),
    });
    if !elixir_dependencies.contains("credo") {
        builder.add_requirement(ProjectRequirement {
            kind: RequirementKind::Lint,
            subject: "mix.exs".to_string(),
            summary: "Elixir projects must include Credo and pass `mix credo --strict`."
                .to_string(),
        });
    }
    if let Some(requirement) = detect_elixir_coverage_requirement(root)? {
        builder.add_requirement(requirement);
    }
    if let Some(requirement) = detect_phoenix_starter_page_requirement(root, &elixir_dependencies)?
    {
        builder.add_requirement(requirement);
    }

    Ok(())
}
