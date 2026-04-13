use std::fs;
use std::process::Command;

use serde_json::Value as JsonValue;
use tempfile::tempdir;

fn run_tool(root: &std::path::Path) {
    let status = Command::new(env!("CARGO_BIN_EXE_explicit"))
        .args(["apply", "--root"])
        .arg(root)
        .status()
        .expect("failed to run explicit");
    assert!(status.success());
}

fn run_doctor(root: &std::path::Path) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_explicit"))
        .args(["doctor", "--root"])
        .arg(root)
        .output()
        .expect("failed to run explicit doctor");
    assert!(output.status.success());
    String::from_utf8(output.stdout).unwrap()
}

fn run_verify(root: &std::path::Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_explicit"))
        .args(["verify", "--root"])
        .arg(root)
        .output()
        .expect("failed to run explicit verify")
}

fn run_scan(root: &std::path::Path) -> JsonValue {
    let output = Command::new(env!("CARGO_BIN_EXE_explicit"))
        .args(["scan", "--root"])
        .arg(root)
        .output()
        .expect("failed to run explicit scan");
    assert!(output.status.success());
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn apply_detects_node_make_and_generates_hooks() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    fs::write(
        root.join("package.json"),
        r#"{
  "name": "demo",
  "packageManager": "pnpm@9.0.0",
  "scripts": {
    "test": "vitest run",
    "lint": "eslint .",
    "build": "vite build"
  }
}"#,
    )
    .unwrap();
    fs::write(root.join("pnpm-lock.yaml"), "lockfileVersion: '9.0'\n").unwrap();
    fs::write(
        root.join("Makefile"),
        "lint:\n\t@echo lint\nbuild:\n\t@echo build\n",
    )
    .unwrap();

    run_tool(root);

    let generated = fs::read_to_string(root.join("explicit.generated.deps.nix")).unwrap();
    assert!(generated.contains("languages.javascript.enable = true;"));
    assert!(generated.contains("pkgs.nodejs"));
    assert!(generated.contains("pkgs.pnpm"));
    assert!(generated.contains("pkgs.gnumake"));

    let guard_payload: JsonValue =
        serde_json::from_str(&fs::read_to_string(root.join(".nono/guard-commands.json")).unwrap())
            .unwrap();
    let commands = guard_payload["commands"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["command"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert!(commands.contains(&"pnpm lint"));
    assert!(commands.contains(&"pnpm build"));
    assert!(commands.contains(&"pnpm test"));
    assert!(commands.contains(&"make lint"));
    assert!(commands.contains(&"make build"));
    let test_entries = guard_payload["commands"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|entry| entry["kind"].as_str() == Some("test"))
        .map(|entry| entry["command"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert!(test_entries.contains(&"pnpm test"));

    let claude: JsonValue = serde_json::from_str(
        &fs::read_to_string(root.join(".claude/settings.local.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        claude["hooks"]["Stop"][0]["hooks"][0]["command"],
        "./.nono/stop-guard.sh"
    );

    let codex_hooks: JsonValue =
        serde_json::from_str(&fs::read_to_string(root.join(".codex/hooks.json")).unwrap()).unwrap();
    assert_eq!(
        codex_hooks["Stop"][0]["hooks"][0]["command"],
        "./.nono/stop-guard.sh"
    );
    assert!(
        fs::read_to_string(root.join(".codex/config.toml"))
            .unwrap()
            .contains("codex_hooks = true")
    );
}

#[test]
fn doctor_reports_detected_test_commands() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    fs::write(
        root.join("package.json"),
        r#"{
  "name": "frontend-demo",
  "packageManager": "pnpm@9.0.0",
  "devDependencies": {
    "vitest": "^3.0.0"
  }
}"#,
    )
    .unwrap();

    let output = run_doctor(root);
    assert!(output.contains("Test commands: pnpm exec vitest run"));
}

#[test]
fn apply_discovers_workspace_leaf_commands() {
    let dir = tempdir().unwrap();
    let root = dir.path();
    let service = root.join("services/api");
    let mobile = root.join("apps/mobile");
    Command::new("git")
        .arg("init")
        .arg("-q")
        .arg(root)
        .status()
        .unwrap();

    fs::create_dir_all(&service).unwrap();
    fs::create_dir_all(&mobile).unwrap();
    fs::write(service.join("Makefile"), "lint:\n\t@echo lint\n").unwrap();
    fs::write(
        mobile.join("package.json"),
        r#"{
  "name": "mobile",
  "packageManager": "yarn@4.0.0",
  "scripts": {
    "test": "jest"
  }
}"#,
    )
    .unwrap();
    fs::write(mobile.join("yarn.lock"), "").unwrap();

    run_tool(root);

    let guard_payload: JsonValue =
        serde_json::from_str(&fs::read_to_string(root.join(".nono/guard-commands.json")).unwrap())
            .unwrap();
    let commands = guard_payload["commands"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["command"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert!(commands.contains(&"cd 'services/api' && make lint"));
    assert!(commands.contains(&"cd 'apps/mobile' && yarn test"));

    let doctor = run_doctor(root);
    assert!(doctor.contains("Workspace: merged 2 leaf projects into the root analysis"));
    assert!(doctor.contains("services/api (Makefile)"));
    assert!(doctor.contains("apps/mobile (package.json)"));
}

#[test]
fn doctor_reports_mixed_workspace_leafs() {
    let dir = tempdir().unwrap();
    let root = dir.path();
    let infra = root.join("infra");
    let service = root.join("services/stuffix");
    Command::new("git")
        .arg("init")
        .arg("-q")
        .arg(root)
        .status()
        .unwrap();

    fs::create_dir_all(&infra).unwrap();
    fs::create_dir_all(&service).unwrap();
    fs::write(
        infra.join("main.tf"),
        "terraform {\n  required_version = \">= 1.6.0\"\n}\n",
    )
    .unwrap();
    fs::write(
        service.join("mix.exs"),
        r#"defmodule Demo.MixProject do
  use Mix.Project

  def project do
    [app: :demo, version: "0.1.0", elixir: "~> 1.15"]
  end

  defp deps do
    [
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false}
    ]
  end
end
"#,
    )
    .unwrap();

    let output = run_doctor(root);
    assert!(output.contains("Markers: terraform, mix.exs, workspace"));
    assert!(output.contains(
        "Lint commands: cd 'infra' && opentofu fmt -check -recursive, cd 'services/stuffix' && mix format --check-formatted, cd 'services/stuffix' && mix credo --strict"
    ));
    assert!(
        output
            .contains("Build commands: cd 'services/stuffix' && mix compile --warnings-as-errors")
    );
    assert!(output.contains("Test commands: cd 'services/stuffix' && mix test"));
    assert!(output.contains("Requirements: none"));
    assert!(output.contains("Workspace members: infra (*.tf), services/stuffix (mix.exs)."));
}

#[test]
fn verify_workspace_root_reports_root_ds_store_policy_before_leaf_commands() {
    let dir = tempdir().unwrap();
    let root = dir.path();
    let infra = root.join("infra");
    let service = root.join("services/stuffix");

    fs::create_dir_all(&infra).unwrap();
    fs::create_dir_all(&service).unwrap();
    fs::write(root.join("README.md"), "# Demo\n\n## License\nMIT\n").unwrap();
    fs::write(
        infra.join("main.tf"),
        "terraform {\n  required_version = \">= 1.6.0\"\n}\n",
    )
    .unwrap();
    fs::write(
        service.join("mix.exs"),
        "defmodule Demo.MixProject do end\n",
    )
    .unwrap();
    Command::new("git")
        .arg("init")
        .arg("-q")
        .arg(root)
        .status()
        .unwrap();

    let output = run_verify(root);
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("Verification failed."));
    assert!(stderr.contains(" - ignore: .gitignore"));
    assert!(stderr.contains("git repositories must ignore .DS_Store"));
    assert!(!stderr.contains("opentofu fmt -check -recursive"));
    assert!(!stderr.contains("mix format --check-formatted"));
}

#[test]
fn verify_reports_missing_readme_license_section_before_commands() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    fs::write(root.join("README.md"), "# Demo\n\n## Usage\nTry it.\n").unwrap();
    fs::write(root.join(".gitignore"), ".DS_Store\n").unwrap();
    fs::write(
        root.join("Cargo.toml"),
        r#"[package]
name = "demo"
version = "0.1.0"
edition = "2021"
"#,
    )
    .unwrap();
    Command::new("git")
        .arg("init")
        .arg("-q")
        .arg(root)
        .status()
        .unwrap();

    let output = run_verify(root);
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("Verification failed."));
    assert!(stderr.contains(" - docs: README.md#License"));
    assert!(
        stderr
            .contains("git repositories must end README.md with exactly one `## License` section")
    );
    assert!(!stderr.contains("cargo fmt --check"));
}

#[test]
fn rust_projects_use_release_builds() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    fs::write(
        root.join("Cargo.toml"),
        r#"[package]
name = "demo"
version = "0.1.0"
edition = "2021"
"#,
    )
    .unwrap();

    let analysis = run_scan(root);
    let builds = analysis["build_commands"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry.as_str().unwrap())
        .collect::<Vec<_>>();
    assert!(builds.contains(&"cargo build --release"));
    assert!(!builds.contains(&"cargo build"));
}

#[test]
fn apply_preserves_existing_claude_settings() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    fs::write(root.join("mix.exs"), "defmodule Demo.MixProject do end\n").unwrap();
    fs::create_dir_all(root.join(".claude")).unwrap();
    fs::write(
        root.join(".claude/settings.local.json"),
        r#"{"enabledMcpjsonServers":["context7"]}"#,
    )
    .unwrap();

    run_tool(root);

    let payload: JsonValue = serde_json::from_str(
        &fs::read_to_string(root.join(".claude/settings.local.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(payload["enabledMcpjsonServers"][0], "context7");
    assert_eq!(
        payload["hooks"]["Stop"][0]["hooks"][0]["command"],
        "./.nono/stop-guard.sh"
    );

    let guard_payload: JsonValue =
        serde_json::from_str(&fs::read_to_string(root.join(".nono/guard-commands.json")).unwrap())
            .unwrap();
    let commands = guard_payload["commands"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["command"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert!(commands.contains(&"mix format --check-formatted"));
    assert!(commands.contains(&"mix credo --strict"));
    assert!(commands.contains(&"mix compile --warnings-as-errors"));
}

#[test]
fn verify_workspace_root_reports_missing_credo_before_leaf_commands() {
    let dir = tempdir().unwrap();
    let root = dir.path();
    let service = root.join("services/stuffix");

    fs::create_dir_all(&service).unwrap();
    fs::write(root.join("README.md"), "# Demo\n\n## License\nMIT\n").unwrap();
    fs::write(root.join(".gitignore"), ".DS_Store\n").unwrap();
    fs::write(
        service.join("mix.exs"),
        r#"defmodule Demo.MixProject do
  use Mix.Project

  def project do
    [app: :demo, version: "0.1.0", elixir: "~> 1.15"]
  end
end
"#,
    )
    .unwrap();
    Command::new("git")
        .arg("init")
        .arg("-q")
        .arg(root)
        .status()
        .unwrap();

    let output = run_verify(root);
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains(" - lint: services/stuffix/mix.exs"));
    assert!(stderr.contains("Elixir projects must include Credo"));
    assert!(!stderr.contains("mix format --check-formatted"));
    assert!(stderr.contains("mix credo --strict"));
}

#[test]
fn verify_blocks_on_default_phoenix_home_page_before_commands() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    fs::create_dir_all(root.join("lib/demo_web/controllers/page_html")).unwrap();
    fs::write(root.join("README.md"), "# Demo\n\n## License\nMIT\n").unwrap();
    fs::write(root.join(".gitignore"), ".DS_Store\n").unwrap();
    fs::write(
        root.join("mix.exs"),
        r#"defmodule Demo.MixProject do
  use Mix.Project

  def project do
    [app: :demo, version: "0.1.0", elixir: "~> 1.15"]
  end

  defp deps do
    [
      {:phoenix, "~> 1.7"},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false}
    ]
  end
end
"#,
    )
    .unwrap();
    fs::write(
        root.join("lib/demo_web/router.ex"),
        r#"defmodule DemoWeb.Router do
  use DemoWeb, :router

  scope "/", DemoWeb do
    pipe_through :browser
    get "/", PageController, :home
  end
end
"#,
    )
    .unwrap();
    fs::write(
        root.join("lib/demo_web/controllers/page_html/home.html.heex"),
        r#"<section>
  <h1>Peace of mind from prototype to production</h1>
  <p>A productive framework that does not compromise speed or maintainability.</p>
</section>
"#,
    )
    .unwrap();
    Command::new("git")
        .arg("init")
        .arg("-q")
        .arg(root)
        .status()
        .unwrap();

    let output = run_verify(root);
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains(" - starter: lib/demo_web/controllers/page_html/home.html.heex"));
    assert!(stderr.contains("Phoenix projects must replace the default getting started home page"));
    assert!(!stderr.contains("mix format --check-formatted"));
}

#[test]
fn apply_detects_nokogiri_and_adds_xml_build_support() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    fs::write(
        root.join("Gemfile"),
        r#"
source "https://rubygems.org"

gem "nokogiri", "~> 1.18"
"#,
    )
    .unwrap();
    fs::write(
        root.join("Gemfile.lock"),
        r#"
GEM
  remote: https://rubygems.org/
  specs:
    mini_portile2 (2.8.8)
    nokogiri (1.18.7)
      mini_portile2 (~> 2.8.2)

PLATFORMS
  ruby

DEPENDENCIES
  nokogiri (~> 1.18)
"#,
    )
    .unwrap();
    fs::write(root.join("sample.xml"), "<root><item>Hello</item></root>\n").unwrap();

    run_tool(root);

    let generated = fs::read_to_string(root.join("explicit.generated.deps.nix")).unwrap();
    assert!(generated.contains("languages.ruby.enable = true;"));
    assert!(generated.contains("pkgs.bundler"));
    assert!(generated.contains("pkgs.pkg-config"));
    assert!(generated.contains("pkgs.libxml2"));
    assert!(generated.contains("pkgs.libxslt"));
    assert!(generated.contains("nokogiri"));
}

#[test]
fn apply_detects_python_native_dependencies_and_services() {
    let dir = tempdir().unwrap();
    let root = dir.path();
    fs::create_dir_all(root.join("tests")).unwrap();
    fs::write(
        root.join("tests/test_smoke.py"),
        "def test_smoke():\n    assert True\n",
    )
    .unwrap();

    fs::write(
        root.join("pyproject.toml"),
        r#"
[project]
name = "django-demo"
version = "0.1.0"
dependencies = [
  "django>=5.1",
  "psycopg[binary]>=3.2",
  "lxml>=5.0",
  "pillow>=11.0",
  "maturin>=1.7",
  "redis>=6.0",
]
"#,
    )
    .unwrap();

    run_tool(root);

    let generated = fs::read_to_string(root.join("explicit.generated.deps.nix")).unwrap();
    assert!(generated.contains("languages.python.enable = true;"));
    assert!(generated.contains("languages.rust.enable = true;"));
    assert!(generated.contains("pkgs.python3"));
    assert!(generated.contains("pkgs.postgresql"));
    assert!(generated.contains("pkgs.libxml2"));
    assert!(generated.contains("pkgs.libxslt"));
    assert!(generated.contains("pkgs.zlib"));
    assert!(generated.contains("pkgs.freetype"));
    assert!(generated.contains("pkgs.libjpeg"));
    assert!(generated.contains("services.postgres.enable = true;"));
    assert!(generated.contains("services.postgres.listen_addresses = \"127.0.0.1\";"));
    assert!(generated.contains("services.redis.enable = true;"));
    assert!(generated.contains("maturin"));
    assert!(generated.contains("psycopg"));
    let analysis: JsonValue =
        serde_json::from_str(&fs::read_to_string(root.join(".nono/analysis.json")).unwrap())
            .unwrap();
    let tests = analysis["test_commands"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry.as_str().unwrap())
        .collect::<Vec<_>>();
    assert!(tests.contains(&"python -m unittest discover"));
}

#[test]
fn apply_detects_nextjs_native_dependencies_and_services() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    fs::write(
        root.join("package.json"),
        r#"{
  "name": "next-demo",
  "packageManager": "pnpm@9.0.0",
  "dependencies": {
    "next": "15.0.0",
    "sharp": "^0.33.0",
    "prisma": "^6.0.0",
    "pg": "^8.13.0",
    "better-sqlite3": "^11.0.0",
    "ioredis": "^5.4.0"
  },
  "scripts": {
    "build": "next build"
  }
}"#,
    )
    .unwrap();

    run_tool(root);

    let generated = fs::read_to_string(root.join("explicit.generated.deps.nix")).unwrap();
    assert!(generated.contains("languages.javascript.enable = true;"));
    assert!(generated.contains("pkgs.nodejs"));
    assert!(generated.contains("pkgs.pnpm"));
    assert!(generated.contains("pkgs.vips"));
    assert!(generated.contains("pkgs.openssl"));
    assert!(generated.contains("pkgs.sqlite"));
    assert!(generated.contains("pkgs.postgresql"));
    assert!(generated.contains("services.postgres.enable = true;"));
    assert!(generated.contains("services.postgres.listen_addresses = \"127.0.0.1\";"));
    assert!(generated.contains("services.redis.enable = true;"));
    assert!(generated.contains("sharp"));
    assert!(generated.contains("Prisma"));
}

#[test]
fn apply_detects_react_native_project_requirements() {
    let dir = tempdir().unwrap();
    let root = dir.path();
    fs::create_dir_all(root.join("android")).unwrap();
    fs::create_dir_all(root.join("ios")).unwrap();

    fs::write(
        root.join("package.json"),
        r#"{
  "name": "rn-demo",
  "private": true,
  "packageManager": "pnpm@9.0.0",
  "scripts": {
    "start": "react-native start",
    "android": "react-native run-android",
    "ios": "react-native run-ios",
    "test": "jest"
  },
  "dependencies": {
    "react": "18.3.1",
    "react-native": "0.76.0"
  },
  "devDependencies": {
    "@react-native-community/cli": "15.0.0",
    "jest": "29.7.0"
  }
}"#,
    )
    .unwrap();

    run_tool(root);

    let generated = fs::read_to_string(root.join("explicit.generated.deps.nix")).unwrap();
    assert!(generated.contains("languages.javascript.enable = true;"));
    assert!(generated.contains("languages.java.enable = true;"));
    assert!(generated.contains("pkgs.nodejs"));
    assert!(generated.contains("pkgs.pnpm"));
    assert!(generated.contains("pkgs.watchman"));
    assert!(generated.contains("android.enable = true;"));
    assert!(generated.contains("android.reactNative.enable = true;"));
    assert!(generated.contains("android.emulator.enable = false;"));
    assert!(generated.contains("android.systemImages.enable = false;"));
    assert!(generated.contains("React Native"));

    let devenv_yaml = fs::read_to_string(root.join("devenv.yaml")).unwrap();
    assert!(devenv_yaml.contains("allowUnfree: true"));

    let analysis: JsonValue =
        serde_json::from_str(&fs::read_to_string(root.join(".nono/analysis.json")).unwrap())
            .unwrap();
    let markers = analysis["markers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry.as_str().unwrap())
        .collect::<Vec<_>>();
    assert!(markers.contains(&"react-native"));
    let tests = analysis["test_commands"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry.as_str().unwrap())
        .collect::<Vec<_>>();
    assert!(tests.contains(&"pnpm test"));
    assert_eq!(analysis["requires_allow_unfree"], JsonValue::Bool(true));

    let doctor = run_doctor(root);
    assert!(doctor.contains("Nix options:"));
    assert!(doctor.contains("android.enable = true;"));
    assert!(doctor.contains("android.reactNative.enable = true;"));
    assert!(doctor.contains("android.emulator.enable = false;"));
    assert!(doctor.contains("android.systemImages.enable = false;"));
    assert!(doctor.contains("Allow unfree: true"));
}

#[test]
fn apply_detects_elixir_nifs_and_services() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    fs::write(
        root.join("mix.exs"),
        r#"
defmodule Demo.MixProject do
  use Mix.Project

  def project do
    [app: :demo, version: "0.1.0", elixir: "~> 1.17", deps: deps()]
  end

  def application do
    [extra_applications: [:logger]]
  end

  defp deps do
    [
      {:phoenix, "~> 1.7.0"},
      {:postgrex, ">= 0.0.0"},
      {:redix, ">= 0.0.0"},
      {:rustler, "~> 0.36"}
    ]
  end
end
"#,
    )
    .unwrap();

    run_tool(root);

    let generated = fs::read_to_string(root.join("explicit.generated.deps.nix")).unwrap();
    assert!(generated.contains("languages.elixir.enable = true;"));
    assert!(generated.contains("languages.rust.enable = true;"));
    assert!(generated.contains("Enabling Rust because Rustler-backed NIFs need a Rust toolchain."));
    assert!(generated.contains("pkgs.postgresql"));
    assert!(generated.contains("services.postgres.enable = true;"));
    assert!(generated.contains("services.postgres.listen_addresses = \"127.0.0.1\";"));
    assert!(generated.contains("services.redis.enable = true;"));
    assert!(generated.contains("rustler"));
    let analysis: JsonValue =
        serde_json::from_str(&fs::read_to_string(root.join(".nono/analysis.json")).unwrap())
            .unwrap();
    let tests = analysis["test_commands"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry.as_str().unwrap())
        .collect::<Vec<_>>();
    assert!(tests.contains(&"mix test"));
}

#[test]
fn apply_detects_rspec_and_blocks_stop_on_tests() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    fs::write(
        root.join("Gemfile"),
        r#"
source "https://rubygems.org"

gem "rails"
gem "rspec-rails"
"#,
    )
    .unwrap();
    fs::create_dir_all(root.join("spec")).unwrap();
    fs::write(root.join(".rspec"), "--format documentation\n").unwrap();

    run_tool(root);

    let analysis: JsonValue =
        serde_json::from_str(&fs::read_to_string(root.join(".nono/analysis.json")).unwrap())
            .unwrap();
    let tests = analysis["test_commands"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry.as_str().unwrap())
        .collect::<Vec<_>>();
    assert!(tests.contains(&"bundle exec rspec"));

    let guard_payload: JsonValue =
        serde_json::from_str(&fs::read_to_string(root.join(".nono/guard-commands.json")).unwrap())
            .unwrap();
    let test_entries = guard_payload["commands"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|entry| entry["kind"].as_str() == Some("test"))
        .map(|entry| entry["command"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert!(test_entries.contains(&"bundle exec rspec"));
}

#[test]
fn apply_installs_managed_pre_push_hook_for_git_repos() {
    let dir = tempdir().unwrap();
    let root = dir.path();
    Command::new("git")
        .arg("init")
        .arg("-q")
        .arg(root)
        .status()
        .unwrap();
    fs::write(root.join("Makefile"), "lint:\n\t@echo lint\n").unwrap();

    run_tool(root);

    let hook = fs::read_to_string(root.join(".git/hooks/pre-push")).unwrap();
    assert!(hook.contains("explicit-managed-pre-push"));
    assert!(hook.contains(".nono/pre-push-verify.sh"));
}

#[test]
fn verify_passes_when_detected_checks_succeed() {
    let dir = tempdir().unwrap();
    let root = dir.path();
    fs::write(
        root.join("Makefile"),
        "lint:\n\t@echo lint-ok\nbuild:\n\t@echo build-ok\ntest:\n\t@echo test-ok\n",
    )
    .unwrap();

    let output = run_verify(root);
    assert!(output.status.success());
    assert_eq!(String::from_utf8(output.stderr).unwrap().trim(), "[PASS]");
}

#[test]
fn verify_prepares_managed_devenv_files() {
    let dir = tempdir().unwrap();
    let root = dir.path();
    fs::write(root.join("Makefile"), "lint:\n\t@echo lint-ok\n").unwrap();

    let output = run_verify(root);
    assert!(output.status.success());
    assert!(root.join("devenv.nix").is_file());
    assert!(root.join("explicit.generated.deps.nix").is_file());
}

#[test]
fn verify_blocks_stop_when_detected_checks_fail() {
    let dir = tempdir().unwrap();
    let root = dir.path();
    fs::write(
        root.join("Makefile"),
        "lint:\n\t@echo lint-ok\nbuild:\n\t@echo 'error: release build exploded' >&2\n\t@exit 1\ntest:\n\t@echo test-ok\n",
    )
    .unwrap();

    let output = run_verify(root);
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("Verification failed."));
    assert!(stderr.contains("build"));
    assert!(stderr.contains("make build"));
    assert!(stderr.contains("release build exploded"));
}

#[test]
fn doctor_reports_detected_runtime_versions() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    fs::write(
        root.join("package.json"),
        r#"{"name":"demo","packageManager":"pnpm@9.0.0"}"#,
    )
    .unwrap();
    fs::write(root.join(".node-version"), "20.18.0\n").unwrap();

    let output = run_doctor(root);
    assert!(output.contains("Language versions: nodejs 20.18.0 (.node-version)"));
}

#[test]
fn apply_pins_detected_language_versions_in_generated_nix() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    fs::write(root.join("Gemfile"), "source \"https://rubygems.org\"\n").unwrap();
    fs::write(root.join(".ruby-version"), "3.3.6\n").unwrap();
    fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"demo\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .unwrap();
    fs::write(
        root.join("rust-toolchain.toml"),
        "[toolchain]\nchannel = \"1.84.0\"\n",
    )
    .unwrap();

    run_tool(root);

    let generated = fs::read_to_string(root.join("explicit.generated.deps.nix")).unwrap();
    assert!(generated.contains("languages.ruby.versionFile = ./.ruby-version;"));
    assert!(generated.contains("languages.rust.toolchainFile = ./rust-toolchain.toml;"));
    assert!(generated.contains("Respecting .ruby-version"));
    assert!(generated.contains("Respecting rust-toolchain.toml"));
}
