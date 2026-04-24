mod analysis;
mod codex_mcp;
mod consult;
mod devenv_file;
mod env_trace;
mod eol;
mod github_app;
mod hooks;
mod host_tools;
mod observe;
mod parallel;
mod registry;
mod runtime;
mod sandbox;
mod verify;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use analysis::Analysis;
use anyhow::{Context, Result};
use clap::{ArgAction, Args, Parser, Subcommand};
use host_tools::preferred_command_path;
use serde_json::json;

#[derive(Parser, Debug)]
#[command(name = "explicit")]
#[command(
    about = "Detect project requirements, manage devenv.nix, and launch a sandboxed agent shell."
)]
struct Cli {
    #[arg(long, global = true, action = ArgAction::SetTrue)]
    no_sandbox: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    #[command(about = "Print the detected project requirements as JSON.")]
    Scan(CommonArgs),
    #[command(about = "Generate devenv files, sandbox metadata, and agent hooks.")]
    Apply(CommonArgs),
    #[command(about = "Show a readable summary of detected tools, services, and commands.")]
    Doctor(CommonArgs),
    #[command(about = "Run the detected lint, build, and test commands for the project.")]
    Verify(VerifyArgs),
    #[command(about = "Launch a devenv-powered sandbox shell for agents or manual use.")]
    Shell(ShellArgs),
    #[command(about = "Attach to a live project run or inspect observed Codex telemetry.")]
    Observe(ObserveArgs),
    #[command(about = "Print GitHub App setup instructions for sandboxed GitHub access.")]
    GithubApp,
    #[command(
        about = "Launch Codex inside the devenv + nono sandbox.",
        disable_help_flag = true,
        disable_help_subcommand = true
    )]
    Codex(AgentArgs),
    #[command(
        about = "Launch Claude inside the devenv + nono sandbox.",
        disable_help_flag = true,
        disable_help_subcommand = true
    )]
    Claude(AgentArgs),
    #[command(
        about = "Launch Gemini inside the devenv + nono sandbox.",
        disable_help_flag = true,
        disable_help_subcommand = true
    )]
    Gemini(AgentArgs),
    #[command(
        about = "Consult a helper LLM in a read-only worktree sandbox (non-interactive).",
        disable_help_subcommand = true
    )]
    Consult(ConsultArgs),
    #[command(hide = true, name = "__sandbox-exec")]
    SandboxExec(SandboxExecArgs),
    #[command(hide = true, name = "__claude-pre-tool-use-bash")]
    ClaudePreToolUseBash,
}

#[derive(Args, Debug, Clone)]
struct CommonArgs {
    #[arg(long, default_value = ".")]
    root: PathBuf,
}

#[derive(Args, Debug, Clone)]
struct ShellArgs {
    #[arg(long, default_value = ".")]
    root: PathBuf,
    #[arg(long)]
    command: Option<String>,
    #[arg(long, action = ArgAction::SetTrue)]
    block_network: bool,
    #[arg(long, action = ArgAction::SetTrue)]
    no_services: bool,
    #[arg(long, action = ArgAction::SetTrue)]
    dangerously_use_end_of_life_versions: bool,
}

#[derive(Args, Debug, Clone)]
struct VerifyArgs {
    #[arg(long, default_value = ".")]
    root: PathBuf,
    #[arg(long, hide = true, action = ArgAction::SetTrue)]
    stop_hook: bool,
    #[arg(long, hide = true, action = ArgAction::SetTrue)]
    git_hook: bool,
}

#[derive(Args, Debug, Clone)]
struct AgentArgs {
    #[arg(long, action = ArgAction::SetTrue)]
    dangerously_use_end_of_life_versions: bool,
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    args: Vec<String>,
}

#[derive(Args, Debug, Clone)]
struct ObserveArgs {
    #[arg(long, default_value = ".")]
    root: PathBuf,
    #[command(subcommand)]
    command: Option<ObserveCommand>,
}

#[derive(Subcommand, Debug, Clone)]
enum ObserveCommand {
    #[command(
        about = "Launch Codex and save model, token, shell, and patch telemetry to SQLite.",
        disable_help_flag = true,
        disable_help_subcommand = true
    )]
    Codex(ObserveAgentArgs),
    #[command(
        about = "Launch Claude and save sandbox, env, and runtime telemetry to SQLite.",
        disable_help_flag = true,
        disable_help_subcommand = true
    )]
    Claude(ObserveAgentArgs),
    #[command(
        about = "Launch Gemini and save sandbox, env, and runtime telemetry to SQLite.",
        disable_help_flag = true,
        disable_help_subcommand = true
    )]
    Gemini(ObserveAgentArgs),
    #[command(about = "List observed runs under the current project.")]
    List(CommonArgs),
    #[command(about = "Print a report for an observed run.")]
    Report(ObserveReportArgs),
}

#[derive(Args, Debug, Clone)]
struct ObserveAgentArgs {
    #[arg(long, default_value = ".")]
    root: PathBuf,
    #[arg(long, action = ArgAction::SetTrue)]
    block_network: bool,
    #[arg(long, action = ArgAction::SetTrue)]
    no_services: bool,
    #[arg(long, action = ArgAction::SetTrue)]
    dangerously_use_end_of_life_versions: bool,
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    args: Vec<String>,
}

#[derive(Args, Debug, Clone)]
struct ObserveReportArgs {
    #[arg(long, default_value = ".")]
    root: PathBuf,
    #[arg(long)]
    run: Option<String>,
    #[arg(long, action = ArgAction::SetTrue)]
    latest: bool,
}

#[derive(Args, Debug, Clone)]
struct SandboxExecArgs {
    #[arg(long)]
    root: PathBuf,
    #[arg(long)]
    env_file: PathBuf,
    #[arg(long)]
    plan_file: PathBuf,
    #[arg(long)]
    command: Option<String>,
}

#[derive(Args, Debug, Clone)]
struct ConsultArgs {
    #[command(subcommand)]
    agent: ConsultAgent,
}

#[derive(Subcommand, Debug, Clone)]
enum ConsultAgent {
    #[command(
        about = "Consult Claude as a helper LLM.",
        disable_help_flag = true,
        disable_help_subcommand = true
    )]
    Claude(ConsultAgentArgs),
    #[command(
        about = "Consult Codex as a helper LLM.",
        disable_help_flag = true,
        disable_help_subcommand = true
    )]
    Codex(ConsultAgentArgs),
    #[command(
        about = "Consult Gemini as a helper LLM.",
        disable_help_flag = true,
        disable_help_subcommand = true
    )]
    Gemini(ConsultAgentArgs),
}

#[derive(Args, Debug, Clone)]
struct ConsultAgentArgs {
    /// Resume a previous consult session using its consult_id.
    #[arg(long)]
    resume: Option<String>,
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    args: Vec<String>,
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(err) => {
            eprintln!("{err:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<ExitCode> {
    let Cli {
        command,
        no_sandbox,
    } = Cli::parse();

    match command {
        Command::Scan(args) => {
            let root = args.root.canonicalize().context("failed to resolve root")?;
            let analysis = Analysis::analyze(&root)?;
            println!("{}", serde_json::to_string_pretty(&analysis)?);
            Ok(ExitCode::SUCCESS)
        }
        Command::Apply(args) => {
            let root = args.root.canonicalize().context("failed to resolve root")?;
            let analysis = Analysis::analyze(&root)?;
            runtime::apply_project(&root, &analysis)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "root": root,
                    "managed_files": [
                        "devenv.nix",
                        "devenv.yaml",
                        "explicit.generated.deps.nix",
                        ".nono/analysis.json",
                        ".nono/sandbox-plan.json"
                    ]
                }))?
            );
            Ok(ExitCode::SUCCESS)
        }
        Command::Doctor(args) => {
            let root = args.root.canonicalize().context("failed to resolve root")?;
            let analysis = Analysis::analyze(&root)?;
            runtime::print_doctor(&analysis)?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Verify(args) => {
            let root = args.root.canonicalize().context("failed to resolve root")?;
            let analysis = Analysis::analyze(&root)?;
            verify::prepare_verify_environment(&root, &analysis)?;
            verify::run_project_checks(&root, &analysis, args.stop_hook, args.git_hook)
        }
        Command::Shell(args) => {
            let root = args.root.canonicalize().context("failed to resolve root")?;
            let analysis = Analysis::analyze(&root)?;
            let status = runtime::launch_shell(
                &root,
                &analysis,
                runtime::LaunchShellOptions {
                    agent: None,
                    command: args.command.as_deref(),
                    block_network: args.block_network,
                    no_services: args.no_services,
                    no_sandbox,
                    dangerously_use_end_of_life_versions: args.dangerously_use_end_of_life_versions,
                    extra_env: None,
                    transcript_path: None,
                    skip_stop_hooks: false,
                },
            )?;
            Ok(status)
        }
        Command::Observe(args) => match args.command {
            Some(ObserveCommand::Codex(args)) => launch_observed_agent("codex", args, no_sandbox),
            Some(ObserveCommand::Claude(args)) => launch_observed_agent("claude", args, no_sandbox),
            Some(ObserveCommand::Gemini(args)) => launch_observed_agent("gemini", args, no_sandbox),
            Some(ObserveCommand::List(args)) => {
                let root = args.root.canonicalize().context("failed to resolve root")?;
                observe::list_runs(&root)?;
                Ok(ExitCode::SUCCESS)
            }
            Some(ObserveCommand::Report(args)) => {
                let root = args.root.canonicalize().context("failed to resolve root")?;
                observe::print_report(&root, args.run.as_deref(), args.latest)?;
                Ok(ExitCode::SUCCESS)
            }
            None => {
                let root = args.root.canonicalize().context("failed to resolve root")?;
                if observe::attach_live_run(&root)? {
                    return Ok(ExitCode::SUCCESS);
                }
                observe::print_report(&root, None, true)?;
                Ok(ExitCode::SUCCESS)
            }
        },
        Command::GithubApp => {
            github_app::print_setup_instructions()?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Codex(args) => launch_agent("codex", args, no_sandbox),
        Command::Claude(args) => launch_agent("claude", args, no_sandbox),
        Command::Gemini(args) => launch_agent("gemini", args, no_sandbox),
        Command::Consult(args) => {
            let (binary, agent_args) = match args.agent {
                ConsultAgent::Claude(a) => ("claude", a),
                ConsultAgent::Codex(a) => ("codex", a),
                ConsultAgent::Gemini(a) => ("gemini", a),
            };
            consult::launch_consult(
                binary,
                agent_args.resume.as_deref(),
                &agent_args.args,
                no_sandbox,
            )
        }
        Command::SandboxExec(args) => {
            sandbox::run_sandbox_exec(args.root, args.env_file, args.plan_file, args.command)?;
            Ok(ExitCode::SUCCESS)
        }
        Command::ClaudePreToolUseBash => {
            hooks::run_claude_pre_tool_use_bash()?;
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn launch_agent(binary: &str, args: AgentArgs, no_sandbox: bool) -> Result<ExitCode> {
    let root = PathBuf::from(".")
        .canonicalize()
        .context("failed to resolve root")?;
    let routed = parallel::route_agent_launch(&root, binary)?;
    let analysis = Analysis::analyze(&routed.root)?;
    let mut extra_env = routed.extra_env.clone();
    extra_env.extend(codex_mcp::sandbox_env()?);
    extra_env.extend(github_app::sandbox_env(&routed.root, &analysis)?);
    let (observe, passthrough_args) = extract_observe_flag(args.args);
    let command = build_agent_command(&routed.root, binary, &passthrough_args)?;
    if observe {
        return observe::launch_observed_agent(
            &routed.root,
            &analysis,
            observe::ObservedAgentOptions {
                agent: binary,
                command,
                agent_args: &passthrough_args,
                block_network: false,
                no_services: false,
                no_sandbox,
                dangerously_use_end_of_life_versions: args.dangerously_use_end_of_life_versions,
                extra_env,
            },
        );
    }
    observe::launch_live_agent(
        &routed.root,
        &analysis,
        observe::LiveAgentOptions {
            agent: binary.to_string(),
            command,
            block_network: false,
            no_services: false,
            no_sandbox,
            dangerously_use_end_of_life_versions: args.dangerously_use_end_of_life_versions,
            extra_env,
        },
    )
}

fn launch_observed_agent(
    binary: &str,
    args: ObserveAgentArgs,
    no_sandbox: bool,
) -> Result<ExitCode> {
    let root = args.root.canonicalize().context("failed to resolve root")?;
    let routed = parallel::route_agent_launch(&root, binary)?;
    let analysis = Analysis::analyze(&routed.root)?;
    let mut extra_env = routed.extra_env.clone();
    extra_env.extend(codex_mcp::sandbox_env()?);
    extra_env.extend(github_app::sandbox_env(&routed.root, &analysis)?);
    let command = build_agent_command(&routed.root, binary, &args.args)?;
    observe::launch_observed_agent(
        &routed.root,
        &analysis,
        observe::ObservedAgentOptions {
            agent: binary,
            command,
            agent_args: &args.args,
            block_network: args.block_network,
            no_services: args.no_services,
            no_sandbox,
            dangerously_use_end_of_life_versions: args.dangerously_use_end_of_life_versions,
            extra_env,
        },
    )
}

fn build_agent_command(root: &Path, binary: &str, args: &[String]) -> Result<String> {
    let executable = preferred_command_path(binary)
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| binary.to_string());

    let command = std::iter::once(shell_escape(&executable))
        .chain(args.iter().map(|arg| shell_escape(arg)))
        .collect::<Vec<_>>()
        .join(" ");
    if let Some(note) = verify::session_start_note(root)? {
        return Ok(format!(
            "printf '%s\\n' {} ; {}",
            shell_escape(&note),
            command
        ));
    }
    Ok(command)
}

fn shell_escape(value: &str) -> String {
    if !value.is_empty()
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.' | '/' | ':'))
    {
        return value.to_string();
    }
    format!("'{}'", value.replace('\'', r#"'"'"'"#))
}

fn extract_observe_flag(args: Vec<String>) -> (bool, Vec<String>) {
    let mut observe = false;
    let mut passthrough_args = Vec::new();
    for arg in args {
        if arg == "--observe" {
            observe = true;
            continue;
        }
        passthrough_args.push(arg);
    }
    (observe, passthrough_args)
}

#[cfg(test)]
mod tests {
    use super::{
        Cli, Command, ObserveCommand, build_agent_command, extract_observe_flag, shell_escape,
    };
    use clap::Parser;
    use std::path::PathBuf;

    #[test]
    fn build_agent_command_quotes_arguments_for_shell() {
        let command = build_agent_command(
            &PathBuf::from("/tmp/project"),
            "codex",
            &[String::from("--prompt"), String::from("hello world")],
        )
        .unwrap();
        assert!(command.ends_with(" --prompt 'hello world'"));
        assert!(command.split_whitespace().next().unwrap().contains("codex"));
    }

    #[test]
    fn shell_escape_handles_single_quotes() {
        let escaped = shell_escape("it's ready");
        assert_eq!(escaped, r#"'it'"'"'s ready'"#);
    }

    #[test]
    fn codex_subcommand_treats_flags_as_agent_arguments() {
        let cli = Cli::try_parse_from(["explicit", "codex", "-m", "gpt-5.4", "--help"])
            .expect("expected codex args to parse");
        let Command::Codex(args) = cli.command else {
            panic!("expected codex command");
        };
        assert_eq!(args.args, vec!["-m", "gpt-5.4", "--help"]);
    }

    #[test]
    fn gemini_subcommand_treats_flags_as_agent_arguments() {
        let cli = Cli::try_parse_from(["explicit", "gemini", "--model", "2.5-pro", "--help"])
            .expect("expected gemini args to parse");
        let Command::Gemini(args) = cli.command else {
            panic!("expected gemini command");
        };
        assert_eq!(args.args, vec!["--model", "2.5-pro", "--help"]);
    }

    #[test]
    fn extracts_observe_flag_from_agent_arguments() {
        let (observe, args) = extract_observe_flag(vec![
            "--observe".to_string(),
            "-m".to_string(),
            "gpt-5.4".to_string(),
        ]);
        assert!(observe);
        assert_eq!(args, vec!["-m", "gpt-5.4"]);
    }

    #[test]
    fn observe_without_subcommand_parses() {
        let cli = Cli::try_parse_from(["explicit", "observe"]).expect("expected observe to parse");
        let Command::Observe(args) = cli.command else {
            panic!("expected observe command");
        };
        assert!(args.command.is_none());
    }

    #[test]
    fn github_app_subcommand_parses() {
        let cli =
            Cli::try_parse_from(["explicit", "github-app"]).expect("expected github-app to parse");
        assert!(matches!(cli.command, Command::GithubApp));
    }

    #[test]
    fn observe_claude_subcommand_parses() {
        let cli = Cli::try_parse_from(["explicit", "observe", "claude", "--", "-p", "hello"])
            .expect("expected observe claude to parse");
        let Command::Observe(args) = cli.command else {
            panic!("expected observe command");
        };
        match args.command {
            Some(ObserveCommand::Claude(args)) => {
                assert_eq!(args.args, vec!["-p", "hello"]);
            }
            _ => panic!("expected observe claude command"),
        }
    }

    #[test]
    fn observe_gemini_subcommand_parses() {
        let cli = Cli::try_parse_from(["explicit", "observe", "gemini", "--", "-p", "hello"])
            .expect("expected observe gemini to parse");
        let Command::Observe(args) = cli.command else {
            panic!("expected observe command");
        };
        match args.command {
            Some(ObserveCommand::Gemini(args)) => {
                assert_eq!(args.args, vec!["-p", "hello"]);
            }
            _ => panic!("expected observe gemini command"),
        }
    }

    #[test]
    fn verify_subcommand_parses() {
        let cli = Cli::try_parse_from(["explicit", "verify", "--root", "/tmp/project"])
            .expect("expected verify to parse");
        let Command::Verify(args) = cli.command else {
            panic!("expected verify command");
        };
        assert_eq!(args.root, PathBuf::from("/tmp/project"));
        assert!(!args.stop_hook);
        assert!(!args.git_hook);
    }

    #[test]
    fn global_no_sandbox_flag_parses_before_subcommand() {
        let cli = Cli::try_parse_from(["explicit", "--no-sandbox", "codex", "resume"])
            .expect("expected no-sandbox to parse");
        assert!(cli.no_sandbox);
        let Command::Codex(args) = cli.command else {
            panic!("expected codex command");
        };
        assert_eq!(args.args, vec!["resume"]);
    }
}
