mod analysis;
mod devenv_file;
mod hooks;
mod host_tools;
mod observe;
mod registry;
mod runtime;
mod sandbox;

use std::path::PathBuf;
use std::process::ExitCode;

use analysis::Analysis;
use anyhow::{Context, Result};
use clap::{ArgAction, Args, Parser, Subcommand};
use serde_json::json;

#[derive(Parser, Debug)]
#[command(name = "explicit")]
#[command(
    about = "Detect project requirements, manage devenv.nix, and launch a sandboxed agent shell."
)]
struct Cli {
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
    #[command(about = "Launch a devenv-powered sandbox shell for agents or manual use.")]
    Shell(ShellArgs),
    #[command(about = "Attach to a live project run or inspect observed Codex telemetry.")]
    Observe(ObserveArgs),
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
    #[command(hide = true, name = "__sandbox-exec")]
    SandboxExec(SandboxExecArgs),
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
}

#[derive(Args, Debug, Clone)]
struct AgentArgs {
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
    let cli = Cli::parse();

    match cli.command {
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
                        "devenv.generated.nix",
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
        Command::Shell(args) => {
            let root = args.root.canonicalize().context("failed to resolve root")?;
            let analysis = Analysis::analyze(&root)?;
            let status = runtime::launch_shell(
                &root,
                &analysis,
                args.command,
                args.block_network,
                args.no_services,
            )?;
            Ok(status)
        }
        Command::Observe(args) => match args.command {
            Some(ObserveCommand::Codex(args)) => launch_observed_agent("codex", args),
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
        Command::Codex(args) => launch_agent("codex", args),
        Command::Claude(args) => launch_agent("claude", args),
        Command::SandboxExec(args) => {
            sandbox::run_sandbox_exec(args.root, args.env_file, args.plan_file, args.command)?;
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn launch_agent(binary: &str, args: AgentArgs) -> Result<ExitCode> {
    let root = PathBuf::from(".")
        .canonicalize()
        .context("failed to resolve root")?;
    let analysis = Analysis::analyze(&root)?;
    let (observe, passthrough_args) = extract_observe_flag(args.args);
    let command = build_agent_command(binary, &passthrough_args);
    if observe {
        return observe::launch_observed_agent(
            &root,
            &analysis,
            binary,
            command,
            &passthrough_args,
            false,
            false,
        );
    }
    observe::launch_live_agent(&root, &analysis, binary, command, false, false)
}

fn launch_observed_agent(binary: &str, args: ObserveAgentArgs) -> Result<ExitCode> {
    let root = args.root.canonicalize().context("failed to resolve root")?;
    let analysis = Analysis::analyze(&root)?;
    let command = build_agent_command(binary, &args.args);
    observe::launch_observed_agent(
        &root,
        &analysis,
        binary,
        command,
        &args.args,
        args.block_network,
        args.no_services,
    )
}

fn build_agent_command(binary: &str, args: &[String]) -> String {
    std::iter::once(binary.to_string())
        .chain(args.iter().map(|arg| shell_escape(arg)))
        .collect::<Vec<_>>()
        .join(" ")
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
    use super::{Cli, Command, build_agent_command, extract_observe_flag, shell_escape};
    use clap::Parser;

    #[test]
    fn build_agent_command_quotes_arguments_for_shell() {
        let command = build_agent_command(
            "codex",
            &[String::from("--prompt"), String::from("hello world")],
        );
        assert_eq!(command, "codex --prompt 'hello world'");
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
}
