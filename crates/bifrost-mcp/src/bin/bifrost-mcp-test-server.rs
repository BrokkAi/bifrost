use brokk_bifrost_mcp::mcp_common::McpRenderOptions;
use brokk_bifrost_mcp::mcp_registry::{resolve_server_spec_for_render_options, workspace_is_git};
use brokk_bifrost_mcp::rmcp_host::run_stdio_server_with_build_identity;
use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    match parse_args(env::args().skip(1)).and_then(run) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}

struct Arguments {
    root: PathBuf,
    root_explicit: bool,
    mode: Option<String>,
    render_options: McpRenderOptions,
}

fn parse_args(mut args: impl Iterator<Item = String>) -> Result<Arguments, String> {
    let mut parsed = Arguments {
        root: env::current_dir().map_err(|err| format!("current directory: {err}"))?,
        root_explicit: false,
        mode: None,
        render_options: McpRenderOptions::default(),
    };
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--root" => {
                parsed.root = args
                    .next()
                    .map(PathBuf::from)
                    .ok_or_else(|| "--root requires a path".to_string())?;
                parsed.root_explicit = true;
            }
            "--mcp" | "--server" => {
                parsed.mode = Some(
                    args.next()
                        .ok_or_else(|| format!("{argument} requires a mode"))?,
                );
            }
            "--no-line-numbers" => parsed.render_options.render_line_numbers = false,
            "--force-semantic-cpu" => unsafe { env::set_var("BIFROST_FORCE_SEMANTIC_CPU", "1") },
            unknown => return Err(format!("unknown argument `{unknown}`")),
        }
    }
    Ok(parsed)
}

fn run(arguments: Arguments) -> Result<(), String> {
    let mode = arguments.mode.as_deref().unwrap_or("searchtools");
    let initial_root = if arguments.root_explicit || arguments.mode.is_none() {
        Some(arguments.root)
    } else {
        None
    };
    let git_repo = initial_root.as_deref().is_none_or(workspace_is_git);
    let spec = resolve_server_spec_for_render_options(mode, arguments.render_options, git_repo)?;
    run_stdio_server_with_build_identity(
        initial_root,
        arguments.render_options,
        &spec,
        None,
        env!("CARGO_PKG_VERSION"),
    )
}
