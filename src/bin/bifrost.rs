use std::env;
use std::process::ExitCode;

use brokk_bifrost::lsp::run_lsp_stdio_server;
use brokk_bifrost::mcp_common::{McpRenderOptions, run_stdio_server};
use brokk_bifrost::mcp_registry::resolve_server_spec;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{err}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let mut args = env::args().skip(1);
    let mut root =
        env::current_dir().map_err(|err| format!("Failed to get current directory: {err}"))?;
    let mut server_mode = Some("searchtools".to_string());
    let mut render_options = McpRenderOptions::default();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--root" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--root requires a path".to_string())?;
                root = value.into();
            }
            "--server" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--server requires a mode".to_string())?;
                server_mode = Some(value);
            }
            "--no-line-numbers" => {
                render_options.render_line_numbers = false;
            }
            "--help" | "-h" => {
                print_help();
                return Ok(());
            }
            "--version" | "-V" => {
                println!("bifrost {}", env!("CARGO_PKG_VERSION"));
                return Ok(());
            }
            other => {
                return Err(format!("Unknown argument: {other}"));
            }
        }
    }

    match server_mode.as_deref() {
        Some("lsp") => run_lsp_stdio_server(root),
        Some(mode) => {
            let spec = resolve_server_spec(mode)?;
            run_stdio_server(root, render_options, &spec)
        }
        None => unreachable!("default server mode should always be set"),
    }
}

fn print_help() {
    println!("Usage: bifrost [--root PROJECT_ROOT] [--server searchtools]");
    println!("       bifrost [--root PROJECT_ROOT] --server core");
    println!("       bifrost [--root PROJECT_ROOT] --server symbol|workspace");
    println!("       bifrost [--root PROJECT_ROOT] --server text|extended");
    println!("       bifrost [--root PROJECT_ROOT] --server slopcop");
    println!("       bifrost [--root PROJECT_ROOT] --server lsp");
    println!("Defaults: --root is the current working directory, --server is searchtools");
    println!("       bifrost --no-line-numbers");
    println!("       bifrost --version");
}
