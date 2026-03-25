use std::env;
use std::process::ExitCode;

use brokk_analyzer::mcp_server::run_searchtools_stdio_server;

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
    let mut server_mode = None;

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
            "--help" | "-h" => {
                print_help();
                return Ok(());
            }
            other => {
                return Err(format!("Unknown argument: {other}"));
            }
        }
    }

    match server_mode.as_deref() {
        Some("searchtools") => run_searchtools_stdio_server(root),
        Some(other) => Err(format!("Unsupported server mode: {other}")),
        None => {
            print_help();
            Err("No mode selected".to_string())
        }
    }
}

fn print_help() {
    println!("Usage: bifrost --root PROJECT_ROOT --server searchtools");
}
