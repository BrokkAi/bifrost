use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    match parse_root(env::args().skip(1)).and_then(brokk_bifrost_lsp::run_lsp_stdio_server) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}

fn parse_root(mut args: impl Iterator<Item = String>) -> Result<PathBuf, String> {
    let mut root = env::current_dir().map_err(|err| format!("current directory: {err}"))?;
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--root" => {
                root = args
                    .next()
                    .map(PathBuf::from)
                    .ok_or_else(|| "--root requires a path".to_string())?;
            }
            "--server" => {
                let mode = args
                    .next()
                    .ok_or_else(|| "--server requires a mode".to_string())?;
                if mode != "lsp" {
                    return Err(format!("unsupported server mode `{mode}`"));
                }
            }
            "--lsp" => {}
            unknown => return Err(format!("unknown argument `{unknown}`")),
        }
    }
    Ok(root)
}
