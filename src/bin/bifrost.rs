use std::env;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use brokk_bifrost::lsp::run_lsp_stdio_server;
use brokk_bifrost::mcp_common::{McpRenderOptions, run_stdio_server};
use brokk_bifrost::mcp_registry::resolve_server_spec;
use brokk_bifrost::searchtools::{SummariesParams, get_summaries};
use brokk_bifrost::searchtools_render::{RenderOptions, RenderText};
use brokk_bifrost::{AnalyzerConfig, FileSetProject, WorkspaceAnalyzer};

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
    let mut summarize_targets: Vec<String> = Vec::new();
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
            "--summarize" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--summarize requires a filename".to_string())?;
                summarize_targets.push(value);
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

    if !summarize_targets.is_empty() {
        if server_mode.is_some() {
            return Err("--summarize cannot be combined with --server".to_string());
        }
        return run_summaries(root, &summarize_targets, render_options);
    }

    match server_mode.as_deref() {
        Some("lsp") => run_lsp_stdio_server(root),
        Some(mode) => {
            let spec = resolve_server_spec(mode)?;
            run_stdio_server(root, render_options, &spec)
        }
        None => {
            print_help();
            Err("No mode selected".to_string())
        }
    }
}

/// Summarize an explicit set of files without indexing the whole workspace.
///
/// A [`FileSetProject`] restricts the analyzer to exactly the requested files,
/// so `WorkspaceAnalyzer::build` parses only those — then we reuse the same
/// `get_summaries` path (and rendering) the MCP `get_summaries` tool exposes.
fn run_summaries(
    root: PathBuf,
    targets: &[String],
    render_options: McpRenderOptions,
) -> Result<(), String> {
    let root = root
        .canonicalize()
        .map_err(|err| format!("Failed to resolve project root {}: {err}", root.display()))?;

    let rel_paths = targets
        .iter()
        .map(|target| resolve_relative_target(&root, target))
        .collect::<Result<Vec<_>, _>>()?;

    let project = Arc::new(FileSetProject::new(root, rel_paths.clone()));
    let workspace = WorkspaceAnalyzer::build(project, AnalyzerConfig::default());

    let summary_targets = rel_paths
        .iter()
        .map(|rel| rel.to_string_lossy().replace('\\', "/"))
        .collect();
    let result = get_summaries(
        workspace.analyzer(),
        SummariesParams {
            targets: summary_targets,
        },
    );

    print!(
        "{}",
        result.render_text(RenderOptions {
            render_line_numbers: render_options.render_line_numbers,
        })
    );
    println!();
    Ok(())
}

/// Resolve a user-supplied filename to a path relative to `root`, erroring if
/// the file is missing or lives outside the project root. The filename is
/// accepted as-is (relative to the current directory) or relative to `root`.
fn resolve_relative_target(root: &Path, target: &str) -> Result<PathBuf, String> {
    let candidate = Path::new(target);
    let absolute = candidate
        .canonicalize()
        .or_else(|_| root.join(candidate).canonicalize())
        .map_err(|_| format!("File not found: {target}"))?;
    absolute
        .strip_prefix(root)
        .map(Path::to_path_buf)
        .map_err(|_| format!("File is outside the project root: {target}"))
}

fn print_help() {
    println!("Usage: bifrost --root PROJECT_ROOT --server searchtools");
    println!("       bifrost --root PROJECT_ROOT --server core");
    println!("       bifrost --root PROJECT_ROOT --server symbol|workspace");
    println!("       bifrost --root PROJECT_ROOT --server text|extended");
    println!("       bifrost --root PROJECT_ROOT --server slopcop");
    println!("       bifrost --root PROJECT_ROOT --server lsp");
    println!("       bifrost --root PROJECT_ROOT --server searchtools --no-line-numbers");
    println!("       bifrost --summarize FILE [--summarize FILE ...] [--no-line-numbers]");
    println!("       bifrost --version");
}
