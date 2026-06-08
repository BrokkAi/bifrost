use std::env;
use std::process::ExitCode;

use brokk_bifrost::lsp::run_lsp_stdio_server;
use brokk_bifrost::mcp_common::{McpRenderOptions, run_stdio_server};
use brokk_bifrost::mcp_registry::resolve_server_spec;
use brokk_bifrost::searchtools_render::RenderOptions;
use brokk_bifrost::tool_arguments::normalize_tool_arguments;
use brokk_bifrost::{SearchToolsService, ToolOutput};
use serde_json::{Value, json};

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
    let mut root_explicit = false;
    let mut server_mode: Option<String> = None;
    let mut tool_name: Option<String> = None;
    let mut tool_args = json!({});
    let mut render_options = McpRenderOptions::default();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--root" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--root requires a path".to_string())?;
                root = value.into();
                root_explicit = true;
            }
            "--server" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--server requires a mode".to_string())?;
                server_mode = Some(value);
            }
            "--tool" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--tool requires a name".to_string())?;
                if tool_name.replace(value).is_some() {
                    return Err("--tool may only be provided once".to_string());
                }
            }
            "--args" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--args requires inline JSON".to_string())?;
                tool_args = serde_json::from_str(&value)
                    .map_err(|err| format!("--args must be valid JSON: {err}"))?;
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

    if let Some(tool_name) = tool_name {
        if server_mode.is_some() {
            return Err("--tool cannot be combined with --server".to_string());
        }
        return run_tool(root, &tool_name, tool_args, render_options);
    }

    if !root_explicit {
        eprintln!(
            "bifrost: no --root supplied, using current directory: {}",
            root.display()
        );
    }

    match server_mode.as_deref().unwrap_or("searchtools") {
        "lsp" => run_lsp_stdio_server(root),
        mode => {
            let spec = resolve_server_spec(mode)?;
            run_stdio_server(root, render_options, &spec)
        }
    }
}

fn run_tool(
    root: std::path::PathBuf,
    tool_name: &str,
    tool_args: Value,
    render_options: McpRenderOptions,
) -> Result<(), String> {
    let root = root
        .canonicalize()
        .map_err(|err| format!("Failed to resolve project root {}: {err}", root.display()))?;
    let arguments = normalize_tool_arguments(tool_name, tool_args, &root)?;
    let service = SearchToolsService::new(root)?;
    let output = service
        .call_tool_output(
            tool_name,
            arguments,
            RenderOptions {
                render_line_numbers: render_options.render_line_numbers,
            },
        )
        .map_err(|err| err.to_string())?;

    let text = match output {
        ToolOutput::Text(text) => text,
        ToolOutput::Structured {
            structured,
            rendered_text,
        } => rendered_text.unwrap_or_else(|| {
            serde_json::to_string_pretty(&structured)
                .unwrap_or_else(|_| "Failed to pretty-print tool result".to_string())
        }),
    };
    print!("{text}");
    if !text.ends_with('\n') {
        println!();
    }
    Ok(())
}

fn print_help() {
    println!("Usage: bifrost [--root PROJECT_ROOT] [--server searchtools] [--no-line-numbers]");
    println!("       bifrost [--root PROJECT_ROOT] --server core");
    println!("       bifrost [--root PROJECT_ROOT] --server symbol|workspace");
    println!("       bifrost [--root PROJECT_ROOT] --server text|extended");
    println!("       bifrost [--root PROJECT_ROOT] --server slopcop");
    println!("       bifrost [--root PROJECT_ROOT] --server lsp");
    println!(
        "       bifrost [--root PROJECT_ROOT] --tool TOOL_NAME [--args '{{\"key\":\"value\"}}'] [--no-line-numbers]"
    );
    println!(
        "Defaults: --root is the current working directory, --server is searchtools when --tool is not used"
    );
    println!("       bifrost --version");
}
