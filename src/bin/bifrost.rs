use std::env;
use std::process::ExitCode;

use brokk_bifrost::lsp::run_lsp_stdio_server;
use brokk_bifrost::mcp_common::{McpRenderOptions, run_stdio_server};
use brokk_bifrost::mcp_registry::resolve_server_spec_for_render_options;
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
            "--force-semantic-cpu" => {
                // Lets semantic_search run (and be advertised) on hosts without a
                // CUDA/Metal accelerator. Consumed via env by the registry + service.
                unsafe { env::set_var("BIFROST_FORCE_SEMANTIC_CPU", "1") };
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
            let git_repo = brokk_bifrost::mcp_registry::workspace_is_git(&root);
            let spec = resolve_server_spec_for_render_options(mode, render_options, git_repo)?;
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
            serde_json::to_string(&structured)
                .unwrap_or_else(|_| "Failed to serialize tool result".to_string())
        }),
    };
    print!("{text}");
    if !text.ends_with('\n') {
        println!();
    }
    Ok(())
}

fn print_help() {
    println!(
        "bifrost {} — Tree-sitter-backed code analyzer with MCP search-tool and LSP servers (stdio).",
        env!("CARGO_PKG_VERSION")
    );
    // Bound to a variable and printed via an inlined placeholder so the JSON
    // braces in the examples stay literal (they live in `body`, not the format
    // string).
    let body = r#"
USAGE:
    bifrost --server MODE      Run a server over stdio  (MODE: an MCP toolset or 'lsp'; default: searchtools)
    bifrost --tool NAME        Run a single tool once, print the result, and exit
    bifrost --version | --help

OPTIONS:
    --root DIR             Project root to analyze (default: current directory)
    --args JSON            Inline JSON arguments for --tool, e.g. '{"patterns":["MyClass"]}'.
                           Required for tools that take arguments; omit for those that don't
                           (defaults to {}, which suits e.g. get_active_workspace).
    --no-line-numbers      Render source output without leading line numbers
    --force-semantic-cpu   Allow semantic_search without a CUDA/Metal accelerator (run the embedder on CPU)
    -h, --help             Show this help and exit
    -V, --version          Show version and exit

SERVER MODES (--server):
    searchtools   (default) Every toolset below
    core          Symbol search, usages, summaries, semantic search, and workspace lifecycle
                  — the set agents typically connect to
    lsp           Language Server Protocol: definitions, references, hover, rename, diagnostics, ...
    symbol        Symbol discovery, sources, summaries, usages, type/definition lookup, commit analysis
    workspace     Index lifecycle: refresh, activate_workspace, get_active_workspace
    text          File contents, text/grep search, git log & diff, jq, XML
    extended      Symbol locations & ancestors, file listing, most-relevant-files, git, structured data
    slopcop       Code-quality smells: complexity, comment density, clones, dead code, secrets
    nlp           Semantic (embedding) search
    Combine toolsets with '|', e.g. --server symbol|workspace

EXAMPLES:
    # MCP server an agent connects to (core toolset), speaking MCP over stdio:
    bifrost --root /path/to/project --server core

    # One-shot: run a single tool and print its result, then exit:
    bifrost --root /path/to/project --tool search_symbols --args '{"patterns":["MyClass"]}'

    # Language server over stdio:
    bifrost --root /path/to/project --server lsp

Servers speak their protocol over stdio (no network port). The workspace index is built
in the background: the server is ready immediately and the first request waits for indexing.
"#;
    print!("{body}");
}
