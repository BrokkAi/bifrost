use std::env;
use std::process::ExitCode;

use brokk_bifrost::lsp::run_lsp_stdio_server;
use brokk_bifrost::mcp_common::{McpRenderOptions, run_stdio_server};
use brokk_bifrost::mcp_registry::{
    resolve_server_spec, resolve_server_spec_for_render_options, searchtools_toolset_order,
};
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
    let mut mcp_mode: Option<String> = None;
    let mut run_lsp = false;
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
            "--mcp" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--mcp requires a toolset expression".to_string())?;
                mcp_mode = Some(value);
            }
            "--lsp" => {
                run_lsp = true;
            }
            // DEPRECATED: superseded by `--mcp <toolsets>` and `--lsp`. Kept as a
            // backwards-compatible alias and intentionally undocumented in --help.
            // `--server lsp` maps to `--lsp`; any other value maps to `--mcp <value>`.
            "--server" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--server requires a mode".to_string())?;
                eprintln!("bifrost: --server is deprecated; use --mcp <toolsets> or --lsp");
                if value == "lsp" {
                    run_lsp = true;
                } else {
                    mcp_mode = Some(value);
                }
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
                // Optional positional topic: `--help <tool>` shows that tool's
                // description and parameters. Ignore a following flag.
                let topic = args.next().filter(|a| !a.starts_with('-'));
                return print_help(topic.as_deref());
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
        if run_lsp || mcp_mode.is_some() {
            return Err("--tool cannot be combined with --mcp or --lsp".to_string());
        }
        return run_tool(root, &tool_name, tool_args, render_options);
    }

    if run_lsp && mcp_mode.is_some() {
        return Err("--lsp cannot be combined with --mcp".to_string());
    }

    if !root_explicit {
        eprintln!(
            "bifrost: no --root supplied, using current directory: {}",
            root.display()
        );
    }

    if run_lsp {
        return run_lsp_stdio_server(root);
    }

    // A mode must be chosen explicitly; there is no implicit default.
    let Some(mode) = mcp_mode.as_deref() else {
        return Err(
            "no mode selected: pass --mcp TOOLSETS (e.g. --mcp core), --lsp, or --tool NAME"
                .to_string(),
        );
    };
    let git_repo = brokk_bifrost::mcp_registry::workspace_is_git(&root);
    let spec = resolve_server_spec_for_render_options(mode, render_options, git_repo)?;
    run_stdio_server(root, render_options, &spec)
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

fn print_help(topic: Option<&str>) -> Result<(), String> {
    // Help reflects the tools this binary actually advertises (same surface as
    // tools/list). `semantic_search` therefore appears only in an nlp-enabled
    // build whose host can run the embedder; the shipped CLI is built without
    // the nlp feature, so it never advertises it.
    match topic {
        Some(name) => print_tool_help(name),
        None => {
            print_general_help();
            Ok(())
        }
    }
}

fn print_general_help() {
    println!(
        "bifrost {} — Tree-sitter-backed code analyzer with MCP search-tool and LSP servers (stdio).",
        env!("CARGO_PKG_VERSION")
    );
    // Static sections, printed via variables so the JSON braces in the examples
    // stay literal. The toolset → tool-name listing between them is generated
    // from the registry so it never drifts.
    let top = r#"
USAGE:
    bifrost --mcp TOOLSETS     Run an MCP server over stdio (e.g. --mcp core)
    bifrost --lsp              Run a Language Server (LSP) over stdio
    bifrost --tool NAME        Run a single tool once, print the result, and exit
    bifrost --version | --help [TOOL]

OPTIONS:
    --root DIR             Project root to analyze (default: current directory)
    --args JSON            Inline JSON arguments for --tool, e.g. '{"patterns":["MyClass"]}'.
                           Required for tools that take arguments; omit for those that don't
                           (defaults to {}, which suits e.g. get_active_workspace).
    --no-line-numbers      Render source output without leading line numbers
    --force-semantic-cpu   Allow semantic_search without a CUDA/Metal accelerator (run the embedder on CPU)
    -h, --help [TOOL]      Show this help, or a single tool's description and parameters
    -V, --version          Show version and exit

MCP TOOLSETS (--mcp):
    searchtools   every toolset below
    core          symbol + workspace + nlp (the set agents typically connect to)
"#;
    print!("{top}");

    for toolset in searchtools_toolset_order() {
        let Ok(spec) = resolve_server_spec(toolset) else {
            continue;
        };
        let names: Vec<&str> = spec
            .tool_descriptors
            .iter()
            .filter_map(|descriptor| descriptor.get("name").and_then(Value::as_str))
            .collect();
        if !names.is_empty() {
            print_toolset_line(toolset, &names);
        }
    }

    let bottom = r#"    Combine toolsets with '|', e.g. --mcp symbol|workspace
    Run `bifrost --help <tool>` for a tool's description and parameters.

EXAMPLES:
    # MCP server an agent connects to (core toolset), speaking MCP over stdio:
    bifrost --root /path/to/project --mcp core

    # One-shot: run a single tool and print its result, then exit:
    bifrost --root /path/to/project --tool search_symbols --args '{"patterns":["MyClass"]}'

    # Language server over stdio:
    bifrost --root /path/to/project --lsp

Servers speak their protocol over stdio (no network port). The workspace index is built
in the background: the server is ready immediately and the first request waits for indexing.
"#;
    print!("{bottom}");
}

/// Print `    <toolset>   name, name, ...`, wrapping the comma-separated names
/// with a hanging indent aligned under the first name.
fn print_toolset_line(toolset: &str, names: &[&str]) {
    const LABEL_WIDTH: usize = 14;
    const WRAP: usize = 96;
    let indent = " ".repeat(4 + LABEL_WIDTH);
    let mut line = format!("    {toolset:<LABEL_WIDTH$}");
    for (i, name) in names.iter().enumerate() {
        if i == 0 {
            line.push_str(name);
        } else if line.chars().count() + 2 + name.chars().count() > WRAP {
            line.push(',');
            println!("{line}");
            line = format!("{indent}{name}");
        } else {
            line.push_str(", ");
            line.push_str(name);
        }
    }
    println!("{line}");
}

fn print_tool_help(name: &str) -> Result<(), String> {
    // `searchtools` advertises every tool, so it is the lookup surface.
    let spec = resolve_server_spec("searchtools")?;
    let descriptor = spec
        .tool_descriptors
        .iter()
        .find(|descriptor| descriptor.get("name").and_then(Value::as_str) == Some(name))
        .ok_or_else(|| {
            format!("unknown tool: {name}\nRun `bifrost --help` to list available tools.")
        })?;

    match toolset_of(name) {
        Some(toolset) => println!("{name}  (toolset: {toolset})"),
        None => println!("{name}"),
    }
    if let Some(description) = descriptor.get("description").and_then(Value::as_str) {
        println!("\n{description}");
    }

    let schema = descriptor.get("inputSchema");
    let properties = schema
        .and_then(|schema| schema.get("properties"))
        .and_then(Value::as_object);
    let required: std::collections::HashSet<&str> = schema
        .and_then(|schema| schema.get("required"))
        .and_then(Value::as_array)
        .map(|values| values.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();

    match properties {
        Some(properties) if !properties.is_empty() => {
            println!("\nPARAMETERS:");
            let width = properties
                .keys()
                .map(|key| key.chars().count())
                .max()
                .unwrap_or(0);
            for (param, param_schema) in properties {
                let kind = param_type(param_schema);
                let presence = if required.contains(param.as_str()) {
                    "required"
                } else {
                    "optional"
                };
                let description = param_schema
                    .get("description")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                println!("    {param:<width$}  {kind:<7}  {presence:<8}  {description}");
            }
        }
        _ => println!("\nPARAMETERS: none"),
    }
    Ok(())
}

/// JSON-Schema "type" for a parameter, collapsing the common non-`type` shapes
/// (`anyOf`, `enum`) into a readable label.
fn param_type(schema: &Value) -> &'static str {
    match schema.get("type").and_then(Value::as_str) {
        Some("string") => "string",
        Some("integer") => "integer",
        Some("number") => "number",
        Some("boolean") => "boolean",
        Some("array") => "array",
        Some("object") => "object",
        Some(_) => "value",
        None if schema.get("anyOf").is_some() => "any",
        None if schema.get("enum").is_some() => "enum",
        None => "value",
    }
}

/// The first toolset (in registry order) that advertises `name`, for the
/// tool-detail header.
fn toolset_of(name: &str) -> Option<&'static str> {
    searchtools_toolset_order().iter().copied().find(|toolset| {
        resolve_server_spec(toolset).is_ok_and(|spec| {
            spec.tool_descriptors
                .iter()
                .any(|descriptor| descriptor.get("name").and_then(Value::as_str) == Some(name))
        })
    })
}
