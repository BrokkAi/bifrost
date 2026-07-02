use std::collections::BTreeSet;
use std::env;
use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use brokk_bifrost::lsp::run_lsp_stdio_server;
use brokk_bifrost::mcp_common::{McpRenderOptions, run_stdio_server};
use brokk_bifrost::mcp_registry::{
    resolve_server_spec, resolve_server_spec_for_render_options, searchtools_toolset_order,
};
use brokk_bifrost::searchtools_render::RenderOptions;
use brokk_bifrost::tool_arguments::{GitHistoryOverlay, normalize_tool_arguments_for_cli};
use brokk_bifrost::{
    FileSetProject, OverlayProject, Project, SearchToolsService, ToolOutput,
    collect_workspace_files,
};
use glob::Pattern;
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
    let mut tool_sources = Vec::new();
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
            "--sources" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--sources requires a path".to_string())?;
                tool_sources.push(value);
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
        return run_tool(root, &tool_name, tool_args, &tool_sources, render_options);
    }

    if !tool_sources.is_empty() {
        return Err("--sources may only be used with --tool".to_string());
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

    let mode = mcp_mode.as_deref().unwrap_or("searchtools");
    let git_repo = brokk_bifrost::mcp_registry::workspace_is_git(&root);
    let spec = resolve_server_spec_for_render_options(mode, render_options, git_repo)?;
    run_stdio_server(root, render_options, &spec)
}

fn run_tool(
    root: PathBuf,
    tool_name: &str,
    tool_args: Value,
    tool_sources: &[String],
    render_options: McpRenderOptions,
) -> Result<(), String> {
    let root = root
        .canonicalize()
        .map_err(|err| format!("Failed to resolve project root {}: {err}", root.display()))?;
    let (arguments, overlays) = normalize_tool_arguments_for_cli(tool_name, tool_args, &root)?;
    let service = if overlays.is_empty() && tool_sources.is_empty() {
        SearchToolsService::new(root.clone())?
    } else if overlays.is_empty() {
        let rel_paths = resolve_tool_sources(&root, tool_sources)?;
        let project = Arc::new(FileSetProject::new(root.clone(), rel_paths));
        SearchToolsService::new_manual_for_project(project)?
    } else {
        let mut rel_paths: BTreeSet<PathBuf> = if tool_sources.is_empty() {
            collect_workspace_files(&root)
                .map_err(|err| {
                    format!(
                        "Failed to enumerate workspace files under {}: {err}",
                        root.display()
                    )
                })?
                .into_iter()
                .map(|file| file.rel_path().to_path_buf())
                .collect()
        } else {
            resolve_tool_sources(&root, tool_sources)?
                .into_iter()
                .collect()
        };
        for overlay in &overlays {
            rel_paths.insert(overlay.rel_path.clone());
        }
        let project = Arc::new(FileSetProject::new(root.clone(), rel_paths));
        let overlay_project = Arc::new(OverlayProject::new(project));
        install_git_history_overlays(&root, &overlay_project, overlays)?;
        let project: Arc<dyn Project> = overlay_project;
        SearchToolsService::new_manual_for_project(project)?
    };
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

fn install_git_history_overlays(
    root: &Path,
    project: &OverlayProject,
    overlays: Vec<GitHistoryOverlay>,
) -> Result<(), String> {
    for overlay in overlays {
        let abs_path = root.join(&overlay.rel_path);
        if !project.set(abs_path.clone(), overlay.content) {
            return Err(format!(
                "git history path `{}` is too large for the analyzer overlay",
                abs_path.display()
            ));
        }
    }
    Ok(())
}

fn resolve_tool_sources(root: &Path, inputs: &[String]) -> Result<Vec<PathBuf>, String> {
    let workspace_files = collect_workspace_files(root).map_err(|err| {
        format!(
            "Failed to enumerate workspace files under {}: {err}",
            root.display()
        )
    })?;
    let workspace_rel_paths: Vec<String> = workspace_files
        .iter()
        .map(|file| file.rel_path().to_string_lossy().replace('\\', "/"))
        .collect();

    let mut selected = std::collections::BTreeSet::new();
    for input in inputs {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            continue;
        }

        if contains_glob_syntax(trimmed) {
            let pattern = normalize_source_pattern(trimmed, root)?;
            let glob = Pattern::new(&pattern)
                .map_err(|err| format!("Invalid --sources glob `{trimmed}`: {err}"))?;
            let mut matched_any = false;
            for rel in &workspace_rel_paths {
                if glob.matches(rel) {
                    matched_any = true;
                    selected.insert(PathBuf::from(rel));
                }
            }
            if !matched_any {
                return Err(format!("--sources glob `{trimmed}` matched no files"));
            }
            continue;
        }

        let rel = normalize_literal_source_path(trimmed, root)?;
        let abs = root.join(&rel);
        if abs.is_file() {
            selected.insert(rel);
            continue;
        }
        if abs.is_dir() {
            let prefix = rel.to_string_lossy().replace('\\', "/");
            let prefix_slash = format!("{prefix}/");
            let mut matched_any = false;
            for workspace_rel in &workspace_rel_paths {
                if workspace_rel == &prefix || workspace_rel.starts_with(&prefix_slash) {
                    matched_any = true;
                    selected.insert(PathBuf::from(workspace_rel));
                }
            }
            if !matched_any {
                return Err(format!(
                    "--sources directory `{trimmed}` contains no analyzer-visible files"
                ));
            }
            continue;
        }

        return Err(format!("--sources path does not exist: {trimmed}"));
    }

    if selected.is_empty() {
        return Err("--sources resolved to an empty workspace".to_string());
    }
    Ok(selected.into_iter().collect())
}

fn normalize_source_pattern(raw: &str, root: &Path) -> Result<String, String> {
    if looks_like_absolute_path(raw) {
        normalize_relative_path(&normalize_absolute_source_string(raw, root)?)
            .map(|path| path.to_string_lossy().replace('\\', "/"))
    } else {
        normalize_relative_path(raw).map(|path| path.to_string_lossy().replace('\\', "/"))
    }
}

fn normalize_literal_source_path(raw: &str, root: &Path) -> Result<PathBuf, String> {
    if looks_like_absolute_path(raw) {
        let abs = Path::new(raw);
        let canonical_root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
        if abs.exists() {
            let normalized_abs = abs
                .canonicalize()
                .map_err(|err| format!("Failed to resolve source path {}: {err}", abs.display()))?;
            let rel = normalized_abs
                .strip_prefix(&canonical_root)
                .map_err(|_| absolute_source_outside_workspace_error(raw, root))?;
            return normalize_relative_path(&rel.to_string_lossy());
        }
        return normalize_relative_path(&normalize_absolute_source_string(raw, root)?);
    }

    normalize_relative_path(raw)
}

fn normalize_absolute_source_string(raw: &str, root: &Path) -> Result<String, String> {
    let raw_norm = raw.replace('\\', "/");
    let root_norm = root.display().to_string().replace('\\', "/");
    let root_trimmed = root_norm.trim_end_matches('/');

    if raw_norm == root_trimmed {
        return Ok(String::new());
    }

    raw_norm
        .strip_prefix(&format!("{root_trimmed}/"))
        .map(str::to_string)
        .ok_or_else(|| absolute_source_outside_workspace_error(raw, root))
}

fn absolute_source_outside_workspace_error(raw: &str, root: &Path) -> String {
    format!(
        "absolute path is outside active workspace: {} (workspace: {})",
        raw,
        root.display()
    )
}

fn normalize_relative_path(raw: &str) -> Result<PathBuf, String> {
    let normalized = raw.replace('\\', "/");
    let mut rel = PathBuf::new();
    for component in Path::new(&normalized).components() {
        match component {
            Component::CurDir => {}
            Component::Normal(part) => rel.push(part),
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(format!("path escapes active workspace: {raw}"));
            }
        }
    }
    if rel.as_os_str().is_empty() {
        return Err(format!("path is empty: {raw}"));
    }
    Ok(rel)
}

fn contains_glob_syntax(raw: &str) -> bool {
    raw.contains(['*', '?', '['])
}

fn looks_like_absolute_path(raw: &str) -> bool {
    Path::new(raw).is_absolute() || is_windows_absolute_path(raw)
}

fn is_windows_absolute_path(raw: &str) -> bool {
    let bytes = raw.as_bytes();
    bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'/' | b'\\')
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
    bifrost                  Run an MCP server over stdio (default: --mcp searchtools)
    bifrost --mcp TOOLSETS     Run an MCP server over stdio (e.g. --mcp core)
    bifrost --lsp              Run a Language Server (LSP) over stdio
    bifrost --tool NAME        Run a single tool once, print the result, and exit
    bifrost --version | --help [TOOL]

OPTIONS:
    --root DIR             Project root to analyze (default: current directory)
    --args JSON            Inline JSON arguments for --tool, e.g. '{"patterns":["MyClass"]}'.
                           File path arguments may use <commit-ish>:<path> in --tool mode.
                           Required for tools that take arguments; omit for those that don't
                           (defaults to {}, which suits e.g. get_active_workspace).
    --sources PATH         Restrict one-shot --tool workspace construction to selected files,
                           directories, or globs. Repeatable; valid only with --tool.
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
    # MCP server from the current directory, using the compatibility searchtools set:
    bifrost

    # MCP server an agent connects to (core toolset), speaking MCP over stdio:
    bifrost --root /path/to/project --mcp core

    # One-shot: run a single tool and print its result, then exit:
    bifrost --root /path/to/project --tool search_symbols --args '{"patterns":["MyClass"]}'

    # One-shot against a subset workspace built from a directory and a glob:
    bifrost --root /path/to/project --tool get_symbol_sources --sources src --sources 'tests/**/*.rs' --args '{"symbols":["src/main.rs"]}'

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
            for (param, param_schema) in properties {
                let summary = param_summary(param_schema, required.contains(param.as_str()));
                println!("    {param}  ({summary})");
                if let Some(description) = param_schema.get("description").and_then(Value::as_str) {
                    println!("        {description}");
                }
            }
        }
        _ => println!("\nPARAMETERS: none"),
    }
    Ok(())
}

/// A human-readable type/constraint summary for one parameter, built entirely
/// from its JSON-Schema, e.g. `array of strings, required` or
/// `integer, optional, default 20, minimum 1`.
fn param_summary(schema: &Value, required: bool) -> String {
    let mut parts = vec![type_phrase(schema)];
    parts.push(if required { "required" } else { "optional" }.to_string());
    if let Some(default) = schema.get("default") {
        parts.push(format!("default {}", scalar(default)));
    }
    if let Some(minimum) = schema.get("minimum") {
        parts.push(format!("minimum {}", scalar(minimum)));
    }
    if let Some(maximum) = schema.get("maximum") {
        parts.push(format!("maximum {}", scalar(maximum)));
    }
    if let Some(min_items) = schema.get("minItems") {
        parts.push(format!("min items {}", scalar(min_items)));
    }
    if let Some(values) = schema.get("enum").and_then(Value::as_array) {
        let rendered: Vec<String> = values.iter().map(scalar).collect();
        parts.push(format!("one of: {}", rendered.join(", ")));
    }
    parts.join(", ")
}

/// The base type phrase, naming the element type for arrays (`array of strings`)
/// and collapsing `anyOf`/untyped schemas to `value`.
fn type_phrase(schema: &Value) -> String {
    match schema.get("type").and_then(Value::as_str) {
        Some("array") => {
            let items = schema.get("items").map(array_item_noun).unwrap_or("items");
            format!("array of {items}")
        }
        Some(other) => other.to_string(),
        None => "value".to_string(),
    }
}

/// Plural noun for an array's element type; `items` when the element schema is
/// a composite (e.g. `anyOf`) with no single `type`.
fn array_item_noun(items: &Value) -> &'static str {
    match items.get("type").and_then(Value::as_str) {
        Some("string") => "strings",
        Some("integer") => "integers",
        Some("number") => "numbers",
        Some("boolean") => "booleans",
        Some("object") => "objects",
        Some("array") => "arrays",
        _ => "items",
    }
}

/// Render a scalar schema value (default/min/max/enum) without JSON quoting.
fn scalar(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Bool(flag) => flag.to_string(),
        Value::Number(number) => number.to_string(),
        Value::Null => "null".to_string(),
        other => other.to_string(),
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
