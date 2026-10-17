use crate::mcp_common::{McpRenderOptions, McpServerSpec, build_server_spec_with_hidden};
use serde_json::Value;
use std::collections::HashSet;

const SEARCHTOOLS_ORDER: &[&str] = &["symbol", "workspace", "diff", "extended", "text", "slopcop"];

/// The `--mcp` mode rejection for `cli` (issue #1116).
///
/// A 40-run BrokkBench sweep made zero agent calls to `classify_test_files`
/// against dozens of calls to the symbol tools, so it is no longer part of
/// any agent-facing toolset composition (`core`, `searchtools`, or a manual
/// `|`-composition such as `symbol|cli`). It stays reachable for programmatic
/// consumers -- `bifrost --tool classify_test_files` and the Rust/Python API
/// -- which is why the message below points there instead of silently
/// dropping the segment.
const CLI_MODE_REJECTED: &str = "Unsupported server mode: cli (classify_test_files is a \
    programmatic-only tool; it is not exposed to MCP agents. Run \
    `bifrost --tool classify_test_files` or call it through the Rust or Python API instead)";

const DISCOVERY_ROUTING_INSTRUCTIONS: &str = "Source-code analysis and repository navigation. Search this server for its advertised language-aware and repository-aware tools. Depending on the selected mode, tools cover symbols, structure, policies, quality, text, or workspace control. Use them when text search cannot reliably answer a structural or cross-file question. Check result completeness before you claim all results or no results.";

#[derive(Default)]
struct ServerSpecResolution {
    descriptors: Vec<Value>,
    seen: HashSet<String>,
    effective_toolsets: HashSet<String>,
}

/// The individual toolset names that compose `searchtools`, in registry order.
/// Exposed so the CLI `--help` can enumerate each toolset and its tools without
/// duplicating the list.
pub fn searchtools_toolset_order() -> &'static [&'static str] {
    SEARCHTOOLS_ORDER
}

pub fn resolve_server_spec(mode_expr: &str) -> Result<McpServerSpec, String> {
    resolve_server_spec_for_render_options(mode_expr, McpRenderOptions::default())
}

pub fn resolve_server_spec_for_render_options(
    mode_expr: &str,
    render_options: McpRenderOptions,
) -> Result<McpServerSpec, String> {
    let mut resolution = ServerSpecResolution::default();
    resolve_mode_expr(mode_expr, render_options, &mut resolution)?;
    if resolution.descriptors.is_empty() {
        return Err("server mode expression produced no tools".to_string());
    }
    build_server_spec_with_hidden(
        discovery_instructions(&resolution.effective_toolsets),
        resolution.descriptors,
        Vec::new(),
    )
}

fn resolve_mode_expr(
    mode_expr: &str,
    render_options: McpRenderOptions,
    resolution: &mut ServerSpecResolution,
) -> Result<(), String> {
    for segment in mode_expr.split('|') {
        let name = segment.trim();
        if name.is_empty() {
            return Err("server mode expression contains an empty segment".to_string());
        }
        expand_toolset(name, render_options, resolution)?;
    }
    Ok(())
}

fn expand_toolset(
    name: &str,
    render_options: McpRenderOptions,
    resolution: &mut ServerSpecResolution,
) -> Result<(), String> {
    match name {
        "symbol" | "workspace" | "diff" | "text" | "extended" | "slopcop" => {
            append_named_toolset(name, render_options, resolution)
        }
        "cli" => Err(CLI_MODE_REJECTED.to_string()),
        "core" => {
            for alias in ["symbol", "workspace", "diff"] {
                expand_toolset(alias, render_options, resolution)?;
            }
            Ok(())
        }
        "searchtools" => {
            for alias in SEARCHTOOLS_ORDER {
                expand_toolset(alias, render_options, resolution)?;
            }
            Ok(())
        }
        other => Err(format!("Unsupported server mode: {other}")),
    }
}

fn append_named_toolset(
    name: &str,
    render_options: McpRenderOptions,
    resolution: &mut ServerSpecResolution,
) -> Result<(), String> {
    let toolset_descriptors = descriptors_for_toolset(name, render_options);
    if !toolset_descriptors.is_empty() {
        resolution.effective_toolsets.insert(name.to_string());
    }
    for descriptor in toolset_descriptors {
        let Some(name) = descriptor.get("name").and_then(Value::as_str) else {
            return Err("tool descriptor missing string name".to_string());
        };
        if resolution.seen.insert(name.to_string()) {
            resolution.descriptors.push(descriptor);
        }
    }
    Ok(())
}

fn discovery_instructions(effective_toolsets: &HashSet<String>) -> String {
    let mut instructions = DISCOVERY_ROUTING_INSTRUCTIONS.to_string();
    for toolset in SEARCHTOOLS_ORDER {
        if !effective_toolsets.contains(*toolset) {
            continue;
        }
        let capability = match *toolset {
            "symbol" => {
                " Symbol tools search declarations and summaries, read symbol source, find usages and definitions, inspect types and usage graphs, and rename symbols."
            }
            "workspace" => " Workspace tools refresh indexed state and manage workspace selection.",
            "diff" => {
                " Diff tools explain semantic patch effects, suggest test scopes, compare cyclomatic complexity, and find changed functions without a complete structured call path from tests."
            }
            "extended" => {
                " Structural tools run CodeQuery and RQL, inspect symbol locations and ancestors, rank related files, inspect Git history, and evaluate repository policies."
            }
            "text" => {
                " Text tools read files, search file contents with regular expressions, and find matching files."
            }
            "slopcop" => {
                " Code-quality tools find complexity, hotspots, clones, smells, dead code, secrets, and risky changes."
            }
            _ => unreachable!("SEARCHTOOLS_ORDER contains only registered toolsets"),
        };
        instructions.push_str(capability);
    }
    instructions
}

fn descriptors_for_toolset(name: &str, render_options: McpRenderOptions) -> Vec<Value> {
    match name {
        "symbol" => crate::mcp_core::symbol_tool_descriptors(render_options.render_line_numbers),
        "workspace" => crate::mcp_core::workspace_tool_descriptors(),
        "diff" => crate::mcp_diff::diff_tool_descriptors(),
        "text" => crate::mcp_text::text_tool_descriptors(),
        "extended" => crate::mcp_extended::extended_tool_descriptors(),
        "slopcop" => crate::mcp_slopcop::slopcop_tool_descriptors(),
        other => panic!("unknown toolset requested from registry: {other}"),
    }
}

/// Descriptors for tools that exist only for programmatic, non-agent
/// consumers: `bifrost --tool <name>` and the Rust/Python API.
///
/// `classify_test_files` is the sole entry (issue #1116). No `--mcp` toolset
/// composition reaches it -- [`expand_toolset`] rejects `cli` outright -- so
/// this is not part of [`resolve_server_spec`]. It exists so the one-shot CLI
/// can still look up the tool's description and parameter schema for
/// `bifrost --help classify_test_files`.
pub fn single_shot_only_tool_descriptors() -> Vec<Value> {
    crate::mcp_cli::cli_tool_descriptors()
}
