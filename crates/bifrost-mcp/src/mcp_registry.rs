use crate::mcp_common::{McpRenderOptions, McpServerSpec, build_server_spec_with_hidden};
use serde_json::Value;
use std::collections::HashSet;

const SEARCHTOOLS_ORDER: &[&str] = &[
    "symbol",
    "workspace",
    "diff",
    "extended",
    "text",
    "slopcop",
    "cli",
];

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
        "symbol" | "workspace" | "diff" | "text" | "extended" | "slopcop" | "cli" => {
            append_named_toolset(name, render_options, resolution)
        }
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
            "cli" => " Test-classification tools identify whether paths contain tests.",
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
        "cli" => crate::mcp_cli::cli_tool_descriptors(),
        other => panic!("unknown toolset requested from registry: {other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::{DISCOVERY_ROUTING_INSTRUCTIONS, resolve_server_spec};
    use crate::mcp_common::MCP_DISCOVERY_TEXT_MAX_CHARS;
    use serde_json::Value;

    fn tool_names(mode_expr: &str) -> Vec<String> {
        resolve_server_spec(mode_expr)
            .expect("server spec")
            .tool_descriptors
            .into_iter()
            .map(|descriptor| {
                descriptor
                    .get("name")
                    .and_then(Value::as_str)
                    .expect("descriptor name")
                    .to_string()
            })
            .collect()
    }

    fn symbol_tool_names() -> Vec<String> {
        [
            "search_symbols",
            "get_symbol_sources",
            "get_summaries",
            "scan_usages_by_location",
            "get_declarations_by_location",
            "get_definitions_by_location",
            "get_type_by_location",
            "rename_symbol",
            "usage_graph",
        ]
        .into_iter()
        .map(str::to_string)
        .collect()
    }

    fn accepted_tool_names(mode_expr: &str) -> Vec<String> {
        let mut names: Vec<String> = resolve_server_spec(mode_expr)
            .expect("server spec")
            .tool_names
            .into_iter()
            .collect();
        names.sort();
        names
    }

    fn workspace_tool_names() -> Vec<String> {
        ["refresh", "activate_workspace", "get_active_workspace"]
            .into_iter()
            .map(str::to_string)
            .collect()
    }

    fn diff_tool_names() -> Vec<String> {
        [
            "analyze_diff",
            "blast_radius",
            "cyclomatic_complexity",
            "missing_tests",
            "score_diff",
        ]
        .into_iter()
        .map(str::to_string)
        .collect()
    }

    #[test]
    fn composition_deduplicates_and_preserves_first_occurrence() {
        let mut expected: Vec<String> = [
            "get_file_contents",
            "search_file_contents",
            "find_files_containing",
        ]
        .into_iter()
        .map(str::to_string)
        .collect();
        expected.extend(symbol_tool_names());
        expected.extend(workspace_tool_names());
        expected.extend(diff_tool_names());
        assert_eq!(tool_names("text|core|text"), expected);
    }

    #[test]
    fn diff_and_core_advertise_the_endpoint_tools_once() {
        assert_eq!(tool_names("diff"), diff_tool_names());

        let mut expected = symbol_tool_names();
        expected.extend(workspace_tool_names());
        expected.extend(diff_tool_names());
        assert_eq!(tool_names("core"), expected);

        let slopcop = tool_names("slopcop");
        assert!(!slopcop.contains(&"analyze_diff".to_string()));
        assert!(!slopcop.contains(&"blast_radius".to_string()));
    }

    #[test]
    fn removed_nlp_toolset_is_rejected() {
        assert_eq!(
            resolve_server_spec("nlp").unwrap_err(),
            "Unsupported server mode: nlp"
        );
    }

    #[test]
    fn symbol_does_not_accept_hidden_list_symbols() {
        let advertised = tool_names("symbol");
        assert_eq!(advertised, symbol_tool_names());

        let accepted = accepted_tool_names("symbol");
        assert!(accepted.contains(&"get_summaries".to_string()));
        assert!(!accepted.contains(&"list_symbols".to_string()));
    }

    #[test]
    fn discovery_instructions_match_effective_toolsets() {
        let symbol = resolve_server_spec("symbol").expect("symbol server spec");
        assert!(
            symbol
                .instructions
                .starts_with(DISCOVERY_ROUTING_INSTRUCTIONS)
        );
        assert!(symbol.instructions.contains("Symbol tools"));
        assert!(!symbol.instructions.contains("repository policies"));

        let extended = resolve_server_spec("extended").expect("extended server spec");
        assert!(extended.instructions.contains("CodeQuery and RQL"));
        assert!(extended.instructions.contains("repository policies"));
        let installed = resolve_server_spec("core").expect("installed server spec");
        assert!(installed.instructions.contains("Symbol tools"));
        assert!(installed.instructions.contains("Workspace tools"));
        assert!(installed.instructions.contains("Diff tools"));
        assert_eq!(installed.instructions.matches("Symbol tools").count(), 1);
        assert_eq!(installed.instructions.matches("Workspace tools").count(), 1);
        assert_eq!(installed.instructions.matches("Diff tools").count(), 1);
    }

    #[test]
    fn discovery_metadata_fits_host_limits() {
        let spec = resolve_server_spec("searchtools").expect("complete server spec");
        assert!(DISCOVERY_ROUTING_INSTRUCTIONS.chars().count() <= 512);
        assert!(spec.instructions.chars().count() <= MCP_DISCOVERY_TEXT_MAX_CHARS);
        for descriptor in spec.tool_descriptors {
            let name = descriptor["name"].as_str().expect("tool name");
            let description = descriptor["description"]
                .as_str()
                .expect("tool description");
            assert!(
                description.chars().count() <= MCP_DISCOVERY_TEXT_MAX_CHARS,
                "tool descriptor `{name}` exceeds the discovery metadata limit"
            );
            // `query_code` stays under the cap because it describes the tool
            // and leaves the step vocabulary to the generated `steps` schema.
            // A description that names a step is a description that grows with
            // the registry, which is how it reached the cap before.
            if name == "query_code" {
                for op in brokk_bifrost_rql::schema::ALL_QUERY_STEP_OPS {
                    assert!(
                        !description.contains(op.label()),
                        "query_code description enumerates step `{}`; the step reference belongs to the steps parameter schema",
                        op.label()
                    );
                }
            }
        }
    }
}
