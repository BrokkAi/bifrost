use crate::mcp_common::{McpRenderOptions, McpServerSpec, build_server_spec_with_hidden};
use serde_json::Value;
use std::collections::HashSet;
use std::path::Path;

const SEARCHTOOLS_ORDER: &[&str] = &[
    "symbol",
    "nlp",
    "workspace",
    "extended",
    "text",
    "slopcop",
    "cli",
];

const DISCOVERY_ROUTING_INSTRUCTIONS: &str = "Semantic source-code analysis and repository navigation. Search this server for its advertised language-aware and repository-aware tools. Depending on the selected mode, tools cover symbols, structure, semantic search, policies, quality, text, or workspace control. Use them when text search cannot reliably answer a structural or cross-file question. Check result completeness before you claim all results or no results.";

#[derive(Default)]
struct ServerSpecResolution {
    descriptors: Vec<Value>,
    seen: HashSet<String>,
    hidden_tool_names: Vec<String>,
    seen_hidden: HashSet<String>,
    effective_toolsets: HashSet<String>,
}

/// The individual toolset names that compose `searchtools`, in registry order.
/// Exposed so the CLI `--help` can enumerate each toolset and its tools without
/// duplicating the list.
pub fn searchtools_toolset_order() -> &'static [&'static str] {
    SEARCHTOOLS_ORDER
}

/// Whether the workspace root is a git repository. Semantic search is git-only,
/// so the `nlp` toolset is hidden for non-git roots. Always false without the
/// `nlp` feature (no nlp tools to gate).
#[cfg(feature = "nlp")]
pub fn workspace_is_git(root: &Path) -> bool {
    crate::nlp::gitcache::is_git_repo(root)
}

#[cfg(not(feature = "nlp"))]
pub fn workspace_is_git(_root: &Path) -> bool {
    false
}

/// Convenience entry that assumes a git repo (used by tests and nlp-free
/// toolsets); the binary calls `resolve_server_spec_for_render_options` with the
/// real git-ness of the active root.
pub fn resolve_server_spec(mode_expr: &str) -> Result<McpServerSpec, String> {
    resolve_server_spec_for_render_options(mode_expr, McpRenderOptions::default(), true)
}

pub fn resolve_server_spec_for_render_options(
    mode_expr: &str,
    render_options: McpRenderOptions,
    git_repo: bool,
) -> Result<McpServerSpec, String> {
    let mut resolution = ServerSpecResolution::default();
    resolve_mode_expr(mode_expr, render_options, git_repo, &mut resolution)?;
    if resolution.descriptors.is_empty() {
        return Err("server mode expression produced no tools".to_string());
    }
    build_server_spec_with_hidden(
        discovery_instructions(&resolution.effective_toolsets),
        resolution.descriptors,
        resolution.hidden_tool_names,
    )
}

fn resolve_mode_expr(
    mode_expr: &str,
    render_options: McpRenderOptions,
    git_repo: bool,
    resolution: &mut ServerSpecResolution,
) -> Result<(), String> {
    for segment in mode_expr.split('|') {
        let name = segment.trim();
        if name.is_empty() {
            return Err("server mode expression contains an empty segment".to_string());
        }
        expand_toolset(name, render_options, git_repo, resolution)?;
    }
    Ok(())
}

fn expand_toolset(
    name: &str,
    render_options: McpRenderOptions,
    git_repo: bool,
    resolution: &mut ServerSpecResolution,
) -> Result<(), String> {
    match name {
        "symbol" | "nlp" | "workspace" | "text" | "extended" | "slopcop" | "cli" => {
            append_named_toolset(name, render_options, git_repo, resolution)
        }
        "core" => {
            for alias in ["symbol", "nlp", "workspace"] {
                expand_toolset(alias, render_options, git_repo, resolution)?;
            }
            Ok(())
        }
        "searchtools" => {
            for alias in SEARCHTOOLS_ORDER {
                expand_toolset(alias, render_options, git_repo, resolution)?;
            }
            Ok(())
        }
        other => Err(format!("Unsupported server mode: {other}")),
    }
}

fn append_named_toolset(
    name: &str,
    render_options: McpRenderOptions,
    git_repo: bool,
    resolution: &mut ServerSpecResolution,
) -> Result<(), String> {
    let toolset_descriptors = descriptors_for_toolset(name, render_options, git_repo);
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
    for hidden in hidden_tool_names_for_toolset(name) {
        if resolution.seen_hidden.insert(hidden.to_string()) {
            resolution.hidden_tool_names.push(hidden.to_string());
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
            "nlp" => {
                " Semantic search finds source files by meaning from a natural-language description."
            }
            "workspace" => " Workspace tools refresh indexed state and manage workspace selection.",
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

fn descriptors_for_toolset(
    name: &str,
    render_options: McpRenderOptions,
    git_repo: bool,
) -> Vec<Value> {
    match name {
        "symbol" => crate::mcp_core::symbol_tool_descriptors(render_options.render_line_numbers),
        "nlp" => crate::mcp_nlp::nlp_tool_descriptors(git_repo),
        "workspace" => crate::mcp_core::workspace_tool_descriptors(),
        "text" => crate::mcp_text::text_tool_descriptors(),
        "extended" => crate::mcp_extended::extended_tool_descriptors(),
        "slopcop" => crate::mcp_slopcop::slopcop_tool_descriptors(),
        "cli" => crate::mcp_cli::cli_tool_descriptors(),
        other => panic!("unknown toolset requested from registry: {other}"),
    }
}

fn hidden_tool_names_for_toolset(name: &str) -> &'static [&'static str] {
    match name {
        #[cfg(feature = "nlp")]
        "nlp" => &[
            "semantic_search_status",
            "get_symbol_sources",
            "get_summaries",
        ],
        _ => &[],
    }
}

#[cfg(test)]
mod tests {
    use super::{DISCOVERY_ROUTING_INSTRUCTIONS, resolve_server_spec};
    use crate::mcp_common::MCP_DISCOVERY_TEXT_MAX_CHARS;
    use serde_json::Value;

    /// `semantic_search` is only advertised when an accelerator is available; force
    /// the CPU override so these structural tests are hardware-independent. (No-op
    /// without the `nlp` feature.)
    fn force_semantic_for_tests() {
        unsafe { std::env::set_var("BIFROST_FORCE_SEMANTIC_CPU", "1") };
        unsafe { std::env::set_var("BIFROST_SEMANTIC_INDEX", "auto") };
    }

    fn tool_names(mode_expr: &str) -> Vec<String> {
        force_semantic_for_tests();
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

    fn nlp_tool_names() -> Vec<String> {
        if cfg!(feature = "nlp") {
            vec!["semantic_search".to_string()]
        } else {
            Vec::new()
        }
    }

    fn accepted_tool_names(mode_expr: &str) -> Vec<String> {
        force_semantic_for_tests();
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

    #[cfg(feature = "nlp")]
    #[test]
    fn nlp_tools_hidden_for_non_git_root() {
        force_semantic_for_tests();
        // Even with the accelerator forced on, a non-git root drops semantic_search
        // (the cache is keyed by blob OID), while the rest of `core` is unaffected.
        let names: Vec<String> = super::resolve_server_spec_for_render_options(
            "core",
            crate::mcp_common::McpRenderOptions::default(),
            false,
        )
        .expect("server spec")
        .tool_names
        .into_iter()
        .collect();
        assert!(
            !names.contains(&"semantic_search".to_string()),
            "semantic_search must be hidden for non-git roots"
        );
        assert!(
            names.contains(&"search_symbols".to_string()),
            "non-nlp tools remain available"
        );
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
        expected.extend(nlp_tool_names());
        expected.extend(workspace_tool_names());
        assert_eq!(tool_names("text|core|text"), expected);
    }

    #[test]
    fn nlp_accepts_internal_support_tools_without_advertising_them() {
        force_semantic_for_tests();
        if !cfg!(feature = "nlp") {
            assert!(resolve_server_spec("nlp").is_err());
            return;
        }

        let advertised = tool_names("nlp");
        assert_eq!(advertised, nlp_tool_names());

        let accepted = accepted_tool_names("nlp");
        assert!(accepted.contains(&"semantic_search".to_string()));
        assert!(accepted.contains(&"semantic_search_status".to_string()));
        assert!(accepted.contains(&"get_symbol_sources".to_string()));
        assert!(accepted.contains(&"get_summaries".to_string()));
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
        force_semantic_for_tests();
        let symbol = resolve_server_spec("symbol").expect("symbol server spec");
        assert!(
            symbol
                .instructions
                .starts_with(DISCOVERY_ROUTING_INSTRUCTIONS)
        );
        assert!(symbol.instructions.contains("Symbol tools"));
        assert!(!symbol.instructions.contains("Semantic search finds"));
        assert!(!symbol.instructions.contains("repository policies"));

        let extended = resolve_server_spec("extended").expect("extended server spec");
        assert!(extended.instructions.contains("CodeQuery and RQL"));
        assert!(extended.instructions.contains("repository policies"));
        assert!(!extended.instructions.contains("Semantic search finds"));

        let installed = resolve_server_spec("core|nlp").expect("installed server spec");
        assert!(installed.instructions.contains("Symbol tools"));
        assert!(installed.instructions.contains("Workspace tools"));
        assert_eq!(installed.instructions.matches("Symbol tools").count(), 1);
        assert_eq!(installed.instructions.matches("Workspace tools").count(), 1);
    }

    #[cfg(feature = "nlp")]
    #[test]
    fn discovery_instructions_omit_unavailable_semantic_search() {
        force_semantic_for_tests();
        let available = resolve_server_spec("nlp").expect("nlp server spec");
        assert!(available.instructions.contains("Semantic search finds"));

        let unavailable = super::resolve_server_spec_for_render_options(
            "symbol|nlp",
            crate::mcp_common::McpRenderOptions::default(),
            false,
        )
        .expect("non-git server spec");
        assert!(!unavailable.instructions.contains("Semantic search finds"));
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
        }
    }
}
