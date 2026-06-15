use crate::mcp_common::{McpServerSpec, SEARCHTOOLS_INSTRUCTIONS, build_server_spec_with_hidden};
use serde_json::Value;
use std::collections::HashSet;

const SEARCHTOOLS_ORDER: &[&str] = &["symbol", "nlp", "workspace", "extended", "text", "slopcop"];

pub fn resolve_server_spec(mode_expr: &str) -> Result<McpServerSpec, String> {
    let mut descriptors = Vec::new();
    let mut seen = HashSet::new();
    let mut hidden_tool_names = Vec::new();
    let mut seen_hidden = HashSet::new();
    resolve_mode_expr(
        mode_expr,
        &mut descriptors,
        &mut seen,
        &mut hidden_tool_names,
        &mut seen_hidden,
    )?;
    if descriptors.is_empty() {
        return Err("server mode expression produced no tools".to_string());
    }
    build_server_spec_with_hidden(SEARCHTOOLS_INSTRUCTIONS, descriptors, hidden_tool_names)
}

fn resolve_mode_expr(
    mode_expr: &str,
    descriptors: &mut Vec<Value>,
    seen: &mut HashSet<String>,
    hidden_tool_names: &mut Vec<String>,
    seen_hidden: &mut HashSet<String>,
) -> Result<(), String> {
    for segment in mode_expr.split('|') {
        let name = segment.trim();
        if name.is_empty() {
            return Err("server mode expression contains an empty segment".to_string());
        }
        expand_toolset(name, descriptors, seen, hidden_tool_names, seen_hidden)?;
    }
    Ok(())
}

fn expand_toolset(
    name: &str,
    descriptors: &mut Vec<Value>,
    seen: &mut HashSet<String>,
    hidden_tool_names: &mut Vec<String>,
    seen_hidden: &mut HashSet<String>,
) -> Result<(), String> {
    match name {
        "symbol" => {
            append_named_toolset("symbol", descriptors, seen, hidden_tool_names, seen_hidden)
        }
        "nlp" => append_named_toolset("nlp", descriptors, seen, hidden_tool_names, seen_hidden),
        "workspace" => append_named_toolset(
            "workspace",
            descriptors,
            seen,
            hidden_tool_names,
            seen_hidden,
        ),
        "text" => append_named_toolset("text", descriptors, seen, hidden_tool_names, seen_hidden),
        "extended" => append_named_toolset(
            "extended",
            descriptors,
            seen,
            hidden_tool_names,
            seen_hidden,
        ),
        "slopcop" => {
            append_named_toolset("slopcop", descriptors, seen, hidden_tool_names, seen_hidden)
        }
        "core" => {
            expand_toolset("symbol", descriptors, seen, hidden_tool_names, seen_hidden)?;
            expand_toolset("nlp", descriptors, seen, hidden_tool_names, seen_hidden)?;
            expand_toolset(
                "workspace",
                descriptors,
                seen,
                hidden_tool_names,
                seen_hidden,
            )
        }
        "searchtools" => {
            for alias in SEARCHTOOLS_ORDER {
                expand_toolset(alias, descriptors, seen, hidden_tool_names, seen_hidden)?;
            }
            Ok(())
        }
        other => Err(format!("Unsupported server mode: {other}")),
    }
}

fn append_named_toolset(
    name: &str,
    descriptors: &mut Vec<Value>,
    seen: &mut HashSet<String>,
    hidden_tool_names: &mut Vec<String>,
    seen_hidden: &mut HashSet<String>,
) -> Result<(), String> {
    for descriptor in descriptors_for_toolset(name) {
        let Some(name) = descriptor.get("name").and_then(Value::as_str) else {
            return Err("tool descriptor missing string name".to_string());
        };
        if seen.insert(name.to_string()) {
            descriptors.push(descriptor);
        }
    }
    for hidden in hidden_tool_names_for_toolset(name) {
        if seen_hidden.insert(hidden.to_string()) {
            hidden_tool_names.push(hidden.to_string());
        }
    }
    Ok(())
}

fn descriptors_for_toolset(name: &str) -> Vec<Value> {
    match name {
        "symbol" => crate::mcp_core::symbol_tool_descriptors(),
        "nlp" => crate::mcp_nlp::nlp_tool_descriptors(),
        "workspace" => crate::mcp_core::workspace_tool_descriptors(),
        "text" => crate::mcp_text::text_tool_descriptors(),
        "extended" => crate::mcp_extended::extended_tool_descriptors(),
        "slopcop" => crate::mcp_slopcop::slopcop_tool_descriptors(),
        other => panic!("unknown toolset requested from registry: {other}"),
    }
}

fn hidden_tool_names_for_toolset(name: &str) -> &'static [&'static str] {
    match name {
        #[cfg(feature = "nlp")]
        "nlp" => &["semantic_search_status"],
        _ => &[],
    }
}

#[cfg(test)]
mod tests {
    use super::resolve_server_spec;
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
            "list_symbols",
            "scan_usages",
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

    #[test]
    fn core_expands_symbol_then_nlp_then_workspace() {
        let mut expected = symbol_tool_names();
        expected.extend(nlp_tool_names());
        expected.extend(workspace_tool_names());
        assert_eq!(tool_names("core"), expected);
    }

    #[test]
    fn searchtools_expands_to_all_toolsets_in_order() {
        let mut expected = symbol_tool_names();
        expected.extend(nlp_tool_names());
        expected.extend(workspace_tool_names());
        expected.extend(
            [
                "get_symbol_locations",
                "get_symbol_ancestors",
                "find_filenames",
                "list_files",
                "most_relevant_files",
                "search_git_commit_messages",
                "get_git_log",
                "get_commit_diff",
                "jq",
                "xml_skim",
                "xml_select",
                "get_file_contents",
                "search_file_contents",
                "find_files_containing",
                "compute_cyclomatic_complexity",
                "compute_cognitive_complexity",
                "report_comment_density_for_code_unit",
                "report_exception_handling_smells",
                "report_comment_density_for_files",
                "analyze_git_hotspots",
                "report_test_assertion_smells",
                "report_structural_clone_smells",
                "report_long_method_and_god_object_smells",
                "report_dead_code_and_unused_abstraction_smells",
                "report_secret_like_code",
            ]
            .into_iter()
            .map(str::to_string),
        );
        assert_eq!(tool_names("searchtools"), expected);
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
    fn nlp_accepts_status_without_advertising_it() {
        if !cfg!(feature = "nlp") {
            assert!(resolve_server_spec("nlp").is_err());
            return;
        }

        let advertised = tool_names("nlp");
        assert_eq!(advertised, nlp_tool_names());

        let accepted = accepted_tool_names("nlp");
        assert!(accepted.contains(&"semantic_search".to_string()));
        assert!(accepted.contains(&"semantic_search_status".to_string()));
    }
}
