use crate::{
    SearchToolsService, SearchToolsServiceError, SearchToolsServiceErrorCode, ToolOutput,
    searchtools_render::RenderOptions,
};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::path::PathBuf;
use std::time::{Duration, Instant};

const GET_SUMMARIES_RESPONSE_BUDGET_BYTES: usize = 4_096;
pub const MCP_ANALYZER_REQUEST_BUDGET_SECS_ENV: &str = "BIFROST_MCP_REQUEST_BUDGET_SECS";
pub(crate) const COLD_WORKSPACE_REQUEST_BUDGET: Duration = Duration::from_millis(4_500);
#[doc(hidden)]
pub const BENCHMARK_MCP_REQUEST_BUDGET_SECS: u64 = 60;
pub(crate) const AGENTS_GUIDANCE_URI: &str = "bifrost://agent-guidance/agents.md";
pub(crate) const AGENTS_GUIDANCE_MIME_TYPE: &str = "text/markdown";
pub(crate) const CODEX_MCP_CLIENT_NAME: &str = "codex-mcp-client";
pub(crate) const CODEX_SANDBOX_STATE_META_CAPABILITY: &str = "codex/sandbox-state-meta";
pub(crate) const AGENTS_GUIDANCE_TEXT: &str =
    include_str!("../resources/agent-guidance/bifrost-agents.md");

#[doc(hidden)]
pub const BENCHMARK_PROFILE_BOUNDARY_METHOD: &str = "bifrost/benchmark-profile-boundary";
#[doc(hidden)]
pub const BENCHMARK_PROFILE_BOUNDARY_MARKER: &str =
    "\n\u{1e}bifrost-benchmark-profile-boundary\u{1e}\n";
#[doc(hidden)]
pub const MCP_FILE_WATCHER_ENV: &str = "BIFROST_MCP_FILE_WATCHER";

pub const SEARCHTOOLS_INSTRUCTIONS: &str =
    "Analyzer-backed search tools for source code workspaces.";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct McpRenderOptions {
    pub render_line_numbers: bool,
}

impl Default for McpRenderOptions {
    fn default() -> Self {
        Self {
            render_line_numbers: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct McpServerSpec {
    pub instructions: &'static str,
    pub tool_names: HashSet<String>,
    pub tool_descriptors: Vec<Value>,
}

pub(crate) fn mcp_analyzer_request_budget() -> Option<Duration> {
    mcp_analyzer_request_budget_secs(std::env::var(MCP_ANALYZER_REQUEST_BUDGET_SECS_ENV).ok())
        .map(Duration::from_secs)
}

pub(crate) fn mcp_request_deadline(accepted_at: Instant, cold_workspace: bool) -> Option<Instant> {
    mcp_request_deadline_with_budget(accepted_at, cold_workspace, mcp_analyzer_request_budget())
}

fn mcp_request_deadline_with_budget(
    accepted_at: Instant,
    cold_workspace: bool,
    configured_budget: Option<Duration>,
) -> Option<Instant> {
    configured_budget
        .or(cold_workspace.then_some(COLD_WORKSPACE_REQUEST_BUDGET))
        .map(|budget| accepted_at + budget)
}

fn mcp_analyzer_request_budget_secs(value: Option<String>) -> Option<u64> {
    let value = value?;
    // A run that asked for a budget must never silently proceed without one:
    // an eval measuring latency against a typo'd budget measures nothing.
    let seconds = value.parse::<u64>().unwrap_or_else(|_| {
        panic!("{MCP_ANALYZER_REQUEST_BUDGET_SECS_ENV} must be a positive integer, got {value:?}")
    });
    assert!(
        seconds > 0,
        "{MCP_ANALYZER_REQUEST_BUDGET_SECS_ENV} must be a positive integer, got 0"
    );
    Some(seconds)
}

pub(crate) fn request_correlation_id(id: &Value) -> String {
    let encoded = serde_json::to_string(id).expect("JSON-RPC request IDs always serialize");
    format!("sha256:{:x}", Sha256::digest(encoded.as_bytes()))
}

pub fn build_server_spec(
    instructions: &'static str,
    tool_descriptors: Vec<Value>,
) -> Result<McpServerSpec, String> {
    build_server_spec_with_hidden(instructions, tool_descriptors, Vec::new())
}

pub fn build_server_spec_with_hidden(
    instructions: &'static str,
    tool_descriptors: Vec<Value>,
    hidden_tool_names: Vec<String>,
) -> Result<McpServerSpec, String> {
    let mut tool_names = HashSet::with_capacity(tool_descriptors.len());
    for descriptor in &tool_descriptors {
        let Some(name) = descriptor.get("name").and_then(Value::as_str) else {
            return Err("tool descriptor missing string name".to_string());
        };
        tool_names.insert(name.to_string());
    }
    tool_names.extend(hidden_tool_names);

    Ok(McpServerSpec {
        instructions,
        tool_names,
        tool_descriptors,
    })
}

pub fn run_stdio_server(
    root: Option<PathBuf>,
    render_options: McpRenderOptions,
    spec: &McpServerSpec,
    diff_snapshot_object_dir: Option<PathBuf>,
) -> Result<(), String> {
    crate::rmcp_host::run_stdio_server_with_build_identity(
        root,
        render_options,
        spec,
        diff_snapshot_object_dir,
        env!("CARGO_PKG_VERSION"),
    )
}

pub(crate) fn file_watching_enabled(value: Option<&OsStr>) -> Result<bool, String> {
    match value {
        None => Ok(true),
        Some(value) if value == "on" => Ok(true),
        Some(value) if value == "off" => Ok(false),
        Some(value) => Err(format!(
            "{MCP_FILE_WATCHER_ENV} must be `on` or `off`, not `{}`",
            value.to_string_lossy()
        )),
    }
}

pub(crate) fn serial_tool_request(tool_name: &str) -> bool {
    matches!(
        tool_name,
        "activate_workspace" | "refresh" | "update_paths" | "get_active_workspace"
    )
}

pub(crate) fn client_root_to_path(root: &str) -> Result<PathBuf, String> {
    let native_path = PathBuf::from(root);
    if native_path.is_absolute() {
        return Ok(native_path);
    }

    file_uri_to_path(root)
}

pub(crate) fn file_uri_to_path(uri: &str) -> Result<PathBuf, String> {
    let parsed =
        url::Url::parse(uri).map_err(|error| format!("invalid root URI `{uri}`: {error}"))?;
    if parsed.scheme() != "file" {
        return Err(format!(
            "unsupported root URI scheme `{}`; expected file",
            parsed.scheme()
        ));
    }
    parsed
        .to_file_path()
        .map_err(|()| format!("root URI is not a local filesystem path: {uri}"))
        .and_then(|path| {
            if path.is_absolute() {
                Ok(path)
            } else {
                Err(format!("root URI is not absolute: {uri}"))
            }
        })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn attach_run_policy_correlation(
    output: ToolOutput,
    request_correlation_id: Option<&str>,
) -> ToolOutput {
    let Some(request_correlation_id) = request_correlation_id else {
        return output;
    };
    match output {
        ToolOutput::Structured {
            mut structured,
            rendered_text,
        } => {
            structured
                .as_object_mut()
                .expect("run_policy structured output must be an object")
                .insert(
                    "request_correlation_id".to_string(),
                    Value::String(request_correlation_id.to_string()),
                );
            ToolOutput::Structured {
                structured,
                rendered_text,
            }
        }
        output => {
            debug_assert!(false, "run_policy output must be structured");
            output
        }
    }
}

pub(crate) const UNBOUND_WORKSPACE_MESSAGE: &str = "Bifrost is not bound to a workspace. The MCP client must provide an approved filesystem root via roots/list or Codex sandbox-state metadata, or configure Bifrost with --root or BIFROST_WORKSPACE_ROOT.";

pub(crate) fn fit_get_summaries_output_to_budget(
    service: &SearchToolsService,
    output: ToolOutput,
    render_options: RenderOptions,
) -> Result<ToolOutput, SearchToolsServiceError> {
    let ToolOutput::Structured {
        mut structured,
        rendered_text: base_rendered_text,
    } = output
    else {
        return Ok(output);
    };

    if let Some(object) = structured.as_object_mut() {
        object
            .entry("degraded".to_string())
            .or_insert_with(|| json!(false));
        object
            .entry("degradation".to_string())
            .or_insert(Value::Null);
    }

    let original_bytes = serialized_json_len(&structured);
    let summaries_len = structured
        .get("summaries")
        .and_then(Value::as_array)
        .map(|items| items.len())
        .unwrap_or(0);
    if original_bytes <= GET_SUMMARIES_RESPONSE_BUDGET_BYTES {
        return Ok(ToolOutput::Structured {
            structured,
            rendered_text: base_rendered_text,
        });
    }

    if summaries_len == 0 {
        mark_listing_budget_degradation(&mut structured, original_bytes);
        let budgeted = shrink_get_summaries_value_to_budget(structured);
        let rendered_text =
            render_budgeted_get_summaries_text(&budgeted, None, render_options.render_line_numbers);
        return Ok(ToolOutput::Structured {
            structured: budgeted,
            rendered_text: Some(rendered_text),
        });
    }

    let (budgeted, rendered_text) =
        degrade_get_summaries_value(service, structured, None, original_bytes, render_options)?;
    Ok(ToolOutput::Structured {
        structured: budgeted,
        rendered_text: Some(rendered_text),
    })
}

fn degrade_get_summaries_value(
    service: &SearchToolsService,
    mut structured: Value,
    compact_text: Option<String>,
    original_bytes: usize,
    render_options: RenderOptions,
) -> Result<(Value, String), SearchToolsServiceError> {
    let mut compact_text = compact_text;
    if let Some(paths) = compact_symbols_paths(&structured) {
        if serialized_json_len(&structured) > GET_SUMMARIES_RESPONSE_BUDGET_BYTES {
            let compact_output = service.call_tool_output(
                "list_symbols",
                json!({ "file_patterns": paths }),
                render_options,
            )?;
            compact_text = rendered_text_for_output(&compact_output);
            let ToolOutput::Structured {
                structured: compact_structured,
                ..
            } = compact_output
            else {
                return Err(SearchToolsServiceError {
                    code: SearchToolsServiceErrorCode::Internal,
                    message: "list_symbols returned non-structured output during MCP budgeting"
                        .to_string(),
                });
            };
            structured =
                compact_only_get_summaries_value(structured, compact_structured, original_bytes);
        }
    } else if let Some((compact_structured, rendered)) = compact_symbols_from_summaries(&structured)
    {
        compact_text = Some(rendered);
        structured =
            compact_only_get_summaries_value(structured, compact_structured, original_bytes);
    } else {
        let compact_paths = summary_paths_for_compaction(&structured);
        if !compact_paths.is_empty() {
            let compact_output = service.call_tool_output(
                "list_symbols",
                json!({ "file_patterns": compact_paths }),
                render_options,
            )?;
            compact_text = rendered_text_for_output(&compact_output);
            let ToolOutput::Structured {
                structured: compact_structured,
                ..
            } = compact_output
            else {
                return Err(SearchToolsServiceError {
                    code: SearchToolsServiceErrorCode::Internal,
                    message: "list_symbols returned non-structured output during MCP budgeting"
                        .to_string(),
                });
            };
            structured =
                compact_only_get_summaries_value(structured, compact_structured, original_bytes);
        }
    }

    let structured = shrink_get_summaries_value_to_budget(structured);
    let text = render_budgeted_get_summaries_text(
        &structured,
        compact_text,
        render_options.render_line_numbers,
    );
    Ok((structured, text))
}

fn mark_listing_budget_degradation(structured: &mut Value, original_bytes: usize) {
    let Some(object) = structured.as_object_mut() else {
        return;
    };
    object.insert("degraded".to_string(), json!(true));
    object.insert(
        "degradation".to_string(),
        json!({
            "reason": "response_budget_exceeded",
            "requested_format": "container_listing",
            "returned_format": "truncated_container_listing",
            "budget_bytes": GET_SUMMARIES_RESPONSE_BUDGET_BYTES,
            "original_bytes": original_bytes,
            "message": "The container listing exceeded the response budget and was truncated. Re-call get_summaries with a narrower directory or package target."
        }),
    );
}

fn summary_paths_for_compaction(structured: &Value) -> Vec<String> {
    structured
        .get("summaries")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|summary| {
            let label = summary.get("label")?.as_str()?;
            let path = summary.get("path")?.as_str()?;
            (label == path).then(|| path.to_string())
        })
        .collect()
}

fn compact_symbols_paths(structured: &Value) -> Option<Vec<String>> {
    let files = structured
        .get("compact_symbols")?
        .get("files")?
        .as_array()?;
    Some(
        files
            .iter()
            .filter_map(|file| file.get("path").and_then(Value::as_str).map(str::to_string))
            .collect(),
    )
}

fn compact_only_get_summaries_value(
    mut structured: Value,
    compact_structured: Value,
    original_bytes: usize,
) -> Value {
    if let Some(object) = structured.as_object_mut() {
        object.insert("summaries".to_string(), json!([]));
        object.insert("compact_symbols".to_string(), compact_structured);
        object.insert("degraded".to_string(), json!(true));
        object.insert(
            "degradation".to_string(),
            json!({
                "reason": "response_budget_exceeded",
                "requested_format": "summaries",
                "returned_format": "compact_symbols",
                "budget_bytes": GET_SUMMARIES_RESPONSE_BUDGET_BYTES,
                "original_bytes": original_bytes,
                "message": "Full summaries exceeded the response budget; returned compact declaration outlines. Re-call get_summaries with narrower targets or get_symbol_sources for exact bodies."
            }),
        );
    }
    structured
}

/// Builds the budgeted outline from the summary payload that was already
/// assembled for this request. Re-running `list_symbols` here would re-resolve
/// every parent and discard the persisted summary projection's work.
fn compact_symbols_from_summaries(structured: &Value) -> Option<(Value, String)> {
    let summaries = structured.get("summaries")?.as_array()?;
    if summaries.is_empty() {
        return None;
    }

    let mut files = Vec::with_capacity(summaries.len());
    for summary in summaries {
        let path = summary.get("path")?.as_str()?;
        if summary.get("label")?.as_str()? != path {
            return None;
        }
        let elements = summary.get("elements")?.as_array()?;
        let file = compact_file_from_summary(path, elements)?;
        files.push(file);
    }
    files.sort_by(|left, right| left["path"].as_str().cmp(&right["path"].as_str()));

    let compact = json!({
        "truncated": false,
        "total_files": files.len(),
        "files": files,
    });
    let text = render_compact_symbols_text(&compact);
    Some((compact, text))
}

fn compact_file_from_summary(path: &str, elements: &[Value]) -> Option<Value> {
    if elements.is_empty() {
        return None;
    }

    let mut parents = HashMap::new();
    for element in elements {
        let symbol = element.get("symbol")?.as_str()?;
        let parent = element
            .get("parent_symbol")
            .and_then(Value::as_str)
            .map(str::to_string);
        let is_module = element.get("kind")?.as_str()? == "module";
        parents
            .entry(symbol.to_string())
            .or_insert((parent, is_module));
    }

    let mut ordered = elements.to_vec();
    ordered.sort_by(|left, right| {
        left["start_line"]
            .as_u64()
            .cmp(&right["start_line"].as_u64())
            .then_with(|| left["end_line"].as_u64().cmp(&right["end_line"].as_u64()))
            .then_with(|| left["symbol"].as_str().cmp(&right["symbol"].as_str()))
    });

    let mut loc = 0;
    let mut lines = Vec::with_capacity(ordered.len());
    for element in ordered {
        let symbol = element.get("symbol")?.as_str()?;
        let kind = element.get("kind")?.as_str()?;
        loc = loc.max(element.get("end_line")?.as_u64()? as usize);
        if kind == "module" {
            lines.push(format!("# {symbol}"));
            continue;
        }

        let parent = element.get("parent_symbol").and_then(Value::as_str);
        let depth = compact_symbol_depth(parent, &parents);
        lines.push(format!(
            "{}- {}",
            "  ".repeat(depth),
            compact_symbol_label(symbol)
        ));
    }
    (loc > 0).then(|| json!({ "path": path, "loc": loc, "lines": lines }))
}

fn compact_symbol_depth(
    parent: Option<&str>,
    parents: &HashMap<String, (Option<String>, bool)>,
) -> usize {
    let mut depth = 0;
    let mut current = parent;
    for _ in 0..parents.len() {
        let Some(symbol) = current else {
            break;
        };
        let Some((next_parent, is_module)) = parents.get(symbol) else {
            break;
        };
        if *is_module {
            break;
        }
        depth += 1;
        current = next_parent.as_deref();
    }
    depth
}

fn compact_symbol_label(symbol: &str) -> &str {
    let mut start = 0;
    for separator in [".", "::", "->", "$", "+"] {
        if let Some(index) = symbol.rfind(separator) {
            start = start.max(index + separator.len());
        }
    }
    symbol
        .get(start..)
        .filter(|label| !label.is_empty())
        .unwrap_or(symbol)
}

fn render_compact_symbols_text(compact: &Value) -> String {
    compact
        .get("files")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|file| {
            let path = file.get("path")?.as_str()?;
            let loc = file.get("loc")?.as_u64()?;
            let lines = file
                .get("lines")?
                .as_array()?
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>();
            Some(format!("{path} ({loc} lines)\n{}", lines.join("\n")))
        })
        .collect::<Vec<_>>()
        .join("\n\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_watching_defaults_on_and_accepts_explicit_modes() {
        assert!(file_watching_enabled(None).unwrap());
        assert!(file_watching_enabled(Some(OsStr::new("on"))).unwrap());
        assert!(!file_watching_enabled(Some(OsStr::new("off"))).unwrap());

        let error = file_watching_enabled(Some(OsStr::new("disabled"))).unwrap_err();
        assert!(error.contains(MCP_FILE_WATCHER_ENV), "{error}");
        assert!(error.contains("on` or `off"), "{error}");
    }

    #[test]
    fn compact_summary_reuses_parent_aware_elements() {
        let structured = json!({
            "summaries": [{
                "label": "src/Thing.java",
                "path": "src/Thing.java",
                "elements": [
                    { "symbol": "demo", "kind": "module", "start_line": 1, "end_line": 1 },
                    { "symbol": "demo.Thing", "kind": "class", "start_line": 3, "end_line": 12 },
                    { "symbol": "demo.Thing.value", "kind": "field", "parent_symbol": "demo.Thing", "start_line": 4, "end_line": 4 },
                    { "symbol": "demo.Thing.Inner", "kind": "class", "parent_symbol": "demo.Thing", "start_line": 6, "end_line": 11 },
                    { "symbol": "demo.Thing.Inner.run", "kind": "function", "parent_symbol": "demo.Thing.Inner", "start_line": 7, "end_line": 9 }
                ]
            }]
        });

        let (compact, text) = compact_symbols_from_summaries(&structured).expect("compact summary");
        assert_eq!(
            compact["files"][0]["lines"],
            json!(["# demo", "- Thing", "  - value", "  - Inner", "    - run"])
        );
        assert_eq!(12, compact["files"][0]["loc"]);
        assert!(text.contains("src/Thing.java (12 lines)"), "{text}");
    }

    #[test]
    fn compact_summary_leaves_symbol_targets_on_the_legacy_path() {
        let structured = json!({
            "summaries": [{
                "label": "demo.Thing",
                "path": "src/Thing.java",
                "elements": [{
                    "symbol": "demo.Thing",
                    "kind": "class",
                    "start_line": 3,
                    "end_line": 12
                }]
            }]
        });

        assert!(compact_symbols_from_summaries(&structured).is_none());
    }

    #[test]
    fn oversized_container_listing_is_truncated_to_budget() {
        let entries = (0..200)
            .map(|index| {
                json!({
                    "kind": "file",
                    "name": format!("generated_file_{index:03}.rs"),
                    "path": format!("src/generated/generated_file_{index:03}.rs"),
                })
            })
            .collect::<Vec<_>>();
        let mut structured = json!({
            "summaries": [],
            "listings": [{
                "target": "src/generated",
                "kind": "directory",
                "entries": entries,
                "total_entries": 200,
                "truncated": false,
            }],
            "not_found": [],
            "ambiguous": [],
            "ambiguous_paths": [],
            "degraded": false,
            "degradation": null,
        });
        let original_bytes = serialized_json_len(&structured);

        mark_listing_budget_degradation(&mut structured, original_bytes);
        let structured = shrink_get_summaries_value_to_budget(structured);

        assert!(
            serialized_json_len(&structured) <= GET_SUMMARIES_RESPONSE_BUDGET_BYTES,
            "{}",
            serialized_json_len(&structured)
        );
        assert_eq!(true, structured["degraded"]);
        assert_eq!(true, structured["listings"][0]["truncated"]);
        assert_eq!(200, structured["listings"][0]["total_entries"]);
        assert!(
            structured["listings"][0]["entries"]
                .as_array()
                .is_some_and(|entries| entries.len() < 200)
        );
        let rendered = render_budgeted_get_summaries_text(&structured, None, true);
        assert!(rendered.contains("Directory src/generated"), "{rendered}");
        assert!(rendered.contains("of 200 entries"), "{rendered}");
    }
}

fn shrink_compact_symbols_value_to_budget(mut structured: Value) -> Value {
    loop {
        if serialized_json_len(&structured) <= GET_SUMMARIES_RESPONSE_BUDGET_BYTES {
            return structured;
        }
        let Some(files) = structured
            .get_mut("compact_symbols")
            .and_then(|value| value.get_mut("files"))
            .and_then(Value::as_array_mut)
        else {
            return structured;
        };
        if files.len() <= 1 {
            if let Some(compact) = structured
                .get_mut("compact_symbols")
                .and_then(Value::as_object_mut)
            {
                compact.insert("truncated".to_string(), json!(true));
            }
            return structured;
        }
        files.pop();
        if let Some(compact) = structured
            .get_mut("compact_symbols")
            .and_then(Value::as_object_mut)
        {
            compact.insert("truncated".to_string(), json!(true));
        }
    }
}

fn shrink_get_summaries_value_to_budget(structured: Value) -> Value {
    let mut structured = shrink_compact_symbols_value_to_budget(structured);
    loop {
        if serialized_json_len(&structured) <= GET_SUMMARIES_RESPONSE_BUDGET_BYTES {
            return structured;
        }
        let Some(listings) = structured.get_mut("listings").and_then(Value::as_array_mut) else {
            return structured;
        };
        let Some(index) = listings
            .iter()
            .enumerate()
            .filter_map(|(index, listing)| {
                let len = listing.get("entries")?.as_array()?.len();
                (len > 0).then_some((index, len))
            })
            .max_by_key(|(_, len)| *len)
            .map(|(index, _)| index)
        else {
            return structured;
        };
        let Some(listing) = listings[index].as_object_mut() else {
            return structured;
        };
        if let Some(entries) = listing.get_mut("entries").and_then(Value::as_array_mut) {
            entries.pop();
        }
        listing.insert("truncated".to_string(), json!(true));
    }
}

fn render_budgeted_get_summaries_text(
    structured: &Value,
    compact_text: Option<String>,
    render_line_numbers: bool,
) -> String {
    let note = structured
        .get("degradation")
        .and_then(|value| value.get("message"))
        .and_then(Value::as_str)
        .map(|message| format!("Note: {message}"))
        .unwrap_or_default();
    let mut blocks = Vec::new();
    if !note.is_empty() {
        blocks.push(note);
    }
    if let Some(compact_text) = compact_text.filter(|text| !text.is_empty()) {
        blocks.push(compact_text);
    }
    blocks.extend(render_container_listings_json(
        structured,
        render_line_numbers,
    ));
    if blocks.is_empty() {
        blocks.push("No matching summaries found.".to_string());
    }
    let mut text = blocks.join("\n\n");
    if text.len() > GET_SUMMARIES_RESPONSE_BUDGET_BYTES {
        let suffix = "\n\n[truncated for MCP text budget; inspect structuredContent for full compact result]";
        let keep = GET_SUMMARIES_RESPONSE_BUDGET_BYTES.saturating_sub(suffix.len());
        text.truncate(keep);
        text.push_str(suffix);
    }
    text
}

fn render_container_listings_json(structured: &Value, render_line_numbers: bool) -> Vec<String> {
    structured
        .get("listings")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|listing| {
            let target = listing.get("target")?.as_str()?;
            let label = match listing.get("kind")?.as_str()? {
                "directory" => "Directory",
                "package" => "Package",
                _ => return None,
            };
            let languages = listing
                .get("languages")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>();
            let language_suffix = if languages.is_empty() {
                String::new()
            } else {
                format!(" ({})", languages.join(", "))
            };
            let mut lines = vec![format!("{label} {target}{language_suffix}")];
            let entries = listing.get("entries")?.as_array()?;
            lines.extend(entries.iter().filter_map(|entry| {
                let kind = entry.get("kind")?.as_str()?;
                match kind {
                    "directory" => Some(format!("[directory] {}", entry.get("path")?.as_str()?)),
                    "file" => Some(format!("[file] {}", entry.get("path")?.as_str()?)),
                    "package" => {
                        let languages = entry
                            .get("languages")
                            .and_then(Value::as_array)
                            .into_iter()
                            .flatten()
                            .filter_map(Value::as_str)
                            .collect::<Vec<_>>();
                        let suffix = if languages.is_empty() {
                            String::new()
                        } else {
                            format!("; {}", languages.join(", "))
                        };
                        Some(format!(
                            "[package{suffix}] {}",
                            entry.get("qualified_name")?.as_str()?
                        ))
                    }
                    "type" => {
                        let path = entry.get("path")?.as_str()?;
                        let location = if render_line_numbers {
                            format!(
                                "{path}:{}..{}",
                                entry.get("start_line")?.as_u64()?,
                                entry.get("end_line")?.as_u64()?
                            )
                        } else {
                            path.to_string()
                        };
                        Some(format!(
                            "[type; {}] {}: {location}",
                            entry.get("language")?.as_str()?,
                            entry.get("symbol")?.as_str()?
                        ))
                    }
                    _ => None,
                }
            }));
            if entries.is_empty() {
                lines.push("(empty)".to_string());
            }
            if listing
                .get("truncated")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                lines.push(format!(
                    "[showing {} of {} entries]",
                    entries.len(),
                    listing
                        .get("total_entries")
                        .and_then(Value::as_u64)
                        .unwrap_or(entries.len() as u64)
                ));
            }
            Some(lines.join("\n"))
        })
        .collect()
}

fn rendered_text_for_output(output: &ToolOutput) -> Option<String> {
    match output {
        ToolOutput::Structured { rendered_text, .. } => rendered_text.clone(),
        ToolOutput::Text(text) => Some(text.clone()),
    }
}

fn serialized_json_len<T: Serialize>(value: &T) -> usize {
    serde_json::to_vec(value)
        .map(|bytes| bytes.len())
        .unwrap_or(usize::MAX)
}

pub fn tool_descriptor(name: &str, description: &str, input_schema: Value) -> Value {
    json!({
        "name": name,
        "description": description,
        "inputSchema": input_schema,
        "annotations": {
            "readOnlyHint": true,
            "destructiveHint": false,
            "idempotentHint": true,
            "openWorldHint": false,
        }
    })
}

pub fn mutating_tool_descriptor(name: &str, description: &str, input_schema: Value) -> Value {
    json!({
        "name": name,
        "description": description,
        "inputSchema": input_schema,
        "annotations": {
            "readOnlyHint": false,
            "destructiveHint": false,
            "idempotentHint": true,
            "openWorldHint": false,
        }
    })
}

pub fn json_schema_object(required: &[&str]) -> Value {
    json!({
        "type": "object",
        "properties": {},
        "required": required,
    })
}

pub fn symbol_names_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "symbols": {
                "type": "array",
                "maxItems": crate::searchtools::SYMBOL_LOOKUP_MAX_SYMBOLS,
                "items": {
                    "type": "string",
                    "maxLength": crate::searchtools::SYMBOL_LOOKUP_MAX_SYMBOL_BYTES
                },
                "description": "Fully qualified or short symbol names to resolve, or project-relative file paths/globs for file-backed symbol views."
            }
        },
        "required": ["symbols"]
    })
}

pub fn file_patterns_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "file_patterns": {
                "type": "array",
                "items": { "type": "string" },
                "description": "Project-relative file paths or glob patterns, or absolute paths/globs inside the active workspace."
            }
        },
        "required": ["file_patterns"]
    })
}

pub fn summaries_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "targets": {
                "type": "array",
                "items": { "type": "string" },
                "description": "Targets may be mixed in one call. Use a project-relative directory like an `ls`: it returns immediate child directories and git-visible files (tracked or unignored), including non-source files, without recursively flattening descendants; gitignored files are excluded. Use an OO namespace or language import/package path like a semantic `ls`: it returns direct child packages and top-level types declared in that exact package. A real filesystem directory wins if a target could mean either. Literal files, globs, and class/module symbols return ranged code summaries. Oversized ordinary summaries degrade to compact_symbols; oversized listings retain a total count and set truncated. Examples: \"src/auth\", \"com.example.auth\", \"github.com/cli/cli/v2/internal/skills/discovery\", \"src/auth/**/*.rs\", \"MyClass\"."
            }
        },
        "required": ["targets"]
    })
}

pub fn weight_knob_descriptor(
    description_prefix: &str,
    default_value: i32,
    pick_threshold: WeightThreshold,
) -> Value {
    let cmp = match pick_threshold {
        WeightThreshold::Negative => "<",
        WeightThreshold::NonPositive => "<=",
    };
    json!({
        "type": "integer",
        "description": format!(
            "{description_prefix}; values {cmp} 0 use the brokk default ({default_value})."
        )
    })
}

#[derive(Clone, Copy)]
pub enum WeightThreshold {
    Negative,
    NonPositive,
}

#[cfg(test)]
mod shared_tests {
    use super::*;

    #[test]
    fn file_uri_round_trips_native_absolute_paths() {
        let path = std::env::current_dir()
            .expect("current directory")
            .join("workspace with spaces");
        let uri = url::Url::from_file_path(&path).expect("file URI");
        assert_eq!(file_uri_to_path(uri.as_str()).unwrap(), path);
    }

    #[test]
    fn absolute_native_workspace_root_is_accepted() {
        let path = std::env::current_dir()
            .expect("current directory")
            .join("workspace with spaces");
        assert_eq!(
            client_root_to_path(path.to_str().expect("native path")).unwrap(),
            path
        );
    }

    #[test]
    fn relative_native_workspace_root_is_rejected() {
        let error = client_root_to_path("workspace").unwrap_err();
        assert!(error.contains("invalid root URI `workspace`"), "{error}");
    }

    #[test]
    fn file_uri_rejects_non_file_schemes() {
        let error = file_uri_to_path("https://example.com/workspace").unwrap_err();
        assert!(
            error.contains("unsupported root URI scheme `https`"),
            "{error}"
        );
    }

    #[test]
    fn request_budget_defaults_to_unbounded_and_opts_into_any_positive_deadline() {
        assert_eq!(mcp_analyzer_request_budget_secs(None), None);
        assert_eq!(
            mcp_analyzer_request_budget_secs(Some("5".to_string())),
            Some(5)
        );
        assert_eq!(
            mcp_analyzer_request_budget_secs(Some(BENCHMARK_MCP_REQUEST_BUDGET_SECS.to_string())),
            Some(BENCHMARK_MCP_REQUEST_BUDGET_SECS)
        );
        assert_eq!(
            mcp_analyzer_request_budget_secs(Some("600".to_string())),
            Some(600)
        );
    }

    #[test]
    fn explicit_request_budget_wins_over_the_cold_workspace_fallback() {
        let accepted_at = Instant::now();
        let configured_budget = Duration::from_secs(8);

        let configured =
            mcp_request_deadline_with_budget(accepted_at, true, Some(configured_budget))
                .expect("configured budget should set a deadline");
        assert_eq!(configured.duration_since(accepted_at), configured_budget);

        let fallback = mcp_request_deadline_with_budget(accepted_at, true, None)
            .expect("cold workspace should use its fallback deadline");
        assert_eq!(
            fallback.duration_since(accepted_at),
            COLD_WORKSPACE_REQUEST_BUDGET
        );
    }

    #[test]
    #[should_panic(expected = "BIFROST_MCP_REQUEST_BUDGET_SECS must be a positive integer")]
    fn request_budget_rejects_unparseable_values_loudly() {
        mcp_analyzer_request_budget_secs(Some("invalid".to_string()));
    }

    #[test]
    #[should_panic(expected = "BIFROST_MCP_REQUEST_BUDGET_SECS must be a positive integer")]
    fn request_budget_rejects_zero_loudly() {
        mcp_analyzer_request_budget_secs(Some("0".to_string()));
    }

    #[test]
    fn oversized_request_ids_produce_bounded_log_safe_correlation_ids() {
        let first = request_correlation_id(&Value::String("x".repeat(1024 * 1024)));
        let second = request_correlation_id(&Value::String("y".repeat(1024 * 1024)));

        assert_eq!(first.len(), "sha256:".len() + 64);
        assert!(first.starts_with("sha256:"));
        assert!(
            first["sha256:".len()..]
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        );
        assert_ne!(first, second);
    }
}
