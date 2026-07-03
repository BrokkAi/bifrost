use crate::{
    SearchToolsService, SearchToolsServiceError, ToolOutput, searchtools_render::RenderOptions,
};
use serde_json::{Value, json};
use std::collections::HashSet;

pub(crate) fn fit_get_summaries_output_to_budget(
    service: &SearchToolsService,
    output: ToolOutput,
    arguments: &Value,
    render_options: RenderOptions,
) -> Result<ToolOutput, SearchToolsServiceError> {
    let ToolOutput::Structured {
        mut structured,
        rendered_text: base_rendered_text,
    } = output
    else {
        return Ok(output);
    };

    let compact_text =
        maybe_add_directory_inventory(service, &mut structured, arguments, render_options)?;
    let rendered_text = render_non_degraded_get_summaries_text(base_rendered_text, compact_text);
    Ok(ToolOutput::Structured {
        structured,
        rendered_text: Some(rendered_text),
    })
}

fn maybe_add_directory_inventory(
    service: &SearchToolsService,
    structured: &mut Value,
    arguments: &Value,
    render_options: RenderOptions,
) -> Result<Option<String>, SearchToolsServiceError> {
    let targets = arguments
        .get("targets")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_string))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if targets.is_empty() {
        return Ok(None);
    }

    let unresolved = unresolved_targets(&targets, structured);
    if unresolved.is_empty() {
        return Ok(None);
    }

    let compact_output = service.call_tool_output(
        "list_symbols",
        json!({ "file_patterns": unresolved }),
        render_options,
    )?;
    let compact_text = rendered_text_for_output(&compact_output);
    let ToolOutput::Structured {
        structured: compact_structured,
        ..
    } = compact_output
    else {
        return Ok(compact_text);
    };
    let has_files = compact_structured
        .get("files")
        .and_then(Value::as_array)
        .map(|files| !files.is_empty())
        .unwrap_or(false);
    if !has_files {
        return Ok(compact_text);
    }

    if let Some(object) = structured.as_object_mut() {
        object.insert("compact_symbols".to_string(), compact_structured);
        object
            .entry("degraded".to_string())
            .or_insert_with(|| json!(false));
        object
            .entry("degradation".to_string())
            .or_insert(Value::Null);
    }
    Ok(compact_text)
}

fn unresolved_targets(targets: &[String], structured: &Value) -> Vec<String> {
    let found_summary_paths: HashSet<_> = structured
        .get("summaries")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|summary| summary.get("path").and_then(Value::as_str))
        .collect();
    let not_found: HashSet<_> = structured
        .get("not_found")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(not_found_input_value)
        .collect();
    targets
        .iter()
        .filter(|target| {
            not_found.contains(target.as_str()) && !found_summary_paths.contains(target.as_str())
        })
        .cloned()
        .collect()
}

fn not_found_input_value(value: &Value) -> Option<&str> {
    value
        .as_str()
        .or_else(|| value.get("input").and_then(Value::as_str))
}

fn render_non_degraded_get_summaries_text(
    base_rendered_text: Option<String>,
    compact_text: Option<String>,
) -> String {
    let base = base_rendered_text.unwrap_or_else(|| "No matching summaries found.".to_string());
    match compact_text {
        Some(compact) if base == "No matching summaries found." => compact,
        Some(compact) => format!("{base}\n\n{compact}"),
        None => base,
    }
}

fn rendered_text_for_output(output: &ToolOutput) -> Option<String> {
    match output {
        ToolOutput::Structured { rendered_text, .. } => rendered_text.clone(),
        ToolOutput::Text(text) => Some(text.clone()),
    }
}
