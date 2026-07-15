use std::collections::BTreeMap;
use std::sync::Arc;

use lsp_types::{
    CallHierarchyIncomingCall, CallHierarchyIncomingCallsParams, CallHierarchyItem,
    CallHierarchyOutgoingCall, CallHierarchyOutgoingCallsParams, CallHierarchyPrepareParams,
    Position, Range as LspRange, Uri,
};

use crate::analyzer::usages::get_definition::{
    DefinitionLookupRequest, DefinitionLookupStatus, resolve_call_reference_definition_with_source,
};
use crate::analyzer::usages::{
    CallRelationService, DEFAULT_MAX_FILES, DEFAULT_MAX_USAGES, UsageProof, is_call_relation_unit,
    nearest_call_relation_unit,
};
use crate::analyzer::{
    AnalyzerQueryScope, CodeUnit, IAnalyzer, Project, ProjectFile, Range, WorkspaceAnalyzer,
};
use crate::lsp::conversion::{
    byte_range_to_lsp_range, path_to_uri_string, position_to_byte_offset,
};
use crate::lsp::handlers::document_symbol::lsp_symbol_parts;
use crate::lsp::handlers::hierarchy_support::{
    cursor_byte_range, hierarchy_item_data, resolve_hierarchy_item_code_unit,
};
use crate::lsp::handlers::util::{FileContentCache, read_document_for_uri};

pub fn prepare(
    workspace: &WorkspaceAnalyzer,
    project: &dyn Project,
    params: &CallHierarchyPrepareParams,
) -> Option<Vec<CallHierarchyItem>> {
    let analyzer = workspace.analyzer();
    let _query_scope = AnalyzerQueryScope::new(analyzer);
    let uri = &params.text_document_position_params.text_document.uri;
    let (file, content, line_starts) = read_document_for_uri(project, uri)?;
    let offset = position_to_byte_offset(
        &content,
        &line_starts,
        &params.text_document_position_params.position,
    );
    let range = cursor_byte_range(&content, offset);
    let callable = prepare_target_at_cursor(
        analyzer,
        &file,
        &content,
        &line_starts,
        &params.text_document_position_params.position,
        &range,
    )?;

    let mut content_cache = FileContentCache::default();
    Some(vec![call_hierarchy_item(
        analyzer,
        project,
        &callable,
        &mut content_cache,
    )?])
}

fn prepare_target_at_cursor(
    analyzer: &dyn IAnalyzer,
    file: &crate::analyzer::ProjectFile,
    content: &str,
    line_starts: &[usize],
    position: &Position,
    range: &Range,
) -> Option<CodeUnit> {
    declaration_target_at_cursor(analyzer, file, content, line_starts, position, range)
        .or_else(|| call_reference_target_at_cursor(analyzer, file, content, range))
}

fn declaration_target_at_cursor(
    analyzer: &dyn IAnalyzer,
    file: &crate::analyzer::ProjectFile,
    content: &str,
    line_starts: &[usize],
    position: &Position,
    range: &Range,
) -> Option<CodeUnit> {
    let enclosing = analyzer.enclosing_code_unit(file, range)?;
    let callable = nearest_call_relation_unit(analyzer, enclosing)?;
    if callable.source() != file {
        return None;
    }
    let parts = lsp_symbol_parts(analyzer, &callable, content, line_starts, None);
    lsp_range_contains_position(&parts.selection_range, position).then_some(callable)
}

fn call_reference_target_at_cursor(
    analyzer: &dyn IAnalyzer,
    file: &crate::analyzer::ProjectFile,
    content: &str,
    range: &Range,
) -> Option<CodeUnit> {
    if range.start_byte >= range.end_byte {
        return None;
    }

    let outcome = resolve_call_reference_definition_with_source(
        analyzer,
        DefinitionLookupRequest {
            file: file.clone(),
            line: None,
            column: None,
            start_byte: Some(range.start_byte),
            end_byte: Some(range.end_byte),
        },
        file.clone(),
        Arc::new(content.to_string()),
    )?;
    if outcome.status != DefinitionLookupStatus::Resolved {
        return None;
    }
    outcome
        .definitions
        .into_iter()
        .find_map(|definition| nearest_call_relation_unit(analyzer, definition))
}

fn lsp_range_contains_position(range: &LspRange, position: &Position) -> bool {
    compare_lsp_position(position, &range.start) != std::cmp::Ordering::Less
        && compare_lsp_position(position, &range.end) == std::cmp::Ordering::Less
}

fn compare_lsp_position(left: &Position, right: &Position) -> std::cmp::Ordering {
    left.line
        .cmp(&right.line)
        .then_with(|| left.character.cmp(&right.character))
}

pub fn incoming_calls(
    workspace: &WorkspaceAnalyzer,
    project: &dyn Project,
    params: &CallHierarchyIncomingCallsParams,
) -> Option<Vec<CallHierarchyIncomingCall>> {
    let analyzer = workspace.analyzer();
    let _query_scope = AnalyzerQueryScope::new(analyzer);
    let target = resolve_item_code_unit(analyzer, project, &params.item)?;

    let relation =
        CallRelationService::incoming(analyzer, &target, DEFAULT_MAX_FILES, DEFAULT_MAX_USAGES);

    let mut grouped: BTreeMap<String, (CodeUnit, Vec<LspRange>)> = BTreeMap::new();
    let mut content_cache = FileContentCache::default();
    for site in relation.sites {
        if site.proof != UsageProof::Proven {
            continue;
        }
        let Some(range) = source_range(project, &site.file, &site.callee_range, &mut content_cache)
        else {
            continue;
        };
        grouped
            .entry(unit_key(&site.caller))
            .or_insert_with(|| (site.caller, Vec::new()))
            .1
            .push(range);
    }

    Some(
        grouped
            .into_values()
            .filter_map(|(caller, mut from_ranges)| {
                from_ranges.sort_by(compare_lsp_range);
                from_ranges.dedup();
                Some(CallHierarchyIncomingCall {
                    from: call_hierarchy_item(analyzer, project, &caller, &mut content_cache)?,
                    from_ranges,
                })
            })
            .collect(),
    )
}

pub fn outgoing_calls(
    workspace: &WorkspaceAnalyzer,
    project: &dyn Project,
    params: &CallHierarchyOutgoingCallsParams,
) -> Option<Vec<CallHierarchyOutgoingCall>> {
    let analyzer = workspace.analyzer();
    let _query_scope = AnalyzerQueryScope::new(analyzer);
    let caller = resolve_item_code_unit(analyzer, project, &params.item)?;
    if !is_call_relation_unit(&caller) {
        return Some(Vec::new());
    }
    let relation = CallRelationService::outgoing(analyzer, &caller, DEFAULT_MAX_USAGES);

    let mut grouped: BTreeMap<String, (CodeUnit, Vec<LspRange>)> = BTreeMap::new();
    let mut content_cache = FileContentCache::default();
    for site in relation.sites {
        if site.proof != UsageProof::Proven {
            continue;
        }
        let Some(range) = source_range(project, &site.file, &site.callee_range, &mut content_cache)
        else {
            continue;
        };
        grouped
            .entry(unit_key(&site.callee))
            .or_insert_with(|| (site.callee, Vec::new()))
            .1
            .push(range);
    }

    Some(
        grouped
            .into_values()
            .filter_map(|(callee, mut from_ranges)| {
                from_ranges.sort_by(compare_lsp_range);
                from_ranges.dedup();
                Some(CallHierarchyOutgoingCall {
                    to: call_hierarchy_item(analyzer, project, &callee, &mut content_cache)?,
                    from_ranges,
                })
            })
            .collect(),
    )
}

fn source_range(
    project: &dyn Project,
    file: &ProjectFile,
    range: &Range,
    cache: &mut FileContentCache,
) -> Option<LspRange> {
    let entry = cache.read_project(project, file)?;
    Some(byte_range_to_lsp_range(
        &entry.body,
        &entry.line_starts,
        range,
    ))
}

fn call_hierarchy_item(
    analyzer: &dyn IAnalyzer,
    project: &dyn Project,
    code_unit: &CodeUnit,
    cache: &mut FileContentCache,
) -> Option<CallHierarchyItem> {
    let entry = cache.read_project(project, code_unit.source())?;
    let parts = lsp_symbol_parts(analyzer, code_unit, &entry.body, &entry.line_starts, None);
    let uri: Uri = path_to_uri_string(&code_unit.source().abs_path())
        .parse()
        .ok()?;

    Some(CallHierarchyItem {
        name: parts.name,
        kind: parts.kind,
        tags: None,
        detail: parts.detail,
        uri: uri.clone(),
        range: parts.range,
        selection_range: parts.selection_range,
        data: Some(hierarchy_item_data(analyzer, code_unit, &uri)),
    })
}

fn resolve_item_code_unit(
    analyzer: &dyn IAnalyzer,
    project: &dyn Project,
    item: &CallHierarchyItem,
) -> Option<CodeUnit> {
    resolve_hierarchy_item_code_unit(analyzer, project, item.data.as_ref(), &item.uri, |unit| {
        is_call_relation_unit(unit)
    })
}

fn unit_key(unit: &CodeUnit) -> String {
    format!(
        "{}\0{}\0{:?}\0{}",
        unit.source().rel_path().display(),
        unit.fq_name(),
        unit.kind(),
        unit.signature().unwrap_or("")
    )
}

fn compare_lsp_range(left: &LspRange, right: &LspRange) -> std::cmp::Ordering {
    compare_lsp_position(&left.start, &right.start)
        .then_with(|| compare_lsp_position(&left.end, &right.end))
}
