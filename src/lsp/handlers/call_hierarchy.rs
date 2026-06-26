use std::collections::BTreeMap;
use std::sync::Arc;

use lsp_types::{
    CallHierarchyIncomingCall, CallHierarchyIncomingCallsParams, CallHierarchyItem,
    CallHierarchyOutgoingCall, CallHierarchyOutgoingCallsParams, CallHierarchyPrepareParams,
    Range as LspRange, Uri,
};

use crate::analyzer::common::language_for_file;
use crate::analyzer::usages::get_definition::{
    DefinitionLookupRequest, DefinitionLookupStatus, call_reference_ranges,
    is_call_reference_range, resolve_definition_batch_with_source,
};
use crate::analyzer::usages::{DEFAULT_MAX_FILES, DEFAULT_MAX_USAGES, UsageFinder, UsageHit};
use crate::analyzer::{
    CodeUnit, CodeUnitType, IAnalyzer, Language, Project, Range, WorkspaceAnalyzer,
};
use crate::lsp::conversion::{
    byte_range_to_lsp_range, path_to_uri_string, position_to_byte_offset,
};
use crate::lsp::handlers::document_symbol::lsp_symbol_parts;
use crate::lsp::handlers::hierarchy_support::{
    cursor_byte_range, hierarchy_item_data, resolve_hierarchy_item_code_unit,
};
use crate::lsp::handlers::util::{FileContentCache, read_document_for_uri};
use crate::text_utils::compute_line_starts;

const MAX_OUTGOING_CANDIDATES: usize = DEFAULT_MAX_USAGES;

pub fn prepare(
    workspace: &WorkspaceAnalyzer,
    project: &dyn Project,
    params: &CallHierarchyPrepareParams,
) -> Option<Vec<CallHierarchyItem>> {
    let analyzer = workspace.analyzer();
    let uri = &params.text_document_position_params.text_document.uri;
    let (file, content, line_starts) = read_document_for_uri(project, uri)?;
    let offset = position_to_byte_offset(
        &content,
        &line_starts,
        &params.text_document_position_params.position,
    );
    let range = cursor_byte_range(&content, offset);
    let enclosing = analyzer.enclosing_code_unit(&file, &range)?;
    let callable = nearest_call_hierarchy_unit(analyzer, enclosing)?;

    let mut content_cache = FileContentCache::default();
    Some(vec![call_hierarchy_item(
        analyzer,
        project,
        &callable,
        &mut content_cache,
    )?])
}

pub fn incoming_calls(
    workspace: &WorkspaceAnalyzer,
    project: &dyn Project,
    params: &CallHierarchyIncomingCallsParams,
) -> Option<Vec<CallHierarchyIncomingCall>> {
    let analyzer = workspace.analyzer();
    let target = resolve_item_code_unit(analyzer, project, &params.item)?;

    let hits = UsageFinder::new()
        .find_usages(
            analyzer,
            std::slice::from_ref(&target),
            DEFAULT_MAX_FILES,
            DEFAULT_MAX_USAGES,
        )
        .all_hits();
    let mut grouped: BTreeMap<String, (CodeUnit, Vec<LspRange>)> = BTreeMap::new();
    let mut content_cache = FileContentCache::default();
    for hit in hits {
        let caller = nearest_call_hierarchy_unit(analyzer, hit.enclosing.clone())
            .or_else(|| caller_for_hit(analyzer, &hit));
        let Some(caller) = caller else {
            continue;
        };
        if same_symbol(&caller, &target) {
            continue;
        }
        if !is_call_usage_hit(project, &hit, &mut content_cache) {
            continue;
        }
        let Some(range) = usage_hit_range(project, &hit, &mut content_cache) else {
            continue;
        };
        grouped
            .entry(unit_key(&caller))
            .or_insert_with(|| (caller, Vec::new()))
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
    let caller = resolve_item_code_unit(analyzer, project, &params.item)?;
    if !is_call_hierarchy_unit(&caller) {
        return Some(Vec::new());
    }
    if language_for_file(caller.source()) == Language::Ruby {
        // Ruby outgoing call hierarchy depends on Ruby get_definition support;
        // keep this explicit until https://github.com/BrokkAi/bifrost/issues/266 lands.
        return Some(Vec::new());
    }

    let source = Arc::new(project.read_source(caller.source()).ok()?);
    let line_starts = compute_line_starts(&source);
    let caller_range = analyzer.ranges(&caller).iter().min().copied()?;
    let candidates = call_reference_ranges(
        caller.source(),
        &source,
        &caller_range,
        MAX_OUTGOING_CANDIDATES,
    );
    if candidates.is_empty() {
        return Some(Vec::new());
    }

    let requests: Vec<_> = candidates
        .iter()
        .take(MAX_OUTGOING_CANDIDATES)
        .map(|node_range| DefinitionLookupRequest {
            file: caller.source().clone(),
            line: None,
            column: None,
            start_byte: Some(node_range.start_byte),
            end_byte: Some(node_range.end_byte),
        })
        .collect();
    let outcomes = resolve_definition_batch_with_source(
        analyzer,
        requests,
        caller.source().clone(),
        Arc::clone(&source),
    );

    let mut grouped: BTreeMap<String, (CodeUnit, Vec<LspRange>)> = BTreeMap::new();
    let mut content_cache = FileContentCache::default();
    for (node_range, outcome) in candidates
        .into_iter()
        .take(MAX_OUTGOING_CANDIDATES)
        .zip(outcomes)
    {
        if outcome.status != DefinitionLookupStatus::Resolved {
            continue;
        }
        for definition in outcome.definitions {
            let Some(callee) = nearest_call_hierarchy_unit(analyzer, definition) else {
                continue;
            };
            if same_symbol(&caller, &callee) {
                continue;
            }
            let lsp_range = byte_range_to_lsp_range(&source, &line_starts, &node_range);
            grouped
                .entry(unit_key(&callee))
                .or_insert_with(|| (callee, Vec::new()))
                .1
                .push(lsp_range);
        }
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

fn nearest_call_hierarchy_unit(analyzer: &dyn IAnalyzer, mut unit: CodeUnit) -> Option<CodeUnit> {
    loop {
        if is_call_hierarchy_unit(&unit) {
            return Some(unit);
        }
        unit = analyzer.parent_of(&unit)?;
    }
}

fn is_call_hierarchy_unit(unit: &CodeUnit) -> bool {
    matches!(unit.kind(), CodeUnitType::Class | CodeUnitType::Function) && !unit.is_synthetic()
}

fn caller_for_hit(analyzer: &dyn IAnalyzer, hit: &UsageHit) -> Option<CodeUnit> {
    analyzer
        .enclosing_code_unit_for_lines(&hit.file, hit.line, hit.line)
        .and_then(|unit| nearest_call_hierarchy_unit(analyzer, unit))
}

fn usage_hit_range(
    project: &dyn Project,
    hit: &UsageHit,
    cache: &mut FileContentCache,
) -> Option<LspRange> {
    let entry = cache.read_project(project, &hit.file)?;
    let range = Range {
        start_byte: hit.start_offset,
        end_byte: hit.end_offset,
        start_line: hit.line,
        end_line: hit.line,
    };
    Some(byte_range_to_lsp_range(
        &entry.body,
        &entry.line_starts,
        &range,
    ))
}

fn is_call_usage_hit(project: &dyn Project, hit: &UsageHit, cache: &mut FileContentCache) -> bool {
    let Some(entry) = cache.read_project(project, &hit.file) else {
        return false;
    };
    is_call_reference_range(&hit.file, &entry.body, hit.start_offset, hit.end_offset)
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
        is_call_hierarchy_unit(unit)
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

fn same_symbol(left: &CodeUnit, right: &CodeUnit) -> bool {
    left.source() == right.source()
        && left.fq_name() == right.fq_name()
        && left.kind() == right.kind()
        && left.signature() == right.signature()
}

fn compare_lsp_range(left: &LspRange, right: &LspRange) -> std::cmp::Ordering {
    left.start
        .line
        .cmp(&right.start.line)
        .then_with(|| left.start.character.cmp(&right.start.character))
        .then_with(|| left.end.line.cmp(&right.end.line))
        .then_with(|| left.end.character.cmp(&right.end.character))
}
