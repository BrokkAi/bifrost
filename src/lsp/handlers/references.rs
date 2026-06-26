use lsp_types::{Location, ReferenceParams, Uri};

use crate::analyzer::usages::{
    DEFAULT_MAX_FILES, DEFAULT_MAX_USAGES, FuzzyResult, UsageFinder, UsageHit,
};
use crate::analyzer::{CodeUnit, IAnalyzer, Project, Range as ByteRange, WorkspaceAnalyzer};
use crate::lsp::conversion::{
    byte_range_to_lsp_range, path_to_uri_string, position_to_byte_offset,
};
use crate::lsp::handlers::util::{
    FileContentCache, identifier_at_offset, read_document_for_uri, resolve_identifier_candidates,
};

/// Resolve `textDocument/references`. Strategy:
/// 1. Identifier under cursor -> resolve all matching CodeUnits (overloads).
/// 2. Run UsageFinder over the workspace.
/// 3. Map each UsageHit to an LSP Location.
/// 4. Optionally include the declaration site itself when
///    `params.context.include_declaration` is true.
pub fn handle(
    workspace: &WorkspaceAnalyzer,
    project: &dyn Project,
    params: &ReferenceParams,
) -> Option<Vec<Location>> {
    let uri = &params.text_document_position.text_document.uri;
    let (_, content, line_starts) = read_document_for_uri(project, uri)?;
    let byte_offset = position_to_byte_offset(
        &content,
        &line_starts,
        &params.text_document_position.position,
    );
    let identifier = identifier_at_offset(&content, byte_offset)?;

    let analyzer = workspace.analyzer();
    let overloads = resolve_identifier_candidates(analyzer, identifier);
    if overloads.is_empty() {
        return None;
    }

    let result =
        UsageFinder::new().find_usages(analyzer, &overloads, DEFAULT_MAX_FILES, DEFAULT_MAX_USAGES);
    let hits = collect_hits(result);

    let mut content_cache = FileContentCache::default();
    let mut locations: Vec<Location> = hits
        .into_iter()
        .filter_map(|hit| usage_hit_to_location(&hit, &mut content_cache))
        .collect();

    if params.context.include_declaration {
        for cu in &overloads {
            if let Some(loc) = code_unit_location(analyzer, cu, &mut content_cache) {
                locations.push(loc);
            }
        }
    }

    locations.sort_by(|a, b| {
        a.uri
            .as_str()
            .cmp(b.uri.as_str())
            .then_with(|| a.range.start.line.cmp(&b.range.start.line))
            .then_with(|| a.range.start.character.cmp(&b.range.start.character))
    });
    locations.dedup_by(|a, b| a.uri.as_str() == b.uri.as_str() && a.range == b.range);

    Some(locations)
}

fn collect_hits(result: FuzzyResult) -> Vec<UsageHit> {
    result.all_hits().into_iter().collect()
}

fn usage_hit_to_location(hit: &UsageHit, cache: &mut FileContentCache) -> Option<Location> {
    let abs_path = hit.file.abs_path();
    let entry = cache.read_disk(&abs_path)?;
    let range = ByteRange {
        start_byte: hit.start_offset,
        end_byte: hit.end_offset,
        start_line: hit.line,
        end_line: hit.line,
    };
    let lsp_range = byte_range_to_lsp_range(&entry.body, &entry.line_starts, &range);
    let uri: Uri = path_to_uri_string(&abs_path).parse().ok()?;
    Some(Location {
        uri,
        range: lsp_range,
    })
}

fn code_unit_location(
    analyzer: &dyn IAnalyzer,
    code_unit: &CodeUnit,
    cache: &mut FileContentCache,
) -> Option<Location> {
    let abs_path = code_unit.source().abs_path();
    let entry = cache.read_disk(&abs_path)?;
    let range = analyzer
        .ranges(code_unit)
        .iter()
        .min()
        .copied()
        .unwrap_or(ByteRange {
            start_byte: 0,
            end_byte: entry.body.len(),
            start_line: 0,
            end_line: 0,
        });
    let lsp_range = byte_range_to_lsp_range(&entry.body, &entry.line_starts, &range);
    let uri: Uri = path_to_uri_string(&abs_path).parse().ok()?;
    Some(Location {
        uri,
        range: lsp_range,
    })
}
