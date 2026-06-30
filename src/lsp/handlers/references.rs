use lsp_types::{Location, ReferenceParams, Uri};

use crate::analyzer::usages::UsageHit;
use crate::analyzer::{CodeUnit, IAnalyzer, Project, Range as ByteRange, WorkspaceAnalyzer};
use crate::lsp::conversion::{byte_range_to_lsp_range, path_to_uri_string};
use crate::lsp::handlers::broad_symbol::broad_symbol_target_at_position;
use crate::lsp::handlers::usage_hits::usage_hits_for_candidates;
use crate::lsp::handlers::util::FileContentCache;

/// Resolve `textDocument/references`. Strategy:
/// 1. Prove the cursor is on a real declaration or structured reference.
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
    let analyzer = workspace.analyzer();
    let target = broad_symbol_target_at_position(
        analyzer,
        project,
        uri,
        &params.text_document_position.position,
    )?;

    let mut content_cache = FileContentCache::default();
    let mut locations: Vec<Location> = usage_hits_for_candidates(analyzer, &target.candidates)
        .into_iter()
        .filter_map(|hit| usage_hit_to_location(&hit, &mut content_cache))
        .collect();

    if params.context.include_declaration {
        for cu in &target.candidates {
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
