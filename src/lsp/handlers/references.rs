use lsp_types::{Location, ReferenceParams, Uri};

use crate::analyzer::usages::UsageHit;
use crate::analyzer::{Project, Range as ByteRange, WorkspaceAnalyzer};
use crate::lsp::conversion::{byte_range_to_lsp_range, path_to_uri_string};
use crate::lsp::handlers::broad_symbol::broad_symbol_target_at_position;
use crate::lsp::handlers::usage_hits::usage_hits_for_candidates_with_cancellation;
use crate::lsp::handlers::util::{FileContentCache, code_unit_location_from_content};
use crate::lsp::request_context::{RequestCancelled, RequestContext};

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
    context: &RequestContext,
) -> Result<Option<Vec<Location>>, RequestCancelled> {
    context.check_cancelled()?;
    let uri = &params.text_document_position.text_document.uri;
    let analyzer = workspace.analyzer();
    let Some(target) = broad_symbol_target_at_position(
        analyzer,
        project,
        uri,
        &params.text_document_position.position,
    ) else {
        return Ok(None);
    };
    context.check_cancelled()?;
    context.report("Searching workspace");

    let mut content_cache = FileContentCache::default();
    let hits = usage_hits_for_candidates_with_cancellation(
        analyzer,
        &target.candidates,
        context.cancellation_token(),
    );
    context.check_cancelled()?;
    context.report("Preparing locations");
    let mut locations = usage_hits_to_locations(project, hits, &mut content_cache, context)?;

    if params.context.include_declaration {
        for cu in &target.candidates {
            context.check_cancelled()?;
            let entry = content_cache.read_project(project, cu.source());
            locations.extend(entry.and_then(|entry| {
                code_unit_location_from_content(
                    analyzer,
                    cu.source(),
                    &entry.body,
                    &entry.line_starts,
                    cu,
                )
            }));
        }
    }

    context.check_cancelled()?;
    locations.sort_by(|a, b| {
        a.uri
            .as_str()
            .cmp(b.uri.as_str())
            .then_with(|| a.range.start.line.cmp(&b.range.start.line))
            .then_with(|| a.range.start.character.cmp(&b.range.start.character))
    });
    locations.dedup_by(|a, b| a.uri.as_str() == b.uri.as_str() && a.range == b.range);
    context.check_cancelled()?;

    Ok(Some(locations))
}

fn usage_hits_to_locations(
    project: &dyn Project,
    hits: impl IntoIterator<Item = UsageHit>,
    cache: &mut FileContentCache,
    context: &RequestContext,
) -> Result<Vec<Location>, RequestCancelled> {
    let mut locations = Vec::new();
    for hit in hits {
        context.check_cancelled()?;
        if let Some(location) = usage_hit_to_location(project, &hit, cache) {
            locations.push(location);
        }
    }
    Ok(locations)
}

fn usage_hit_to_location(
    project: &dyn Project,
    hit: &UsageHit,
    cache: &mut FileContentCache,
) -> Option<Location> {
    let abs_path = hit.file.abs_path();
    let entry = cache.read_project(project, &hit.file)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::{CodeUnit, CodeUnitType, FileSetProject, ProjectFile};
    use crate::cancellation::CancellationToken;
    use std::path::PathBuf;
    use std::sync::Arc;

    #[test]
    fn pre_cancelled_mapping_discards_analyzer_hits() {
        let root = std::env::temp_dir();
        let file = ProjectFile::new(root.clone(), PathBuf::from("Target.java"));
        let enclosing = CodeUnit::new(file.clone(), CodeUnitType::Function, "pkg", "Target.call");
        let hit = UsageHit::new(file, 0, 0, 6, enclosing, 1.0, "Target");
        let project = FileSetProject::new(root, [PathBuf::from("Target.java")]);
        let cancellation = CancellationToken::default();
        cancellation.cancel();
        let context = RequestContext::new(
            cancellation,
            None,
            "Finding references",
            "Resolving symbol",
            Arc::new(|_| Ok(())),
        );

        let result =
            usage_hits_to_locations(&project, [hit], &mut FileContentCache::default(), &context);

        assert_eq!(result, Err(RequestCancelled));
    }
}
