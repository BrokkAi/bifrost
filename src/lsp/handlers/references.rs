use std::collections::HashMap;
use std::path::{Path, PathBuf};

use lsp_types::{Location, ReferenceParams, Uri};

use crate::analyzer::{
    CodeUnit, IAnalyzer, Range as ByteRange, WorkspaceAnalyzer,
};
use crate::lsp::conversion::{
    byte_range_to_lsp_range, path_to_uri_string, position_to_byte_offset,
};
use crate::lsp::handlers::util::{identifier_at_offset, project_file_for_uri};
use crate::text_utils::compute_line_starts;
use crate::usages::{DEFAULT_MAX_FILES, DEFAULT_MAX_USAGES, FuzzyResult, UsageFinder, UsageHit};

/// Resolve `textDocument/references`. Strategy:
/// 1. Identifier under cursor -> resolve all matching CodeUnits (overloads).
/// 2. Run UsageFinder over the workspace.
/// 3. Map each UsageHit to an LSP Location.
/// 4. Optionally include the declaration site itself when
///    `params.context.include_declaration` is true.
pub fn handle(
    workspace: &WorkspaceAnalyzer,
    project_root: &Path,
    params: &ReferenceParams,
) -> Option<Vec<Location>> {
    let uri = &params.text_document_position.text_document.uri;
    let project_file = project_file_for_uri(project_root, uri)?;

    let content = project_file.read_to_string().ok()?;
    let line_starts = compute_line_starts(&content);
    let byte_offset = position_to_byte_offset(
        &content,
        &line_starts,
        &params.text_document_position.position,
    );
    let identifier = identifier_at_offset(&content, byte_offset)?;

    let analyzer = workspace.analyzer();
    let overloads = resolve_overloads(analyzer, identifier);
    if overloads.is_empty() {
        return None;
    }

    let result = UsageFinder::new().find_usages(
        analyzer,
        &overloads,
        DEFAULT_MAX_FILES,
        DEFAULT_MAX_USAGES,
    );
    let hits = collect_hits(result);

    let mut content_cache: HashMap<PathBuf, FileContent> = HashMap::new();
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

fn resolve_overloads(analyzer: &dyn IAnalyzer, identifier: &str) -> Vec<CodeUnit> {
    let mut out = analyzer.get_definitions(identifier);
    if !out.is_empty() {
        return out;
    }
    let pattern = format!(r"^{}$", regex::escape(identifier));
    out.extend(
        analyzer
            .search_definitions(&pattern, false)
            .into_iter()
            .filter(|cu| cu.identifier() == identifier),
    );
    out
}

fn collect_hits(result: FuzzyResult) -> Vec<UsageHit> {
    result.all_hits().into_iter().collect()
}

struct FileContent {
    body: String,
    line_starts: Vec<usize>,
}

fn ensure_cached<'a>(
    cache: &'a mut HashMap<PathBuf, FileContent>,
    abs_path: &Path,
) -> Option<&'a FileContent> {
    if !cache.contains_key(abs_path) {
        let body = std::fs::read_to_string(abs_path).ok()?;
        let line_starts = compute_line_starts(&body);
        cache.insert(abs_path.to_path_buf(), FileContent { body, line_starts });
    }
    cache.get(abs_path)
}

fn usage_hit_to_location(
    hit: &UsageHit,
    cache: &mut HashMap<PathBuf, FileContent>,
) -> Option<Location> {
    let abs_path = hit.file.abs_path();
    let entry = ensure_cached(cache, &abs_path)?;
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
    cache: &mut HashMap<PathBuf, FileContent>,
) -> Option<Location> {
    let abs_path = code_unit.source().abs_path();
    let entry = ensure_cached(cache, &abs_path)?;
    let range = analyzer.ranges(code_unit).iter().min().copied().unwrap_or(ByteRange {
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
