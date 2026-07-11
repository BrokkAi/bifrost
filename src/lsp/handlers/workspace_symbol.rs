use lsp_types::{
    Location, OneOf, SymbolKind, Uri, WorkspaceSymbol, WorkspaceSymbolParams,
    WorkspaceSymbolResponse,
};

use crate::analyzer::common::display_identifier_for_target;
use crate::analyzer::{CodeUnit, CodeUnitType, IAnalyzer, Range as ByteRange, WorkspaceAnalyzer};
use crate::lsp::conversion::{byte_range_to_lsp_range, path_to_uri_string};
use crate::lsp::handlers::util::FileContentCache;

/// Soft cap: workspace/symbol queries can match thousands of definitions in
/// a large repo, but most editors only display the top results.
const MAX_RESULTS: usize = 500;

pub fn handle(
    workspace: &WorkspaceAnalyzer,
    params: &WorkspaceSymbolParams,
) -> Option<WorkspaceSymbolResponse> {
    let analyzer = workspace.analyzer();
    let mut matches = if params.query.is_empty() {
        // LSP says an empty query may return "all symbols". Cap to avoid
        // shipping the whole index over the wire.
        analyzer.get_all_declarations()
    } else if analyzer.is_empty() {
        analyzer
            .search_definitions(&params.query, true)
            .into_iter()
            .collect()
    } else {
        analyzer.autocomplete_definitions(&params.query)
    };
    matches.retain(|code_unit| !code_unit.is_anonymous() && !code_unit.is_synthetic());
    matches.truncate(MAX_RESULTS);

    let mut content_cache = FileContentCache::default();
    let mut results = Vec::with_capacity(matches.len());
    for code_unit in matches {
        if let Some(symbol) = build_symbol(analyzer, &code_unit, &mut content_cache) {
            results.push(symbol);
        }
    }

    Some(WorkspaceSymbolResponse::Nested(results))
}

fn build_symbol(
    analyzer: &dyn IAnalyzer,
    code_unit: &CodeUnit,
    cache: &mut FileContentCache,
) -> Option<WorkspaceSymbol> {
    let abs_path = code_unit.source().abs_path();
    let entry = cache.read_disk_or_empty(&abs_path);

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

    let location = Location {
        uri,
        range: lsp_range,
    };

    Some(WorkspaceSymbol {
        name: display_identifier_for_target(code_unit),
        kind: map_kind(code_unit.kind()),
        tags: None,
        container_name: container_name(code_unit),
        location: OneOf::Left(location),
        data: None,
    })
}

fn container_name(code_unit: &CodeUnit) -> Option<String> {
    let pkg = code_unit.package_name();
    if pkg.is_empty() {
        None
    } else {
        Some(pkg.to_string())
    }
}

fn map_kind(kind: CodeUnitType) -> SymbolKind {
    match kind {
        CodeUnitType::Class => SymbolKind::CLASS,
        CodeUnitType::Function => SymbolKind::FUNCTION,
        CodeUnitType::Field => SymbolKind::FIELD,
        CodeUnitType::Module => SymbolKind::MODULE,
        CodeUnitType::Macro => SymbolKind::CONSTANT,
        CodeUnitType::FileScope => SymbolKind::FILE,
    }
}
