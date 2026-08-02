use lsp_types::{
    Location, OneOf, Position, Range, SymbolKind, Uri, WorkspaceSymbol, WorkspaceSymbolParams,
    WorkspaceSymbolResponse,
};

use crate::analyzer::common::display_identifier_for_target;
use crate::analyzer::{
    CodeUnit, CodeUnitType, IAnalyzer, Range as ByteRange, SearchSymbolPatternBatch,
    WorkspaceAnalyzer,
};
use crate::hash::HashSet;
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
    let mut authored_names = HashSet::default();
    for code_unit in matches {
        if let Some(symbol) = build_symbol(analyzer, &code_unit, &mut content_cache) {
            authored_names.insert(code_unit.fq_name());
            results.push(symbol);
        }
    }
    if let Some(overlay) = analyzer.semantic_model_overlay() {
        let patterns = SearchSymbolPatternBatch::compile(vec![params.query.clone()], true, None);
        let (modeled, _, _) =
            overlay.search_with_limit(&patterns, MAX_RESULTS.saturating_sub(results.len()), None);
        for symbol in modeled
            .into_iter()
            .filter(|symbol| !authored_names.contains(&symbol.qualified_name))
        {
            if let Some(symbol) = build_model_symbol(analyzer, symbol, &mut content_cache) {
                results.push(symbol);
            }
        }
    }

    Some(WorkspaceSymbolResponse::Nested(results))
}

fn build_model_symbol(
    analyzer: &dyn IAnalyzer,
    symbol: &crate::analyzer::semantic_model::SemanticModelSymbol,
    cache: &mut FileContentCache,
) -> Option<WorkspaceSymbol> {
    let (uri, range): (Uri, Range) = match &symbol.location {
        crate::analyzer::semantic_model::SemanticModelLocation::Authored(anchor) => {
            let path = analyzer.project().root().join(&anchor.path);
            let uri = path_to_uri_string(&path).parse().ok()?;
            let source = cache.read_disk_or_empty(&path);
            let byte_range = ByteRange {
                start_byte: anchor.range.start_byte,
                end_byte: anchor.range.end_byte,
                start_line: anchor.range.start_line,
                end_line: anchor.range.end_line,
            };
            (
                uri,
                byte_range_to_lsp_range(&source.body, &source.line_starts, &byte_range),
            )
        }
        crate::analyzer::semantic_model::SemanticModelLocation::Model(location) => (
            location.uri.parse().ok()?,
            Range {
                start: Position {
                    line: u32::try_from(location.range.start_line.saturating_sub(1))
                        .unwrap_or(u32::MAX),
                    character: 0,
                },
                end: Position {
                    line: u32::try_from(location.range.end_line.saturating_sub(1))
                        .unwrap_or(u32::MAX),
                    character: 0,
                },
            },
        ),
    };
    Some(WorkspaceSymbol {
        name: symbol.name.clone(),
        kind: map_model_kind(symbol.kind),
        tags: None,
        container_name: symbol
            .qualified_name
            .strip_suffix(&format!(".{}", symbol.name))
            .map(str::to_string),
        location: OneOf::Left(Location { uri, range }),
        data: serde_json::to_value(symbol).ok(),
    })
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
        data: analyzer.semantic_model_overlay().and_then(|overlay| {
            let modeled = overlay.symbols_named(&code_unit.fq_name());
            (modeled.disposition
                == crate::analyzer::semantic_model::SemanticModelOverlayDisposition::Unique)
                .then(|| serde_json::to_value(modeled.records[0]).ok())
                .flatten()
        }),
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

fn map_model_kind(kind: crate::analyzer::semantic_model::SemanticModelSymbolKind) -> SymbolKind {
    use crate::analyzer::semantic_model::SemanticModelSymbolKind as ModelKind;
    match kind {
        ModelKind::Class | ModelKind::Record => SymbolKind::CLASS,
        ModelKind::Annotation | ModelKind::Interface | ModelKind::Trait => SymbolKind::INTERFACE,
        ModelKind::Delegate => SymbolKind::FUNCTION,
        ModelKind::Struct | ModelKind::Union => SymbolKind::STRUCT,
        ModelKind::Enum => SymbolKind::ENUM,
        ModelKind::Module => SymbolKind::MODULE,
        ModelKind::TypeAlias => SymbolKind::TYPE_PARAMETER,
        ModelKind::Constructor => SymbolKind::CONSTRUCTOR,
        ModelKind::Method => SymbolKind::METHOD,
        ModelKind::Function => SymbolKind::FUNCTION,
        ModelKind::Field => SymbolKind::FIELD,
        ModelKind::Property => SymbolKind::PROPERTY,
        ModelKind::Constant => SymbolKind::CONSTANT,
        ModelKind::Static => SymbolKind::VARIABLE,
        ModelKind::Macro => SymbolKind::CONSTANT,
        ModelKind::Event => SymbolKind::EVENT,
    }
}
