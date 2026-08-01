use lsp_types::{
    Position, Range, SymbolKind, TypeHierarchyItem, TypeHierarchyPrepareParams,
    TypeHierarchySubtypesParams, TypeHierarchySupertypesParams, Uri,
};

use crate::analyzer::{AnalyzerQueryScope, CodeUnit, IAnalyzer, Project, WorkspaceAnalyzer};
use crate::lsp::conversion::{byte_range_to_lsp_range, path_to_uri_string};
use crate::lsp::handlers::document_symbol::lsp_symbol_parts;
use crate::lsp::handlers::hierarchy_support::{
    hierarchy_item_data, resolve_hierarchy_item_code_unit,
};
use crate::lsp::handlers::type_target::{TypeTargetEligibility, resolve_type_target};
use crate::text_utils::compute_line_starts;

pub fn prepare(
    workspace: &WorkspaceAnalyzer,
    project: &dyn Project,
    params: &TypeHierarchyPrepareParams,
) -> Option<Vec<TypeHierarchyItem>> {
    let analyzer = workspace.analyzer();
    let _query_scope = AnalyzerQueryScope::new(analyzer);
    let uri = &params.text_document_position_params.text_document.uri;
    if uri.as_str().starts_with("bifrost-model://")
        && let Some(overlay) = analyzer.semantic_model_overlay()
    {
        let matched = overlay.symbols_at_uri(uri.as_str());
        if matched.disposition
            == crate::analyzer::semantic_model::SemanticModelOverlayDisposition::Unique
        {
            return Some(vec![model_type_hierarchy_item(
                analyzer,
                matched.records[0],
            )?]);
        }
    }
    let provider = analyzer.type_hierarchy_provider()?;
    let target = resolve_type_target(
        workspace,
        project,
        uri,
        &params.text_document_position_params.position,
        TypeTargetEligibility::TypeHierarchy,
    )?;
    let type_unit = target.units.into_iter().next()?;
    if !provider.supports_type_hierarchy(&type_unit) {
        return None;
    }

    Some(vec![type_hierarchy_item(analyzer, project, &type_unit)?])
}

pub fn supertypes(
    workspace: &WorkspaceAnalyzer,
    project: &dyn Project,
    params: &TypeHierarchySupertypesParams,
) -> Option<Vec<TypeHierarchyItem>> {
    let analyzer = workspace.analyzer();
    let _query_scope = AnalyzerQueryScope::new(analyzer);
    if let Some(items) = model_hierarchy_items(analyzer, &params.item, true) {
        return Some(items);
    }
    let provider = analyzer.type_hierarchy_provider()?;
    let code_unit = resolve_item_code_unit(analyzer, project, &params.item)?;
    if !provider.supports_type_hierarchy(&code_unit) {
        return None;
    }
    let mut items = hierarchy_items(
        analyzer,
        project,
        provider.get_direct_ancestors(&code_unit).into_iter(),
    )?;
    append_source_model_hierarchy(analyzer, &code_unit, true, &mut items);
    Some(items)
}

pub fn subtypes(
    workspace: &WorkspaceAnalyzer,
    project: &dyn Project,
    params: &TypeHierarchySubtypesParams,
) -> Option<Vec<TypeHierarchyItem>> {
    let analyzer = workspace.analyzer();
    let _query_scope = AnalyzerQueryScope::new(analyzer);
    if let Some(items) = model_hierarchy_items(analyzer, &params.item, false) {
        return Some(items);
    }
    let provider = analyzer.type_hierarchy_provider()?;
    let code_unit = resolve_item_code_unit(analyzer, project, &params.item)?;
    if !provider.supports_type_hierarchy(&code_unit) {
        return None;
    }
    let mut items = hierarchy_items(
        analyzer,
        project,
        provider.get_direct_descendants(&code_unit).into_iter(),
    )?;
    append_source_model_hierarchy(analyzer, &code_unit, false, &mut items);
    Some(items)
}

fn hierarchy_items(
    analyzer: &dyn IAnalyzer,
    project: &dyn Project,
    code_units: impl Iterator<Item = CodeUnit>,
) -> Option<Vec<TypeHierarchyItem>> {
    Some(
        code_units
            .filter_map(|code_unit| type_hierarchy_item(analyzer, project, &code_unit))
            .collect(),
    )
}

fn type_hierarchy_item(
    analyzer: &dyn IAnalyzer,
    project: &dyn Project,
    code_unit: &CodeUnit,
) -> Option<TypeHierarchyItem> {
    let content = project.read_source(code_unit.source()).ok()?;
    let line_starts = compute_line_starts(&content);
    let parts = lsp_symbol_parts(analyzer, code_unit, &content, &line_starts, None);
    let uri: Uri = path_to_uri_string(&code_unit.source().abs_path())
        .parse()
        .ok()?;

    Some(TypeHierarchyItem {
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
    item: &TypeHierarchyItem,
) -> Option<CodeUnit> {
    resolve_hierarchy_item_code_unit(analyzer, project, item.data.as_ref(), &item.uri, |unit| {
        unit.is_class()
    })
}

fn append_source_model_hierarchy(
    analyzer: &dyn IAnalyzer,
    code_unit: &CodeUnit,
    supertypes: bool,
    items: &mut Vec<TypeHierarchyItem>,
) {
    let Some(overlay) = analyzer.semantic_model_overlay() else {
        return;
    };
    let matched = overlay.symbols_named(&code_unit.fq_name());
    if matched.disposition
        != crate::analyzer::semantic_model::SemanticModelOverlayDisposition::Unique
    {
        return;
    }
    append_model_relation_items(analyzer, &overlay, matched.records[0], supertypes, items);
}

fn model_hierarchy_items(
    analyzer: &dyn IAnalyzer,
    item: &TypeHierarchyItem,
    supertypes: bool,
) -> Option<Vec<TypeHierarchyItem>> {
    let overlay = analyzer.semantic_model_overlay()?;
    let id = item
        .data
        .as_ref()
        .and_then(|data| data.get("semanticModelId"))
        .and_then(serde_json::Value::as_str);
    let matched = if let Some(id) = id {
        let active_hash = item
            .data
            .as_ref()
            .and_then(|data| data.get("activeModelSetHash"))
            .and_then(serde_json::Value::as_str);
        if active_hash != Some(overlay.active_model_set_hash()) {
            return Some(Vec::new());
        }
        overlay.symbols_with_id(id)
    } else {
        overlay.symbols_at_uri(item.uri.as_str())
    };
    if matched.records.is_empty() {
        return None;
    }
    if matched.disposition
        != crate::analyzer::semantic_model::SemanticModelOverlayDisposition::Unique
    {
        return Some(Vec::new());
    }
    if model_symbol_uri(analyzer, matched.records[0]).as_ref() != Some(&item.uri) {
        return Some(Vec::new());
    }
    let mut items = Vec::new();
    append_model_relation_items(
        analyzer,
        &overlay,
        matched.records[0],
        supertypes,
        &mut items,
    );
    Some(items)
}

fn append_model_relation_items(
    analyzer: &dyn IAnalyzer,
    overlay: &crate::analyzer::semantic_model::SemanticModelOverlay,
    symbol: &crate::analyzer::semantic_model::SemanticModelSymbol,
    supertypes: bool,
    items: &mut Vec<TypeHierarchyItem>,
) {
    let relations = if supertypes {
        overlay.relations_from(&symbol.id)
    } else {
        overlay.relations_to(&symbol.id)
    };
    for relation in relations.records {
        if relation.provenance.ambiguous {
            continue;
        }
        if !matches!(
            relation.kind.as_str(),
            "extends" | "implements" | "usestrait" | "uses_trait"
        ) {
            continue;
        }
        let endpoint = if supertypes {
            &relation.to
        } else {
            &relation.from
        };
        let mut matched = overlay.symbols_with_id(endpoint);
        if matched.records.is_empty() {
            matched = overlay.symbols_named(endpoint);
        }
        if matched.disposition
            == crate::analyzer::semantic_model::SemanticModelOverlayDisposition::Unique
            && let Some(item) = model_type_hierarchy_item(analyzer, matched.records[0])
            && !items
                .iter()
                .any(|existing| existing.uri == item.uri && existing.name == item.name)
        {
            items.push(item);
        }
    }
}

fn model_type_hierarchy_item(
    analyzer: &dyn IAnalyzer,
    symbol: &crate::analyzer::semantic_model::SemanticModelSymbol,
) -> Option<TypeHierarchyItem> {
    let uri = model_symbol_uri(analyzer, symbol)?;
    let range = match &symbol.location {
        crate::analyzer::semantic_model::SemanticModelLocation::Authored(anchor) => {
            let file = analyzer
                .project()
                .file_by_rel_path(std::path::Path::new(&anchor.path))?;
            let content = analyzer.project().read_source(&file).ok()?;
            let line_starts = compute_line_starts(&content);
            let byte_range = crate::analyzer::Range {
                start_byte: anchor.range.start_byte,
                end_byte: anchor.range.end_byte,
                start_line: anchor.range.start_line,
                end_line: anchor.range.end_line,
            };
            byte_range_to_lsp_range(&content, &line_starts, &byte_range)
        }
        crate::analyzer::semantic_model::SemanticModelLocation::Model(location) => Range {
            start: Position {
                line: u32::try_from(location.range.start_line.saturating_sub(1))
                    .unwrap_or(u32::MAX),
                character: 0,
            },
            end: Position {
                line: u32::try_from(location.range.end_line.saturating_sub(1)).unwrap_or(u32::MAX),
                character: 0,
            },
        },
    };
    Some(TypeHierarchyItem {
        name: symbol.name.clone(),
        kind: model_symbol_kind(symbol.kind),
        tags: None,
        detail: Some(format!(
            "modeled by {}@{} ({:?})",
            symbol.provenance.pack_id, symbol.provenance.pack_version, symbol.provenance.origin
        )),
        uri,
        range,
        selection_range: range,
        data: Some(serde_json::json!({
            "semanticModelId": symbol.id,
            "activeModelSetHash": symbol.provenance.active_model_set_hash,
            "provenance": symbol.provenance,
        })),
    })
}

fn model_symbol_uri(
    analyzer: &dyn IAnalyzer,
    symbol: &crate::analyzer::semantic_model::SemanticModelSymbol,
) -> Option<Uri> {
    match &symbol.location {
        crate::analyzer::semantic_model::SemanticModelLocation::Authored(anchor) => {
            path_to_uri_string(&analyzer.project().root().join(&anchor.path))
                .parse()
                .ok()
        }
        crate::analyzer::semantic_model::SemanticModelLocation::Model(location) => {
            location.uri.parse().ok()
        }
    }
}

fn model_symbol_kind(kind: crate::analyzer::semantic_model::SemanticModelSymbolKind) -> SymbolKind {
    use crate::analyzer::semantic_model::SemanticModelSymbolKind as ModelKind;
    match kind {
        ModelKind::Class | ModelKind::Record => SymbolKind::CLASS,
        ModelKind::Annotation | ModelKind::Interface | ModelKind::Trait => SymbolKind::INTERFACE,
        ModelKind::Delegate | ModelKind::Function => SymbolKind::FUNCTION,
        ModelKind::Struct => SymbolKind::STRUCT,
        ModelKind::Enum => SymbolKind::ENUM,
        ModelKind::Module => SymbolKind::MODULE,
        ModelKind::TypeAlias => SymbolKind::TYPE_PARAMETER,
        ModelKind::Constructor => SymbolKind::CONSTRUCTOR,
        ModelKind::Method => SymbolKind::METHOD,
        ModelKind::Field => SymbolKind::FIELD,
        ModelKind::Property => SymbolKind::PROPERTY,
        ModelKind::Constant => SymbolKind::CONSTANT,
        ModelKind::Event => SymbolKind::EVENT,
    }
}
