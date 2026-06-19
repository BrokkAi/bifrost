use lsp_types::{
    TypeHierarchyItem, TypeHierarchyPrepareParams, TypeHierarchySubtypesParams,
    TypeHierarchySupertypesParams, Uri,
};
use serde_json::json;

use crate::analyzer::{CodeUnit, IAnalyzer, Project, Range as ByteRange, WorkspaceAnalyzer};
use crate::lsp::conversion::{path_to_uri_string, position_to_byte_offset};
use crate::lsp::handlers::document_symbol::lsp_symbol_parts;
use crate::lsp::handlers::util::{project_file_for_uri, read_document_for_uri};
use crate::text_utils::compute_line_starts;

pub fn prepare(
    workspace: &WorkspaceAnalyzer,
    project: &dyn Project,
    params: &TypeHierarchyPrepareParams,
) -> Option<Vec<TypeHierarchyItem>> {
    let analyzer = workspace.analyzer();
    let provider = analyzer.type_hierarchy_provider()?;
    let uri = &params.text_document_position_params.text_document.uri;
    let (file, content, line_starts) = read_document_for_uri(project, uri)?;
    let offset = position_to_byte_offset(
        &content,
        &line_starts,
        &params.text_document_position_params.position,
    );
    let range = cursor_byte_range(&content, offset);
    let enclosing = analyzer.enclosing_code_unit(&file, &range)?;
    let type_unit = nearest_type_unit(analyzer, enclosing)?;
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
    let provider = analyzer.type_hierarchy_provider()?;
    let code_unit = resolve_item_code_unit(analyzer, project, &params.item)?;
    if !provider.supports_type_hierarchy(&code_unit) {
        return None;
    }
    hierarchy_items(
        analyzer,
        project,
        provider.get_direct_ancestors(&code_unit).into_iter(),
    )
}

pub fn subtypes(
    workspace: &WorkspaceAnalyzer,
    project: &dyn Project,
    params: &TypeHierarchySubtypesParams,
) -> Option<Vec<TypeHierarchyItem>> {
    let analyzer = workspace.analyzer();
    let provider = analyzer.type_hierarchy_provider()?;
    let code_unit = resolve_item_code_unit(analyzer, project, &params.item)?;
    if !provider.supports_type_hierarchy(&code_unit) {
        return None;
    }
    hierarchy_items(
        analyzer,
        project,
        provider.get_direct_descendants(&code_unit).into_iter(),
    )
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

fn nearest_type_unit(analyzer: &dyn IAnalyzer, mut code_unit: CodeUnit) -> Option<CodeUnit> {
    loop {
        if code_unit.is_class() {
            return Some(code_unit);
        }
        code_unit = analyzer.parent_of(&code_unit)?;
    }
}

fn cursor_byte_range(content: &str, offset: usize) -> ByteRange {
    let start = offset.min(content.len());
    let end = if start < content.len() {
        start
            + content[start..]
                .chars()
                .next()
                .map(char::len_utf8)
                .unwrap_or(0)
    } else {
        start
    };
    ByteRange {
        start_byte: start,
        end_byte: end,
        start_line: 0,
        end_line: 0,
    }
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
        data: Some(json!({
            "fqName": code_unit.fq_name(),
            "uri": uri.as_str(),
        })),
    })
}

fn resolve_item_code_unit(
    analyzer: &dyn IAnalyzer,
    project: &dyn Project,
    item: &TypeHierarchyItem,
) -> Option<CodeUnit> {
    let data = item.data.as_ref()?;
    let fq_name = data.get("fqName")?.as_str()?;
    let uri = data
        .get("uri")
        .and_then(|value| value.as_str())
        .unwrap_or_else(|| item.uri.as_str());
    let uri: Uri = uri.parse().ok()?;
    let file = project_file_for_uri(project.root(), &uri)?;

    analyzer
        .declarations(&file)
        .find(|candidate| candidate.fq_name() == fq_name)
        .cloned()
        .or_else(|| {
            analyzer
                .definitions(fq_name)
                .find(|candidate| candidate.source() == &file)
                .cloned()
        })
}
