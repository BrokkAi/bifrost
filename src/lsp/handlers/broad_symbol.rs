use std::sync::Arc;

use lsp_types::{Position, Uri};
use tree_sitter::Node;

use crate::analyzer::common::language_for_file;
use crate::analyzer::usages::get_definition::{
    DefinitionLookupRequest, DefinitionLookupStatus, parse_tree_for_language,
    resolve_definition_batch_with_source,
};
use crate::analyzer::{CodeUnit, IAnalyzer, Project, ProjectFile, Range as ByteRange};
use crate::lsp::conversion::position_to_byte_offset;
use crate::lsp::handlers::import_ambiguity::is_ambiguous_imported_reference;
use crate::lsp::handlers::util::{identifier_span_at_offset, read_document_for_uri};

pub(super) struct BroadSymbolTarget {
    pub(super) file: ProjectFile,
    pub(super) content: String,
    pub(super) line_starts: Vec<usize>,
    pub(super) start_byte: usize,
    pub(super) end_byte: usize,
    pub(super) candidates: Vec<CodeUnit>,
}

pub(super) fn broad_symbol_target_at_position(
    analyzer: &dyn IAnalyzer,
    project: &dyn Project,
    uri: &Uri,
    position: &Position,
) -> Option<BroadSymbolTarget> {
    let (file, content, line_starts) = read_document_for_uri(project, uri)?;
    let byte_offset = position_to_byte_offset(&content, &line_starts, position);
    let (start_byte, end_byte) = identifier_span_at_offset(&content, byte_offset)?;
    let selected = ByteRange {
        start_byte,
        end_byte,
        start_line: 0,
        end_line: 0,
    };
    let candidates =
        selected_code_unit_declaration_at_cursor(analyzer, &file, &content, &selected, |_| true)
            .map(|declaration| vec![declaration])
            .or_else(|| {
                let identifier = content.get(start_byte..end_byte)?;
                if is_ambiguous_imported_reference(analyzer, &file, identifier) {
                    return None;
                }
                resolved_reference_candidates(
                    analyzer,
                    &file,
                    Arc::new(content.clone()),
                    start_byte,
                    end_byte,
                )
            })?;

    Some(BroadSymbolTarget {
        file,
        content,
        line_starts,
        start_byte,
        end_byte,
        candidates,
    })
}

pub(super) fn selected_code_unit_declaration_at_cursor(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    content: &str,
    cursor_range: &ByteRange,
    predicate: impl Fn(&CodeUnit) -> bool,
) -> Option<CodeUnit> {
    let code_unit = analyzer.enclosing_code_unit(file, cursor_range)?;
    if code_unit.source() != file || !predicate(&code_unit) {
        return None;
    }
    let selection = code_unit_declaration_name_range(analyzer, file, content, &code_unit)?;
    (cursor_range.start_byte >= selection.start_byte
        && cursor_range.start_byte < selection.end_byte)
        .then_some(code_unit)
}

pub(super) fn code_unit_declaration_name_range(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    content: &str,
    code_unit: &CodeUnit,
) -> Option<ByteRange> {
    let declaration_range = analyzer.ranges(code_unit).iter().min().copied()?;
    let language = language_for_file(file);
    let tree = parse_tree_for_language(file, language, content)?;
    let declaration_node = node_for_exact_range(tree.root_node(), &declaration_range)?;
    let name_node = declaration_name_node(declaration_node, code_unit.identifier(), content)?;
    Some(node_byte_range(name_node))
}

fn node_for_exact_range<'tree>(root: Node<'tree>, range: &ByteRange) -> Option<Node<'tree>> {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.start_byte() == range.start_byte && node.end_byte() == range.end_byte {
            return Some(node);
        }
        if node.start_byte() > range.start_byte || node.end_byte() < range.end_byte {
            continue;
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if child.start_byte() <= range.start_byte && child.end_byte() >= range.end_byte {
                stack.push(child);
            }
        }
    }
    None
}

fn declaration_name_node<'tree>(
    declaration_node: Node<'tree>,
    identifier: &str,
    content: &str,
) -> Option<Node<'tree>> {
    let mut stack = vec![declaration_node];
    while let Some(node) = stack.pop() {
        if let Some(name) = node.child_by_field_name("name")
            && let Some(identifier_node) = matching_identifier_node(name, identifier, content)
        {
            return Some(identifier_node);
        }
        for field in ["declarator", "declaration", "definition"] {
            if let Some(child) = node.child_by_field_name(field) {
                stack.push(child);
            }
        }
    }
    None
}

fn matching_identifier_node<'tree>(
    root: Node<'tree>,
    identifier: &str,
    content: &str,
) -> Option<Node<'tree>> {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.utf8_text(content.as_bytes()).ok()? == identifier {
            return Some(node);
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            stack.push(child);
        }
    }
    None
}

fn node_byte_range(node: Node<'_>) -> ByteRange {
    ByteRange {
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        start_line: node.start_position().row,
        end_line: node.end_position().row,
    }
}

fn resolved_reference_candidates(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    content: Arc<String>,
    start_byte: usize,
    end_byte: usize,
) -> Option<Vec<CodeUnit>> {
    let outcome = resolve_definition_batch_with_source(
        analyzer,
        vec![DefinitionLookupRequest {
            file: file.clone(),
            line: None,
            column: None,
            start_byte: Some(start_byte),
            end_byte: Some(end_byte),
        }],
        file.clone(),
        content,
    )
    .into_iter()
    .next()?;
    if outcome.status != DefinitionLookupStatus::Resolved || outcome.definitions.is_empty() {
        return None;
    }
    Some(outcome.definitions)
}
