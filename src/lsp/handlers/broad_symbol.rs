use std::sync::Arc;

use lsp_types::{Position, Uri};

use crate::analyzer::declaration_range::code_unit_declaration_name_range;
use crate::analyzer::lexical_definitions::LexicalDefinition;
use crate::analyzer::usages::get_definition::{
    DefinitionLookupRequest, DefinitionLookupStatus, navigation_declaration_site_target,
    resolve_definition_batch_with_source, resolve_navigation_batch_with_source,
};
use crate::analyzer::{CodeUnit, IAnalyzer, Project, ProjectFile, Range as ByteRange};
use crate::lsp::conversion::position_to_byte_offset;
use crate::lsp::handlers::import_ambiguity::is_ambiguous_imported_reference;
use crate::lsp::handlers::util::{identifier_span_at_offset, read_document_for_uri};
use crate::navigation::NavigationOperation;

pub(super) struct BroadSymbolTarget {
    pub(super) file: ProjectFile,
    pub(super) content: String,
    pub(super) line_starts: Vec<usize>,
    pub(super) start_byte: usize,
    pub(super) end_byte: usize,
    pub(super) declaration_site: bool,
    pub(super) candidates: Vec<CodeUnit>,
    pub(super) lexical_definition: Option<LexicalDefinition>,
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
    let declaration =
        selected_code_unit_declaration_at_cursor(analyzer, &file, &content, &selected, |_| true);
    let declaration_site = declaration.is_some();
    let (candidates, lexical_definition) = declaration
        .map(|declaration| (vec![declaration], None))
        .or_else(|| {
            let identifier = content.get(start_byte..end_byte)?;
            if is_ambiguous_imported_reference(analyzer, &file, identifier) {
                return None;
            }
            resolved_reference_target(
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
        declaration_site,
        candidates,
        lexical_definition,
    })
}

pub(super) fn navigation_target_at_position(
    analyzer: &dyn IAnalyzer,
    project: &dyn Project,
    uri: &Uri,
    position: &Position,
    operation: NavigationOperation,
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
    let identifier = content.get(start_byte..end_byte)?;
    if is_ambiguous_imported_reference(analyzer, &file, identifier) {
        return None;
    }
    let resolved = resolved_navigation_target(
        analyzer,
        &file,
        Arc::new(content.clone()),
        start_byte,
        end_byte,
        operation,
    );
    let declaration =
        selected_code_unit_declaration_at_cursor(analyzer, &file, &content, &selected, |_| true);
    let (candidates, lexical_definition, declaration_site) = match resolved {
        Some((candidates, lexical_definition)) => (candidates, lexical_definition, false),
        None => (
            vec![navigation_declaration_site_target(
                analyzer,
                declaration?,
                operation,
            )?],
            None,
            true,
        ),
    };

    Some(BroadSymbolTarget {
        file,
        content,
        line_starts,
        start_byte,
        end_byte,
        declaration_site,
        candidates,
        lexical_definition,
    })
}

pub(super) fn selected_code_unit_declaration_at_cursor(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    content: &str,
    cursor_range: &ByteRange,
    predicate: impl Fn(&CodeUnit) -> bool,
) -> Option<CodeUnit> {
    if let Some(code_unit) = analyzer.enclosing_code_unit(file, cursor_range)
        && code_unit.source() == file
        && predicate(&code_unit)
        && let Some(selection) =
            code_unit_declaration_name_range(analyzer, file, content, &code_unit)
        && cursor_range.start_byte >= selection.start_byte
        && cursor_range.start_byte < selection.end_byte
    {
        return Some(code_unit);
    }

    analyzer
        .declarations(file)
        .into_iter()
        .filter(|code_unit| code_unit.source() == file && predicate(code_unit))
        .filter(|code_unit| {
            analyzer.ranges(code_unit).iter().any(|range| {
                cursor_range.start_byte >= range.start_byte
                    && cursor_range.start_byte < range.end_byte
            })
        })
        .filter_map(|code_unit| {
            let selection = code_unit_declaration_name_range(analyzer, file, content, &code_unit)?;
            (cursor_range.start_byte >= selection.start_byte
                && cursor_range.start_byte < selection.end_byte)
                .then_some((selection.end_byte - selection.start_byte, code_unit))
        })
        .min_by_key(|(name_len, code_unit)| {
            (
                *name_len,
                analyzer
                    .ranges(code_unit)
                    .iter()
                    .map(|range| range.end_byte.saturating_sub(range.start_byte))
                    .min()
                    .unwrap_or(usize::MAX),
            )
        })
        .map(|(_, code_unit)| code_unit)
}

fn resolved_reference_target(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    content: Arc<String>,
    start_byte: usize,
    end_byte: usize,
) -> Option<(Vec<CodeUnit>, Option<LexicalDefinition>)> {
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
    if outcome.status != DefinitionLookupStatus::Resolved
        || (outcome.definitions.is_empty() && outcome.lexical_definition.is_none())
    {
        return None;
    }
    Some((outcome.definitions, outcome.lexical_definition))
}

fn resolved_navigation_target(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    content: Arc<String>,
    start_byte: usize,
    end_byte: usize,
    operation: NavigationOperation,
) -> Option<(Vec<CodeUnit>, Option<LexicalDefinition>)> {
    let outcome = resolve_navigation_batch_with_source(
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
        operation,
    )
    .into_iter()
    .next()?;
    if outcome.status != DefinitionLookupStatus::Resolved
        || (outcome.definitions.is_empty() && outcome.lexical_definition.is_none())
    {
        return None;
    }
    Some((outcome.definitions, outcome.lexical_definition))
}
