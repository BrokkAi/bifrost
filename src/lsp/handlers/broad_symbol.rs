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

#[derive(Clone, Copy)]
enum TargetResolution {
    Broad,
    Navigation(NavigationOperation),
}

pub(super) fn broad_symbol_target_at_position(
    analyzer: &dyn IAnalyzer,
    project: &dyn Project,
    uri: &Uri,
    position: &Position,
) -> Option<BroadSymbolTarget> {
    symbol_target_at_position(analyzer, project, uri, position, TargetResolution::Broad)
}

pub(super) fn navigation_target_at_position(
    analyzer: &dyn IAnalyzer,
    project: &dyn Project,
    uri: &Uri,
    position: &Position,
    operation: NavigationOperation,
) -> Option<BroadSymbolTarget> {
    symbol_target_at_position(
        analyzer,
        project,
        uri,
        position,
        TargetResolution::Navigation(operation),
    )
}

fn symbol_target_at_position(
    analyzer: &dyn IAnalyzer,
    project: &dyn Project,
    uri: &Uri,
    position: &Position,
    resolution: TargetResolution,
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
    let (candidates, lexical_definition, declaration_site) = match resolution {
        TargetResolution::Broad => {
            let declaration_site = declaration.is_some();
            let target = declaration
                .map(|declaration| (vec![declaration], None))
                .or_else(|| {
                    reject_ambiguous_import(analyzer, &file, &content, start_byte, end_byte)?;
                    resolved_target(
                        analyzer,
                        &file,
                        Arc::new(content.clone()),
                        start_byte,
                        end_byte,
                        resolution,
                    )
                })?;
            (target.0, target.1, declaration_site)
        }
        TargetResolution::Navigation(operation) => {
            reject_ambiguous_import(analyzer, &file, &content, start_byte, end_byte)?;
            match resolved_target(
                analyzer,
                &file,
                Arc::new(content.clone()),
                start_byte,
                end_byte,
                resolution,
            ) {
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
            }
        }
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

fn reject_ambiguous_import(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    content: &str,
    start_byte: usize,
    end_byte: usize,
) -> Option<()> {
    let identifier = content.get(start_byte..end_byte)?;
    (!is_ambiguous_imported_reference(analyzer, file, identifier)).then_some(())
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

fn resolved_target(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    content: Arc<String>,
    start_byte: usize,
    end_byte: usize,
    resolution: TargetResolution,
) -> Option<(Vec<CodeUnit>, Option<LexicalDefinition>)> {
    let requests = vec![DefinitionLookupRequest {
        file: file.clone(),
        line: None,
        column: None,
        start_byte: Some(start_byte),
        end_byte: Some(end_byte),
    }];
    let outcomes = match resolution {
        TargetResolution::Broad => {
            resolve_definition_batch_with_source(analyzer, requests, file.clone(), content)
        }
        TargetResolution::Navigation(operation) => resolve_navigation_batch_with_source(
            analyzer,
            requests,
            file.clone(),
            content,
            operation,
        ),
    };
    let outcome = outcomes.into_iter().next()?;
    if !matches!(
        outcome.status,
        DefinitionLookupStatus::Resolved | DefinitionLookupStatus::Ambiguous
    ) || (outcome.definitions.is_empty() && outcome.lexical_definition.is_none())
    {
        return None;
    }
    Some((outcome.definitions, outcome.lexical_definition))
}
