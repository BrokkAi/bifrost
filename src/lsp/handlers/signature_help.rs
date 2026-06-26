use std::sync::Arc;

use lsp_types::{SignatureHelp, SignatureHelpParams, SignatureInformation};

use crate::analyzer::common::is_unparseable_source;
use crate::analyzer::usages::get_definition::{
    DefinitionLookupRequest, DefinitionLookupStatus, call_signature_context,
    resolve_definition_batch_with_source,
};
use crate::analyzer::{CodeUnit, Project, WorkspaceAnalyzer};
use crate::lsp::conversion::position_to_byte_offset;
use crate::lsp::handlers::util::read_document_for_uri;

const MAX_SIGNATURE_HELP_SOURCE_BYTES: usize = 1_000_000;

pub fn handle(
    workspace: &WorkspaceAnalyzer,
    project: &dyn Project,
    params: &SignatureHelpParams,
) -> Option<SignatureHelp> {
    let uri = &params.text_document_position_params.text_document.uri;
    let (file, content, line_starts) = read_document_for_uri(project, uri)?;
    if content.len() > MAX_SIGNATURE_HELP_SOURCE_BYTES || is_unparseable_source(&content) {
        return None;
    }
    let byte_offset = position_to_byte_offset(
        &content,
        &line_starts,
        &params.text_document_position_params.position,
    );
    let context = call_signature_context(&file, &content, byte_offset)?;
    let analyzer = workspace.analyzer();
    let outcomes = resolve_definition_batch_with_source(
        analyzer,
        vec![DefinitionLookupRequest {
            file: file.clone(),
            line: None,
            column: None,
            start_byte: Some(context.callee_range.start_byte),
            end_byte: Some(context.callee_range.end_byte),
        }],
        file,
        Arc::new(content),
    );
    let outcome = outcomes.into_iter().next()?;
    if outcome.status != DefinitionLookupStatus::Resolved {
        return None;
    }

    let signatures: Vec<_> = outcome
        .definitions
        .into_iter()
        .filter(|candidate| candidate.is_function() || candidate.is_class())
        .filter_map(|candidate| signature_information(analyzer, &candidate))
        .collect();
    if signatures.is_empty() {
        return None;
    }

    Some(SignatureHelp {
        signatures,
        active_signature: Some(0),
        active_parameter: Some(context.active_parameter),
    })
}

fn signature_information(
    analyzer: &dyn crate::analyzer::IAnalyzer,
    candidate: &CodeUnit,
) -> Option<SignatureInformation> {
    let label = if candidate.is_class() {
        analyzer
            .get_skeleton(candidate)
            .or_else(|| analyzer.get_skeleton_header(candidate))?
    } else {
        analyzer
            .get_skeleton_header(candidate)
            .or_else(|| analyzer.get_skeleton(candidate))?
    };
    let label = label.trim().to_string();
    if label.is_empty() {
        return None;
    }
    Some(SignatureInformation {
        label,
        documentation: None,
        parameters: None,
        active_parameter: None,
    })
}
