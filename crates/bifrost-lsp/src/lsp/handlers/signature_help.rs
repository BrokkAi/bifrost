use std::sync::Arc;

use lsp_types::{
    Documentation, MarkupContent, MarkupKind, ParameterInformation, ParameterLabel, SignatureHelp,
    SignatureHelpParams, SignatureInformation,
};

use crate::analyzer::common::is_unparseable_source;
use crate::analyzer::usages::get_definition::{
    DefinitionLookupRequest, DefinitionLookupStatus, call_signature_context,
    resolve_definition_batch_with_source,
};
use crate::analyzer::{CodeUnit, IAnalyzer, Project, SignatureMetadata, WorkspaceAnalyzer};
use crate::lsp::conversion::position_to_byte_offset;
use crate::lsp::handlers::util::{
    leading_doc_comment_for_code_unit, python_model_symbols_at_offset, read_document_for_uri,
};

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
        Arc::from(content),
    );
    let outcome = outcomes.into_iter().next()?;
    let overlay = analyzer.semantic_model_overlay();
    let modeled_signature = outcome
        .resolved_reference_target()
        .and_then(|target| {
            let matched = overlay.as_ref()?.symbols_named(target);
            (matched.disposition
                == crate::analyzer::semantic_model::SemanticModelOverlayDisposition::Unique)
                .then(|| matched.records[0].clone())
        })
        .filter(|symbol| symbol.externally_visible())
        .and_then(|symbol| symbol.signature.clone());
    if outcome.status != DefinitionLookupStatus::Resolved && modeled_signature.is_none() {
        return model_signature_help(
            analyzer,
            &file,
            &content,
            context.callee_range.end_byte,
            context.active_parameter,
        );
    }

    let mut signatures: Vec<_> = outcome
        .definitions
        .into_iter()
        .filter(|candidate| candidate.is_function() || candidate.is_class())
        .filter_map(|candidate| signature_information(analyzer, &candidate))
        .collect();
    if let Some(label) = modeled_signature {
        signatures.push(SignatureInformation {
            label,
            documentation: None,
            parameters: None,
            active_parameter: None,
        });
    }
    if signatures.is_empty() {
        return None;
    }

    Some(SignatureHelp {
        signatures,
        active_signature: Some(0),
        active_parameter: Some(context.active_parameter),
    })
}

fn model_signature_help(
    analyzer: &dyn IAnalyzer,
    file: &crate::analyzer::ProjectFile,
    content: &str,
    callee_end: usize,
    active_parameter: u32,
) -> Option<SignatureHelp> {
    let overlay = analyzer.semantic_model_overlay()?;
    let symbols =
        python_model_symbols_at_offset(&overlay, file, content, callee_end.saturating_sub(1));
    if symbols.is_empty() {
        return None;
    }
    Some(SignatureHelp {
        signatures: symbols
            .into_iter()
            .map(|symbol| SignatureInformation {
                label: symbol
                    .signature
                    .clone()
                    .unwrap_or_else(|| symbol.qualified_name.clone()),
                documentation: Some(Documentation::MarkupContent(MarkupContent {
                    kind: MarkupKind::Markdown,
                    value: format!(
                        "Provided by `{}` {}",
                        symbol.provenance.pack_id, symbol.provenance.pack_version
                    ),
                })),
                parameters: None,
                active_parameter: None,
            })
            .collect(),
        active_signature: Some(0),
        active_parameter: Some(active_parameter),
    })
}

fn signature_information(
    analyzer: &dyn IAnalyzer,
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
    let signature_metadata = analyzer.signature_metadata(candidate);
    let metadata = matching_signature_metadata(&signature_metadata, &label);
    Some(SignatureInformation {
        parameters: metadata.and_then(|metadata| parameter_information(&label, metadata)),
        documentation: leading_doc_comment_for_code_unit(analyzer, candidate).map(|value| {
            Documentation::MarkupContent(MarkupContent {
                kind: MarkupKind::Markdown,
                value,
            })
        }),
        label,
        active_parameter: None,
    })
}

fn matching_signature_metadata<'a>(
    metadata: &'a [SignatureMetadata],
    label: &str,
) -> Option<&'a SignatureMetadata> {
    metadata
        .iter()
        .find(|metadata| metadata.label().trim() == label)
}

fn parameter_information(
    label: &str,
    metadata: &SignatureMetadata,
) -> Option<Vec<ParameterInformation>> {
    let mut parameters = Vec::new();
    for parameter in metadata.parameters() {
        if parameter.label().is_empty()
            || label.get(parameter.start_byte()..parameter.end_byte())? != parameter.label()
        {
            return None;
        }
        let start = utf16_offset(label, parameter.start_byte())?;
        let end = utf16_offset(label, parameter.end_byte())?;
        parameters.push(ParameterInformation {
            label: ParameterLabel::LabelOffsets([start, end]),
            documentation: None,
        });
    }
    (!parameters.is_empty()).then_some(parameters)
}

fn utf16_offset(content: &str, byte_offset: usize) -> Option<u32> {
    Some(
        content
            .get(..byte_offset)?
            .chars()
            .map(|ch| ch.len_utf16() as u32)
            .sum(),
    )
}
