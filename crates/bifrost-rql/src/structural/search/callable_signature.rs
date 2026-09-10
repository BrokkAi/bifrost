//! Pipeline execution for the `callable_signature` and `signature_parameters`
//! steps (issue #1478, Milestone 2).
//!
//! Both steps project
//! [`crate::analyzer::usages::callable_signature::callable_signature_reports`],
//! which is a pure function of the analyzer's persisted `SignatureMetadata`.
//! Nothing is re-parsed here and no declaration is re-read from source, so the
//! rows a warm cache produces are the rows a cold run produces.
//!
//! `callable_signature` is mandatory per input declaration: a declaration
//! whose language publishes no signature metadata still emits exactly one row,
//! stating `unrecorded` coverage, so zero parameter rows can never be read as
//! a proven-empty parameter list. A declaration with several persisted entries
//! -- an overload set sharing one fully qualified name -- emits one row per
//! entry.

use super::*;

use crate::analyzer::usages::callable_signature::{
    CallableSignatureReport, callable_signature_reports,
};

/// One declaration's projected signature entry, shared by its signature row
/// and each of its parameter rows so a parameter never re-derives the report.
#[derive(Debug, Clone)]
pub(super) struct CallableSignatureValue {
    pub(super) declaration: DeclarationValue,
    pub(super) report: Arc<CallableSignatureReport>,
}

impl CallableSignatureValue {
    pub(super) fn file(&self) -> &ProjectFile {
        self.declaration.unit.source()
    }
}

/// One declared parameter row of one signature entry.
#[derive(Debug, Clone)]
pub(super) struct SignatureParameterValue {
    pub(super) signature: CallableSignatureValue,
    pub(super) parameter_index: usize,
}

impl SignatureParameterValue {
    pub(super) fn file(&self) -> &ProjectFile {
        self.signature.file()
    }

    pub(super) fn row(
        &self,
    ) -> &crate::analyzer::usages::callable_signature::SignatureParameterRow {
        &self.signature.report.parameters[self.parameter_index]
    }
}

/// Project the persisted signature entries of one declaration into rows.
///
/// Always at least one row: a declaration whose language publishes no
/// signature metadata still gets the mandatory `unrecorded` row.
pub(super) fn callable_signature_expansions_for_declaration(
    analyzer: &dyn IAnalyzer,
    declaration: &DeclarationValue,
) -> Vec<PipelineExpansion> {
    // Overloads with the same displayed name remain distinct because the
    // analyzer declaration identity includes their structured signature. The
    // source span then distinguishes multiple indexed sites of that identity.
    let declaration_site_id = declaration.site_id();
    let entries = analyzer.signature_metadata(&declaration.unit);
    callable_signature_reports(&declaration_site_id, &declaration.unit, &entries)
        .into_iter()
        .map(|report| {
            pipeline_expansion(PipelineValue::CallableSignature(Box::new(
                CallableSignatureValue {
                    declaration: declaration.clone(),
                    report: Arc::new(report),
                },
            )))
        })
        .collect()
}

/// Expand one already-derived signature row into its ordered parameter rows.
pub(super) fn signature_parameter_expansions(
    value: &CallableSignatureValue,
) -> Vec<PipelineExpansion> {
    (0..value.report.parameters.len())
        .map(|parameter_index| {
            pipeline_expansion(PipelineValue::SignatureParameter(Box::new(
                SignatureParameterValue {
                    signature: value.clone(),
                    parameter_index,
                },
            )))
        })
        .collect()
}
