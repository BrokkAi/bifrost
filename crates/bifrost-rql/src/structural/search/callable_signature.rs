//! Pipeline execution for the `callable_signature` and `signature_parameters`
//! steps (issue #1478, Milestone 2).
//!
//! Signature and parameter rows project
//! [`crate::analyzer::usages::callable_signature::callable_signature_reports`]
//! from persisted `SignatureMetadata`. For Python special methods, the
//! signature row is enriched at query time from prepared syntax with the
//! protocol arity verdict and placeholder status; no special-method facts are
//! persisted.
//!
//! `callable_signature` is mandatory per input declaration: a declaration
//! whose language publishes no signature metadata still emits exactly one row,
//! stating `unrecorded` coverage, so zero parameter rows can never be read as
//! a proven-empty parameter list. A declaration with several persisted entries
//! -- an overload set sharing one fully qualified name -- emits one row per
//! entry.

use super::*;

use super::python_special_method_signature::{
    PythonSpecialMethodContract, python_special_method_context,
};
use crate::analyzer::usages::callable_signature::{
    CallableSignatureReport, callable_signature_reports,
};

/// One declaration's projected signature entry, shared by its signature row
/// and each of its parameter rows so a parameter never re-derives the report.
#[derive(Debug, Clone)]
pub(super) struct CallableSignatureValue {
    pub(super) declaration: DeclarationValue,
    pub(super) report: Arc<CallableSignatureReport>,
    pub(super) python_special_method: Option<PythonSpecialMethodContract>,
    pub(super) python_receiver: super::python_method_receiver::PythonMethodReceiverEvidence,
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
    environment_cache: &mut EnvironmentTraversalCache,
    declaration: &DeclarationValue,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> Vec<PipelineExpansion> {
    // Overloads with the same displayed name remain distinct because the
    // analyzer declaration identity includes their structured signature. The
    // source span then distinguishes multiple indexed sites of that identity.
    let declaration_site_id = declaration.site_id();
    let special_method_context = python_special_method_context(analyzer, declaration);
    let python_receiver = super::python_method_receiver::receiver_evidence(
        analyzer,
        environment_cache,
        declaration,
        cancellation,
        diagnostics,
    );
    let entries = analyzer.signature_metadata(&declaration.unit);
    callable_signature_reports(&declaration_site_id, &declaration.unit, &entries)
        .into_iter()
        .map(|report| {
            let python_special_method =
                special_method_context.map(|context| context.contract(report.signature.arity));
            // The actual premises live once in the pipeline trace, including
            // parameter projections; the row's private derivation state is spent.
            let mut receiver = python_receiver.clone();
            receiver.hierarchy_premises.clear();
            let mut expansion = pipeline_expansion(PipelineValue::CallableSignature(Box::new(
                CallableSignatureValue {
                    declaration: declaration.clone(),
                    report: Arc::new(report),
                    python_special_method,
                    python_receiver: receiver,
                },
            )));
            super::python_class_hierarchy::attach_hierarchy_premises(
                &mut expansion,
                &python_receiver.hierarchy_premises,
            );
            expansion
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
