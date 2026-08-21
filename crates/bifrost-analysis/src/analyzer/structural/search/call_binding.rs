//! Pipeline execution for the `call_bindings` step (issue #2438, first slice).
//!
//! The step takes a `call_shape` row -- the facts-arena side of a call, which
//! already owns the stable site, group and argument identities -- and pairs it
//! with the callee the production definition resolver names for the same site.
//! [`crate::analyzer::usages::call_binding::call_binding_report`] then applies
//! the shared formal-slot matcher and returns one row per actual.
//!
//! Nothing here decides an overload. Resolving the callee reference runs the
//! same definition resolver every other exact-call consumer runs, and that
//! resolver is the consumer of
//! [`crate::analyzer::usages::applicability::ApplicabilityOutcome::winners`],
//! so the target a binding row names is the target the workspace binds. This
//! module never measures arity to choose between candidates.
//!
//! Every call shape produces at least one row. An unreadable shape, an
//! unresolved or ambiguous callee, a callable whose formals nobody recorded,
//! and a language whose receiver occupies a declared parameter slot each
//! produce the mandatory terminal row with the typed reason, so zero rows can
//! never be read as "this call binds no argument".

use super::*;

use crate::analyzer::usages::call_binding::{
    CallBindingReport, CallBindingRow, CallBindingTarget, call_binding_report,
};
use crate::analyzer::usages::callable_signature::callable_signature_reports;
use crate::analyzer::usages::get_definition::{
    DefinitionLookupRequest, DefinitionLookupStatus, resolve_call_target_batch_with_source,
};

/// One derived binding report shared by every row of one call site, beside the
/// rendering of the target the report named.
#[derive(Debug, Clone)]
pub(super) struct CallBindingSiteValue {
    pub(super) report: Arc<CallBindingReport>,
    /// The target rendered as a workspace declaration, when the workspace
    /// indexes an exact range for it.
    pub(super) target: Option<DeclarationValue>,
    /// The `callable_signature` row this binding selects, when the target
    /// publishes exactly one signature entry so the selection is not a guess.
    pub(super) signature_id: Option<String>,
}

/// One row of one call site's binding report.
#[derive(Debug, Clone)]
pub(super) struct CallBindingValue {
    pub(super) site: CallBindingSiteValue,
    pub(super) index: usize,
}

impl CallBindingValue {
    pub(super) fn row(&self) -> &CallBindingRow {
        &self.site.report.rows[self.index]
    }

    pub(super) fn file(&self) -> &ProjectFile {
        &self.site.report.file
    }
}

/// Derive the binding rows of one already-derived call shape.
pub(super) fn call_binding_expansions(
    analyzer: &dyn IAnalyzer,
    indexed: &mut IndexedDeclarations,
    bindings: &mut CallBindingCache,
    shape: &CallShapeValue,
    cancellation: Option<&CancellationToken>,
) -> Vec<PipelineExpansion> {
    let file = shape.report.outcome.file.clone();
    let resolved = resolve_call_target(analyzer, shape, cancellation);
    let (target, declaration, signature_id) = match resolved {
        ResolvedCallTarget::Unit(unit) => {
            let declaration = indexed.get(analyzer, &unit);
            let signature_id = declaration
                .as_ref()
                .and_then(|declaration| selected_signature_id(analyzer, declaration));
            // A layout nobody recorded is stated, never defaulted to "no
            // parameters": an empty parameter list and an unread one are
            // different answers about the same callable.
            let target = match bindings.formal_layout(analyzer, &unit) {
                Some(layout) if layout.python_binding.is_some() => {
                    // The language binds a receiver into the declared list, and
                    // this seam carries no receiver evidence to decide whether
                    // this call did. Refusing to guess keeps a wrong formal
                    // index out of the relation.
                    CallBindingTarget::ReceiverBindingUnsupported { unit }
                }
                Some(layout) => CallBindingTarget::Resolved { unit, layout },
                None => CallBindingTarget::FormalsUnrecorded { unit },
            };
            (target, declaration, signature_id)
        }
        ResolvedCallTarget::Ambiguous => (CallBindingTarget::Ambiguous, None, None),
        ResolvedCallTarget::Unresolved => (CallBindingTarget::Unresolved, None, None),
    };

    let report = Arc::new(call_binding_report(&file, &shape.report, target));
    let site = CallBindingSiteValue {
        report,
        target: declaration,
        signature_id,
    };
    (0..site.report.rows.len())
        .map(|index| {
            pipeline_expansion(PipelineValue::CallBinding(Box::new(CallBindingValue {
                site: site.clone(),
                index,
            })))
        })
        .collect()
}

/// What the production definition resolver names for one call site's callee
/// token.
enum ResolvedCallTarget {
    Unit(CodeUnit),
    Ambiguous,
    Unresolved,
}

/// Resolve the callee reference of one call shape through the production
/// definition resolver.
///
/// The lookup is anchored on the call shape's own `callee_range` -- the span of
/// the token that names the callee -- so no text is matched and no name is
/// compared here. A callable-object call (`proc.(x)`) records no callee token
/// and is therefore unresolved rather than guessed at.
fn resolve_call_target(
    analyzer: &dyn IAnalyzer,
    shape: &CallShapeValue,
    cancellation: Option<&CancellationToken>,
) -> ResolvedCallTarget {
    let outcome = &shape.report.outcome;
    let Some(callee_range) = outcome.callee_range else {
        return ResolvedCallTarget::Unresolved;
    };
    let Some(source) = analyzer.indexed_source(&outcome.file).map(Arc::<str>::from) else {
        return ResolvedCallTarget::Unresolved;
    };
    let scope = AnalyzerQueryScope::new(analyzer);
    let Some(lookup) = resolve_call_target_batch_with_source(
        analyzer,
        scope.token(),
        vec![DefinitionLookupRequest {
            file: outcome.file.clone(),
            line: None,
            column: None,
            start_byte: Some(callee_range.start_byte),
            end_byte: Some(callee_range.end_byte),
        }],
        outcome.file.clone(),
        source,
        cancellation,
    )
    .into_iter()
    .next() else {
        return ResolvedCallTarget::Unresolved;
    };
    if lookup.outcome.status != DefinitionLookupStatus::Resolved {
        return ResolvedCallTarget::Unresolved;
    }
    let mut definitions = lookup.outcome.definitions;
    definitions.sort();
    definitions.dedup();
    match definitions.len() {
        0 => ResolvedCallTarget::Unresolved,
        1 => ResolvedCallTarget::Unit(definitions.remove(0)),
        _ => ResolvedCallTarget::Ambiguous,
    }
}

/// The `callable_signature` row id this binding selects, when the target
/// publishes exactly one signature row.
///
/// A declaration with several persisted entries is an overload set this slice
/// does not choose between, and naming entry zero would be a claim nothing
/// checked. The id is minted by the same projection the `callable_signature`
/// step publishes, so it joins that domain exactly.
fn selected_signature_id(
    analyzer: &dyn IAnalyzer,
    declaration: &DeclarationValue,
) -> Option<String> {
    let declaration_id = callable_signature::declaration_site_id(declaration);
    let entries = analyzer.signature_metadata(&declaration.unit);
    let mut reports = callable_signature_reports(&declaration_id, &declaration.unit, &entries);
    (reports.len() == 1).then(|| reports.remove(0).signature.id)
}
