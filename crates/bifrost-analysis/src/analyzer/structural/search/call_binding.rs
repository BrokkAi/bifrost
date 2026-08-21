//! Pipeline execution for the `call_bindings` step (issues #2438 and #2499).
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
//! and a receiver whose own resolution failed in a language that writes the
//! receiver into the declared parameter list each produce the mandatory
//! terminal row with the typed reason, so zero rows can never be read as "this
//! call binds no argument".
//!
//! This module owns the workspace-side evidence the row producer must not
//! re-derive: which callable owns the formals (a Python class callee's are
//! `__init__`'s), what fills the receiver position, and which published
//! signature entry the call selects.

use super::*;

use crate::analyzer::lexical_definitions::{FormalParameterLayout, receiver_is_declared_parameter};
use crate::analyzer::usages::call_binding::{
    CallBindingReport, CallBindingRow, CallBindingTarget, CallReceiverBinding, call_binding_report,
};
use crate::analyzer::usages::call_relations::{
    formal_owner_for_callee, python_first_formal_is_bound,
};
use crate::analyzer::usages::callable_signature::{
    CallableSignatureReport, callable_signature_reports,
};
use crate::analyzer::usages::get_definition::{
    DefinitionLookupRequest, DefinitionLookupStatus, resolve_call_target_batch_with_source,
};
use brokk_bifrost_core::analyzer::structural::callable::ReceiverContract;

/// One derived binding report shared by every row of one call site, beside the
/// rendering of the target the report named.
#[derive(Debug, Clone)]
pub(super) struct CallBindingSiteValue {
    pub(super) report: Arc<CallBindingReport>,
    /// The target rendered as a workspace declaration, when the workspace
    /// indexes an exact range for it.
    pub(super) target: Option<DeclarationValue>,
    /// The `callable_signature` row this binding selects: the target's only
    /// entry, or the entry of a multi-entry set that this call's arity accepts.
    /// Absent when entries with different parameter lists accept it, or none
    /// does, because naming one would be a selection nothing made.
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
            let selection = declaration.as_ref().map(|declaration| {
                selected_signature(analyzer, declaration, shape.report.arguments.len())
            });
            let signature_id = selection
                .as_ref()
                .and_then(|selection| selection.signature_id.clone());
            let contract = selection.and_then(|selection| selection.receiver_contract);
            // A class callee is a constructor call in the one language that
            // spells it that way, and its formals are the constructor's.
            let owner = formal_owner_for_callee(analyzer, &unit);
            // A layout nobody recorded is stated, never defaulted to "no
            // parameters": an empty parameter list and an unread one are
            // different answers about the same callable.
            let layout = owner
                .as_ref()
                .and_then(|(owner, _)| bindings.formal_layout(analyzer, owner));
            let target = match (owner, layout) {
                (Some((owner, constructor)), Some(layout)) => {
                    match receiver_binding(
                        analyzer,
                        shape,
                        &owner,
                        &layout,
                        contract,
                        constructor,
                        bindings,
                    ) {
                        // The receiver's own resolution failed in a language
                        // that binds it into the declared parameter list, so
                        // which slot the first actual reaches is exactly what
                        // is unknown. Refusing keeps a wrong formal index out
                        // of the relation.
                        None => CallBindingTarget::ReceiverBindingUnsupported { unit },
                        Some(receiver) => CallBindingTarget::Resolved {
                            unit,
                            layout,
                            receiver,
                        },
                    }
                }
                _ => CallBindingTarget::FormalsUnrecorded { unit },
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

/// What the callee's published signature entries say about this call site.
struct SelectedSignature {
    /// The `callable_signature` row this binding selects, when the entries name
    /// exactly one.
    signature_id: Option<String>,
    /// The receiver contract the selected entry declares, or the one every
    /// entry agrees on when selection did not narrow to one.
    receiver_contract: Option<ReceiverContract>,
}

/// Select the `callable_signature` row this binding names, out of every entry
/// the target publishes.
///
/// A declaration with one entry names it. A declaration with several is either
/// an overload set sharing one identity or a C++ declaration beside its
/// definition, and both are narrowed by the same applicability rule overload
/// selection itself applies: [`CallableArity::accepts`] over the actuals the
/// call wrote. Exactly one accepting entry is the selection.
///
/// Several accepting entries are only genuinely ambiguous when they describe
/// different parameter lists. Entries that agree on every recorded parameter
/// are one signature the language published twice -- a header and its body --
/// so the entry carrying the body is named. Anything else names nothing, and
/// the row says so rather than naming entry zero (issue #2499).
///
/// An entry whose arity the adapter never recorded makes the whole set
/// undecidable: a parameter list nobody read cannot be shown not to accept
/// this call.
///
/// The id is minted by the same projection the `callable_signature` step
/// publishes, so it joins that domain exactly.
fn selected_signature(
    analyzer: &dyn IAnalyzer,
    declaration: &DeclarationValue,
    actual_count: usize,
) -> SelectedSignature {
    let declaration_id = callable_signature::declaration_site_id(declaration);
    let entries = analyzer.signature_metadata(&declaration.unit);
    let reports = callable_signature_reports(&declaration_id, &declaration.unit, &entries);
    let selected = match reports.as_slice() {
        [] => None,
        [only] => Some(only),
        several
            if several
                .iter()
                .all(|report| report.signature.arity.is_some()) =>
        {
            let accepting = several
                .iter()
                .filter(|report| {
                    report
                        .signature
                        .arity
                        .is_some_and(|arity| arity.accepts(actual_count))
                })
                .collect::<Vec<_>>();
            match accepting.as_slice() {
                [only] => Some(*only),
                [first, rest @ ..]
                    if rest
                        .iter()
                        .all(|report| declares_the_same_parameters(first, report)) =>
                {
                    accepting
                        .iter()
                        .copied()
                        .find(|report| !report.signature.declaration_only)
                        .or(Some(*first))
                }
                _ => None,
            }
        }
        _ => None,
    };
    SelectedSignature {
        signature_id: selected.map(|report| report.signature.id.clone()),
        receiver_contract: selected
            .map(|report| report.signature.receiver_contract)
            .unwrap_or_else(|| agreed_receiver_contract(&reports)),
    }
}

/// Whether two published entries describe the same declared parameter list,
/// which is what makes a header and its definition one signature rather than
/// two overloads. The comparison is over the recorded parameter labels and
/// declared type spellings, both of which the adapter published; nothing here
/// parses either.
fn declares_the_same_parameters(
    left: &CallableSignatureReport,
    right: &CallableSignatureReport,
) -> bool {
    left.parameters.len() == right.parameters.len()
        && left
            .parameters
            .iter()
            .zip(&right.parameters)
            .all(|(left, right)| {
                left.label == right.label && left.declared_type == right.declared_type
            })
}

/// The receiver contract every published entry declares, when they all declare
/// the same one. Which overload a call selects cannot change whether the
/// callable is instance-bound, so an unselected overload set still answers
/// this; entries that disagree answer nothing.
fn agreed_receiver_contract(reports: &[CallableSignatureReport]) -> Option<ReceiverContract> {
    let mut contracts = reports
        .iter()
        .map(|report| report.signature.receiver_contract);
    let first = contracts.next().flatten()?;
    contracts
        .all(|contract| contract == Some(first))
        .then_some(first)
}

/// What fills the resolved callee's receiver position at this call site.
///
/// `None` is the honest refusal: a language that writes its receiver as a
/// declared parameter and whose receiver expression did not resolve leaves
/// every ordinary ordinal in doubt, which is what
/// `receiver_binding_unsupported` states.
///
/// The decision order is the languages' own. Python answers from its method
/// binding alone -- `python_first_formal_is_bound` is the production binder's
/// own function, so a row can never disagree with what `call_input` binds --
/// and every other language answers from the declaration: a declared receiver
/// slot (Rust's `self`, Java's and Go's receiver parameter), otherwise the
/// published receiver contract. A call whose receiver token is a scope
/// qualifier -- `App.staticHelper(1)` -- reaches neither, and mints no receiver
/// row, because a type name binds no value. A language whose adapter records no
/// modifiers at all, such as TypeScript, cannot tell those two apart, and gets
/// the stated `receiver_binding_unsupported` row rather than silence.
fn receiver_binding(
    analyzer: &dyn IAnalyzer,
    shape: &CallShapeValue,
    formal_owner: &CodeUnit,
    layout: &FormalParameterLayout,
    contract: Option<ReceiverContract>,
    constructor_binding: bool,
    bindings: &mut CallBindingCache,
) -> Option<CallReceiverBinding> {
    let outcome = &shape.report.outcome;
    let declared_first_ordinary = python_first_formal_is_bound(
        analyzer,
        &outcome.file,
        outcome.receiver_range,
        formal_owner,
        layout,
        bindings,
        constructor_binding,
    )?;
    if constructor_binding {
        // The object the call allocates fills `__init__`'s `self`, with no
        // source syntax of its own. A module or package qualifier written
        // before the class name is a scope, not that object.
        return Some(CallReceiverBinding::Implicit {
            declared_first_ordinary,
        });
    }
    let Some(range) = outcome.receiver_range else {
        return Some(CallReceiverBinding::Absent);
    };
    if layout.python_binding.is_some() {
        return Some(if declared_first_ordinary {
            CallReceiverBinding::Actual {
                range,
                declared_first_ordinary,
            }
        } else {
            // A static method, or a class-qualified unbound call whose first
            // written actual is the instance: neither binds a receiver.
            CallReceiverBinding::Absent
        });
    }
    let declares_receiver_slot = layout.slots.iter().any(|slot| slot.receiver);
    Some(
        if declares_receiver_slot || contract == Some(ReceiverContract::Instance) {
            CallReceiverBinding::Actual {
                range,
                declared_first_ordinary: false,
            }
        } else if receiver_is_declared_parameter(crate::analyzer::common::language_for_file(
            formal_owner.source(),
        )) {
            // Rust and Go declare every receiver they take, so a layout with
            // no receiver slot is the complete answer: `Client::new(port)` is
            // an associated function and the path before it is a scope.
            CallReceiverBinding::Absent
        } else if contract.is_none() {
            // The callee's adapter records no modifiers, so "instance method"
            // and "static method reached through its owner" are the same
            // published fact here. The row says that rather than vanishing,
            // which would read as "this call has no receiver".
            CallReceiverBinding::Unestablished { range }
        } else {
            CallReceiverBinding::Absent
        },
    )
}
