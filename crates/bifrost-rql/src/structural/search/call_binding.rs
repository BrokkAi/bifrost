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

use crate::analyzer::lexical_definitions::{
    FormalParameterLayout, FormalParameterPassingMode, FormalParameterSlot, FormalVariadicKind,
    receiver_is_declared_parameter,
};
use crate::analyzer::semantic::LengthDelimitedDigest;
use crate::analyzer::semantic_model::{
    Completeness, ParameterPassingMode, ProcedureSummaryMemberKey, SemanticModelCallApplication,
    SemanticModelCallableDisposition, SemanticModelCallableIncompleteReason,
    SemanticModelCallableKey, SemanticModelCompleteness, SemanticModelMatchDisposition,
    SemanticModelOriginKind, SemanticModelProof, SemanticModelProvenance,
};
use crate::analyzer::usages::call_binding::{
    CallBindingCoverage, CallBindingMapping, CallBindingReport, CallBindingRow, CallBindingTarget,
    CallReceiverBinding, call_binding_report,
};
use crate::analyzer::usages::call_relations::{
    formal_owner_for_callee, python_first_formal_is_bound,
};
use crate::analyzer::usages::callable_signature::{
    CallableSignatureReport, callable_signature_reports,
};
use crate::analyzer::usages::effects::ModeledProcedureKey;
use crate::analyzer::usages::get_definition::DefinitionLookupStatus;
use brokk_bifrost_core::analyzer::structural::callable::{CallShapeCoverage, ReceiverContract};

use super::dispatch::DispatchSiteAnswer;

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
    /// Exact callable-family identity. Complete overload families retain one
    /// identity here without selecting an overload record.
    pub(super) model_callable_id: Option<String>,
    /// Exact formal-layout identity for this call application. This remains
    /// available when compatible overloads share the layout.
    pub(super) formal_layout_id: Option<String>,
    /// The semantic dispatch answer for this exact call range. Its target
    /// identity is the #2438 dispatch identity; source declarations remain a
    /// presentation-only materialized view.
    pub(super) dispatch: CallBindingDispatch,
    /// Exactness of the endpoint selector, kept separate from runtime dispatch.
    /// `authored_summary` means the declaration identity is exact and the one
    /// residual override boundary is covered by an explicit reviewed contract.
    pub(super) selector: CallBindingSelectorProof,
    /// The declared semantic target identity. This is separate from the
    /// dispatch identity because a model can identify one external declaration
    /// while runtime dispatch remains open or partial.
    pub(super) semantic_target_id: Option<String>,
    /// Whether the declared target came from an indexed source declaration or
    /// the activated semantic-model overlay.
    pub(super) target_origin: Option<&'static str>,
    pub(super) model_id: Option<String>,
    pub(super) pack_id: Option<String>,
    pub(super) semantic_model_provenance: Option<Arc<SemanticModelProvenance>>,
    /// Stable identity of the type that owns this callable's receiver, when
    /// the shared binder establishes one. An exact model owner takes
    /// precedence; otherwise this is the source declaration identity. It is
    /// never a qualified/display name.
    pub(super) receiver_type_id: Option<String>,
}

#[derive(Debug, Clone)]
pub(super) struct CallBindingSelectorProof {
    pub(super) exact: bool,
    pub(super) tier: Option<&'static str>,
    pub(super) summary_id: Option<String>,
    pub(super) summary_model_id: Option<String>,
    pub(super) summary_provenance: Option<Arc<SemanticModelProvenance>>,
}

impl CallBindingSelectorProof {
    fn unavailable() -> Self {
        Self {
            exact: false,
            tier: None,
            summary_id: None,
            summary_model_id: None,
            summary_provenance: None,
        }
    }

    fn derived() -> Self {
        Self {
            exact: true,
            tier: Some("derived"),
            summary_id: None,
            summary_model_id: None,
            summary_provenance: None,
        }
    }

    fn authored_summary(
        summary_id: String,
        summary_model_id: String,
        provenance: SemanticModelProvenance,
    ) -> Self {
        Self {
            exact: true,
            tier: Some("authored_summary"),
            summary_id: Some(summary_id),
            summary_model_id: Some(summary_model_id),
            summary_provenance: Some(Arc::new(provenance)),
        }
    }
}

/// The dispatch quality carried alongside every binding row of one call.
///
/// A singular target id is published only when dispatch retained exactly one
/// target arm. The proof, completeness, and candidate coverage remain
/// independently visible, so an open or partial one-arm answer cannot be read
/// as an exact target merely because it has an id.
#[derive(Debug, Clone)]
pub(super) struct CallBindingDispatch {
    pub(super) target_id: Option<String>,
    pub(super) proof: Option<&'static str>,
    pub(super) completeness: Option<&'static str>,
    pub(super) outcome: &'static str,
    pub(super) coverage: &'static str,
    pub(super) target_count: usize,
    pub(super) targets_truncated: bool,
}

impl CallBindingDispatch {
    fn unavailable() -> Self {
        Self {
            target_id: None,
            proof: None,
            completeness: None,
            outcome: "unknown",
            coverage: "open",
            target_count: 0,
            targets_truncated: false,
        }
    }

    fn is_exact(&self) -> bool {
        self.target_id.is_some()
            && self.outcome == "resolved"
            && self.coverage == "exhaustive"
            && self.proof == Some("proven")
            && self.completeness == Some("complete")
    }

    fn from_answer(
        answer: &DispatchSiteAnswer,
        source_target: Option<&CodeUnit>,
        model_target_id: Option<&str>,
    ) -> Self {
        let compatible = |arm: &&super::dispatch::DispatchArm| {
            (arm.target_unit.as_ref() == source_target && source_target.is_some())
                || (arm.target_unit.is_none()
                    && model_target_id.is_some_and(|id| id == arm.target_id))
        };
        // An exact external declaration identifies the selected endpoint even
        // when dispatch retains an unnamed override boundary. Keep that open
        // runtime coverage below, but do not erase the independently exact
        // declaration join. Multiple distinct external ids remain ambiguous.
        let mut exact_external = answer
            .arms
            .iter()
            .filter(|arm| arm.exact_external_target.is_some())
            .filter(compatible)
            .collect::<Vec<_>>();
        exact_external.sort_by(|left, right| left.target_id.cmp(&right.target_id));
        exact_external.dedup_by(|left, right| left.target_id == right.target_id);
        let singular = match exact_external.as_slice() {
            [arm] => Some(*arm),
            [] => (answer.arms.len() == 1 && answer.unnamed_boundaries.is_empty())
                .then(|| &answer.arms[0])
                .filter(compatible),
            _ => None,
        };
        Self {
            target_id: singular.map(|arm| arm.target_id.clone()),
            proof: singular.map(|arm| arm.proof),
            completeness: singular.map(|arm| arm.completeness),
            outcome: answer.outcome,
            coverage: answer.coverage.label(),
            target_count: answer.arms.len(),
            targets_truncated: answer.coverage.is_truncated(),
        }
    }
}

enum ModelCallBinding {
    Unique {
        layout: FormalParameterLayout,
        receiver: CallReceiverBinding,
        key: ModeledProcedureKey,
        model_id: String,
        model_callable_id: String,
        pack_id: String,
        receiver_type_id: Option<String>,
        signature_id: String,
        semantic_model_provenance: Arc<SemanticModelProvenance>,
    },
    CompatibleLayout {
        layout: FormalParameterLayout,
        receiver: CallReceiverBinding,
        key: ModeledProcedureKey,
        model_callable_id: String,
        formal_layout_id: String,
        pack_id: String,
        receiver_type_id: Option<String>,
    },
    Conflict,
    Incomplete {
        model_id: Option<String>,
        pack_id: Option<String>,
        reason: SemanticModelCallableIncompleteReason,
        semantic_model_provenance: Option<Arc<SemanticModelProvenance>>,
    },
    Empty,
    Unavailable,
}

fn model_formal_layout(
    signature: &crate::analyzer::semantic_model::Signature,
    shape: &CallShapeValue,
) -> FormalParameterLayout {
    let slots = signature
        .parameters
        .iter()
        .map(|parameter| {
            let name = parameter
                .name
                .clone()
                .expect("an applicable model layout has every formal name");
            let passing_mode = match parameter.passing_mode {
                ParameterPassingMode::PositionalOnly => FormalParameterPassingMode::PositionalOnly,
                ParameterPassingMode::PositionalOrNamed => {
                    FormalParameterPassingMode::PositionalOrNamed
                }
                ParameterPassingMode::NamedOnly => FormalParameterPassingMode::NamedOnly,
            };
            let variadic = parameter.variadic.then_some(match parameter.passing_mode {
                ParameterPassingMode::NamedOnly => FormalVariadicKind::Keyword,
                ParameterPassingMode::PositionalOnly | ParameterPassingMode::PositionalOrNamed => {
                    FormalVariadicKind::Positional
                }
            });
            FormalParameterSlot {
                names: vec![name],
                // Model records have no source parameter range. The call
                // range is the only source-backed location available; it is
                // used only to keep default rows addressable.
                declaration_range: shape.report.outcome.range,
                receiver: false,
                variadic,
                passing_mode,
                default_range: parameter.optional.then_some(shape.report.outcome.range),
            }
        })
        .collect();
    FormalParameterLayout {
        slots,
        python_binding: None,
    }
}

fn model_receiver_binding(
    target: &crate::analyzer::semantic::UnmaterializedExternalTarget,
    shape: &CallShapeValue,
) -> CallReceiverBinding {
    if target.has_receiver() {
        shape
            .report
            .outcome
            .receiver_range
            .map(|range| CallReceiverBinding::Actual {
                range,
                declared_first_ordinary: false,
            })
            .unwrap_or(CallReceiverBinding::Unestablished {
                range: shape.report.outcome.range,
            })
    } else {
        CallReceiverBinding::Absent
    }
}

fn model_call_binding(
    analyzer: &dyn IAnalyzer,
    arm: &super::dispatch::DispatchArm,
    shape: &CallShapeValue,
) -> ModelCallBinding {
    let Some(target) = arm.unmaterialized_target.as_ref() else {
        return ModelCallBinding::Unavailable;
    };
    let Some(overlay) = analyzer.semantic_model_overlay() else {
        return ModelCallBinding::Unavailable;
    };
    let modeled_key = ModeledProcedureKey {
        language: target.language().semantic_pack_label().to_owned(),
        owner: target.owner_fqn().to_owned(),
        member: target.member().to_owned(),
        has_receiver: target.has_receiver(),
        parameter_count: target.arity(),
    };
    let key = SemanticModelCallableKey::new(
        &modeled_key.language,
        &modeled_key.owner,
        &modeled_key.member,
        modeled_key.has_receiver,
        modeled_key.parameter_count,
    );
    let application = structured_model_application(shape);
    let model_callable_id = overlay.callable_family_id_for_target(key);
    let matched = overlay.callable_for_application(key, &application);
    let provenance = matched
        .records
        .first()
        .map(|symbol| Arc::new(symbol.provenance.clone()));
    let model_id = matched.records.first().map(|symbol| symbol.id.clone());
    match matched.disposition {
        SemanticModelCallableDisposition::Unique => {
            let Some(symbol) = matched.unique() else {
                return ModelCallBinding::Unavailable;
            };
            let Some(signature) = symbol.structured_signature() else {
                return ModelCallBinding::Incomplete {
                    model_id: model_id.clone(),
                    pack_id: provenance.as_ref().map(|value| value.pack_id.clone()),
                    reason: SemanticModelCallableIncompleteReason::MissingSignature,
                    semantic_model_provenance: provenance,
                };
            };
            let layout = model_formal_layout(signature, shape);
            let receiver = model_receiver_binding(target, shape);
            let Some(model_provenance) = provenance else {
                return ModelCallBinding::Unavailable;
            };
            let model_id = symbol.id.clone();
            let pack_id = model_provenance.pack_id.clone();
            let signature_id = model_signature_id(&model_id, signature);
            let Some(model_callable_id) = model_callable_id else {
                return ModelCallBinding::Conflict;
            };
            let receiver_type_id = target
                .has_receiver()
                .then(|| symbol.owner_id.clone())
                .flatten();
            ModelCallBinding::Unique {
                layout,
                receiver,
                key: modeled_key,
                model_id,
                model_callable_id,
                pack_id,
                receiver_type_id,
                signature_id,
                semantic_model_provenance: model_provenance,
            }
        }
        SemanticModelCallableDisposition::CompatibleLayout => {
            let Some(symbol) = matched.records.first().copied() else {
                return ModelCallBinding::Unavailable;
            };
            let Some(signature) = symbol.structured_signature() else {
                return ModelCallBinding::Unavailable;
            };
            let layout = model_formal_layout(signature, shape);
            let Some(model_callable_id) = model_callable_id else {
                return ModelCallBinding::Conflict;
            };
            let formal_layout_id = model_signature_id(&model_callable_id, signature);
            let Some(pack_id) = matched
                .records
                .iter()
                .map(|candidate| candidate.provenance.pack_id.as_str())
                .reduce(|left, right| if left == right { left } else { "" })
                .filter(|pack_id| !pack_id.is_empty())
                .map(str::to_owned)
            else {
                return ModelCallBinding::Conflict;
            };
            ModelCallBinding::CompatibleLayout {
                layout,
                receiver: model_receiver_binding(target, shape),
                key: modeled_key,
                model_callable_id,
                formal_layout_id,
                pack_id,
                receiver_type_id: target
                    .has_receiver()
                    .then(|| symbol.owner_id.clone())
                    .flatten(),
            }
        }
        SemanticModelCallableDisposition::Conflict => ModelCallBinding::Conflict,
        SemanticModelCallableDisposition::Incomplete(reason) => ModelCallBinding::Incomplete {
            model_id,
            pack_id: provenance.as_ref().map(|value| value.pack_id.clone()),
            reason,
            semantic_model_provenance: provenance,
        },
        SemanticModelCallableDisposition::Empty => ModelCallBinding::Empty,
    }
}

enum SourceTargetModelProvenance {
    Absent,
    Exact {
        model_id: String,
        model_callable_id: String,
        receiver_type_id: Option<String>,
        provenance: Arc<SemanticModelProvenance>,
        key: ModeledProcedureKey,
    },
    Incomplete {
        model_id: Option<String>,
        provenance: Option<Arc<SemanticModelProvenance>>,
    },
}

fn model_provenance_for_source_target(
    analyzer: &dyn IAnalyzer,
    target: &CodeUnit,
) -> SourceTargetModelProvenance {
    let Some(overlay) = analyzer.semantic_model_overlay() else {
        return SourceTargetModelProvenance::Absent;
    };
    let Some(key) =
        crate::analyzer::usages::effects::modeled_procedure_key_for_unit(analyzer, target)
    else {
        return SourceTargetModelProvenance::Absent;
    };
    let model_callable_id = overlay.callable_family_id_for_target(SemanticModelCallableKey::new(
        &key.language,
        &key.owner,
        &key.member,
        key.has_receiver,
        key.parameter_count,
    ));
    let matched = overlay.callable_for_target(SemanticModelCallableKey::new(
        &key.language,
        &key.owner,
        &key.member,
        key.has_receiver,
        key.parameter_count,
    ));
    let incomplete_provenance = matched
        .records
        .first()
        .map(|symbol| Arc::new(symbol.provenance.clone()));
    let Some(symbol) = matched.unique() else {
        return match matched.disposition {
            SemanticModelCallableDisposition::Empty => SourceTargetModelProvenance::Absent,
            SemanticModelCallableDisposition::Unique => unreachable!("unique match has a record"),
            SemanticModelCallableDisposition::CompatibleLayout => {
                SourceTargetModelProvenance::Incomplete {
                    model_id: None,
                    provenance: None,
                }
            }
            SemanticModelCallableDisposition::Conflict => SourceTargetModelProvenance::Incomplete {
                model_id: None,
                provenance: None,
            },
            SemanticModelCallableDisposition::Incomplete(_) => {
                SourceTargetModelProvenance::Incomplete {
                    model_id: matched.records.first().map(|symbol| symbol.id.clone()),
                    provenance: incomplete_provenance,
                }
            }
        };
    };
    debug_assert!(!symbol.provenance.ambiguous);
    SourceTargetModelProvenance::Exact {
        model_id: symbol.id.clone(),
        model_callable_id: model_callable_id
            .expect("an exact source model target must retain its callable family identity"),
        receiver_type_id: key.has_receiver.then(|| symbol.owner_id.clone()).flatten(),
        provenance: Arc::new(symbol.provenance.clone()),
        key,
    }
}

/// Select an authored override contract only for the one residual shape #2371
/// can discharge. The named `unresolved` boundary distinguishes that contract
/// residual from real target-limit or workspace-hierarchy truncation.
fn authored_residual_arm(answer: &DispatchSiteAnswer) -> Option<&super::dispatch::DispatchArm> {
    (matches!(answer.outcome, "unknown" | "unproven")
        && answer.call_site_count == 1
        && answer.arms.len() == 1
        && is_authored_override_residual(&answer.unnamed_boundaries))
    .then(|| &answer.arms[0])
}

fn authored_selector_proof_for_source_target(
    analyzer: &dyn IAnalyzer,
    answer: &DispatchSiteAnswer,
    source_target: &CodeUnit,
    key: &ModeledProcedureKey,
) -> Option<CallBindingSelectorProof> {
    let arm = authored_residual_arm(answer)?;
    if arm.target_unit.as_ref() != Some(source_target) {
        return None;
    }
    authored_summary_selector_proof(analyzer, key)
}

fn authored_selector_proof_for_external_target(
    analyzer: &dyn IAnalyzer,
    answer: &DispatchSiteAnswer,
    key: &ModeledProcedureKey,
) -> Option<CallBindingSelectorProof> {
    let target = authored_residual_arm(answer)?
        .unmaterialized_target
        .as_ref()?;
    if target.language().semantic_pack_label() != key.language
        || target.owner_fqn() != key.owner
        || target.member() != key.member
        || target.has_receiver() != key.has_receiver
        || target.arity() != key.parameter_count
    {
        return None;
    }
    authored_summary_selector_proof(analyzer, key)
}

fn authored_summary_selector_proof(
    analyzer: &dyn IAnalyzer,
    key: &ModeledProcedureKey,
) -> Option<CallBindingSelectorProof> {
    let active = analyzer.active_semantic_models()?;
    let matched = active.procedure_summaries_for_member(ProcedureSummaryMemberKey::new(
        &key.language,
        &key.owner,
        &key.member,
        key.has_receiver,
        key.parameter_count,
    ));
    if matched.disposition != SemanticModelMatchDisposition::Unique {
        return None;
    }
    let selected = matched.records.first()?;
    if selected.record.completeness != Completeness::Complete || !selected.record.covers_overrides {
        return None;
    }
    Some(CallBindingSelectorProof::authored_summary(
        selected.record.id.clone(),
        selected.record.model_id.clone(),
        selected.provenance(&active),
    ))
}

fn is_authored_override_residual(boundaries: &[&str]) -> bool {
    boundaries == ["unresolved"]
}

fn resolver_proven_static_model_selector(answer: &DispatchSiteAnswer) -> bool {
    answer.outcome == "resolved"
        && answer.coverage.is_exhaustive()
        && answer.unnamed_boundaries.is_empty()
        && matches!(
            answer.arms.as_slice(),
            [arm]
                if arm.proof == "proven"
                    && arm
                        .unmaterialized_target
                        .as_ref()
                        .is_some_and(|target| target.resolver_proves_static_call())
        )
}

#[cfg(test)]
mod authored_override_residual_tests {
    use super::{DispatchSiteAnswer, authored_residual_arm, is_authored_override_residual};

    #[test]
    fn only_one_unresolved_boundary_is_the_contract_residual() {
        assert!(is_authored_override_residual(&["unresolved"]));
        assert!(!is_authored_override_residual(&[]));
        assert!(!is_authored_override_residual(&["truncated"]));
        assert!(!is_authored_override_residual(&["external"]));
        assert!(!is_authored_override_residual(&[
            "unresolved",
            "unresolved"
        ]));
        assert!(!is_authored_override_residual(&["unresolved", "truncated"]));
    }

    #[test]
    fn only_unknown_or_unproven_answers_can_carry_the_contract_residual() {
        let answer = |outcome| DispatchSiteAnswer {
            outcome,
            coverage: crate::analyzer::semantic::CandidateCoverage::Open,
            call_site_count: 1,
            semantic_unsupported: None,
            exceeded_limit: None,
            arms: Vec::new(),
            call_contexts: vec![super::super::dispatch::DispatchCallContext {
                caller: None,
                caller_is_exact: false,
            }],
            unnamed_boundaries: vec!["unresolved"],
        };
        for outcome in ["unknown", "unproven"] {
            let mut answer = answer(outcome);
            answer.arms.push(super::super::dispatch::DispatchArm {
                call_context: 0,
                execution_timing: crate::analyzer::semantic::ExecutionTiming::Unknown,
                target_id: "target".to_owned(),
                target_path: "target".to_owned(),
                target_unit: None,
                exact_external_target: None,
                unmaterialized_target: None,
                proof: "proven",
                completeness: "partial",
                boundary_kind: Some("external"),
            });
            assert!(authored_residual_arm(&answer).is_some());
        }
        for outcome in [
            "resolved",
            "ambiguous",
            "unsupported",
            "exceeded_budget",
            "cancelled",
        ] {
            assert!(authored_residual_arm(&answer(outcome)).is_none());
        }
    }
}

/// Derive a stable RQL signature identity from the model symbol identity and
/// its structured signature. The signature is serialized as structured data;
/// no display spelling or source-text parsing participates in this join.
fn model_signature_id(
    model_id: &str,
    signature: &crate::analyzer::semantic_model::Signature,
) -> String {
    let encoded = serde_json::to_vec(signature).expect("model signatures are serializable");
    let mut digest = LengthDelimitedDigest::new(b"bifrost.code_query.model_signature.v1");
    digest.push(model_id.as_bytes());
    digest.push(&encoded);
    digest.finish().to_string()
}

pub(super) const fn semantic_model_origin_label(origin: SemanticModelOriginKind) -> &'static str {
    match origin {
        SemanticModelOriginKind::WorkspaceSource => "workspace_source",
        SemanticModelOriginKind::ExactGeneratedOutput => "exact_generated_output",
        SemanticModelOriginKind::DependencySource => "dependency_source",
        SemanticModelOriginKind::DependencyBinary => "dependency_binary",
        SemanticModelOriginKind::PrebuiltApiIndex => "prebuilt_api_index",
        SemanticModelOriginKind::DeclarativeModel => "declarative_model",
    }
}

pub(super) const fn semantic_model_proof_label(proof: SemanticModelProof) -> &'static str {
    match proof {
        SemanticModelProof::AuthoredAnchor => "authored_anchor",
        SemanticModelProof::ExactArtifact => "exact_artifact",
        SemanticModelProof::PackFact => "pack_fact",
    }
}

pub(super) const fn semantic_model_completeness_label(
    completeness: SemanticModelCompleteness,
) -> &'static str {
    match completeness {
        SemanticModelCompleteness::Partial => "partial",
        SemanticModelCompleteness::Complete => "complete",
    }
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
    semantic: Option<&mut SemanticQueryContext<'_>>,
    indexed: &mut IndexedDeclarations,
    bindings: &mut CallBindingCache,
    shape: &CallShapeValue,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> Vec<PipelineExpansion> {
    let file = shape.report.outcome.file.clone();
    let resolved = resolve_call_target(analyzer, shape, bindings, cancellation);
    let (mut target, declaration, mut signature_id, source_target) = match resolved {
        ResolvedCallTarget::Unit(unit) => {
            let source_target = unit.clone();
            let declaration = indexed.get(analyzer, &unit);
            // A class-shaped callee and its constructor formal owner are
            // intentionally different identities. Binding rows retain the
            // class as their resolved target, while signature selection joins
            // the constructor declaration that owns the formals.
            let owner = formal_owner_for_callee(analyzer, &unit);
            let signature_unit = owner.as_ref().map(|(owner, _)| owner).unwrap_or(&unit);
            let signature_declaration = indexed.get(analyzer, signature_unit);
            let selection = signature_declaration.as_ref().map(|declaration| {
                selected_signature(analyzer, declaration, shape.report.arguments.len())
            });
            let signature_id = selection
                .as_ref()
                .and_then(|selection| selection.signature_id.clone());
            let signature_ambiguous = selection
                .as_ref()
                .map(|selection| selection.ambiguous)
                .unwrap_or_else(|| {
                    signature_set_is_ambiguous(
                        analyzer,
                        signature_unit,
                        shape.report.arguments.len(),
                    )
                });
            let contract = selection.and_then(|selection| selection.receiver_contract);
            // A layout nobody recorded is stated, never defaulted to "no
            // parameters": an empty parameter list and an unread one are
            // different answers about the same callable.
            let layout = owner
                .as_ref()
                .and_then(|(owner, _)| bindings.formal_layout(analyzer, owner));
            let target = if signature_ambiguous {
                CallBindingTarget::Ambiguous
            } else {
                match (owner, layout) {
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
                }
            };
            (target, declaration, signature_id, Some(source_target))
        }
        ResolvedCallTarget::Ambiguous => (CallBindingTarget::Ambiguous, None, None, None),
        ResolvedCallTarget::Unresolved => (CallBindingTarget::Unresolved, None, None, None),
    };

    let dispatch_answer =
        semantic.map(|semantic| semantic.dispatch_at_source(&file, shape.report.outcome.range));
    let has_semantic = dispatch_answer.is_some();
    let dispatch = dispatch_answer
        .as_ref()
        .map_or_else(CallBindingDispatch::unavailable, |answer| {
            CallBindingDispatch::from_answer(answer, source_target.as_ref(), None)
        });
    let mut model_id = None;
    let mut model_callable_id = None;
    let mut formal_layout_id = None;
    let mut pack_id = None;
    let mut receiver_type_id = None;
    let mut semantic_target_id = source_target
        .as_ref()
        .and_then(|_| dispatch.target_id.clone());
    let mut target_origin = source_target.as_ref().map(|_| "source");
    let mut semantic_model_provenance = None;
    let mut modeled_key = None;
    let mut model_static_selector_proven = false;
    let mut model_layout_compatible = false;
    // A unique model record can describe the source resolver's declaration
    // even when runtime dispatch remains open. Keep those two facts separate:
    // model provenance never upgrades the dispatch proof below.
    if let Some(source_target) = source_target.as_ref() {
        match model_provenance_for_source_target(analyzer, source_target) {
            SourceTargetModelProvenance::Absent => {}
            SourceTargetModelProvenance::Exact {
                model_id: resolved_model_id,
                model_callable_id: resolved_model_callable_id,
                receiver_type_id: resolved_receiver_type_id,
                provenance,
                key,
            } => {
                model_id = Some(resolved_model_id);
                model_callable_id = Some(resolved_model_callable_id);
                pack_id = Some(provenance.pack_id.clone());
                receiver_type_id = resolved_receiver_type_id;
                semantic_model_provenance = Some(provenance);
                modeled_key = Some(key);
            }
            SourceTargetModelProvenance::Incomplete {
                model_id: incomplete_model_id,
                provenance,
            } => {
                model_id = incomplete_model_id;
                pack_id = provenance.as_ref().map(|value| value.pack_id.clone());
                semantic_model_provenance = provenance;
                diagnostics.push(CodeQueryDiagnostic {
                    code: CodeQueryDiagnosticCode::SemanticAnalysisPartial,
                    impact: CodeQueryDiagnosticImpact::Incomplete,
                    branch: Vec::new(),
                    language: crate::analyzer::common::language_for_file(&file).config_label(),
                    message: "call_bindings found incomplete or conflicting semantic-model provenance for an exact source target".to_owned(),
                });
            }
        }
    }
    if source_target.is_none()
        && let Some(arm) = dispatch_answer.as_ref().and_then(|answer| {
            (answer.arms.len() == 1
                && answer.arms[0].target_unit.is_none()
                && answer.arms[0].unmaterialized_target.is_some())
            .then(|| &answer.arms[0])
        })
    {
        match model_call_binding(analyzer, arm, shape) {
            ModelCallBinding::Unique {
                layout,
                receiver,
                key,
                model_id: resolved_model_id,
                model_callable_id: resolved_model_callable_id,
                pack_id: resolved_pack_id,
                receiver_type_id: resolved_receiver_type_id,
                signature_id: resolved_signature_id,
                semantic_model_provenance: resolved_provenance,
            } => {
                model_static_selector_proven = dispatch_answer
                    .as_ref()
                    .is_some_and(resolver_proven_static_model_selector);
                target = CallBindingTarget::ResolvedExternal { layout, receiver };
                signature_id = Some(resolved_signature_id);
                model_id = Some(resolved_model_id);
                model_callable_id = Some(resolved_model_callable_id);
                formal_layout_id = signature_id.clone();
                pack_id = Some(resolved_pack_id);
                receiver_type_id = resolved_receiver_type_id;
                semantic_target_id = Some(arm.target_id.clone());
                target_origin = Some("semantic_model");
                semantic_model_provenance = Some(resolved_provenance);
                modeled_key = Some(key);
            }
            ModelCallBinding::CompatibleLayout {
                layout,
                receiver,
                key,
                model_callable_id: resolved_model_callable_id,
                formal_layout_id: resolved_formal_layout_id,
                pack_id: resolved_pack_id,
                receiver_type_id: resolved_receiver_type_id,
            } => {
                model_static_selector_proven = dispatch_answer
                    .as_ref()
                    .is_some_and(resolver_proven_static_model_selector);
                model_layout_compatible = true;
                model_callable_id = Some(resolved_model_callable_id);
                formal_layout_id = Some(resolved_formal_layout_id);
                target = CallBindingTarget::ResolvedExternal { layout, receiver };
                pack_id = Some(resolved_pack_id);
                receiver_type_id = resolved_receiver_type_id;
                semantic_target_id = Some(arm.target_id.clone());
                target_origin = Some("semantic_model");
                modeled_key = Some(key);
            }
            ModelCallBinding::Conflict => {
                target = CallBindingTarget::Ambiguous;
            }
            ModelCallBinding::Incomplete {
                model_id: incomplete_model_id,
                pack_id: incomplete_pack_id,
                reason,
                semantic_model_provenance: incomplete_provenance,
            } => {
                target = CallBindingTarget::Unresolved;
                model_id = incomplete_model_id;
                pack_id = incomplete_pack_id;
                target_origin = incomplete_provenance.as_ref().map(|_| "semantic_model");
                semantic_model_provenance = incomplete_provenance;
                diagnostics.push(CodeQueryDiagnostic {
                    code: CodeQueryDiagnosticCode::SemanticAnalysisPartial,
                    impact: CodeQueryDiagnosticImpact::Incomplete,
                    branch: Vec::new(),
                    language: crate::analyzer::common::language_for_file(&file).config_label(),
                    message: format!(
                        "call_bindings semantic model callable is incomplete: {reason:?}"
                    ),
                });
            }
            ModelCallBinding::Empty | ModelCallBinding::Unavailable => {
                target = CallBindingTarget::Unresolved;
            }
        }
    }

    if model_callable_id.is_none() {
        model_callable_id = model_id.clone();
    }
    if formal_layout_id.is_none() {
        formal_layout_id = signature_id.clone();
    }
    let report = Arc::new(call_binding_report(&file, &shape.report, target));
    // The owner identity is meaningful only when this call's shared binder
    // emitted an exact receiver/implicit row. In particular, do not attach a
    // model member's owner to static, unestablished, or terminal rows.
    if report.rows.iter().any(|row| {
        matches!(
            row.binding_kind,
            Some(crate::analyzer::usages::call_binding::CallBindingKind::Receiver)
                | Some(crate::analyzer::usages::call_binding::CallBindingKind::Implicit)
        ) && matches!(row.mapping, CallBindingMapping::Exact)
    }) {
        if receiver_type_id.is_none()
            && let Some(source_target) = source_target.as_ref()
        {
            receiver_type_id = analyzer
                .parent_of(source_target)
                .map(|parent| parent.declaration_id().to_string());
        }
    } else {
        receiver_type_id = None;
    }
    let binding_is_exact = matches!(report.coverage, CallBindingCoverage::Exhaustive)
        && (signature_id.is_some() || model_layout_compatible)
        && report
            .rows
            .iter()
            .all(|row| matches!(row.mapping, CallBindingMapping::Exact));
    let selector = if binding_is_exact && (dispatch.is_exact() || model_static_selector_proven) {
        CallBindingSelectorProof::derived()
    } else if binding_is_exact {
        dispatch_answer
            .as_ref()
            .and_then(|answer| {
                let key = modeled_key.as_ref()?;
                match source_target.as_ref() {
                    Some(target) => {
                        authored_selector_proof_for_source_target(analyzer, answer, target, key)
                    }
                    None => authored_selector_proof_for_external_target(analyzer, answer, key),
                }
            })
            .unwrap_or_else(CallBindingSelectorProof::unavailable)
    } else {
        CallBindingSelectorProof::unavailable()
    };
    if has_semantic && !binding_is_exact {
        diagnostics.push(CodeQueryDiagnostic {
            code: CodeQueryDiagnosticCode::SemanticAnalysisPartial,
            impact: CodeQueryDiagnosticImpact::Incomplete,
            branch: Vec::new(),
            language: crate::analyzer::common::language_for_file(&file).config_label(),
            message: format!(
                "call_bindings did not establish complete actual-to-formal coverage (dispatch outcome={}, coverage={}, target_count={}, binding coverage={})",
                dispatch.outcome,
                dispatch.coverage,
                dispatch.target_count,
                report.coverage.label(),
            ),
        });
    } else if has_semantic && !selector.exact {
        diagnostics.push(CodeQueryDiagnostic {
            code: CodeQueryDiagnosticCode::CallBindingDispatchPartial,
            impact: CodeQueryDiagnosticImpact::Incomplete,
            branch: Vec::new(),
            language: crate::analyzer::common::language_for_file(&file).config_label(),
            message: format!(
                "call_bindings established an exact declared target and actual-to-formal mapping, but exact selector proof remains unavailable (dispatch outcome={}, coverage={}, target_count={})",
                dispatch.outcome, dispatch.coverage, dispatch.target_count,
            ),
        });
    }
    let site = CallBindingSiteValue {
        report,
        target: declaration,
        signature_id,
        model_callable_id,
        formal_layout_id,
        dispatch,
        selector,
        semantic_target_id,
        target_origin,
        model_id,
        pack_id,
        semantic_model_provenance,
        receiver_type_id,
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

/// The exact call partition already published by the shared shape relation.
/// Missing or non-exact coverage is typed unknown; no source reparse happens
/// here, and no argument is inferred from a callee display string.
fn structured_model_application(shape: &CallShapeValue) -> SemanticModelCallApplication {
    if shape.report.outcome.coverage != CallShapeCoverage::Exact {
        return SemanticModelCallApplication::Unknown;
    }

    let mut positional_count = 0usize;
    let mut named_labels = Vec::new();
    let mut has_spread = false;
    for argument in &shape.report.arguments {
        has_spread |= argument.spread;
        if let Some(name) = argument.name.as_ref() {
            named_labels.push(name.clone());
        } else if !argument.spread {
            positional_count += 1;
        }
    }
    SemanticModelCallApplication::structured(positional_count, named_labels, has_spread)
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
///
/// The resolution itself runs through `bindings`' per-file prefetch (issue
/// #2765): the first call site of a file resolves every call site's callee
/// range in one batch, and every other call site of that file is served from
/// the cached outcome instead of re-deriving a fresh per-file resolution
/// context. This changes nothing about which resolver runs or what it
/// answers -- same resolver, same per-request outcome -- only how many times
/// its shared per-file setup work is paid.
fn resolve_call_target(
    analyzer: &dyn IAnalyzer,
    shape: &CallShapeValue,
    bindings: &mut CallBindingCache,
    cancellation: Option<&CancellationToken>,
) -> ResolvedCallTarget {
    let outcome = &shape.report.outcome;
    let Some(callee_range) = outcome.callee_range else {
        return ResolvedCallTarget::Unresolved;
    };
    let Some(lookup) =
        bindings.resolved_call_target(analyzer, &outcome.file, callee_range, cancellation)
    else {
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
    /// More than one structurally different signature accepts the written
    /// arity. Without a language-owned applicability/type verdict, no formal
    /// layout may be selected from that set.
    ambiguous: bool,
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
/// An entry whose arity the adapter never recorded normally makes the whole
/// set undecidable. There is one conservative exception: two declaration-only
/// overload headers that each publish exactly as many parameter rows as the
/// call writes are both possible targets. That proves ambiguity without
/// pretending to perform the language's missing type-applicability step.
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
    signature_choice(&reports, actual_count)
}

/// Whether a source target whose declaration-site projection is unavailable
/// still publishes an overload set that the written arity cannot distinguish.
/// The temporary row-id anchor is never rendered; selection reads only the
/// adapter-owned arity and parameter metadata.
fn signature_set_is_ambiguous(
    analyzer: &dyn IAnalyzer,
    unit: &CodeUnit,
    actual_count: usize,
) -> bool {
    let entries = analyzer.signature_metadata(unit);
    let reports = callable_signature_reports("unprojected-source-target", unit, &entries);
    signature_choice(&reports, actual_count).ambiguous
}

fn signature_choice(reports: &[CallableSignatureReport], actual_count: usize) -> SelectedSignature {
    let (selected, mut ambiguous) = match reports {
        [] => (None, false),
        [only] => (Some(only), false),
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
                [only] => (Some(*only), false),
                [first, rest @ ..]
                    if rest
                        .iter()
                        .all(|report| declares_the_same_parameters(first, report)) =>
                {
                    (
                        accepting
                            .iter()
                            .copied()
                            .find(|report| !report.signature.declaration_only)
                            .or(Some(*first)),
                        false,
                    )
                }
                [_, _, ..] => (None, true),
                [] => (None, false),
            }
        }
        _ => (None, false),
    };
    if selected.is_none() && !ambiguous {
        ambiguous = reports
            .iter()
            .filter(|report| {
                report.signature.declaration_only
                    && report.signature.parameter_count == actual_count
            })
            .take(2)
            .count()
            == 2;
    }
    SelectedSignature {
        signature_id: selected.map(|report| report.signature.id.clone()),
        ambiguous,
        receiver_contract: selected
            .map(|report| report.signature.receiver_contract)
            .unwrap_or_else(|| agreed_receiver_contract(reports)),
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
