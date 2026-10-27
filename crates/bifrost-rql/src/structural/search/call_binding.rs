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
use crate::analyzer::semantic::UnmaterializedExternalTarget;
use crate::analyzer::semantic::{ClassIdentity, LengthDelimitedDigest, MemberDeclaration};
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
use crate::analyzer::usages::call_conversion::ConversionUnknown;
use crate::analyzer::usages::call_relations::{
    formal_owner_for_callee, python_first_formal_is_bound,
};
use crate::analyzer::usages::callable_signature::{
    SelectedSignature, callable_signature_reports, signature_choice,
};
use crate::analyzer::usages::effects::ModeledProcedureKey;
use crate::analyzer::usages::get_definition::{
    DefinitionLookupDiagnostic, DefinitionLookupStatus, DefinitionResolutionAuthority,
};
use brokk_bifrost_core::analyzer::structural::callable::{
    ArgumentListKind, CallKind, CallShapeCoverage, ReceiverContract,
};

use super::dispatch::DispatchSiteAnswer;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CallBindingIdentityRequest {
    None,
    PathIdentityAndProgramPoint,
    ProgramPoint,
}

impl CallBindingIdentityRequest {
    fn needs_program_point(self) -> bool {
        matches!(self, Self::PathIdentityAndProgramPoint | Self::ProgramPoint)
    }
}

/// One derived binding report shared by every row of one call site, beside the
/// rendering of the target the report named.
#[derive(Debug, Clone)]
pub(super) struct CallBindingSiteValue {
    pub(super) report: Arc<CallBindingReport>,
    /// The exact call-shape report that supplied the actual argument rows.
    pub(super) shape: CallShapeValue,
    /// The target rendered as a workspace declaration, when the workspace
    /// indexes an exact range for it.
    pub(super) target: Option<DeclarationValue>,
    /// Process-independent identity of the workspace declaration selected by
    /// the production resolver. Unlike the rendered declaration `id`, this is
    /// independent of source ranges and is suitable for policy predicates.
    pub(super) declared_target_id: Option<String>,
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
    /// Exact aliases declared by the selected semantic-model member. These
    /// are identity locators, not display-name fallbacks.
    pub(super) model_aliases: Vec<String>,
    pub(super) pack_id: Option<String>,
    pub(super) semantic_model_provenance: Option<Arc<SemanticModelProvenance>>,
    /// Stable identity of the type that owns this callable's receiver, when
    /// the shared binder establishes one. An exact model owner takes
    /// precedence; otherwise this is the source declaration identity. It is
    /// never a qualified/display name.
    pub(super) receiver_type_id: Option<String>,
    /// Resolver-owned semantic identity for a modeled callable. Format
    /// relations use this structured key to select a reviewed library
    /// contract; they never infer a library from the callee display name.
    pub(super) modeled_key: Option<ModeledProcedureKey>,
    /// Exact semantic program point of the modeled call, when the source call
    /// maps uniquely into the semantic artifact.
    pub(super) program_point_id: Option<String>,
    /// Query-local lexical binding identities for actual arguments, aligned
    /// with `report.rows`. A missing identity is structured unknown.
    pub(super) binding_ids: Vec<Option<String>>,
    /// Correlation identity for a path argument: a lexical binding identity
    /// or a direct decoded literal, with disjoint prefixes so the two domains
    /// cannot compare equal accidentally.
    pub(super) path_identities: Vec<Option<String>>,
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
        self.outcome == "resolved"
            && self.coverage == "exhaustive"
            && self.proof == Some("proven")
            && self.completeness == Some("complete")
            && self.target_count > 0
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

    fn from_receiver_proof_targets(target_ids: &[String]) -> Self {
        assert!(
            !target_ids.is_empty(),
            "receiver proof has at least one target"
        );
        Self {
            target_id: (target_ids.len() == 1).then(|| target_ids[0].clone()),
            proof: Some("proven"),
            completeness: Some("complete"),
            outcome: "resolved",
            coverage: "exhaustive",
            target_count: target_ids.len(),
            targets_truncated: false,
        }
    }

    fn from_resolver_owned_external(target_id: &str) -> Self {
        Self {
            target_id: Some(target_id.to_owned()),
            proof: Some("proven"),
            completeness: Some("complete"),
            outcome: "resolved",
            coverage: "exhaustive",
            target_count: 1,
            targets_truncated: false,
        }
    }

    fn keep_open_for_receiver_evidence(&mut self) {
        self.outcome = "unproven";
        self.coverage = "open";
        if self.target_id.is_some() {
            self.proof = Some("unproven");
            self.completeness = Some("partial");
        }
    }
}

fn receiver_proof_can_close_dispatch(
    answer: &DispatchSiteAnswer,
    proof: &super::type_flow::ExactReceiverDispatchProof,
) -> bool {
    let named_targets = !proof.targets.is_empty()
        && !answer.arms.is_empty()
        && answer.arms.iter().all(|arm| arm.proof == "proven")
        && matches!(answer.outcome, "resolved" | "unproven");
    let unresolved_targets = !proof.targets.is_empty()
        && answer.arms.is_empty()
        && answer.outcome == "unknown"
        && answer.unnamed_boundaries.as_slice() == ["unresolved"];
    answer.call_site_count == 1
        && (named_targets || unresolved_targets)
        && !answer.coverage.is_truncated()
        && answer.semantic_unsupported.is_none()
        && answer.exceeded_limit.is_none()
        && (answer.unnamed_boundaries.is_empty()
            || is_authored_override_residual(&answer.unnamed_boundaries))
        && answer.call_contexts.len() == 1
        && answer.call_contexts[0].unnamed_boundaries == answer.unnamed_boundaries
}

fn receiver_proven_arms<'a>(
    analyzer: &dyn IAnalyzer,
    answer: &'a DispatchSiteAnswer,
    proof: &super::type_flow::ExactReceiverDispatchProof,
    source_target: Option<&CodeUnit>,
    semantic_target_id: Option<&str>,
) -> Option<Vec<&'a super::dispatch::DispatchArm>> {
    if !receiver_proof_can_close_dispatch(answer, proof) {
        return None;
    }
    if answer.arms.is_empty() {
        return Some(Vec::new());
    }
    let mut matched = Vec::new();
    for (class, declaration) in &proof.targets {
        let semantic_model_id = match declaration {
            MemberDeclaration::External(declaration) => {
                let [member_id] = declaration.symbol_ids() else {
                    return None;
                };
                Some(member_id.as_ref())
            }
            MemberDeclaration::Workspace(_) => None,
        };
        let candidates = answer
            .arms
            .iter()
            .filter(|arm| {
                receiver_proven_arm_for_target(
                    analyzer,
                    arm,
                    proof,
                    (class, declaration),
                    source_target,
                    semantic_target_id,
                    semantic_model_id,
                )
            })
            .collect::<Vec<_>>();
        let [arm] = candidates.as_slice() else {
            return None;
        };
        matched.push(*arm);
    }
    let matched_ids = matched
        .iter()
        .map(|arm| arm.target_id.as_str())
        .collect::<std::collections::HashSet<_>>();
    if matched_ids.len() != answer.arms.len()
        || answer
            .arms
            .iter()
            .any(|arm| !matched_ids.contains(arm.target_id.as_str()))
    {
        return None;
    }
    matched.sort_by(|left, right| left.target_id.cmp(&right.target_id));
    matched.dedup_by(|left, right| left.target_id == right.target_id);
    Some(matched)
}

fn receiver_proven_arm_for_target(
    analyzer: &dyn IAnalyzer,
    arm: &super::dispatch::DispatchArm,
    proof: &super::type_flow::ExactReceiverDispatchProof,
    target: (&ClassIdentity, &MemberDeclaration),
    source_target: Option<&CodeUnit>,
    semantic_target_id: Option<&str>,
    semantic_model_id: Option<&str>,
) -> bool {
    let (class, declaration) = target;
    if semantic_target_id.is_some_and(|target| target != arm.target_id)
        || source_target.is_some_and(|target| arm.target_unit.as_ref() != Some(target))
    {
        return false;
    }
    match (class, declaration) {
        (ClassIdentity::Workspace(_), MemberDeclaration::Workspace(declaration)) => {
            declaration.terminal_name() == proof.member
                && arm.target_unit.as_ref() == Some(declaration)
                && source_target.is_none_or(|target| target == declaration)
        }
        (ClassIdentity::External { .. }, MemberDeclaration::External(declaration)) => {
            let Some(identity) = arm.external_callee_identity.as_ref() else {
                return false;
            };
            let Some(overlay) = analyzer.semantic_model_overlay() else {
                return false;
            };
            let mut declaring_owners = Vec::new();
            let mut declared_member_ids = Vec::new();
            for symbol_id in declaration.symbol_ids() {
                let matched = overlay.symbols_with_id(symbol_id);
                let [symbol] = matched.records.as_slice() else {
                    return false;
                };
                if symbol.id != symbol_id.as_ref()
                    || symbol.name != proof.member
                    || symbol.language != Language::Python.config_label()
                    || symbol.kind
                        != crate::analyzer::semantic_model::SemanticModelSymbolKind::Method
                    || !symbol.has_receiver()
                    || symbol.provenance.ambiguous
                {
                    return false;
                }
                let Some(owner_id) = symbol.owner_id.as_deref() else {
                    return false;
                };
                let owner = overlay.symbols_with_id(owner_id);
                let [owner] = owner.records.as_slice() else {
                    return false;
                };
                if owner.kind != crate::analyzer::semantic_model::SemanticModelSymbolKind::Class
                    || owner.language != Language::Python.config_label()
                    || owner.provenance.ambiguous
                {
                    return false;
                }
                declaring_owners.push(owner.qualified_name.clone());
                declared_member_ids.push(symbol.id.clone());
            }
            if declaring_owners.is_empty()
                || declaring_owners
                    .iter()
                    .any(|owner| *owner != declaring_owners[0])
            {
                return false;
            }
            let mut selected_symbols = Vec::new();
            if let Some(target) = arm.exact_external_target.as_ref() {
                selected_symbols.push(target.symbol());
            }
            if let Some(symbol) = semantic_model_id {
                selected_symbols.push(symbol);
            }
            source_target.is_none()
                && identity.owner_fqn() == declaring_owners[0]
                && identity.member() == proof.member
                && !selected_symbols.is_empty()
                && selected_symbols.iter().all(|selected| {
                    declared_member_ids
                        .iter()
                        .any(|declared| declared == selected)
                })
        }
        _ => false,
    }
}

#[derive(Clone)]
enum ModelCallBinding {
    Unique {
        python_constructor: bool,
        layout: FormalParameterLayout,
        receiver: CallReceiverBinding,
        key: Box<ModeledProcedureKey>,
        model_id: String,
        model_callable_id: String,
        pack_id: String,
        receiver_type_id: Option<String>,
        signature_id: String,
        signature: Box<crate::analyzer::semantic_model::Signature>,
        semantic_model_provenance: Arc<SemanticModelProvenance>,
        model_aliases: Vec<String>,
    },
    CompatibleLayout {
        layout: FormalParameterLayout,
        receiver: CallReceiverBinding,
        key: Box<ModeledProcedureKey>,
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
    ConversionUnavailable {
        model_id: Option<String>,
        pack_id: Option<String>,
        reason: ConversionUnknown,
        semantic_model_provenance: Option<Arc<SemanticModelProvenance>>,
    },
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
            let names = parameter.name.clone().into_iter().collect();
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
                names,
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
    has_receiver: bool,
    implicit_constructor: bool,
    shape: &CallShapeValue,
) -> CallReceiverBinding {
    if has_receiver {
        if implicit_constructor && shape.report.outcome.receiver_range.is_none() {
            CallReceiverBinding::Implicit {
                declared_first_ordinary: false,
            }
        } else {
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
        }
    } else {
        CallReceiverBinding::Absent
    }
}

/// Whether this Java constructor's source facts state every actual position.
/// This can support formal binding without claiming that any overload applies.
fn exact_java_constructor_shape(shape: &CallShapeValue) -> bool {
    shape.report.outcome.coverage == CallShapeCoverage::Exact
        && shape.report.outcome.call_kind == CallKind::Constructor
        && shape.report.groups.len() <= 1
        && shape
            .report
            .groups
            .iter()
            .all(|group| group.kind == ArgumentListKind::Ordinary)
        && shape
            .report
            .arguments
            .iter()
            .all(|argument| argument.name.is_none() && !argument.spread)
}

fn model_call_bindings_for_receiver_proof(
    analyzer: &dyn IAnalyzer,
    proof: &super::type_flow::ExactReceiverDispatchProof,
    shape: &CallShapeValue,
) -> Option<Vec<ModelCallBinding>> {
    let mut bindings = Vec::new();
    let mut model_ids = std::collections::HashSet::new();
    let mut signature: Option<crate::analyzer::semantic_model::Signature> = None;
    for (class, declaration) in &proof.targets {
        let binding = model_call_binding_for_receiver_target(
            analyzer,
            class,
            declaration,
            &proof.member,
            shape,
        );
        let ModelCallBinding::Unique {
            model_id,
            signature: current_signature,
            ..
        } = &binding
        else {
            return None;
        };
        if signature
            .as_ref()
            .is_some_and(|signature| signature != current_signature.as_ref())
        {
            return None;
        }
        signature.get_or_insert_with(|| current_signature.as_ref().clone());
        if model_ids.insert(model_id.clone()) {
            bindings.push(binding);
        }
    }
    (!bindings.is_empty()).then_some(bindings)
}

fn model_call_binding_for_receiver_target(
    analyzer: &dyn IAnalyzer,
    class: &ClassIdentity,
    declaration: &MemberDeclaration,
    member_name: &str,
    shape: &CallShapeValue,
) -> ModelCallBinding {
    let (
        crate::analyzer::semantic::ClassIdentity::External {
            symbol_id: owner_id,
            ..
        },
        MemberDeclaration::External(declaration),
    ) = (class, declaration)
    else {
        return ModelCallBinding::Unavailable;
    };
    let Some(overlay) = analyzer.semantic_model_overlay() else {
        return ModelCallBinding::Unavailable;
    };
    let [member_id] = declaration.symbol_ids() else {
        return ModelCallBinding::Unavailable;
    };
    let matched_member = overlay.symbols_with_id(member_id);
    let [member] = matched_member.records.as_slice() else {
        return ModelCallBinding::Unavailable;
    };
    if member.provenance.ambiguous
        || member_id.as_ref() != member.id
        || member.owner_id.is_none()
        || member.name != member_name
        || member.language != Language::Python.config_label()
        || !member.has_receiver()
        || member.kind != crate::analyzer::semantic_model::SemanticModelSymbolKind::Method
        || !member.has_complete_callable_shape_evidence()
    {
        return ModelCallBinding::Unavailable;
    }
    let Some(declaring_owner_id) = member.owner_id.as_deref() else {
        return ModelCallBinding::Unavailable;
    };
    let declaring_owner_match = overlay.symbols_with_id(declaring_owner_id);
    let [declaring_owner] = declaring_owner_match.records.as_slice() else {
        return ModelCallBinding::Unavailable;
    };
    if declaring_owner.kind != crate::analyzer::semantic_model::SemanticModelSymbolKind::Class
        || declaring_owner.language != Language::Python.config_label()
        || declaring_owner.provenance.ambiguous
    {
        return ModelCallBinding::Unavailable;
    }
    let Some(signature) = member.structured_signature() else {
        return ModelCallBinding::Incomplete {
            model_id: Some(member.id.clone()),
            pack_id: Some(member.provenance.pack_id.clone()),
            reason: SemanticModelCallableIncompleteReason::MissingSignature,
            semantic_model_provenance: Some(Arc::new(member.provenance.clone())),
        };
    };
    let Ok(parameter_count) = u32::try_from(signature.parameters.len()) else {
        return ModelCallBinding::Unavailable;
    };
    let modeled_key = ModeledProcedureKey {
        language: Language::Python.config_label().to_owned(),
        owner: declaring_owner.qualified_name.clone(),
        member: member_name.to_owned(),
        has_receiver: true,
        parameter_count,
    };
    let key = SemanticModelCallableKey::new(
        &modeled_key.language,
        &modeled_key.owner,
        &modeled_key.member,
        modeled_key.has_receiver,
        modeled_key.parameter_count,
    );
    let matched = overlay.callable_for_application(key, &structured_model_application(shape));
    let Some(selected) = matched.unique() else {
        return ModelCallBinding::Unavailable;
    };
    if selected.id != member.id {
        return ModelCallBinding::Unavailable;
    }
    let model_callable_id = overlay
        .callable_family_id_for_target(key)
        .unwrap_or_else(|| member.id.clone());
    let signature_id = model_signature_id(&member.id, signature);
    ModelCallBinding::Unique {
        python_constructor: false,
        layout: model_formal_layout(signature, shape),
        receiver: model_receiver_binding(true, false, shape),
        key: Box::new(modeled_key),
        model_id: member.id.clone(),
        model_callable_id,
        pack_id: member.provenance.pack_id.clone(),
        receiver_type_id: Some(owner_id.to_string()),
        signature_id,
        signature: Box::new(signature.clone()),
        semantic_model_provenance: Arc::new(member.provenance.clone()),
        model_aliases: member.aliases.clone(),
    }
}

fn model_call_binding(
    analyzer: &dyn IAnalyzer,
    arm: &super::dispatch::DispatchArm,
    shape: &CallShapeValue,
    bindings: &mut CallBindingCache,
) -> ModelCallBinding {
    if let Some(binding) = model_python_constructor_binding(analyzer, arm, shape) {
        return binding;
    }
    let identity = arm.external_callee_identity.as_ref();
    let unmaterialized = arm.unmaterialized_target.as_ref();
    let Some((language, owner, member, has_receiver, arity)) = identity
        .and_then(|identity| {
            let has_receiver = arm
                .exact_external_target
                .as_ref()
                .map(|target| target.has_receiver())
                .or_else(|| unmaterialized.map(|target| target.has_receiver()))?;
            let arity = arm
                .exact_external_target
                .as_ref()
                .map(|target| target.parameter_count())
                .or_else(|| unmaterialized.map(|target| target.arity()))?;
            Some((
                identity.language().config_label(),
                identity.owner_fqn(),
                identity.member(),
                has_receiver,
                arity,
            ))
        })
        .or_else(|| {
            unmaterialized.map(|target| {
                (
                    target.language().semantic_pack_label(),
                    target.owner_fqn(),
                    target.member(),
                    target.has_receiver(),
                    target.arity(),
                )
            })
        })
        .or_else(|| {
            let identity = identity?;
            if identity.language() != Language::Java
                || identity.member() != "<init>"
                || !exact_java_constructor_shape(shape)
            {
                return None;
            }
            Some((
                identity.language().config_label(),
                identity.owner_fqn(),
                identity.member(),
                false,
                u32::try_from(shape.report.arguments.len()).ok()?,
            ))
        })
    else {
        return ModelCallBinding::Unavailable;
    };
    let modeled_key = ModeledProcedureKey {
        language: language.to_owned(),
        owner: owner.to_owned(),
        member: member.to_owned(),
        has_receiver,
        parameter_count: arity,
    };
    model_call_binding_for_external_shape(
        analyzer,
        modeled_key,
        arm.exact_external_target.as_ref(),
        shape,
        bindings,
    )
}

fn model_call_binding_for_external_dispatch(
    analyzer: &dyn IAnalyzer,
    target: &crate::analyzer::usages::call_relations::ResolverOwnedExternalCallDispatch,
    shape: &CallShapeValue,
    bindings: &mut CallBindingCache,
) -> ModelCallBinding {
    let identity = target.identity();
    let modeled_key = ModeledProcedureKey {
        language: identity.language().config_label().to_owned(),
        owner: identity.owner_fqn().to_owned(),
        member: identity.member().to_owned(),
        has_receiver: target.has_receiver(),
        parameter_count: target.parameter_count(),
    };
    model_call_binding_for_external_shape(analyzer, modeled_key, None, shape, bindings)
}

fn model_call_binding_for_external_shape(
    analyzer: &dyn IAnalyzer,
    modeled_key: ModeledProcedureKey,
    exact_external_target: Option<&crate::analyzer::semantic::ExactExternalProcedureTarget>,
    shape: &CallShapeValue,
    bindings: &mut CallBindingCache,
) -> ModelCallBinding {
    let implicit_constructor = modeled_key.language == Language::Python.config_label()
        && modeled_key.member == "__init__"
        && modeled_key.has_receiver
        && shape.report.outcome.receiver_range.is_none();
    let Some(overlay) = analyzer.semantic_model_overlay() else {
        return ModelCallBinding::Unavailable;
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
    let exact_target_matches = |symbol: &crate::analyzer::semantic_model::SemanticModelSymbol| {
        exact_external_target.is_none_or(|target| {
            symbol.has_exact_artifact_locator(target.procedure().path().as_str(), target.symbol())
        })
    };
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
            if !exact_target_matches(&symbol) {
                return ModelCallBinding::Conflict;
            }
            let Some(signature) = symbol.structured_signature() else {
                return ModelCallBinding::Incomplete {
                    model_id: model_id.clone(),
                    pack_id: provenance.as_ref().map(|value| value.pack_id.clone()),
                    reason: SemanticModelCallableIncompleteReason::MissingSignature,
                    semantic_model_provenance: provenance,
                };
            };
            let layout = model_formal_layout(signature, shape);
            let receiver =
                model_receiver_binding(modeled_key.has_receiver, implicit_constructor, shape);
            let Some(model_provenance) = provenance else {
                return ModelCallBinding::Unavailable;
            };
            let model_id = symbol.id.clone();
            let pack_id = model_provenance.pack_id.clone();
            let signature_id = model_signature_id(&model_id, signature);
            let Some(model_callable_id) = model_callable_id else {
                return ModelCallBinding::Conflict;
            };
            let receiver_type_id = modeled_key
                .has_receiver
                .then(|| symbol.owner_id.clone())
                .flatten();
            ModelCallBinding::Unique {
                python_constructor: false,
                layout,
                receiver,
                key: Box::new(modeled_key),
                model_id,
                model_callable_id,
                pack_id,
                receiver_type_id,
                signature_id,
                signature: Box::new(signature.clone()),
                semantic_model_provenance: model_provenance,
                model_aliases: symbol.aliases.clone(),
            }
        }
        SemanticModelCallableDisposition::CompatibleLayout => {
            let Some(symbol) = matched.records.first().cloned() else {
                return ModelCallBinding::Unavailable;
            };
            let Some(signature) = symbol.structured_signature() else {
                return ModelCallBinding::Unavailable;
            };
            let Some(model_callable_id) = model_callable_id else {
                return ModelCallBinding::Conflict;
            };
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
            let language = crate::analyzer::common::language_for_file(&shape.report.outcome.file);
            if !matches!(language, Language::Java | Language::CSharp) {
                let receiver_type_id = modeled_key
                    .has_receiver
                    .then(|| symbol.owner_id.clone())
                    .flatten();
                return ModelCallBinding::CompatibleLayout {
                    layout: model_formal_layout(signature, shape),
                    receiver: model_receiver_binding(
                        modeled_key.has_receiver,
                        implicit_constructor,
                        shape,
                    ),
                    key: Box::new(modeled_key),
                    model_callable_id: model_callable_id.clone(),
                    formal_layout_id: model_signature_id(&model_callable_id, signature),
                    pack_id,
                    receiver_type_id,
                };
            }
            let candidates = matched
                .records
                .iter()
                .filter(|candidate| exact_target_matches(candidate))
                .filter_map(|candidate| {
                    let signature = candidate.structured_signature()?;
                    Some((candidate.id.clone(), signature.clone()))
                })
                .collect::<Vec<_>>();
            if exact_external_target.is_some() && candidates.is_empty() {
                return ModelCallBinding::Conflict;
            }
            match bindings.select_model_signature(
                analyzer,
                &shape.report,
                shape
                    .source
                    .as_deref()
                    .map(|source| (&shape.report.outcome.file, source)),
                &candidates,
            ) {
                Ok(Some((selected_model_id, selected_signature))) => {
                    let Some(selected_symbol) = matched
                        .records
                        .iter()
                        .find(|candidate| candidate.id == selected_model_id)
                    else {
                        return ModelCallBinding::Unavailable;
                    };
                    let receiver_type_id = if modeled_key.has_receiver {
                        selected_symbol.owner_id.clone()
                    } else {
                        None
                    };
                    let signature_id = model_signature_id(&selected_model_id, &selected_signature);
                    let layout = model_formal_layout(&selected_signature, shape);
                    ModelCallBinding::Unique {
                        python_constructor: false,
                        layout,
                        receiver: model_receiver_binding(
                            modeled_key.has_receiver,
                            implicit_constructor,
                            shape,
                        ),
                        key: Box::new(modeled_key),
                        model_id: selected_model_id,
                        model_callable_id,
                        pack_id,
                        receiver_type_id,
                        signature_id,
                        signature: Box::new(selected_signature),
                        semantic_model_provenance: Arc::new(selected_symbol.provenance.clone()),
                        model_aliases: selected_symbol.aliases.clone(),
                    }
                }
                Ok(None) => ModelCallBinding::ConversionUnavailable {
                    model_id: model_id.clone(),
                    pack_id: Some(pack_id),
                    reason: ConversionUnknown::SignatureApplicability,
                    semantic_model_provenance: provenance,
                },
                Err(reason) => ModelCallBinding::ConversionUnavailable {
                    model_id: model_id.clone(),
                    pack_id: Some(pack_id),
                    reason,
                    semantic_model_provenance: provenance,
                },
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

/// Bind a direct active-model class call through that class's declared
/// `__init__` signature. Python model signatures store the receiver separately
/// from ordinary parameters, so the allocated instance is implicit and does
/// not consume a formal slot.
fn model_python_constructor_binding(
    analyzer: &dyn IAnalyzer,
    arm: &super::dispatch::DispatchArm,
    shape: &CallShapeValue,
) -> Option<ModelCallBinding> {
    let (owner_fqn, member) = if let Some(identity) = arm.external_callee_identity.as_ref() {
        if identity.language() != Language::Python {
            return None;
        }
        (identity.owner_fqn(), identity.member())
    } else {
        let target = arm.unmaterialized_target.as_ref()?;
        if target.language().language() != Language::Python
            || !target.has_resolver_owned_call_shape()
            || target.has_receiver()
        {
            return None;
        }
        (target.owner_fqn(), target.member())
    };
    let overlay = analyzer.semantic_model_overlay()?;
    let canonical = format!("{owner_fqn}.{member}");
    let classes = overlay
        .symbols_named(&canonical)
        .records
        .into_iter()
        .filter(|symbol| {
            symbol.qualified_name == canonical
                && symbol.language == Language::Python.config_label()
                && symbol.kind == crate::analyzer::semantic_model::SemanticModelSymbolKind::Class
                && symbol.owner_id.is_none()
                && !symbol.provenance.ambiguous
        })
        .collect::<Vec<_>>();
    let [class] = classes.as_slice() else {
        return None;
    };
    let (initializer, declaring_class) = python_constructor_initializer(&overlay, class)?;
    let signature = initializer.structured_signature()?;
    let parameter_count = u32::try_from(signature.parameters.len()).ok()?;
    let modeled_key = ModeledProcedureKey {
        language: Language::Python.config_label().to_owned(),
        owner: declaring_class.qualified_name.clone(),
        member: "__init__".to_owned(),
        has_receiver: true,
        parameter_count,
    };
    // C3 has already selected the unique active initializer declaration.
    // Keep its signature even when this call's actuals do not match: RQL must
    // report the bad keyword or argument against that declaration.
    let key = SemanticModelCallableKey::new(
        &modeled_key.language,
        &modeled_key.owner,
        &modeled_key.member,
        true,
        parameter_count,
    );
    let model_callable_id = overlay
        .callable_family_id_for_target(key)
        .unwrap_or_else(|| initializer.id.clone());
    let signature_id = model_signature_id(&initializer.id, signature);
    Some(ModelCallBinding::Unique {
        python_constructor: true,
        layout: model_formal_layout(signature, shape),
        receiver: model_receiver_binding(true, true, shape),
        key: Box::new(modeled_key),
        model_id: initializer.id.clone(),
        model_callable_id,
        pack_id: initializer.provenance.pack_id.clone(),
        receiver_type_id: Some(class.id.clone()),
        signature_id,
        signature: Box::new(signature.clone()),
        semantic_model_provenance: Arc::new(initializer.provenance.clone()),
        model_aliases: initializer.aliases.clone(),
    })
}

#[derive(Debug)]
struct PythonConstructorMroFrame {
    class_id: String,
    bases: Option<Vec<String>>,
    next_base: usize,
}

fn python_constructor_initializer(
    overlay: &crate::analyzer::semantic_model::SemanticModelOverlay,
    class: &std::sync::Arc<crate::analyzer::semantic_model::SemanticModelSymbol>,
) -> Option<(
    std::sync::Arc<crate::analyzer::semantic_model::SemanticModelSymbol>,
    std::sync::Arc<crate::analyzer::semantic_model::SemanticModelSymbol>,
)> {
    let mut direct_initializers = overlay
        .members_of(&class.id)
        .records
        .into_iter()
        .filter(|symbol| {
            symbol.owner_id.as_deref() == Some(class.id.as_str())
                && symbol.name == "__init__"
                && symbol.language == Language::Python.config_label()
        })
        .collect::<Vec<_>>();
    direct_initializers.sort_by(|left, right| left.id.cmp(&right.id));
    direct_initializers.dedup_by(|left, right| left.id == right.id);
    if !direct_initializers.is_empty() {
        let [initializer] = direct_initializers.as_slice() else {
            return None;
        };
        if initializer.kind != crate::analyzer::semantic_model::SemanticModelSymbolKind::Method
            || !initializer.has_receiver()
            || initializer.provenance.ambiguous
            || initializer.provenance.completeness != SemanticModelCompleteness::Complete
            || !initializer.has_complete_callable_shape_evidence()
            || initializer.provenance.pack_id != class.provenance.pack_id
        {
            return None;
        }
        return Some((
            std::sync::Arc::clone(initializer),
            std::sync::Arc::clone(class),
        ));
    }
    if class.provenance.completeness != SemanticModelCompleteness::Complete {
        return None;
    }
    let mro = python_constructor_class_mro(overlay, &class.id)?;
    for class_id in mro.into_iter().skip(1) {
        let declaring_class_match = overlay.symbols_with_id(&class_id);
        let [declaring_class] = declaring_class_match.records.as_slice() else {
            return None;
        };
        let mut initializers = overlay
            .members_of(&class_id)
            .records
            .into_iter()
            .filter(|symbol| {
                symbol.owner_id.as_deref() == Some(class_id.as_str())
                    && symbol.name == "__init__"
                    && symbol.language == Language::Python.config_label()
            })
            .collect::<Vec<_>>();
        initializers.sort_by(|left, right| left.id.cmp(&right.id));
        initializers.dedup_by(|left, right| left.id == right.id);
        if initializers.is_empty() {
            continue;
        }
        let [initializer] = initializers.as_slice() else {
            return None;
        };
        if declaring_class.provenance.completeness != SemanticModelCompleteness::Complete
            || overlay
                .gapped_member_surface(&declaring_class.qualified_name, "__init__")
                .is_some()
            || initializer.kind != crate::analyzer::semantic_model::SemanticModelSymbolKind::Method
            || !initializer.has_receiver()
            || initializer.provenance.ambiguous
            || initializer.provenance.completeness != SemanticModelCompleteness::Complete
            || !initializer.has_complete_callable_shape_evidence()
            || initializer.provenance.pack_id != declaring_class.provenance.pack_id
        {
            return None;
        }
        return Some((
            std::sync::Arc::clone(initializer),
            std::sync::Arc::clone(declaring_class),
        ));
    }
    None
}

fn python_constructor_class_mro(
    overlay: &crate::analyzer::semantic_model::SemanticModelOverlay,
    root_id: &str,
) -> Option<Vec<String>> {
    let mut linearizations = HashMap::<String, Vec<String>>::default();
    let mut visiting = HashSet::<String>::default();
    let mut stack = vec![PythonConstructorMroFrame {
        class_id: root_id.to_owned(),
        bases: None,
        next_base: 0,
    }];
    visiting.insert(root_id.to_owned());
    while !stack.is_empty() {
        let top = stack.len() - 1;
        if stack[top].bases.is_none() {
            let class_id = stack[top].class_id.clone();
            let class_match = overlay.symbols_with_id(&class_id);
            let [class] = class_match.records.as_slice() else {
                return None;
            };
            if class.language != Language::Python.config_label()
                || class.kind != crate::analyzer::semantic_model::SemanticModelSymbolKind::Class
                || class.provenance.ambiguous
                || class.provenance.completeness != SemanticModelCompleteness::Complete
                || overlay
                    .gapped_member_surface(&class.qualified_name, "__init__")
                    .is_some()
            {
                return None;
            }
            stack[top].bases = Some(python_constructor_direct_bases(overlay, class)?);
        }
        let bases = stack[top].bases.as_ref().expect("bases were initialized");
        if stack[top].next_base < bases.len() {
            let base = bases[stack[top].next_base].clone();
            stack[top].next_base += 1;
            if linearizations.contains_key(&base) {
                continue;
            }
            if !visiting.insert(base.clone()) {
                return None;
            }
            stack.push(PythonConstructorMroFrame {
                class_id: base,
                bases: None,
                next_base: 0,
            });
            continue;
        }

        let frame = stack.pop().expect("the MRO stack is nonempty");
        let bases = frame.bases.expect("bases were initialized");
        let mut sequences = bases
            .iter()
            .map(|base| linearizations.get(base).cloned())
            .collect::<Option<Vec<_>>>()?;
        sequences.push(bases.clone());
        let mut merged = Vec::new();
        loop {
            sequences.retain(|sequence| !sequence.is_empty());
            if sequences.is_empty() {
                break;
            }
            let candidate = sequences.iter().find_map(|sequence| {
                let head = sequence.first()?;
                (!sequences
                    .iter()
                    .any(|other| other.iter().skip(1).any(|tail| tail == head)))
                .then(|| head.clone())
            })?;
            merged.push(candidate.clone());
            for sequence in &mut sequences {
                if sequence.first() == Some(&candidate) {
                    sequence.remove(0);
                }
            }
        }
        let mut linearization = Vec::with_capacity(merged.len() + 1);
        linearization.push(frame.class_id.clone());
        linearization.extend(merged);
        visiting.remove(&frame.class_id);
        linearizations.insert(frame.class_id, linearization);
    }
    linearizations.remove(root_id)
}

fn python_constructor_direct_bases(
    overlay: &crate::analyzer::semantic_model::SemanticModelOverlay,
    class: &crate::analyzer::semantic_model::SemanticModelSymbol,
) -> Option<Vec<String>> {
    if class.qualified_name == "builtins.object" {
        return Some(Vec::new());
    }
    let relations = overlay
        .relations_from(&class.id)
        .records
        .into_iter()
        .filter(|relation| relation.kind == "extends")
        .collect::<Vec<_>>();
    if relations.is_empty() {
        return Some(Vec::new());
    }
    let mut ordered = relations;
    if ordered.len() > 1
        && ordered
            .iter()
            .any(|relation| relation.declaration_ordinal.is_none())
    {
        return None;
    }
    ordered.sort_by_key(|relation| relation.declaration_ordinal.unwrap_or(0));
    if ordered
        .windows(2)
        .any(|pair| pair[0].declaration_ordinal == pair[1].declaration_ordinal)
        || ordered.iter().any(|relation| {
            relation.provenance.ambiguous
                || relation.provenance.completeness != SemanticModelCompleteness::Complete
        })
    {
        return None;
    }
    let mut bases = Vec::with_capacity(ordered.len());
    for relation in ordered {
        let base_match = overlay.symbols_with_id(&relation.to);
        let no_id_match = base_match.records.is_empty();
        let records = if no_id_match {
            overlay
                .symbols_named(&relation.to)
                .records
                .into_iter()
                .filter(|symbol| {
                    symbol.qualified_name == relation.to
                        || symbol.aliases.iter().any(|alias| alias == &relation.to)
                })
                .collect::<Vec<_>>()
        } else {
            base_match.records
        };
        let [base] = records.as_slice() else {
            if relation.to == "builtins.object" && no_id_match {
                continue;
            }
            return None;
        };
        if base.language != Language::Python.config_label()
            || base.kind != crate::analyzer::semantic_model::SemanticModelSymbolKind::Class
            || base.provenance.ambiguous
            || base.provenance.completeness != SemanticModelCompleteness::Complete
        {
            return None;
        }
        bases.push(base.id.clone());
    }
    Some(bases)
}

/// Whether every written actual is either bound exactly or classified as a
/// definite arity/name mismatch against the selected formal layout.
/// `CallBindingCoverage` keeps its narrower meaning: known mismatches remain
/// `partial` or `unknown`, since they do not bind to a formal.
fn actual_binding_classification_is_complete(report: &CallBindingReport) -> bool {
    let mut actual_count = 0usize;
    let mut known_mismatch_count = 0usize;
    for row in &report.rows {
        if row.argument_id.is_some() {
            actual_count += 1;
            match (row.mapping, row.reason) {
                (CallBindingMapping::Exact, None) => {}
                (
                    CallBindingMapping::Incomplete,
                    Some(
                        crate::analyzer::usages::call_binding::CallBindingReason::NoMatchingFormal
                        | crate::analyzer::usages::call_binding::CallBindingReason::UnknownKeyword,
                    ),
                ) => known_mismatch_count += 1,
                _ => return false,
            }
        } else if row.mapping != CallBindingMapping::Exact || row.reason.is_some() {
            return false;
        }
    }
    if actual_count != report.actual_count
        || report.bound_count + known_mismatch_count != report.actual_count
    {
        return false;
    }
    if known_mismatch_count == 0 {
        report.coverage == CallBindingCoverage::Exhaustive
    } else {
        matches!(
            report.coverage,
            CallBindingCoverage::Partial | CallBindingCoverage::Unknown
        )
    }
}

enum SourceTargetModelProvenance {
    Absent,
    Exact {
        model_id: String,
        model_aliases: Vec<String>,
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
        model_aliases: symbol.aliases.clone(),
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
    authored_summary_selector_proof_for_target(analyzer, target, key)
}

/// Select the authored claim for the #3406 closed shape: the reviewed complete
/// summary was consumed at dispatch, so the answer is already resolved and
/// exhaustive with no residual arm. The selector still names the authored
/// claim that closed the target set, exactly like the residual-arm path; only
/// the point at which it was consumed differs.
fn closed_model_selector_proof_for_external_target(
    analyzer: &dyn IAnalyzer,
    answer: &DispatchSiteAnswer,
    key: &ModeledProcedureKey,
) -> Option<CallBindingSelectorProof> {
    if answer.outcome != "resolved"
        || !answer.coverage.is_exhaustive()
        || answer.call_site_count != 1
        || !answer.unnamed_boundaries.is_empty()
    {
        return None;
    }
    let [arm] = answer.arms.as_slice() else {
        return None;
    };
    if arm.proof != "proven" || arm.completeness != "complete" {
        return None;
    }
    let target = arm.unmaterialized_target.as_ref()?;
    authored_summary_selector_proof_for_target(analyzer, target, key)
}

fn authored_summary_selector_proof_for_target(
    analyzer: &dyn IAnalyzer,
    target: &UnmaterializedExternalTarget,
    key: &ModeledProcedureKey,
) -> Option<CallBindingSelectorProof> {
    if !unmaterialized_target_has_key(target, key) {
        return None;
    }
    authored_summary_selector_proof(analyzer, key)
}

/// Whether the resolver's canonical external identity is the same
/// `(language, owner, member, receiver, arity)` member that `key` names.
fn unmaterialized_target_has_key(
    target: &UnmaterializedExternalTarget,
    key: &ModeledProcedureKey,
) -> bool {
    target.language().semantic_pack_label() == key.language
        && target.owner_fqn() == key.owner
        && target.member() == key.member
        && target.has_receiver() == key.has_receiver
        && target.arity() == key.parameter_count
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

/// Whether the oracle's answer for this one call site is closed on `arm`
/// alone: resolved, exhaustive, one proven and complete arm, and nothing the
/// oracle could not name.
fn answer_closed_on_arm(answer: &DispatchSiteAnswer, arm: &super::dispatch::DispatchArm) -> bool {
    answer.outcome == "resolved"
        && answer.coverage.is_exhaustive()
        && answer.call_site_count == 1
        && answer.call_contexts.len() == 1
        && answer.semantic_unsupported.is_none()
        && answer.exceeded_limit.is_none()
        && answer.unnamed_boundaries.is_empty()
        && matches!(answer.arms.as_slice(), [only] if only.target_id == arm.target_id)
        && arm.proof == "proven"
        && arm.completeness == "complete"
}

/// A modeled external call whose dispatch answer is already closed on the one
/// external arm that the unique model binding was keyed from. The oracle can
/// close such an arm from resolver structure alone, for example a Rust
/// inherent method on one concrete nominal receiver whose body has one
/// complete summary. The model binding then names the endpoint that dispatch
/// selected, so the selector is exact without a static-call claim and without
/// an authored override-coverage claim. The agreement is the arm's resolver
/// target carrying the same `(language, owner, member, receiver, arity)` as
/// the model key; neither the language nor receiver presence selects it.
fn model_bound_closed_external_selector(
    answer: &DispatchSiteAnswer,
    arm: &super::dispatch::DispatchArm,
    key: &ModeledProcedureKey,
) -> bool {
    answer_closed_on_arm(answer, arm)
        && arm.target_unit.is_none()
        && arm
            .unmaterialized_target
            .as_ref()
            .is_some_and(|target| unmaterialized_target_has_key(target, key))
}

/// A direct class call retains the class identity while the dispatch target
/// names its selected initializer. The complete initializer family has
/// already supplied the binding layout; this closes only the exact call row.
fn resolver_proven_python_constructor_selector(
    answer: &DispatchSiteAnswer,
    arm: &super::dispatch::DispatchArm,
    key: &ModeledProcedureKey,
) -> bool {
    if !answer_closed_on_arm(answer, arm)
        || key.language != Language::Python.config_label()
        || !key.has_receiver
        || key.member != "__init__"
    {
        return false;
    }
    let Some(identity) = arm.external_callee_identity.as_ref() else {
        return false;
    };
    let Some(target) = arm.unmaterialized_target.as_ref() else {
        return false;
    };
    identity.language() == Language::Python
        && target.language()
            == crate::analyzer::semantic::SemanticLanguage::Standard(Language::Python)
        && target.has_resolver_owned_call_shape()
        && target.has_receiver()
        && target.member() == key.member
        && target.owner_fqn() == key.owner
        && target.owner_fqn() == format!("{}.{}", identity.owner_fqn(), identity.member())
}

#[cfg(test)]
mod authored_override_residual_tests {
    use super::{DispatchSiteAnswer, authored_residual_arm, is_authored_override_residual};
    use brokk_bifrost_test_macros::hardwon;

    #[test]
    #[hardwon(
        "#2738: unrelated dispatch boundaries could be mistaken for an exact selector residual"
    )]
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
            coverage_reasons: Vec::new(),
            outcome,
            coverage: crate::analyzer::semantic::CandidateCoverage::Open,
            call_site_count: 1,
            semantic_unsupported: None,
            exceeded_limit: None,
            arms: Vec::new(),
            call_contexts: vec![super::super::dispatch::DispatchCallContext {
                procedure_id: "test-procedure".to_owned(),
                caller: None,
                caller_is_exact: false,
                unnamed_boundaries: vec!["unresolved"],
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
                external_callee_identity: None,
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
#[allow(clippy::too_many_arguments)]
pub(super) fn call_binding_expansions(
    analyzer: &dyn IAnalyzer,
    semantic: Option<&mut SemanticQueryContext<'_>>,
    indexed: &mut IndexedDeclarations,
    bindings: &mut CallBindingCache,
    occurrence_cache: &mut OccurrenceTraversalCache,
    environment_cache: &mut EnvironmentTraversalCache,
    identity_request: CallBindingIdentityRequest,
    shape: &CallShapeValue,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> Vec<PipelineExpansion> {
    let file = shape.report.outcome.file.clone();
    let mut semantic = semantic;
    let program_point_id = identity_request
        .needs_program_point()
        .then(|| {
            semantic
                .as_deref_mut()
                .and_then(|semantic| {
                    semantic.call_site_identity_at_source(&file, shape.report.outcome.range)
                })
                .map(|(_, program_point)| program_point)
        })
        .flatten();
    let resolved = resolve_call_target(analyzer, shape, bindings, cancellation);
    let mut native_resolution_gap = None;
    let mut incomplete_callee_diagnostics = None;
    let mut native_selected = false;
    let (mut target, mut declaration, mut signature_id, mut source_target) = match resolved {
        ResolvedCallTarget::Unit(candidate) => {
            let native_incomplete = candidate.incomplete_native_diagnostics.is_some();
            native_resolution_gap = candidate.incomplete_native_diagnostics;
            let unit = candidate.unit;
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
            let layout = owner.as_ref().and_then(|(owner, _)| {
                bindings.formal_layout(analyzer, owner, shape.report.arguments.len())
            });
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
            let target = match target {
                CallBindingTarget::Resolved {
                    unit,
                    layout,
                    receiver,
                } if native_incomplete => CallBindingTarget::ResolvedIncomplete {
                    unit,
                    layout,
                    receiver,
                },
                target => target,
            };
            (target, declaration, signature_id, Some(source_target))
        }
        ResolvedCallTarget::Incomplete {
            unit,
            diagnostics: reasons,
        } => {
            incomplete_callee_diagnostics = Some(reasons);
            let declaration = unit.as_ref().and_then(|unit| indexed.get(analyzer, unit));
            (
                CallBindingTarget::Incomplete { unit: unit.clone() },
                declaration,
                None,
                unit,
            )
        }
        ResolvedCallTarget::Ambiguous => (CallBindingTarget::Ambiguous, None, None, None),
        ResolvedCallTarget::AmbiguousNative => {
            native_selected = true;
            (CallBindingTarget::Ambiguous, None, None, None)
        }
        ResolvedCallTarget::UnresolvedNative => {
            native_selected = true;
            (CallBindingTarget::Unresolved, None, None, None)
        }
        ResolvedCallTarget::Unresolved => (CallBindingTarget::Unresolved, None, None, None),
    };

    let dispatch_answer = semantic
        .as_deref_mut()
        .map(|semantic| semantic.dispatch_at_source(&file, shape.report.outcome.range));
    let external_model_arm = dispatch_answer.as_ref().and_then(|answer| {
        (answer.arms.len() == 1
            && answer.arms[0].target_unit.is_none()
            && (answer.arms[0].unmaterialized_target.is_some()
                || answer.arms[0].exact_external_target.is_some()
                || (answer.arms[0].boundary_kind == Some("external")
                    && answer.arms[0]
                        .external_callee_identity
                        .as_ref()
                        .is_some_and(|identity| {
                            identity.language() == Language::Java
                                && identity.member() == "<init>"
                                && exact_java_constructor_shape(shape)
                        }))))
        .then(|| &answer.arms[0])
    });
    let resolver_owned_external_dispatch = (shape.report.outcome.coverage
        == CallShapeCoverage::ExactMacroDerived)
        .then(|| {
            bindings.resolved_external_call_dispatch(
                analyzer,
                &file,
                shape.report.outcome.range,
                cancellation,
            )
        })
        .flatten();
    if resolver_owned_external_dispatch.is_some() {
        // A source-level macro declaration is not the callable whose formal
        // layout the language's macro lowering selected. External semantic
        // model candidates likewise bind through their exact resolver-owned
        // identity rather than through an independently rendered target.
        target = CallBindingTarget::Unresolved;
        declaration = None;
        signature_id = None;
        source_target = None;
    }
    // An exact macro-derived call whose resolver-owned external dispatch
    // proves one target is decided by that proof, not by the generic callee
    // lookup. The lookup may still be Incomplete for the same call; its
    // diagnostics stay attached below as information and no longer withhold
    // the proven binding. Every other shape keeps the Incomplete gate.
    let incomplete_lookup_withholds_binding =
        incomplete_callee_diagnostics.is_some() && resolver_owned_external_dispatch.is_none();
    let has_semantic = dispatch_answer.is_some();
    let mut dispatch =
        dispatch_answer
            .as_ref()
            .map_or_else(CallBindingDispatch::unavailable, |answer| {
                // A unique incomplete selected-native source candidate is
                // still safe for candidate-local dispatch evidence. Its
                // original navigation gap remains attached to this row and
                // keeps the result incomplete.
                CallBindingDispatch::from_answer(answer, source_target.as_ref(), None)
            });
    if incomplete_callee_diagnostics.is_some() {
        dispatch.keep_open_for_receiver_evidence();
    }
    let receiver_assessment = if crate::analyzer::common::language_for_file(&file)
        == Language::Python
        && shape.report.outcome.receiver_range.is_some()
    {
        semantic
            .as_mut()
            .map(|semantic| {
                semantic.receiver_dispatch_assessment(&file, shape.report.outcome.range)
            })
            .unwrap_or(super::type_flow::ReceiverDispatchAssessment::NotApplicable)
    } else {
        super::type_flow::ReceiverDispatchAssessment::NotApplicable
    };
    let receiver_proof = match &receiver_assessment {
        super::type_flow::ReceiverDispatchAssessment::Closed(proof) => Some(proof),
        super::type_flow::ReceiverDispatchAssessment::NotApplicable
        | super::type_flow::ReceiverDispatchAssessment::Open => None,
    };
    let mut model_id = None;
    let mut model_aliases = Vec::new();
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
    let mut python_constructor_selector_proven = false;
    let mut model_layout_compatible = false;
    let mut model_conversion_context: Option<(
        String,
        String,
        crate::analyzer::semantic_model::Signature,
    )> = None;
    // A unique model record can describe the source resolver's declaration
    // even when runtime dispatch remains open. Keep those two facts separate:
    // model provenance never upgrades the dispatch proof below.
    if let Some(source_target) = source_target.as_ref() {
        match model_provenance_for_source_target(analyzer, source_target) {
            SourceTargetModelProvenance::Absent => {}
            SourceTargetModelProvenance::Exact {
                model_id: resolved_model_id,
                model_aliases: resolved_model_aliases,
                model_callable_id: resolved_model_callable_id,
                receiver_type_id: resolved_receiver_type_id,
                provenance,
                key,
            } => {
                model_id = Some(resolved_model_id.clone());
                model_aliases = resolved_model_aliases;
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
                    related: Vec::new(),
                    source: None,
                    code: CodeQueryDiagnosticCode::SemanticAnalysisPartial,
                    impact: CodeQueryDiagnosticImpact::Incomplete,
                    branch: Vec::new(),
                    language: crate::analyzer::common::language_for_file(&file).config_label(),
                    message: "call_bindings found incomplete or conflicting semantic-model provenance for an exact source target".to_owned(),
                exhausted_roots: Vec::new(),
                    withheld_rows_path: None,
                });
            }
        }
    }
    // A selected native lookup can still bind an external semantic-pack
    // declaration when the same native call relation published its exact
    // owner/member identity and call shape. A materialized declaration carries
    // its exact target; an unmaterialized declaration must retain the exact
    // resolver-owned call shape and match that identity. A direct Python class
    // call keeps the class identity while the selected initializer supplies
    // its formals. A Java constructor with incomplete applicability can use its
    // exact AST shape to find formals. Neither upgrades the independent
    // dispatch completeness
    // answer.
    let native_external_model_arm = native_selected
        && external_model_arm.is_some_and(|arm| {
            arm.target_unit.is_none()
                && arm.boundary_kind == Some("external")
                && arm
                    .external_callee_identity
                    .as_ref()
                    .is_some_and(|identity| {
                        crate::analyzer::common::language_for_file(&file) == identity.language()
                        && (arm.exact_external_target.is_some()
                            || arm.unmaterialized_target.as_ref().is_some_and(|target| {
                                let exact_callee = target.owner_fqn() == identity.owner_fqn()
                                    && target.member() == identity.member();
                                let python_constructor = identity.language() == Language::Python
                                    && target.language()
                                        == crate::analyzer::semantic::SemanticLanguage::Standard(
                                            Language::Python,
                                        )
                                    && target.has_receiver()
                                    && target.member() == "__init__"
                                    && target.owner_fqn()
                                        == format!(
                                            "{}.{}",
                                            identity.owner_fqn(),
                                            identity.member()
                                        );
                                target.has_resolver_owned_call_shape()
                                    && target.language()
                                        == crate::analyzer::semantic::SemanticLanguage::Standard(
                                            identity.language(),
                                        )
                                    && (exact_callee || python_constructor)
                            })
                            || (identity.member() == "<init>"
                                && exact_java_constructor_shape(shape)))
                    })
        });
    let receiver_proof_model = receiver_proof.is_some_and(|proof| {
        !proof.targets.is_empty()
            && proof.targets.iter().all(|(class, declaration)| {
                matches!(class, ClassIdentity::External { .. })
                    && matches!(declaration, MemberDeclaration::External(_))
            })
    });
    let receiver_proof_model_bindings = receiver_proof
        .filter(|_| receiver_proof_model)
        .and_then(|proof| model_call_bindings_for_receiver_proof(analyzer, proof, shape));
    let receiver_proof_target_id = external_model_arm
        .map(|arm| arm.target_id.as_str())
        .or_else(|| {
            receiver_proof_model
                .then(|| {
                    let proof = receiver_proof.as_ref()?;
                    let [(_, MemberDeclaration::External(declaration))] = proof.targets.as_slice()
                    else {
                        return None;
                    };
                    let [symbol_id] = declaration.symbol_ids() else {
                        return None;
                    };
                    Some(symbol_id.as_ref())
                })
                .flatten()
        });
    let resolved_model_call_binding = if receiver_proof_model {
        Some(
            receiver_proof_model_bindings
                .as_ref()
                .and_then(|bindings| bindings.first())
                .cloned()
                .unwrap_or(ModelCallBinding::Unavailable),
        )
    } else {
        external_model_arm
            .map(|arm| model_call_binding(analyzer, arm, shape, bindings))
            .or_else(|| {
                resolver_owned_external_dispatch.as_ref().map(|target| {
                    model_call_binding_for_external_dispatch(analyzer, target, shape, bindings)
                })
            })
    };
    if source_target.is_none()
        && !incomplete_lookup_withholds_binding
        && (!native_selected
            || native_external_model_arm
            || receiver_proof_model
            || resolver_owned_external_dispatch.is_some())
        && let Some(model_binding) = resolved_model_call_binding
    {
        match model_binding {
            ModelCallBinding::Unique {
                python_constructor,
                layout,
                receiver,
                key,
                model_id: resolved_model_id,
                model_callable_id: resolved_model_callable_id,
                pack_id: resolved_pack_id,
                receiver_type_id: resolved_receiver_type_id,
                signature_id: resolved_signature_id,
                signature: resolved_signature,
                semantic_model_provenance: resolved_provenance,
                model_aliases: resolved_model_aliases,
            } => {
                model_static_selector_proven = resolver_owned_external_dispatch.is_some()
                    || dispatch_answer
                        .as_ref()
                        .is_some_and(resolver_proven_static_model_selector);
                if resolver_owned_external_dispatch.is_some() {
                    dispatch =
                        CallBindingDispatch::from_resolver_owned_external(&resolved_model_id);
                }
                if python_constructor
                    && let (Some(answer), Some(arm)) =
                        (dispatch_answer.as_ref(), external_model_arm)
                    && resolver_proven_python_constructor_selector(answer, arm, &key)
                {
                    dispatch = CallBindingDispatch::from_answer(
                        answer,
                        source_target.as_ref(),
                        Some(&arm.target_id),
                    );
                    python_constructor_selector_proven = true;
                }
                // The binding above was keyed from the dispatch arm itself, so
                // a closed one-arm answer names the same endpoint the model
                // record binds. Keep that arm's own proof instead of the
                // id-less dispatch built before the model was known. When a
                // complete override-covering summary exists, the authored
                // selector below names that claim, so it is not reattributed.
                if !python_constructor
                    && !receiver_proof_model
                    && resolver_owned_external_dispatch.is_none()
                    && let (Some(answer), Some(arm)) =
                        (dispatch_answer.as_ref(), external_model_arm)
                    && model_bound_closed_external_selector(answer, arm, &key)
                    && closed_model_selector_proof_for_external_target(analyzer, answer, &key)
                        .is_none()
                {
                    dispatch = CallBindingDispatch::from_answer(answer, None, Some(&arm.target_id));
                }
                target = CallBindingTarget::ResolvedExternal { layout, receiver };
                model_callable_id = Some(resolved_model_callable_id);
                formal_layout_id = signature_id.clone();
                model_conversion_context = Some((
                    resolved_model_id.clone(),
                    resolved_signature_id.clone(),
                    *resolved_signature,
                ));
                model_id = Some(resolved_model_id.clone());
                model_aliases = resolved_model_aliases;
                signature_id = Some(resolved_signature_id);
                pack_id = Some(resolved_pack_id);
                receiver_type_id = resolved_receiver_type_id;
                semantic_target_id = if resolver_owned_external_dispatch.is_some() {
                    Some(resolved_model_id.clone())
                } else {
                    receiver_proof_target_id.map(str::to_owned)
                };
                target_origin = Some("semantic_model");
                semantic_model_provenance = Some(resolved_provenance);
                modeled_key = Some(*key);
            }
            ModelCallBinding::ConversionUnavailable {
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
                    related: Vec::new(),
                    source: None,
                    code: CodeQueryDiagnosticCode::SemanticAnalysisPartial,
                    impact: CodeQueryDiagnosticImpact::Incomplete,
                    branch: Vec::new(),
                    language: crate::analyzer::common::language_for_file(&file).config_label(),
                    message: format!(
                        "call_bindings model signature conversion is unavailable: {reason:?}"
                    ),
                    exhausted_roots: Vec::new(),
                    withheld_rows_path: None,
                });
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
                target = CallBindingTarget::ResolvedExternal { layout, receiver };
                model_callable_id = Some(resolved_model_callable_id);
                formal_layout_id = Some(resolved_formal_layout_id);
                pack_id = Some(resolved_pack_id);
                receiver_type_id = resolved_receiver_type_id;
                semantic_target_id = receiver_proof_target_id.map(str::to_owned);
                target_origin = Some("semantic_model");
                modeled_key = Some(*key);
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
                    related: Vec::new(),
                    source: None,
                    code: CodeQueryDiagnosticCode::SemanticAnalysisPartial,
                    impact: CodeQueryDiagnosticImpact::Incomplete,
                    branch: Vec::new(),
                    language: crate::analyzer::common::language_for_file(&file).config_label(),
                    message: format!(
                        "call_bindings semantic model callable is incomplete: {reason:?}"
                    ),
                    exhausted_roots: Vec::new(),
                    withheld_rows_path: None,
                });
            }
            ModelCallBinding::Empty | ModelCallBinding::Unavailable => {
                target = if resolver_owned_external_dispatch.is_some() {
                    semantic_target_id = dispatch_answer.as_ref().and_then(|answer| {
                        (answer.arms.len() == 1).then(|| answer.arms[0].target_id.clone())
                    });
                    CallBindingTarget::FormalsUnrecordedExternal
                } else {
                    CallBindingTarget::Unresolved
                };
            }
        }
    }

    if model_callable_id.is_none() {
        model_callable_id = model_id.clone();
    }
    if formal_layout_id.is_none() {
        formal_layout_id = signature_id.clone();
    }
    if !incomplete_lookup_withholds_binding && let Some(answer) = dispatch_answer.as_ref() {
        match &receiver_assessment {
            super::type_flow::ReceiverDispatchAssessment::Open => {
                // A qualified external class construction has a syntactic
                // receiver (algorithms in algorithms.ARC4(...)), but that
                // module qualifier is not a runtime object receiver whose
                // dynamic members can replace the selected class. The
                // constructor proof already checked the class's complete
                // initializer and surface; do not let open type-flow evidence
                // for the module qualifier erase that independent proof.
                if !python_constructor_selector_proven {
                    dispatch.keep_open_for_receiver_evidence();
                }
            }
            super::type_flow::ReceiverDispatchAssessment::Closed(proof)
                if receiver_proof_can_close_dispatch(answer, proof) =>
            {
                let exact_arms = receiver_proven_arms(
                    analyzer,
                    answer,
                    proof,
                    source_target.as_ref(),
                    semantic_target_id.as_deref(),
                );
                let target_ids = exact_arms.and_then(|arms| {
                    if !arms.is_empty() {
                        Some(
                            arms.iter()
                                .map(|arm| arm.target_id.clone())
                                .collect::<Vec<_>>(),
                        )
                    } else {
                        receiver_proof_model_bindings.as_ref().map(|bindings| {
                            bindings
                                .iter()
                                .filter_map(|binding| match binding {
                                    ModelCallBinding::Unique { model_id, .. } => {
                                        Some(model_id.clone())
                                    }
                                    _ => None,
                                })
                                .collect::<Vec<_>>()
                        })
                    }
                });
                if let Some(target_ids) = target_ids.filter(|targets| !targets.is_empty()) {
                    dispatch = CallBindingDispatch::from_receiver_proof_targets(&target_ids);
                    if semantic_target_id.is_none() && target_ids.len() == 1 {
                        semantic_target_id = target_ids.first().cloned();
                    }
                } else {
                    dispatch.keep_open_for_receiver_evidence();
                }
            }
            super::type_flow::ReceiverDispatchAssessment::NotApplicable
            | super::type_flow::ReceiverDispatchAssessment::Closed(_) => {}
        }
    }
    let receiver_owner_applicable = crate::analyzer::common::language_for_file(&file)
        == Language::Go
        || !matches!(
            &target,
            CallBindingTarget::Resolved {
                receiver: CallReceiverBinding::Absent,
                ..
            } | CallBindingTarget::ResolvedExternal {
                receiver: CallReceiverBinding::Absent,
                ..
            } | CallBindingTarget::ResolvedIncomplete {
                receiver: CallReceiverBinding::Absent,
                ..
            }
        );
    let mut report = call_binding_report(&file, &shape.report, target);
    if let Some(original_gap) = native_resolution_gap.as_ref() {
        diagnostics.push(CodeQueryDiagnostic {
            related: Vec::new(),
            source: None,
            code: CodeQueryDiagnosticCode::SemanticAnalysisPartial,
            impact: CodeQueryDiagnosticImpact::Incomplete,
            branch: Vec::new(),
            language: crate::analyzer::common::language_for_file(&file).config_label(),
            message: format!(
                "native Java or Go call-target binding retained one source candidate with an incomplete selected frontier; original diagnostics: {}", original_gap.iter().map(|diagnostic| format!("{}: {}", diagnostic.kind, diagnostic.message)).collect::<Vec<_>>().join("; ")
            ),
            exhausted_roots: Vec::new(),
            withheld_rows_path: None,
        });
    }
    if let Some(original_reasons) = incomplete_callee_diagnostics.as_ref() {
        diagnostics.push(CodeQueryDiagnostic {
            related: Vec::new(),
            source: None,
            code: CodeQueryDiagnosticCode::SemanticAnalysisPartial,
            impact: CodeQueryDiagnosticImpact::Incomplete,
            branch: Vec::new(),
            language: crate::analyzer::common::language_for_file(&file).config_label(),
            message: format!(
                "call_bindings retained an incomplete callee lookup; original diagnostics: {}",
                original_reasons
                    .iter()
                    .map(|diagnostic| format!("{}: {}", diagnostic.kind, diagnostic.message))
                    .collect::<Vec<_>>()
                    .join("; ")
            ),
            exhausted_roots: Vec::new(),
            withheld_rows_path: None,
        });
    }
    // The initial producer consumes exact source signatures. Model signature
    // substitution must not lend a different signature's proof to these rows.
    let conversion_signature = signature_id.as_deref();
    let model_conversion_signature =
        model_conversion_context
            .as_ref()
            .map(|(target, signature_id, signature)| {
                (target.as_str(), signature_id.as_str(), signature)
            });
    // An incomplete native candidate still has an exact source signature, so
    // conversion facts may describe each actual/formal pair. The incomplete
    // binding coverage and open dispatch remain separate and are not promoted
    // by those pair-local proofs.
    bindings.populate_conversions(
        analyzer,
        &mut report,
        conversion_signature,
        model_conversion_signature,
    );
    let (binding_ids, path_identities) = match identity_request {
        CallBindingIdentityRequest::None | CallBindingIdentityRequest::ProgramPoint => {
            (Vec::new(), Vec::new())
        }
        CallBindingIdentityRequest::PathIdentityAndProgramPoint => {
            let binding_ids: Vec<Option<String>> = report
                .rows
                .iter()
                .map(|row| {
                    let argument_id = row.argument_id.as_ref()?;
                    let argument = shape
                        .report
                        .arguments
                        .iter()
                        .find(|argument| &argument.id == argument_id)?;
                    super::row_relations::binding_identity_for_range(
                        analyzer,
                        occurrence_cache,
                        environment_cache,
                        &file,
                        shape
                            .facts
                            .as_deref()
                            .expect("call-shape binding rows retain their structural facts"),
                        argument.range,
                        cancellation,
                        diagnostics,
                    )
                })
                .collect();
            let path_identities = report
                .rows
                .iter()
                .enumerate()
                .map(|(index, row)| {
                    binding_ids[index]
                        .as_ref()
                        .map(|binding_id| format!("binding:{binding_id}"))
                        .or_else(|| {
                            row.argument_id.as_ref().and_then(|argument_id| {
                                let argument = shape
                                    .report
                                    .arguments
                                    .iter()
                                    .find(|argument| &argument.id == argument_id)?;
                                shape
                                    .facts
                                    .as_ref()?
                                    .nodes()
                                    .iter()
                                    .find_map(|node| {
                                        (node.kind == NormalizedKind::StringLiteral
                                            && node.range == argument.range)
                                            .then(|| node.string_value.clone())
                                            .flatten()
                                    })
                                    .map(|literal| format!("literal:{literal}"))
                            })
                        })
                })
                .collect();
            (binding_ids, path_identities)
        }
    };
    // Conversion proof is independent of exact argument mapping. Its typed
    // uncertainty travels on the conversion field and is charged only when a
    // consumer reads that field, not when a policy selects the binding itself.
    let report = Arc::new(report);
    // Publish the resolved member owner only for a call whose typed binder did
    // not classify the qualifier as a scope. An unestablished receiver may
    // still retain the independently proven member owner, while an associated
    // or static call must not acquire receiver identity from that owner. A Go
    // declaration beneath a type is necessarily a receiver method, so its
    // resolver-proven owner remains applicable even when its receiver clause
    // was not materialized into the shared formal layout.
    if receiver_owner_applicable {
        if receiver_type_id.is_none()
            && let Some(source_target) = source_target.as_ref()
        {
            receiver_type_id = analyzer
                .parent_of(source_target)
                .filter(CodeUnit::is_class)
                .map(|parent| parent.declaration_id().to_string());
        }
    } else {
        receiver_type_id = None;
    }
    let binding_is_complete = actual_binding_classification_is_complete(&report)
        && (signature_id.is_some() || model_layout_compatible);
    // A direct Python name whose production resolver selected one workspace
    // declaration has an exact binding selector even when the semantic oracle
    // has no runtime dispatch target (unknown/open/0). This proves the
    // declaration/formal relation only; named, ambiguous, and partial dispatch
    // answers never use this path, and `dispatch` retains its oracle answer.
    let python_direct_source_selector_proven = source_target.is_some()
        && crate::analyzer::common::language_for_file(&file) == Language::Python
        && shape.report.outcome.receiver_range.is_none()
        && native_resolution_gap.is_none()
        && dispatch.outcome == "unknown"
        && dispatch.coverage == "open"
        && dispatch.target_count == 0
        && signature_id.is_some()
        && formal_layout_id.is_some();
    let selector = if binding_is_complete
        && (dispatch.is_exact()
            || model_static_selector_proven
            || python_direct_source_selector_proven)
    {
        CallBindingSelectorProof::derived()
    } else if binding_is_complete {
        dispatch_answer
            .as_ref()
            .and_then(|answer| {
                let key = modeled_key.as_ref()?;
                match source_target.as_ref() {
                    Some(target) => {
                        authored_selector_proof_for_source_target(analyzer, answer, target, key)
                    }
                    None => authored_selector_proof_for_external_target(analyzer, answer, key)
                        .or_else(|| {
                            closed_model_selector_proof_for_external_target(analyzer, answer, key)
                        }),
                }
            })
            .unwrap_or_else(CallBindingSelectorProof::unavailable)
    } else {
        CallBindingSelectorProof::unavailable()
    };
    if has_semantic && !binding_is_complete {
        diagnostics.push(CodeQueryDiagnostic {
            related: Vec::new(),
            source: None,
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
        exhausted_roots: Vec::new(),
            withheld_rows_path: None,
        });
    } else if has_semantic && !selector.exact {
        diagnostics.push(CodeQueryDiagnostic {
            related: Vec::new(),
            source: None,
            code: CodeQueryDiagnosticCode::CallBindingDispatchPartial,
            impact: CodeQueryDiagnosticImpact::Incomplete,
            branch: Vec::new(),
            language: crate::analyzer::common::language_for_file(&file).config_label(),
            message: format!(
                "call_bindings established an exact declared target and actual-to-formal mapping, but exact selector proof remains unavailable (dispatch outcome={}, coverage={}, target_count={})",
                dispatch.outcome, dispatch.coverage, dispatch.target_count,
            ),
        exhausted_roots: Vec::new(),
            withheld_rows_path: None,
        });
    }
    let site = CallBindingSiteValue {
        report,
        shape: shape.clone(),
        target: declaration,
        declared_target_id: source_target
            .as_ref()
            .map(|target| target.declaration_id().to_string()),
        signature_id,
        model_callable_id,
        formal_layout_id,
        dispatch,
        selector,
        semantic_target_id,
        target_origin,
        model_id,
        model_aliases,
        pack_id,
        semantic_model_provenance,
        receiver_type_id,
        modeled_key,
        program_point_id,
        binding_ids,
        path_identities,
    };
    let sites = if source_target.is_none() && !incomplete_lookup_withholds_binding {
        receiver_proof_model_bindings.map(|bindings| {
            bindings
                .into_iter()
                .map(|binding| {
                    let ModelCallBinding::Unique {
                        model_id,
                        model_callable_id,
                        pack_id,
                        receiver_type_id,
                        signature_id,
                        semantic_model_provenance,
                        model_aliases,
                        key,
                        ..
                    } = binding
                    else {
                        unreachable!("exact receiver model bindings are complete and unique")
                    };
                    let mut target_site = site.clone();
                    let mut target_report = target_site.report.as_ref().clone();
                    for row in &mut target_report.rows {
                        let mut digest = LengthDelimitedDigest::new(
                            b"bifrost.code_query.call_binding.target.v1",
                        );
                        digest.push(row.id.as_bytes());
                        digest.push(model_id.as_bytes());
                        row.id = digest.finish().to_string();
                    }
                    target_site.report = Arc::new(target_report);
                    target_site.model_id = Some(model_id.clone());
                    target_site.semantic_target_id = Some(model_id);
                    target_site.model_callable_id = Some(model_callable_id);
                    target_site.pack_id = Some(pack_id);
                    target_site.receiver_type_id = receiver_type_id;
                    target_site.signature_id = Some(signature_id.clone());
                    target_site.formal_layout_id = Some(signature_id);
                    target_site.semantic_model_provenance = Some(semantic_model_provenance);
                    target_site.model_aliases = model_aliases;
                    target_site.modeled_key = Some(*key);
                    target_site
                })
                .collect::<Vec<_>>()
        })
    } else {
        None
    }
    .unwrap_or_else(|| vec![site]);
    sites
        .into_iter()
        .flat_map(|site| {
            (0..site.report.rows.len()).map(move |index| {
                pipeline_expansion(PipelineValue::CallBinding(Box::new(CallBindingValue {
                    site: site.clone(),
                    index,
                })))
            })
        })
        .collect()
}

/// The exact call partition already published by the shared shape relation.
/// Missing or non-exact coverage is typed unknown; no source reparse happens
/// here, and no argument is inferred from a callee display string.
fn structured_model_application(shape: &CallShapeValue) -> SemanticModelCallApplication {
    if !shape.report.outcome.coverage.is_exact() {
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
    Unit(ResolvedCallTargetUnit),
    Incomplete {
        unit: Option<CodeUnit>,
        diagnostics: Vec<DefinitionLookupDiagnostic>,
    },
    Ambiguous,
    /// The selected-native Java operation returned several source candidates.
    /// Runtime dispatch cannot collapse that ambiguity into a model candidate.
    AmbiguousNative,
    /// The selected-native Java operation returned no source declaration.
    /// Its independent runtime-dispatch observation cannot manufacture a
    /// call-binding candidate or model identity.
    UnresolvedNative,
    Unresolved,
}

struct ResolvedCallTargetUnit {
    unit: CodeUnit,
    incomplete_native_diagnostics: Option<Vec<DefinitionLookupDiagnostic>>,
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
    let native_selected = matches!(
        lookup.authority,
        DefinitionResolutionAuthority::NativeJavaSelected
            | DefinitionResolutionAuthority::NativeGoSelected
    );
    let status = lookup.outcome.status;
    let incomplete_diagnostics =
        (status == DefinitionLookupStatus::Incomplete).then(|| lookup.outcome.diagnostics.clone());
    let incomplete_native_diagnostics = lookup
        .unique_incomplete_native_source_candidate()
        .map(|_| lookup.outcome.diagnostics.clone());
    let mut definitions = lookup.outcome.definitions;
    definitions.sort();
    definitions.dedup();
    match definitions.len() {
        0 if native_selected => ResolvedCallTarget::UnresolvedNative,
        0 if status == DefinitionLookupStatus::Incomplete => ResolvedCallTarget::Incomplete {
            unit: None,
            diagnostics: incomplete_diagnostics
                .expect("an incomplete lookup retains its typed diagnostics"),
        },
        0 => ResolvedCallTarget::Unresolved,
        1 if status == DefinitionLookupStatus::Resolved => {
            ResolvedCallTarget::Unit(ResolvedCallTargetUnit {
                unit: definitions.remove(0),
                incomplete_native_diagnostics: None,
            })
        }
        1 if incomplete_native_diagnostics.is_some() => {
            ResolvedCallTarget::Unit(ResolvedCallTargetUnit {
                unit: definitions.remove(0),
                incomplete_native_diagnostics,
            })
        }
        1 if status == DefinitionLookupStatus::Incomplete => ResolvedCallTarget::Incomplete {
            unit: Some(definitions.remove(0)),
            diagnostics: incomplete_diagnostics
                .expect("an incomplete lookup retains its typed diagnostics"),
        },
        _ if native_selected => ResolvedCallTarget::AmbiguousNative,
        _ => ResolvedCallTarget::Ambiguous,
    }
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
    let declaration_site_id = declaration.site_id();
    let entries = analyzer.signature_metadata(&declaration.unit);
    let reports = callable_signature_reports(&declaration_site_id, &declaration.unit, &entries);
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
        if declares_receiver_slot
            || contract == Some(ReceiverContract::Instance)
            // Kotlin declares the extension receiver outside the ordinary
            // parameter list. Other extension adapters (such as C#'s `this`
            // parameter) must establish their own consumed-slot convention.
            || (contract == Some(ReceiverContract::Extension)
                && crate::analyzer::common::language_for_file(formal_owner.source())
                    == Language::Kotlin)
        {
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
