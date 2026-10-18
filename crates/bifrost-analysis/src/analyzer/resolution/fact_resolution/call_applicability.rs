//! Structured call-shape mapping and candidate selection.
//!
//! The adapters own language rules. This module owns only candidate
//! retention and the partial order over already-established conversion
//! evidence. All values are query-local; no call assessment is persisted.

use brokk_bifrost_core::analyzer::Language;
use brokk_bifrost_core::analyzer::resolution_facts::IntrinsicTypeKind;
use brokk_bifrost_core::analyzer::structural::callable::{
    ApplicabilityVerdict, CallableRejectionReason,
};

use super::super::fact_source::{
    JavaInheritanceDeclarationKind, SelectedTypedRow, language_method_is_instance_for_override,
};
use super::super::model::ResolutionAnswer;
use super::super::model::ResolutionCompletion;
use super::super::model::SemanticId;
use super::super::typed_fact_lowering::{
    LoweredCallApplicabilityObligation, LoweredCallArgumentProperty,
    LoweredCallableParameterProperty, LoweredCallableResultTypeProperty,
    LoweredCallableSignatureProperty,
};
use super::{
    AnswerMap, CallCandidateApplicability, FactEvaluation, InternedFactRow, ResolutionNamespace,
    StateMap, StoreResult,
};
use crate::hash::{HashMap, HashSet};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ArgumentFormalBinding {
    pub argument_index: usize,
    pub parameter_index: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum MappingAssessment {
    Mapped {
        bindings: Vec<ArgumentFormalBinding>,
        used_defaults: u32,
        used_vararg: bool,
        result_application_lists: Vec<u32>,
    },
    Inapplicable(CallableRejectionReason),
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PartialOrder {
    Better,
    Equal,
    Worse,
    Incomparable,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConversionKind {
    Exact,
    Subtype,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IntrinsicCallType {
    Boolean,
    String,
    Byte,
    Short,
    Char,
    Int,
    Long,
    Float,
    Double,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ConversionEvidence {
    pub argument_ordinal: u32,
    pub parameter_ordinal: u32,
    pub source_type: Option<SemanticId>,
    pub target_type: Option<SemanticId>,
    pub kind: ConversionKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CandidateAssessment {
    pub candidate: SemanticId,
    pub verdict: ApplicabilityVerdict,
    pub reason: Option<CallableRejectionReason>,
    pub conversions: Vec<ConversionEvidence>,
    pub used_vararg: bool,
    pub used_defaults: u32,
}

pub(super) enum ResultApplicationAssessment {
    Applicable {
        conversions: Vec<ConversionEvidence>,
        result_slot: Option<SemanticId>,
    },
    Inapplicable(CallableRejectionReason),
    Unknown,
}

pub(super) struct ResultApplicationRequest<'a> {
    pub(super) call: &'a LoweredCallApplicabilityObligation,
    pub(super) lists: &'a [u32],
    pub(super) member_names: &'a [&'a str],
    /// Type arguments not already consumed by the original declaration call.
    pub(super) explicit_type_argument_count: u32,
    pub(super) type_argument_slots: &'a [SemanticId],
    pub(super) previous_answers: &'a AnswerMap,
    pub(super) previous_states: &'a StateMap,
}

impl CandidateAssessment {
    /// Exact conversion evidence must cover every supplied argument. Unknown
    /// identities, defaults and expanded varargs cannot close an overload set.
    pub(super) fn is_exact_match(&self, argument_count: usize) -> bool {
        self.verdict == ApplicabilityVerdict::Applicable
            && !self.used_vararg
            && self.used_defaults == 0
            && self.conversions.iter().all(|conversion| {
                conversion.kind == ConversionKind::Exact
                    && conversion.source_type.is_some()
                    && conversion.target_type.is_some()
            })
            && self
                .conversions
                .iter()
                .filter(|conversion| conversion.argument_ordinal != u32::MAX)
                .count()
                == argument_count
    }

    pub fn unknown(candidate: SemanticId) -> Self {
        Self {
            candidate,
            verdict: ApplicabilityVerdict::Unknown,
            reason: None,
            conversions: Vec::new(),
            used_vararg: false,
            used_defaults: 0,
        }
    }

    pub fn inapplicable(candidate: SemanticId, reason: CallableRejectionReason) -> Self {
        Self {
            candidate,
            verdict: ApplicabilityVerdict::Inapplicable,
            reason: Some(reason),
            conversions: Vec::new(),
            used_vararg: false,
            used_defaults: 0,
        }
    }
}

/// What a language means by a type name written where a call is expected
/// (`Client(host)`). This is the one language input to the shared rule that
/// lets a callee lookup land on a type: the lookup also searches the Type
/// namespace, and the answer's types are interpreted through this value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TypeInCallPosition {
    /// A type is not callable (Java, Rust): the call names only callables.
    Nothing,
    /// The call is a conversion to the type (Go): the type itself is the
    /// answer, and no callable signature is involved.
    Conversion,
    /// The call invokes a constructor of the type (Kotlin): the answer's
    /// type targets are replaced by the type's constructor members.
    Constructors,
    /// The call applies the type's `apply` members (Scala): `Client(host)` is
    /// `Client.apply(host)`. An object target is replaced by its `apply`
    /// members, a class target by its companion's `apply` members, or by its
    /// constructors when the companion declares no `apply`.
    ApplyMembers,
}

pub(crate) trait CallApplicabilityAdapter: Sync {
    fn no_applicable_call_diagnostic(&self) -> Option<&'static str> {
        None
    }

    fn has_receiver_binding_obligation(&self) -> bool {
        false
    }

    /// Receiver-dependent declaration evidence that still constrains binding.
    /// The shared engine combines it with the selected call-target answer.
    fn receiver_binding_completion(
        &self,
        _evaluation: &mut FactEvaluation<'_, '_>,
        _candidate: SemanticId,
        _call: &LoweredCallApplicabilityObligation,
        _signature: &LoweredCallableSignatureProperty,
    ) -> StoreResult<Option<ResolutionCompletion>> {
        Ok(Some(ResolutionCompletion::Complete))
    }

    /// Receiver syntax can name a lexically visible extension declaration.
    fn has_scoped_receiver_extensions(&self) -> bool {
        false
    }

    /// Retain an unmodeled callable as a partial receiver candidate.
    fn retains_unmodeled_receiver_callables(&self) -> bool {
        true
    }

    /// A missing receiver member stays open when an extension search is not modeled.
    fn missing_receiver_extension_reason(&self) -> Option<&'static [u8]> {
        None
    }

    /// A language may leave unmatched explicit constructions open.
    fn unmatched_construction_reason(&self) -> Option<&'static [u8]> {
        None
    }

    /// Assess the receiver member family before a separate extension phase.
    /// A surviving conditional member also prevents extension fallback.
    fn scoped_extensions_follow_member_selection(&self) -> bool {
        false
    }

    fn has_intrinsic_call_type_table(&self) -> bool {
        false
    }

    fn type_in_call_position(&self) -> TypeInCallPosition {
        TypeInCallPosition::Nothing
    }

    fn map_arguments(
        &self,
        call: &LoweredCallApplicabilityObligation,
        signature: &LoweredCallableSignatureProperty,
    ) -> MappingAssessment;

    fn result_application_member_names(&self) -> &'static [&'static str] {
        &[]
    }

    /// Declared members whose eligibility is proved by the selected facts.
    /// Intrinsic function signatures do not require declaration eligibility.
    fn declared_result_application_member_names(&self) -> &'static [&'static str] {
        self.result_application_member_names()
    }

    fn intrinsic_call_type(
        &self,
        _kind: IntrinsicTypeKind,
        _spelling: &str,
    ) -> Option<IntrinsicCallType> {
        None
    }

    fn intrinsic_call_type_converts(
        &self,
        source: IntrinsicCallType,
        target: IntrinsicCallType,
    ) -> bool {
        source == target
    }

    #[allow(clippy::too_many_arguments)]
    fn assess_candidate(
        &self,
        evaluation: &mut FactEvaluation<'_, '_>,
        candidate: SemanticId,
        call: &LoweredCallApplicabilityObligation,
        signature: &LoweredCallableSignatureProperty,
        call_inventory_complete: bool,
        previous_answers: &AnswerMap,
        previous_states: &StateMap,
        completion: &mut ResolutionCompletion,
    ) -> StoreResult<Option<CandidateAssessment>> {
        let mapping = self.map_arguments(call, signature);
        if !call_inventory_complete || signature.completion() != &ResolutionCompletion::Complete {
            return Ok(Some(CandidateAssessment::unknown(candidate)));
        }
        match mapping {
            MappingAssessment::Mapped {
                bindings,
                used_defaults,
                used_vararg,
                result_application_lists,
            } => {
                let Some(type_substitution) = evaluation.explicit_call_type_substitution(
                    candidate,
                    call,
                    signature,
                    previous_states,
                )?
                else {
                    return Ok(None);
                };
                let Some(type_substitution) = type_substitution else {
                    return Ok(Some(CandidateAssessment::unknown(candidate)));
                };
                let Some(mut assessment) = self.assess_mapped_candidate(
                    evaluation,
                    candidate,
                    call,
                    signature,
                    &bindings,
                    used_vararg,
                    &type_substitution,
                    previous_answers,
                    previous_states,
                    completion,
                )?
                else {
                    return Ok(None);
                };
                assessment.used_defaults = used_defaults;
                if !result_application_lists.is_empty() {
                    match evaluation.assess_result_application_chain(
                        self,
                        signature,
                        ResultApplicationRequest {
                            call,
                            lists: &result_application_lists,
                            member_names: self.result_application_member_names(),
                            explicit_type_argument_count: 0,
                            type_argument_slots: &[],
                            previous_answers,
                            previous_states,
                        },
                        completion,
                    )? {
                        Some(ResultApplicationAssessment::Applicable { conversions, .. }) => {
                            assessment.conversions.extend(conversions);
                        }
                        Some(ResultApplicationAssessment::Inapplicable(reason)) => {
                            return Ok(Some(CandidateAssessment::inapplicable(candidate, reason)));
                        }
                        Some(ResultApplicationAssessment::Unknown) => {
                            assessment.verdict = ApplicabilityVerdict::Unknown;
                        }
                        None => return Ok(None),
                    }
                }
                Ok(Some(assessment))
            }
            MappingAssessment::Inapplicable(reason) => {
                Ok(Some(CandidateAssessment::inapplicable(candidate, reason)))
            }
            MappingAssessment::Unknown => Ok(Some(CandidateAssessment::unknown(candidate))),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn assess_mapped_candidate(
        &self,
        evaluation: &mut FactEvaluation<'_, '_>,
        candidate: SemanticId,
        call: &LoweredCallApplicabilityObligation,
        signature: &LoweredCallableSignatureProperty,
        bindings: &[ArgumentFormalBinding],
        used_vararg: bool,
        type_substitution: &super::CallTypeSubstitution,
        _previous_answers: &AnswerMap,
        previous_states: &StateMap,
        completion: &mut ResolutionCompletion,
    ) -> StoreResult<Option<CandidateAssessment>> {
        evaluation.assess_legacy_call_candidate(
            candidate,
            call,
            signature,
            bindings,
            used_vararg,
            type_substitution,
            previous_states,
            completion,
        )
    }

    fn compare_conversion(
        &self,
        left: ConversionEvidence,
        right: ConversionEvidence,
        _subtype_relations: &HashMap<(SemanticId, SemanticId), bool>,
    ) -> PartialOrder {
        if left == right {
            PartialOrder::Equal
        } else {
            PartialOrder::Incomparable
        }
    }

    fn compare_specificity(
        &self,
        _left: &CandidateAssessment,
        _right: &CandidateAssessment,
    ) -> PartialOrder {
        PartialOrder::Incomparable
    }

    /// Inheritance precedes invocation. Member references reuse this hook
    /// without constructing a call or applying argument applicability.
    fn refine_member_inheritance(
        &self,
        _evaluation: &mut FactEvaluation<'_, '_>,
        answer: ResolutionAnswer,
        _reference: SemanticId,
        _signatures: &HashMap<
            SemanticId,
            InternedFactRow<SelectedTypedRow<LoweredCallableSignatureProperty>>,
        >,
        _previous_states: &StateMap,
    ) -> StoreResult<Option<ResolutionAnswer>> {
        Ok(Some(answer))
    }

    #[allow(clippy::too_many_arguments)]
    fn prefilter_candidates(
        &self,
        _evaluation: &mut FactEvaluation<'_, '_>,
        answer: ResolutionAnswer,
        _obligation: &LoweredCallApplicabilityObligation,
        _signatures: &HashMap<
            SemanticId,
            InternedFactRow<SelectedTypedRow<LoweredCallableSignatureProperty>>,
        >,
        _previous_states: &StateMap,
    ) -> StoreResult<Option<(ResolutionAnswer, Option<SemanticId>)>> {
        Ok(Some((answer, None)))
    }

    fn classify_primitive_pairs(
        &self,
        evaluation: &mut FactEvaluation<'_, '_>,
        pairs: &[(SemanticId, SemanticId)],
    ) -> StoreResult<Option<CallCandidateApplicability>> {
        evaluation.classify_intrinsic_call_pairs(self, pairs)
    }
}

impl FactEvaluation<'_, '_> {
    pub(super) fn assess_value_application(
        &mut self,
        definition: SemanticId,
        call: &LoweredCallApplicabilityObligation,
        previous_answers: &AnswerMap,
        previous_states: &StateMap,
        completion: &mut ResolutionCompletion,
    ) -> StoreResult<Option<ResultApplicationAssessment>> {
        let read = self
            .session
            .declaration_types_for_definitions(&[definition])?;
        let Some(declarations) = self.accept_session_read(read) else {
            return Ok(None);
        };
        let slots = declarations
            .iter()
            .filter_map(|row| {
                let row = row.get(self.session).row();
                matches!(
                    row.role(),
                    super::DeclarationTypeRole::Value | super::DeclarationTypeRole::Parameter
                )
                .then_some(row.slot())
            })
            .collect::<Vec<_>>();
        let [slot] = slots.as_slice() else {
            return Ok(Some(ResultApplicationAssessment::Unknown));
        };
        let adapter = adapter(call.language());
        self.assess_result_application_from_slot(
            adapter,
            *slot,
            ResultApplicationRequest {
                call,
                lists: call.argument_lists(),
                member_names: adapter.result_application_member_names(),
                explicit_type_argument_count: call.explicit_type_argument_count(),
                type_argument_slots: call.type_argument_slots(),
                previous_answers,
                previous_states,
            },
            completion,
        )
    }

    pub(super) fn indexed_jvm_type_origin_owners(
        &mut self,
        selection: &super::QualifiedOriginSelection,
        rust_owners: &BTreeSet<SemanticId>,
    ) -> StoreResult<Option<BTreeSet<SemanticId>>> {
        // The Rust classifier already proved these owners' language. Avoid
        // another source read on the existing Rust point path.
        let owners = selection
            .origins
            .iter()
            .filter(|origin| {
                origin.shape.namespace == ResolutionNamespace::Callable
                    && origin.shape.receiver_indirection == 0
                    && !rust_owners.contains(&origin.owner)
            })
            .map(|origin| origin.owner)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let Some(rows) = self.session.java_declarations(&owners)? else {
            self.cancellation_observed = true;
            return Ok(None);
        };
        Ok(Some(
            rows.into_iter()
                .filter_map(|row| {
                    matches!(row.kind, JavaInheritanceDeclarationKind::Type { .. })
                        .then_some(row.definition)
                })
                .collect(),
        ))
    }

    /// Collapse only same-signature members dominated in the receiver's owner
    /// hierarchy. Additional member dominance (Java static hiding and its
    /// class-over-interface rule) is proved by the language hook.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn overridden_methods(
        &mut self,
        candidates: &[SemanticId],
        owners: &HashMap<SemanticId, Option<super::FactMemberOwner>>,
        signatures: &HashMap<
            SemanticId,
            InternedFactRow<SelectedTypedRow<LoweredCallableSignatureProperty>>,
        >,
        previous_states: &StateMap,
        additional_dominance: impl Fn(
            SemanticId,
            SemanticId,
            &super::FactMemberOwner,
            &super::FactMemberOwner,
            bool,
        ) -> bool,
        language: Language,
    ) -> StoreResult<Option<(HashSet<SemanticId>, bool)>> {
        let mut requested = candidates.iter().copied().collect::<BTreeSet<_>>();
        requested.extend(
            owners
                .values()
                .filter_map(|owner| owner.as_ref().map(super::FactMemberOwner::owner)),
        );
        let Some(rows) = self
            .session
            .java_declarations(&requested.into_iter().collect::<Vec<_>>())?
        else {
            self.cancellation_observed = true;
            return Ok(None);
        };
        let declarations = rows
            .into_iter()
            .map(|row| (row.definition, row.kind))
            .collect::<HashMap<_, _>>();
        let accesses = owners
            .iter()
            .filter_map(|(&target, owner)| {
                owner.as_ref().map(|owner| {
                    (
                        target,
                        self.method_access_for_override(owner, declarations.get(&target)),
                    )
                })
            })
            .collect::<HashMap<_, _>>();
        let mut removed = HashSet::default();
        let mut unresolved = false;
        for &base in candidates {
            let Some(Some(base_owner)) = owners.get(&base) else {
                continue;
            };
            if base_owner.hierarchy_depth() == 0 {
                continue;
            }
            for &derived in candidates {
                if self.poll_cancelled() {
                    return Ok(None);
                }
                if base == derived {
                    continue;
                }
                let Some(Some(derived_owner)) = owners.get(&derived) else {
                    continue;
                };
                // Independent imports or enclosing scopes are distinct receiver
                // searches, even if their declaring owners are related.
                if base_owner.receiver() != derived_owner.receiver() {
                    continue;
                }
                let Some(nearer) =
                    self.method_owner_inherits(derived_owner.owner(), base_owner.owner())
                else {
                    return Ok(None);
                };
                let language_dominates =
                    additional_dominance(base, derived, base_owner, derived_owner, nearer);
                if !nearer && !language_dominates {
                    continue;
                }
                if !language_dominates {
                    match (
                        language_method_is_instance_for_override(
                            language,
                            accesses.get(&base).copied().flatten(),
                            declarations.get(&base_owner.owner()),
                        ),
                        language_method_is_instance_for_override(
                            language,
                            accesses.get(&derived).copied().flatten(),
                            declarations.get(&derived_owner.owner()),
                        ),
                    ) {
                        (Some(true), Some(true)) => {}
                        (Some(false), _) | (_, Some(false)) => continue,
                        _ => {
                            unresolved = true;
                            continue;
                        }
                    }
                }
                let (Some(base_signature), Some(derived_signature)) =
                    (signatures.get(&base), signatures.get(&derived))
                else {
                    unresolved = true;
                    continue;
                };
                let base_signature = base_signature.get(self.session).row().clone();
                let derived_signature = derived_signature.get(self.session).row().clone();
                match self.same_override_signature(
                    &base_signature,
                    &derived_signature,
                    previous_states,
                    language,
                )? {
                    Some(true) => {
                        removed.insert(base);
                        break;
                    }
                    Some(false) => {}
                    None => unresolved = true,
                }
            }
        }
        Ok(Some((removed, unresolved)))
    }

    pub(super) fn filter_scala_overridden_methods(
        &mut self,
        answer: ResolutionAnswer,
        signatures: &HashMap<
            SemanticId,
            InternedFactRow<SelectedTypedRow<LoweredCallableSignatureProperty>>,
        >,
        previous_states: &StateMap,
    ) -> StoreResult<Option<ResolutionAnswer>> {
        if answer.targets().len() < 2 {
            return Ok(Some(answer));
        }
        let owners = answer
            .targets()
            .iter()
            .filter_map(|target| {
                self.member_owner_by_target
                    .get(target)
                    .map(|owner| (*target, owner.clone()))
            })
            .collect();
        let Some((removed, unresolved)) = self.overridden_methods(
            answer.targets(),
            &owners,
            signatures,
            previous_states,
            |_, _, _, _, _| false,
            Language::Scala,
        )?
        else {
            return Ok(None);
        };
        let (targets, witnesses, mut completion) = answer.into_parts();
        if unresolved {
            completion = completion.combine(&super::incomplete(super::canonical_service_reason(
                self.session,
                &*self.hierarchy,
                b"method-override-unproven",
                &[super::CanonicalIdentityPart::identity(self.root)],
            )?));
        }
        Ok(Some(ResolutionAnswer::new(
            targets
                .into_vec()
                .into_iter()
                .filter(|target| !removed.contains(target))
                .collect::<Vec<_>>(),
            witnesses
                .into_vec()
                .into_iter()
                .filter(|witness| !removed.contains(&witness.target()))
                .collect::<Vec<_>>(),
            completion,
        )))
    }
    /// Hierarchy candidates have exact admitted ownership rows. A lexical
    /// candidate may not have visited that cache; its selected declaration's
    /// modifiers then prove the same access category. A known missing or
    /// conflicting ownership row cannot be replaced by that declaration proof.
    pub(super) fn method_access_for_override(
        &self,
        member: &super::FactMemberOwner,
        declaration: Option<&JavaInheritanceDeclarationKind>,
    ) -> Option<brokk_bifrost_core::analyzer::resolution_facts::ResolutionMemberAccess> {
        use brokk_bifrost_core::analyzer::resolution_facts::{
            ResolutionMemberAccess, ResolutionMemberKind,
        };
        if member.kind() != ResolutionMemberKind::Method {
            return None;
        }
        match self.hierarchy.member_owner_metadata.get(&member.target()) {
            Some(super::ExactMemberOwnerMetadata::Unique(row)) => {
                let row = row.get(self.session).row();
                (row.kind() == ResolutionMemberKind::Method
                    && row.owner_definition() == member.owner())
                .then_some(row.access())
            }
            Some(_) => None,
            None => match declaration {
                Some(JavaInheritanceDeclarationKind::Method { is_static, .. }) => {
                    Some(if *is_static {
                        ResolutionMemberAccess::Type
                    } else {
                        ResolutionMemberAccess::Instance
                    })
                }
                _ => None,
            },
        }
    }

    // A recorded candidate path is just one path through an interface DAG.
    // Dominance asks whether the declaring owners are related, independently
    // of which shortest path discovered the base declaration first.
    pub(super) fn method_owner_inherits(
        &mut self,
        derived: SemanticId,
        base: SemanticId,
    ) -> Option<bool> {
        if derived == base {
            return Some(false);
        }
        let mut pending = vec![derived];
        let mut visited = HashSet::default();
        while let Some(owner) = pending.pop() {
            if self.poll_cancelled() {
                return None;
            }
            if !visited.insert(owner) {
                continue;
            }
            let node = self
                .hierarchy
                .edge_node_snapshot(owner)
                .expect("Callable collection sealed the ancestor closure");
            for ordinal in 0..node.edge_count {
                if self.poll_cancelled() {
                    return None;
                }
                let edge = self.hierarchy.edge_snapshot(owner, ordinal);
                // An ambiguous supertype cannot prove overriding. Its existing
                // hierarchy completion keeps the candidate answer incomplete.
                if edge.target_count != 1 {
                    continue;
                }
                let target = self.hierarchy.edge_target(owner, ordinal, 0);
                if target == base {
                    return Some(true);
                }
                pending.push(target);
            }
        }
        Some(false)
    }

    fn same_override_signature(
        &mut self,
        base: &LoweredCallableSignatureProperty,
        derived: &LoweredCallableSignatureProperty,
        previous_states: &StateMap,
        language: Language,
    ) -> StoreResult<Option<bool>> {
        if base.parameters().len() != derived.parameters().len() {
            return Ok(Some(false));
        }
        // Erasure/substitution needs its own proof. Unknown generic signatures
        // remain candidates with explicit incompleteness.
        if base.type_parameter_count() != 0 || derived.type_parameter_count() != 0 {
            return Ok(None);
        }
        let mut unknown = false;
        for (left, right) in base.parameters().iter().zip(derived.parameters()) {
            if self.poll_cancelled() {
                return Ok(None);
            }
            let parameter_slots = [left.slot(), right.slot()];
            self.demand_slot(left.slot());
            self.demand_slot(right.slot());
            let (Some(left), Some(right)) = (
                previous_states.get(&left.slot()),
                previous_states.get(&right.slot()),
            ) else {
                unknown = true;
                continue;
            };
            if left.completion() != &ResolutionCompletion::Complete
                || right.completion() != &ResolutionCompletion::Complete
            {
                if language != Language::Java
                    || !self.java_parameter_lookups_equivalent(parameter_slots, previous_states)?
                {
                    unknown = true;
                }
                continue;
            }
            let ([left], [right]) = (left.possible_values(), right.possible_values()) else {
                unknown = true;
                continue;
            };
            if left.ty() != right.ty() {
                return Ok(Some(false));
            }
        }
        Ok((!unknown).then_some(true))
    }

    fn classify_intrinsic_call_pairs<A: CallApplicabilityAdapter + ?Sized>(
        &mut self,
        adapter: &A,
        pairs: &[(SemanticId, SemanticId)],
    ) -> StoreResult<Option<CallCandidateApplicability>> {
        if !adapter.has_intrinsic_call_type_table() {
            return Ok(Some(CallCandidateApplicability::Unresolved));
        }
        let identities = pairs
            .iter()
            .flat_map(|(source, target)| [*source, *target])
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let Some(intrinsics) = self.session.intrinsic_call_type_descriptors(&identities)? else {
            return Ok(None);
        };
        let mut types = HashMap::default();
        for intrinsic in intrinsics {
            if self.poll_cancelled() {
                return Ok(None);
            }
            if let Some(value_type) =
                adapter.intrinsic_call_type(intrinsic.kind(), intrinsic.spelling())
            {
                types.insert(intrinsic.identity(), value_type);
            }
        }
        let applicable = pairs.iter().all(|(source, target)| {
            types
                .get(source)
                .zip(types.get(target))
                .is_some_and(|(&source, &target)| {
                    adapter.intrinsic_call_type_converts(source, target)
                })
        });
        if applicable {
            return Ok(Some(CallCandidateApplicability::ProvenApplicable));
        }
        let every_pair_is_intrinsic = pairs
            .iter()
            .all(|(source, target)| types.contains_key(source) && types.contains_key(target));
        Ok(Some(if every_pair_is_intrinsic {
            CallCandidateApplicability::PrimitiveTypeMismatch
        } else {
            CallCandidateApplicability::Unresolved
        }))
    }
}

pub(crate) struct PositionalAdapter;

static POSITIONAL_ADAPTER: PositionalAdapter = PositionalAdapter;

pub(crate) fn adapter(language: Language) -> &'static dyn CallApplicabilityAdapter {
    crate::analyzer::languages::language_support(language)
        .and_then(|support| support.call_applicability_adapter())
        .unwrap_or(&POSITIONAL_ADAPTER)
}

impl CallApplicabilityAdapter for PositionalAdapter {
    fn map_arguments(
        &self,
        call: &LoweredCallApplicabilityObligation,
        signature: &LoweredCallableSignatureProperty,
    ) -> MappingAssessment {
        map_call_shape(
            call,
            signature,
            false,
            false,
            CallableRejectionReason::ArityBelowRequired,
        )
    }
}

pub(crate) fn map_call_shape(
    call: &LoweredCallApplicabilityObligation,
    signature: &LoweredCallableSignatureProperty,
    allow_defaults: bool,
    allow_labels: bool,
    missing_required_reason: CallableRejectionReason,
) -> MappingAssessment {
    if call.argument_lists().is_empty() || signature.parameter_lists().is_empty() {
        return MappingAssessment::Unknown;
    }
    let Some(mapping) = map_explicit_argument_lists(call.argument_lists(), signature, false) else {
        return MappingAssessment::Inapplicable(CallableRejectionReason::ListShapeMismatch);
    };
    if signature.parameter_lists()[mapping.next_parameter_list..]
        .iter()
        .any(|list| !signature.contextual_parameter_lists().contains(list))
    {
        return MappingAssessment::Unknown;
    }
    map_matching_argument_lists(
        call,
        signature,
        &mapping.mapped_lists,
        allow_defaults,
        allow_labels,
        missing_required_reason,
        mapping.result_application_lists,
    )
}

pub(crate) fn map_scala_call_shape(
    call: &LoweredCallApplicabilityObligation,
    signature: &LoweredCallableSignatureProperty,
    allow_defaults: bool,
    allow_labels: bool,
    missing_required_reason: CallableRejectionReason,
) -> MappingAssessment {
    if call.argument_lists().is_empty() {
        return MappingAssessment::Unknown;
    }
    let Some(mapping) = map_explicit_argument_lists(call.argument_lists(), signature, true) else {
        return MappingAssessment::Inapplicable(CallableRejectionReason::ListShapeMismatch);
    };
    map_matching_argument_lists(
        call,
        signature,
        &mapping.mapped_lists,
        allow_defaults,
        allow_labels,
        missing_required_reason,
        mapping.result_application_lists,
    )
}

struct ExplicitArgumentListMapping {
    mapped_lists: Vec<(u32, u32)>,
    result_application_lists: Vec<u32>,
    next_parameter_list: usize,
}

fn map_explicit_argument_lists(
    call_lists: &[u32],
    signature: &LoweredCallableSignatureProperty,
    allow_result_application: bool,
) -> Option<ExplicitArgumentListMapping> {
    let formal_lists = signature.parameter_lists();
    let contextual_lists = signature.contextual_parameter_lists();
    let mut mapped_lists = Vec::with_capacity(call_lists.len().min(formal_lists.len()));
    let mut result_application_lists = Vec::new();
    let mut parameter_list_index = 0;
    for (call_list_index, &call_list) in call_lists.iter().enumerate() {
        let mut skipped_contextual = false;
        while parameter_list_index < formal_lists.len()
            && contextual_lists.contains(&formal_lists[parameter_list_index])
            && call_lists.len() - call_list_index < formal_lists.len() - parameter_list_index
        {
            parameter_list_index += 1;
            skipped_contextual = true;
        }
        if let Some(&parameter_list) = formal_lists.get(parameter_list_index) {
            if !skipped_contextual && call_list != parameter_list {
                return None;
            }
            mapped_lists.push((call_list, parameter_list));
            parameter_list_index += 1;
        } else if allow_result_application {
            result_application_lists.push(call_list);
        } else {
            return None;
        }
    }

    Some(ExplicitArgumentListMapping {
        mapped_lists,
        result_application_lists,
        next_parameter_list: parameter_list_index,
    })
}

fn map_matching_argument_lists(
    call: &LoweredCallApplicabilityObligation,
    signature: &LoweredCallableSignatureProperty,
    mapped_lists: &[(u32, u32)],
    allow_defaults: bool,
    allow_labels: bool,
    missing_required_reason: CallableRejectionReason,
    result_application_lists: Vec<u32>,
) -> MappingAssessment {
    let arguments = call.arguments();
    let parameters = signature.parameters();
    let metadata = signature.parameter_applicability();
    let mut bindings = Vec::with_capacity(arguments.len());
    let mut used_parameters = vec![false; parameters.len()];
    let mut used_defaults = 0_u32;
    let mut used_vararg = false;

    for &(call_list_ordinal, parameter_list_ordinal) in mapped_lists {
        let list_arguments = arguments
            .iter()
            .enumerate()
            .filter(|(_, argument)| argument.list_ordinal() == call_list_ordinal)
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        let list_parameters = metadata
            .iter()
            .enumerate()
            .filter(|(_, parameter)| parameter.list_ordinal() == parameter_list_ordinal)
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        let repeated = list_parameters
            .iter()
            .copied()
            .filter(|&index| parameters[index].repeated())
            .collect::<Vec<_>>();
        if repeated.len() > 1
            || repeated
                .first()
                .is_some_and(|index| list_parameters.last() != Some(index))
        {
            return MappingAssessment::Unknown;
        }
        let repeated_index = repeated.first().copied();
        let mut next_parameter = 0_usize;
        let mut named_argument_seen = false;

        for argument_index in list_arguments {
            let argument = &arguments[argument_index];
            let parameter_index = if let Some(label) = argument.label() {
                named_argument_seen = true;
                if !allow_labels {
                    return MappingAssessment::Unknown;
                }
                let mut matched = None;
                for &index in &list_parameters {
                    let Some(parameter_label) = metadata[index].label() else {
                        return MappingAssessment::Unknown;
                    };
                    if parameter_label == label && matched.replace(index).is_some() {
                        return MappingAssessment::Unknown;
                    }
                }
                let Some(index) = matched else {
                    return MappingAssessment::Inapplicable(
                        CallableRejectionReason::UnknownNamedArgument,
                    );
                };
                index
            } else {
                if named_argument_seen {
                    return MappingAssessment::Unknown;
                }
                while next_parameter < list_parameters.len()
                    && used_parameters[list_parameters[next_parameter]]
                {
                    next_parameter += 1;
                }
                let index = match list_parameters.get(next_parameter).copied() {
                    Some(index) => index,
                    None => match repeated_index {
                        Some(repeated_index) => repeated_index,
                        None => {
                            return MappingAssessment::Inapplicable(
                                CallableRejectionReason::ArityAboveTotal,
                            );
                        }
                    },
                };
                if Some(index) != repeated_index {
                    next_parameter += 1;
                }
                index
            };

            if used_parameters[parameter_index] && Some(parameter_index) != repeated_index {
                return MappingAssessment::Unknown;
            }
            used_parameters[parameter_index] = true;
            used_vararg |= Some(parameter_index) == repeated_index;
            bindings.push(ArgumentFormalBinding {
                argument_index,
                parameter_index,
            });
        }

        for &parameter_index in &list_parameters {
            if used_parameters[parameter_index] || Some(parameter_index) == repeated_index {
                continue;
            }
            let parameter = &metadata[parameter_index];
            if allow_defaults {
                if !parameter.semantics_known() {
                    return MappingAssessment::Unknown;
                }
                if parameter.has_default() {
                    used_defaults = used_defaults
                        .checked_add(1)
                        .expect("defaulted parameter count fits u32");
                    continue;
                }
            }
            return MappingAssessment::Inapplicable(missing_required_reason);
        }
    }

    bindings.sort_unstable_by_key(|binding| binding.argument_index);
    MappingAssessment::Mapped {
        bindings,
        used_defaults,
        used_vararg,
        result_application_lists,
    }
}

pub(super) fn select_candidate_indices<A: CallApplicabilityAdapter + ?Sized>(
    adapter: &A,
    assessments: &[CandidateAssessment],
    subtype_relations: &HashMap<(SemanticId, SemanticId), bool>,
) -> Vec<usize> {
    assessments
        .iter()
        .enumerate()
        .filter_map(|(index, candidate)| {
            if candidate.verdict == ApplicabilityVerdict::Inapplicable {
                return None;
            }
            if candidate.verdict == ApplicabilityVerdict::Unknown {
                return Some(index);
            }
            let dominated = assessments.iter().enumerate().any(|(other_index, other)| {
                index != other_index
                    && other.verdict == ApplicabilityVerdict::Applicable
                    && dominates(adapter, other, candidate, subtype_relations)
            });
            (!dominated).then_some(index)
        })
        .collect()
}

impl FactEvaluation<'_, '_> {
    fn intrinsic_function_member(
        &mut self,
        slot: SemanticId,
        member_names: &[&str],
        answers: &AnswerMap,
        states: &StateMap,
    ) -> StoreResult<Option<Option<LoweredCallableSignatureProperty>>> {
        self.demand_slot(slot);
        let Some(state) = states.get(&slot) else {
            return Ok(Some(None));
        };
        let Some(ty) = super::singleton_runtime_type(state) else {
            return Ok(Some(None));
        };
        let read = self
            .session
            .intrinsics_for_type_identities(&[ty.identity()])?;
        let Some(rows) = self.accept_session_read(read) else {
            return Ok(None);
        };
        let shape = rows.iter().find_map(|row| {
            let seed = row.get(self.session).row();
            if seed.kind() != IntrinsicTypeKind::LanguageBuiltin {
                return None;
            }
            [("scala.Function", "apply"), ("kotlin.Function", "invoke")]
                .into_iter()
                .find_map(|(prefix, member)| {
                    member_names.contains(&member).then_some(())?;
                    let arity = seed.spelling().strip_prefix(prefix)?.parse::<u32>().ok()?;
                    Some(arity)
                })
        });
        let Some(arity) = shape else {
            return Ok(Some(None));
        };
        let Some(arguments) =
            self.sparse_type_arguments_from_value(slot, ty.identity(), answers, states)?
        else {
            return Ok(None);
        };
        let super::SparseReceiverOwnerTypeArguments::Known { arguments, .. } = arguments else {
            return Ok(Some(None));
        };
        let Some(arguments) = arguments
            .into_iter()
            .map(|argument| {
                argument
                    .filter(|argument| {
                        argument.indirection_delta == 0 && argument.reference_indirection_delta == 0
                    })
                    .map(|argument| argument.slot)
            })
            .collect::<Option<Vec<_>>>()
        else {
            return Ok(Some(None));
        };
        if arguments.len() != arity as usize + 1 {
            return Ok(Some(None));
        }
        let read = self.session.transfers_from_sources(&arguments)?;
        let Some(rows) = self.accept_session_read(read) else {
            return Ok(None);
        };
        let mut runtime_slots = HashMap::default();
        for row in rows {
            let transfer = row.get(self.session).row();
            let rule = transfer.rule();
            if transfer.kind() == super::ResolutionTypeTransferKind::DeclaredType
                && rule.indirection_delta() == 0
                && rule.reference_indirection_delta() == 0
                && matches!(
                    rule.value_transform(),
                    super::TypeTransferValueTransform::ToRuntime { addressable: false }
                )
            {
                assert!(
                    runtime_slots
                        .insert(transfer.source_slot(), rule.target_slot())
                        .is_none(),
                    "a function type argument has one runtime projection"
                );
            }
        }
        let Some(arguments) = arguments
            .iter()
            .map(|slot| runtime_slots.get(slot).copied())
            .collect::<Option<Vec<_>>>()
        else {
            return Ok(Some(None));
        };
        for &slot in &arguments {
            self.demand_slot(slot);
        }
        let (&result, inputs) = arguments
            .split_last()
            .expect("a function type has a result");
        let parameters = inputs
            .iter()
            .enumerate()
            .map(|(ordinal, &slot)| {
                LoweredCallableParameterProperty::new(
                    u32::try_from(ordinal).expect("function arity fits u32"),
                    slot,
                    slot,
                    false,
                )
            })
            .collect::<Vec<_>>();
        Ok(Some(Some(
            LoweredCallableSignatureProperty::new(
                ty.identity(),
                0,
                parameters,
                ResolutionCompletion::Complete,
            )
            .with_result_types(vec![LoweredCallableResultTypeProperty::new(0, result)]),
        )))
    }

    pub(super) fn assess_result_application_chain<A: CallApplicabilityAdapter + ?Sized>(
        &mut self,
        adapter: &A,
        signature: &LoweredCallableSignatureProperty,
        request: ResultApplicationRequest<'_>,
        completion: &mut ResolutionCompletion,
    ) -> StoreResult<Option<ResultApplicationAssessment>> {
        if request.member_names.is_empty() {
            return Ok(Some(ResultApplicationAssessment::Unknown));
        }
        let [result_type] = signature.result_types() else {
            return Ok(Some(ResultApplicationAssessment::Unknown));
        };
        self.assess_result_application_from_slot(adapter, result_type.slot(), request, completion)
    }

    pub(super) fn assess_result_application_from_slot<A: CallApplicabilityAdapter + ?Sized>(
        &mut self,
        adapter: &A,
        mut result_slot: SemanticId,
        request: ResultApplicationRequest<'_>,
        completion: &mut ResolutionCompletion,
    ) -> StoreResult<Option<ResultApplicationAssessment>> {
        if request.member_names.is_empty() {
            return Ok(Some(ResultApplicationAssessment::Unknown));
        }
        let mut conversions = Vec::new();
        let mut final_result = Some(result_slot);

        for (application_index, &list_ordinal) in request.lists.iter().enumerate() {
            if self.poll_cancelled() {
                return Ok(None);
            }
            self.demand_slot(result_slot);
            let Some(state) = request.previous_states.get(&result_slot) else {
                return Ok(Some(ResultApplicationAssessment::Unknown));
            };
            if state.completion() != &ResolutionCompletion::Complete {
                *completion = completion.combine(state.completion());
            }
            let mut result_types = state
                .possible_values()
                .iter()
                .map(|value| value.ty())
                .collect::<Vec<_>>();
            result_types.sort_unstable();
            result_types.dedup();
            if result_types.is_empty()
                || result_types
                    .iter()
                    .any(|result_type| result_type.indirection() != 0)
            {
                return Ok(Some(ResultApplicationAssessment::Unknown));
            }
            let Some(intrinsic) = self.intrinsic_function_member(
                result_slot,
                request.member_names,
                request.previous_answers,
                request.previous_states,
            )?
            else {
                return Ok(None);
            };
            let (members, signatures, receiver_slot) = if let Some(signature) = intrinsic {
                // Function type arguments carry types, not proven formal labels.
                if request.call.arguments().iter().any(|argument| {
                    argument.list_ordinal() == list_ordinal && argument.label().is_some()
                }) {
                    return Ok(Some(ResultApplicationAssessment::Unknown));
                }
                let member = signature.definition();
                (
                    vec![member],
                    HashMap::from_iter([(member, signature)]),
                    None,
                )
            } else {
                let member_names = adapter.declared_result_application_member_names();
                if member_names.is_empty() {
                    return Ok(Some(ResultApplicationAssessment::Unknown));
                }
                let owners = result_types
                    .iter()
                    .map(|result_type| result_type.identity())
                    .collect::<Vec<_>>();
                let Some(members_by_owner) = self.applied_value_members(
                    &owners,
                    member_names,
                    request.call,
                    request.previous_states,
                )?
                else {
                    return Ok(None);
                };
                let has_open_owner = result_types
                    .iter()
                    .any(|result_type| !members_by_owner.contains_key(&result_type.identity()));
                if has_open_owner {
                    return Ok(Some(ResultApplicationAssessment::Unknown));
                }
                if members_by_owner.values().any(Vec::is_empty) {
                    if result_types
                        .iter()
                        .all(|result_type| members_by_owner[&result_type.identity()].is_empty())
                        && self.result_types_prove_non_callable(&owners)?
                    {
                        return Ok(Some(ResultApplicationAssessment::Inapplicable(
                            CallableRejectionReason::ListShapeMismatch,
                        )));
                    }
                    return Ok(Some(ResultApplicationAssessment::Unknown));
                }
                let mut members = members_by_owner
                    .values()
                    .flatten()
                    .copied()
                    .collect::<Vec<_>>();
                members.sort_unstable();
                members.dedup();
                if members.is_empty() {
                    if !self.result_types_prove_non_callable(&owners)? {
                        return Ok(Some(ResultApplicationAssessment::Unknown));
                    }
                    return Ok(Some(ResultApplicationAssessment::Inapplicable(
                        CallableRejectionReason::ListShapeMismatch,
                    )));
                }

                let signature_read = self.session.signatures_for_definitions(&members)?;
                let Some(signature_rows) = self.accept_session_read(signature_read) else {
                    return Ok(None);
                };
                let signatures = signature_rows
                    .iter()
                    .map(|row| {
                        let signature = row.get(self.session).row().clone();
                        (signature.definition(), signature)
                    })
                    .collect::<HashMap<_, _>>();
                (members, signatures, Some(result_slot))
            };
            let (type_argument_count, type_argument_slots) = if application_index == 0 {
                (
                    request.explicit_type_argument_count,
                    request.type_argument_slots,
                )
            } else {
                (0, &[][..])
            };
            let Some(invocation) = result_application_obligation(
                request.call,
                receiver_slot,
                list_ordinal,
                type_argument_count,
                type_argument_slots,
            ) else {
                return Ok(Some(ResultApplicationAssessment::Unknown));
            };
            let mut assessments = Vec::with_capacity(members.len());
            for &member in &members {
                let Some(apply_signature) = signatures.get(&member) else {
                    assessments.push(CandidateAssessment::unknown(member));
                    continue;
                };
                let transfers_list = matches!(
                    adapter.map_arguments(&invocation, apply_signature),
                    MappingAssessment::Mapped { result_application_lists, .. }
                        if !result_application_lists.is_empty()
                );
                if transfers_list {
                    // A getter transfers this same list to its result. The
                    // candidate assessment does not return that applied result
                    // slot, so accepting it would reuse the unapplied getter
                    // result for the next list. Keep this continuation unknown
                    // rather than recurse through a potentially cyclic chain.
                    assessments.push(CandidateAssessment::unknown(member));
                    continue;
                }
                let Some(assessment) = adapter.assess_candidate(
                    self,
                    member,
                    &invocation,
                    apply_signature,
                    true,
                    request.previous_answers,
                    request.previous_states,
                    completion,
                )?
                else {
                    return Ok(None);
                };
                assessments.push(assessment);
            }
            let selected = select_candidate_indices(adapter, &assessments, &HashMap::default());
            if selected.is_empty() {
                return Ok(Some(ResultApplicationAssessment::Inapplicable(
                    CallableRejectionReason::ListShapeMismatch,
                )));
            }
            let [selected_index] = selected.as_slice() else {
                return Ok(Some(ResultApplicationAssessment::Unknown));
            };
            let selected = &assessments[*selected_index];
            match selected.verdict {
                ApplicabilityVerdict::Applicable => {
                    conversions.extend(selected.conversions.iter().copied());
                    let selected_signature = &signatures[&selected.candidate];
                    let [result_type] = selected_signature.result_types() else {
                        final_result = None;
                        if list_ordinal != *request.lists.last().unwrap() {
                            return Ok(Some(ResultApplicationAssessment::Unknown));
                        }
                        continue;
                    };
                    result_slot = result_type.slot();
                    self.demand_slot(result_slot);
                    final_result = Some(result_slot);
                }
                ApplicabilityVerdict::Inapplicable => {
                    if assessments
                        .iter()
                        .any(|assessment| assessment.verdict == ApplicabilityVerdict::Unknown)
                    {
                        return Ok(Some(ResultApplicationAssessment::Unknown));
                    }
                    return Ok(Some(ResultApplicationAssessment::Inapplicable(
                        CallableRejectionReason::ListShapeMismatch,
                    )));
                }
                ApplicabilityVerdict::Unknown => {
                    return Ok(Some(ResultApplicationAssessment::Unknown));
                }
            }
        }
        Ok(Some(ResultApplicationAssessment::Applicable {
            conversions,
            result_slot: final_result,
        }))
    }

    fn result_types_prove_non_callable(&mut self, owners: &[SemanticId]) -> StoreResult<bool> {
        let intrinsic_read = self.session.intrinsics_for_type_identities(owners)?;
        let Some(intrinsics) = self.accept_session_read(intrinsic_read) else {
            return Ok(false);
        };
        if intrinsics.iter().any(|intrinsic| {
            intrinsic.get(self.session).row().kind() == super::IntrinsicTypeKind::Primitive
        }) {
            return Ok(true);
        }
        let Some(declarations) = self.session.java_declarations(owners)? else {
            self.cancellation_observed = true;
            return Ok(false);
        };
        if declarations.len() != owners.len()
            || declarations.iter().any(|declaration| {
                !matches!(
                    declaration.kind,
                    super::super::fact_source::JavaInheritanceDeclarationKind::Type { .. }
                )
            })
        {
            return Ok(false);
        }
        let supertype_read = self.session.supertypes_for_definitions(owners)?;
        let Some(supertypes) = self.accept_session_read(supertype_read) else {
            return Ok(false);
        };
        Ok(supertypes.is_empty())
    }
}

fn result_application_obligation(
    call: &LoweredCallApplicabilityObligation,
    receiver_slot: Option<SemanticId>,
    list_ordinal: u32,
    explicit_type_argument_count: u32,
    type_argument_slots: &[SemanticId],
) -> Option<LoweredCallApplicabilityObligation> {
    let arguments = call
        .arguments()
        .iter()
        .filter(|argument| argument.list_ordinal() == list_ordinal)
        .enumerate()
        .map(|(ordinal, argument)| {
            LoweredCallArgumentProperty::new(
                0,
                u32::try_from(ordinal).expect("result application argument count fits u32"),
                argument.slot(),
                argument
                    .label()
                    .map(|label| label.to_owned().into_boxed_str()),
            )
        })
        .collect::<Vec<_>>();
    let slots = arguments
        .iter()
        .map(LoweredCallArgumentProperty::slot)
        .collect::<Vec<_>>();
    Some(
        LoweredCallApplicabilityObligation::new(
            call.call(),
            call.callee_reference(),
            receiver_slot,
            call.result_slot(),
            slots,
            Vec::new(),
            explicit_type_argument_count,
            call.applicability_reason(),
            call.completion().clone(),
        )
        .with_argument_shape(call.language(), arguments, vec![0])
        .with_type_argument_slots(type_argument_slots.to_vec()),
    )
}

fn dominates<A: CallApplicabilityAdapter + ?Sized>(
    adapter: &A,
    left: &CandidateAssessment,
    right: &CandidateAssessment,
    subtype_relations: &HashMap<(SemanticId, SemanticId), bool>,
) -> bool {
    if left.conversions.len() != right.conversions.len() {
        return false;
    }
    let mut strictly_better = false;
    for (&left_conversion, &right_conversion) in left.conversions.iter().zip(&right.conversions) {
        match adapter.compare_conversion(left_conversion, right_conversion, subtype_relations) {
            PartialOrder::Better => strictly_better = true,
            PartialOrder::Equal => {}
            PartialOrder::Worse | PartialOrder::Incomparable | PartialOrder::Unknown => {
                return false;
            }
        }
    }
    if strictly_better {
        return true;
    }
    adapter.compare_specificity(left, right) == PartialOrder::Better
}

#[cfg(test)]
mod tests {
    use super::*;

    struct RankedAdapter;

    impl CallApplicabilityAdapter for RankedAdapter {
        fn map_arguments(
            &self,
            _call: &LoweredCallApplicabilityObligation,
            _signature: &LoweredCallableSignatureProperty,
        ) -> MappingAssessment {
            MappingAssessment::Unknown
        }

        fn compare_conversion(
            &self,
            left: ConversionEvidence,
            right: ConversionEvidence,
            _subtype_relations: &HashMap<(SemanticId, SemanticId), bool>,
        ) -> PartialOrder {
            match (left.kind, right.kind) {
                (ConversionKind::Exact, ConversionKind::Subtype) => PartialOrder::Better,
                (ConversionKind::Subtype, ConversionKind::Exact) => PartialOrder::Worse,
                (left, right) if left == right => PartialOrder::Equal,
                _ => PartialOrder::Incomparable,
            }
        }
    }

    fn assessment(
        candidate: u64,
        verdict: ApplicabilityVerdict,
        kind: ConversionKind,
    ) -> CandidateAssessment {
        CandidateAssessment {
            candidate: SemanticId::for_test(candidate.to_le_bytes()),
            verdict,
            reason: None,
            conversions: vec![ConversionEvidence {
                argument_ordinal: 0,
                parameter_ordinal: 0,
                source_type: None,
                target_type: None,
                kind,
            }],
            used_vararg: false,
            used_defaults: 0,
        }
    }

    #[test]
    fn kotlin_prefers_the_candidate_that_uses_fewer_defaults_after_equal_conversions() {
        let mut fewer_defaults =
            assessment(1, ApplicabilityVerdict::Applicable, ConversionKind::Exact);
        let mut more_defaults =
            assessment(2, ApplicabilityVerdict::Applicable, ConversionKind::Exact);
        fewer_defaults.used_defaults = 0;
        more_defaults.used_defaults = 1;
        // Equal conversions need known source and target identities; an
        // unknown pair is incomparable, not equal.
        let int = Some(SemanticId::for_test(100_u64.to_le_bytes()));
        for assessment in [&mut fewer_defaults, &mut more_defaults] {
            for evidence in &mut assessment.conversions {
                evidence.source_type = int;
                evidence.target_type = int;
            }
        }
        assert_eq!(
            select_candidate_indices(
                adapter(Language::Kotlin),
                &[fewer_defaults, more_defaults],
                &HashMap::default()
            ),
            vec![0]
        );
    }

    #[test]
    fn selector_discards_only_proven_dominated_candidates() {
        let adapter = RankedAdapter;
        let candidates = [
            assessment(1, ApplicabilityVerdict::Applicable, ConversionKind::Exact),
            assessment(2, ApplicabilityVerdict::Applicable, ConversionKind::Subtype),
            assessment(3, ApplicabilityVerdict::Applicable, ConversionKind::Subtype),
            assessment(4, ApplicabilityVerdict::Unknown, ConversionKind::Unknown),
            CandidateAssessment::inapplicable(
                SemanticId::for_test(b"rejected"),
                CallableRejectionReason::ArityAboveTotal,
            ),
        ];
        assert_eq!(
            select_candidate_indices(&adapter, &candidates, &HashMap::default()),
            vec![0, 3]
        );
    }

    #[test]
    fn incomparable_conversion_vectors_remain_ambiguous() {
        struct IncomparableAdapter;
        impl CallApplicabilityAdapter for IncomparableAdapter {
            fn map_arguments(
                &self,
                _call: &LoweredCallApplicabilityObligation,
                _signature: &LoweredCallableSignatureProperty,
            ) -> MappingAssessment {
                MappingAssessment::Unknown
            }

            fn compare_conversion(
                &self,
                left: ConversionEvidence,
                right: ConversionEvidence,
                _subtype_relations: &HashMap<(SemanticId, SemanticId), bool>,
            ) -> PartialOrder {
                match (left.argument_ordinal, left.kind, right.kind) {
                    (0, ConversionKind::Exact, ConversionKind::Subtype)
                    | (1, ConversionKind::Exact, ConversionKind::Subtype) => PartialOrder::Better,
                    (0, ConversionKind::Subtype, ConversionKind::Exact)
                    | (1, ConversionKind::Subtype, ConversionKind::Exact) => PartialOrder::Worse,
                    (_, left, right) if left == right => PartialOrder::Equal,
                    _ => PartialOrder::Incomparable,
                }
            }
        }

        let mut first = assessment(1, ApplicabilityVerdict::Applicable, ConversionKind::Exact);
        let mut second = assessment(2, ApplicabilityVerdict::Applicable, ConversionKind::Exact);
        first.conversions[0].argument_ordinal = 0;
        first.conversions[0].kind = ConversionKind::Exact;
        second.conversions[0].argument_ordinal = 0;
        second.conversions[0].kind = ConversionKind::Subtype;
        first.conversions.push(ConversionEvidence {
            argument_ordinal: 1,
            parameter_ordinal: 1,
            source_type: None,
            target_type: None,
            kind: ConversionKind::Subtype,
        });
        second.conversions.push(ConversionEvidence {
            argument_ordinal: 1,
            parameter_ordinal: 1,
            source_type: None,
            target_type: None,
            kind: ConversionKind::Exact,
        });
        assert_eq!(
            select_candidate_indices(&IncomparableAdapter, &[first, second], &HashMap::default(),),
            vec![0, 1]
        );
    }

    #[test]
    fn kotlin_maps_named_arguments_defaults_and_a_trailing_vararg() {
        use super::super::super::model::ResolutionCompletion;
        use super::super::super::typed_fact_lowering::{
            LoweredCallArgumentProperty, LoweredCallableParameterApplicability,
            LoweredCallableParameterProperty,
        };

        let id = |label: &'static [u8]| SemanticId::for_test(label);
        let call = LoweredCallApplicabilityObligation::new(
            id(b"call"),
            id(b"reference"),
            None,
            id(b"result"),
            vec![id(b"actual")],
            Vec::new(),
            0,
            id(b"reason"),
            ResolutionCompletion::Complete,
        )
        .with_argument_shape(
            Language::Kotlin,
            vec![LoweredCallArgumentProperty::new(
                0,
                0,
                id(b"actual"),
                Some(Box::from("rest")),
            )],
            vec![0],
        );
        let signature = LoweredCallableSignatureProperty::new(
            id(b"callable"),
            0,
            vec![
                LoweredCallableParameterProperty::new(
                    0,
                    id(b"default"),
                    id(b"default-type"),
                    false,
                ),
                LoweredCallableParameterProperty::new(1, id(b"rest"), id(b"rest-type"), true),
            ],
            ResolutionCompletion::Complete,
        )
        .with_applicability_shape(
            vec![0],
            vec![
                LoweredCallableParameterApplicability::new(
                    0,
                    0,
                    Some(Box::from("prefix")),
                    true,
                    true,
                ),
                LoweredCallableParameterApplicability::new(
                    1,
                    0,
                    Some(Box::from("rest")),
                    false,
                    true,
                ),
            ],
            None,
        );

        assert_eq!(
            adapter(Language::Kotlin).map_arguments(&call, &signature),
            MappingAssessment::Mapped {
                bindings: vec![ArgumentFormalBinding {
                    argument_index: 0,
                    parameter_index: 1,
                }],
                used_defaults: 1,
                used_vararg: true,
                result_application_lists: vec![],
            }
        );
    }

    #[test]
    fn scala_named_labels_select_the_matching_formal() {
        use super::super::super::model::ResolutionCompletion;
        use super::super::super::typed_fact_lowering::{
            LoweredCallArgumentProperty, LoweredCallableParameterApplicability,
            LoweredCallableParameterProperty,
        };

        let id = |label: &'static [u8]| SemanticId::for_test(label);
        let call = LoweredCallApplicabilityObligation::new(
            id(b"call"),
            id(b"reference"),
            None,
            id(b"result"),
            vec![id(b"actual-right"), id(b"actual-left")],
            Vec::new(),
            0,
            id(b"reason"),
            ResolutionCompletion::Complete,
        )
        .with_argument_shape(
            Language::Scala,
            vec![
                LoweredCallArgumentProperty::new(
                    0,
                    0,
                    id(b"actual-right"),
                    Some(Box::from("right")),
                ),
                LoweredCallArgumentProperty::new(0, 1, id(b"actual-left"), Some(Box::from("left"))),
            ],
            vec![0],
        );
        let signature = LoweredCallableSignatureProperty::new(
            id(b"callable"),
            0,
            vec![
                LoweredCallableParameterProperty::new(0, id(b"left"), id(b"left-type"), false),
                LoweredCallableParameterProperty::new(1, id(b"right"), id(b"right-type"), false),
            ],
            ResolutionCompletion::Complete,
        )
        .with_applicability_shape(
            vec![0],
            vec![
                LoweredCallableParameterApplicability::new(
                    0,
                    0,
                    Some(Box::from("left")),
                    false,
                    true,
                ),
                LoweredCallableParameterApplicability::new(
                    1,
                    0,
                    Some(Box::from("right")),
                    false,
                    true,
                ),
            ],
            None,
        );

        assert_eq!(
            adapter(Language::Scala).map_arguments(&call, &signature),
            MappingAssessment::Mapped {
                bindings: vec![
                    ArgumentFormalBinding {
                        argument_index: 0,
                        parameter_index: 1,
                    },
                    ArgumentFormalBinding {
                        argument_index: 1,
                        parameter_index: 0,
                    },
                ],
                used_defaults: 0,
                used_vararg: false,
                result_application_lists: vec![],
            }
        );
    }

    #[test]
    fn go_maps_every_extra_argument_to_the_trailing_variadic_formal() {
        use super::super::super::model::ResolutionCompletion;
        use super::super::super::typed_fact_lowering::{
            LoweredCallArgumentProperty, LoweredCallableParameterApplicability,
            LoweredCallableParameterProperty,
        };

        let id = |label: &'static [u8]| SemanticId::for_test(label);
        let call = LoweredCallApplicabilityObligation::new(
            id(b"call"),
            id(b"reference"),
            None,
            id(b"result"),
            vec![id(b"first"), id(b"second")],
            Vec::new(),
            0,
            id(b"reason"),
            ResolutionCompletion::Complete,
        )
        .with_argument_shape(
            Language::Go,
            vec![
                LoweredCallArgumentProperty::new(0, 0, id(b"first"), None),
                LoweredCallArgumentProperty::new(0, 1, id(b"second"), None),
            ],
            vec![0],
        );
        let signature = LoweredCallableSignatureProperty::new(
            id(b"callable"),
            0,
            vec![LoweredCallableParameterProperty::new(
                0,
                id(b"variadic"),
                id(b"variadic-type"),
                true,
            )],
            ResolutionCompletion::Complete,
        )
        .with_applicability_shape(
            vec![0],
            vec![LoweredCallableParameterApplicability::new(
                0, 0, None, false, true,
            )],
            None,
        );

        assert_eq!(
            adapter(Language::Go).map_arguments(&call, &signature),
            MappingAssessment::Mapped {
                bindings: vec![
                    ArgumentFormalBinding {
                        argument_index: 0,
                        parameter_index: 0,
                    },
                    ArgumentFormalBinding {
                        argument_index: 1,
                        parameter_index: 0,
                    },
                ],
                used_defaults: 0,
                used_vararg: true,
                result_application_lists: vec![],
            }
        );
    }
}
