//! Structured call-shape mapping and candidate selection.
//!
//! The adapters own language rules. This module owns only candidate
//! retention and the partial order over already-established conversion
//! evidence. All values are query-local; no call assessment is persisted.

use brokk_bifrost_core::analyzer::Language;
use brokk_bifrost_core::analyzer::structural::callable::{
    ApplicabilityVerdict, CallableRejectionReason,
};

use super::super::fact_source::SelectedTypedRow;
use super::super::model::ResolutionAnswer;
use super::super::model::ResolutionCompletion;
use super::super::model::SemanticId;
use super::super::typed_fact_lowering::{
    LoweredCallApplicabilityObligation, LoweredCallArgumentProperty,
    LoweredCallableSignatureProperty,
};
use super::{
    AnswerMap, CallCandidateApplicability, FactEvaluation, InternedFactRow, StateMap, StoreResult,
};
use crate::hash::HashMap;

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
    Applicable(Vec<ConversionEvidence>),
    Inapplicable(CallableRejectionReason),
    Unknown,
}

pub(super) struct ResultApplicationRequest<'a> {
    pub(super) call: &'a LoweredCallApplicabilityObligation,
    pub(super) lists: &'a [u32],
    pub(super) member_names: &'a [&'a str],
    pub(super) previous_states: &'a StateMap,
}

impl CandidateAssessment {
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

    #[allow(clippy::too_many_arguments)]
    fn assess_candidate(
        &self,
        evaluation: &mut FactEvaluation<'_, '_>,
        candidate: SemanticId,
        call: &LoweredCallApplicabilityObligation,
        signature: &LoweredCallableSignatureProperty,
        call_inventory_complete: bool,
        _previous_answers: &AnswerMap,
        previous_states: &StateMap,
        completion: &mut ResolutionCompletion,
    ) -> StoreResult<Option<CandidateAssessment>> {
        let mapping = self.map_arguments(call, signature);
        if !call_inventory_complete
            || signature.completion() != &ResolutionCompletion::Complete
            || call.explicit_type_argument_count() != 0
            || signature.type_parameter_count() != 0
        {
            return Ok(Some(CandidateAssessment::unknown(candidate)));
        }
        match mapping {
            MappingAssessment::Mapped {
                bindings,
                used_defaults,
                used_vararg,
                result_application_lists,
            } => {
                let Some(mut assessment) = self.assess_mapped_candidate(
                    evaluation,
                    candidate,
                    call,
                    signature,
                    &bindings,
                    used_vararg,
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
                            previous_states,
                        },
                        completion,
                    )? {
                        Some(ResultApplicationAssessment::Applicable(conversions)) => {
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
        previous_states: &StateMap,
        completion: &mut ResolutionCompletion,
    ) -> StoreResult<Option<CandidateAssessment>> {
        evaluation.assess_legacy_call_candidate(
            candidate,
            call,
            signature,
            bindings,
            used_vararg,
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
        evaluation.classify_java_primitive_pairs(pairs)
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
    if call.argument_lists() != signature.parameter_lists() {
        return MappingAssessment::Inapplicable(CallableRejectionReason::ListShapeMismatch);
    }

    map_matching_argument_lists(
        call,
        signature,
        call.argument_lists(),
        allow_defaults,
        allow_labels,
        missing_required_reason,
        Vec::new(),
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
    let matched_count = call
        .argument_lists()
        .len()
        .min(signature.parameter_lists().len());
    let matched_lists = &call.argument_lists()[..matched_count];
    if matched_lists != &signature.parameter_lists()[..matched_count] {
        return MappingAssessment::Inapplicable(CallableRejectionReason::ListShapeMismatch);
    }
    let result_application_lists = call.argument_lists()[matched_count..].to_vec();
    map_matching_argument_lists(
        call,
        signature,
        matched_lists,
        allow_defaults,
        allow_labels,
        missing_required_reason,
        result_application_lists,
    )
}

fn map_matching_argument_lists(
    call: &LoweredCallApplicabilityObligation,
    signature: &LoweredCallableSignatureProperty,
    matched_lists: &[u32],
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

    for &list_ordinal in matched_lists {
        let list_arguments = arguments
            .iter()
            .enumerate()
            .filter(|(_, argument)| argument.list_ordinal() == list_ordinal)
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        let list_parameters = metadata
            .iter()
            .enumerate()
            .filter(|(_, parameter)| parameter.list_ordinal() == list_ordinal)
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

        for &list_ordinal in request.lists {
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
            let owners = result_types
                .iter()
                .map(|result_type| result_type.identity())
                .collect::<Vec<_>>();
            let Some(members_by_owner) =
                self.applied_type_members(&owners, request.member_names)?
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
            let Some(invocation) = result_application_obligation(request.call, list_ordinal) else {
                return Ok(Some(ResultApplicationAssessment::Unknown));
            };
            let mut assessments = Vec::with_capacity(members.len());
            for &member in &members {
                let Some(apply_signature) = signatures.get(&member) else {
                    assessments.push(CandidateAssessment::unknown(member));
                    continue;
                };
                let Some(assessment) = adapter.assess_candidate(
                    self,
                    member,
                    &invocation,
                    apply_signature,
                    true,
                    &AnswerMap::default(),
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
                        if list_ordinal != *request.lists.last().unwrap() {
                            return Ok(Some(ResultApplicationAssessment::Unknown));
                        }
                        continue;
                    };
                    result_slot = result_type.slot();
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
        Ok(Some(ResultApplicationAssessment::Applicable(conversions)))
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
    list_ordinal: u32,
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
            None,
            call.result_slot(),
            slots,
            Vec::new(),
            0,
            call.applicability_reason(),
            call.completion().clone(),
        )
        .with_argument_shape(call.language(), arguments, vec![0]),
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
