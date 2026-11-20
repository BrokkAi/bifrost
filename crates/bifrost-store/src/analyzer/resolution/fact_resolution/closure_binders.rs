//! The contextual closure-parameter step (#12159, stage 2).
//!
//! A closure written as a call argument has unannotated identifier binders
//! whose types its context decides: when the call's callee is selected
//! uniquely and completely, and the formal at the closure's position is
//! bounded by the standard `Fn`, `FnMut` or `FnOnce` trait, the bound's
//! parameter types, with the callee's solved generics substituted, are the
//! binders' types. This module is the only reader of the closure-literal and
//! function-shape facts. Everything else keeps the binder's `InferredType`
//! gap: an ambiguous or incomplete callee, a formal with no function shape, a
//! head that does not resolve to the standard trait (a user trait named `Fn`),
//! a supertrait-implied or conflicting bound (no shape is published), an
//! arity mismatch, and any type that still names an unsolved generic.
//!
//! Nothing flows from the closure's return into the callee's generics here.
use super::*;
use crate::analyzer::resolution::fact_source::{ClosureBinderContext, FormalFunctionShape};

/// What the contextual signature decides for one binder.
pub(super) enum ClosureBinderFill {
    /// The binder keeps its gap.
    Unfilled,
    Filled(ResolutionSlotValue),
}

impl FactEvaluation<'_, '_> {
    /// The answer for `reference`, demanding it when it is not yet known.
    fn closure_context_answer(
        &mut self,
        reference: SemanticId,
        answers: &AnswerMap,
    ) -> Option<SharedAnswer> {
        self.demand_reference(reference);
        if let Some(answer) = answers.get(&reference) {
            return Some(Arc::clone(answer));
        }
        self.query_obligations.node(QueryNode::Lexical(reference));
        self.lexical_answers.get(&reference).map(Arc::clone)
    }

    /// Whether a type names no generic argument of its own: a primitive, or a
    /// source declaration with no generic formal. Anything else may carry
    /// arguments that this step cannot substitute, so it stays gapped. `None`
    /// reports cancellation.
    fn closure_type_has_no_generics(&mut self, identity: SemanticId) -> StoreResult<Option<bool>> {
        let Some(descriptors) = self.session.intrinsic_type_descriptors(&[identity])? else {
            return Ok(None);
        };
        if descriptors
            .iter()
            .any(|descriptor| descriptor.kind() == IntrinsicTypeKind::Primitive)
        {
            return Ok(Some(true));
        }
        if identity.ordinal().is_none() {
            return Ok(Some(false));
        }
        // As in call-result instantiation, a generic parameter's declaration
        // is symbolic even when it declares no generic formals of its own.
        let Some(parameters) = self
            .session
            .typed_source
            .generic_parameter_declarations(&[identity], self.cancellation)?
        else {
            return Ok(None);
        };
        if !parameters.is_empty() {
            return Ok(Some(false));
        }
        let read = self.session.generic_formals_for_owners(&[identity])?;
        let Some(rows) = self.accept_session_read(read) else {
            return Ok(None);
        };
        Ok(Some(rows.is_empty()))
    }

    /// The type a contextual signature gives one closure binder, or the
    /// reason to keep its gap. The outer `None` reports cancellation.
    pub(super) fn contextual_closure_binder(
        &mut self,
        context: &ClosureBinderContext,
        projections: &HashMap<SemanticId, LoweredBindingProjection>,
        answers: &AnswerMap,
        previous_states: &StateMap,
    ) -> StoreResult<Option<ClosureBinderFill>> {
        use ClosureBinderFill::Unfilled;
        // The callee must be selected, uniquely and completely.
        let Some(callee) = self.closure_context_answer(context.callee_reference, answers) else {
            return Ok(Some(Unfilled));
        };
        let [target] = callee.targets() else {
            return Ok(Some(Unfilled));
        };
        let target = *target;
        if callee.completion() != &ResolutionCompletion::Complete {
            return Ok(Some(Unfilled));
        }

        // The formal the closure is passed for.
        let read = self
            .session
            .calls_for_references(&[context.callee_reference])?;
        let Some(rows) = self.accept_session_read(read) else {
            return Ok(None);
        };
        let [call] = rows.as_slice() else {
            return Ok(Some(Unfilled));
        };
        let obligation = call.get(self.session).row().clone();
        let Some(argument_index) = obligation
            .argument_slots()
            .iter()
            .position(|&slot| slot == context.argument)
        else {
            return Ok(Some(Unfilled));
        };
        let read = self.session.signatures_for_definitions(&[target])?;
        let Some(rows) = self.accept_session_read(read) else {
            return Ok(None);
        };
        let [signature] = rows.as_slice() else {
            return Ok(Some(Unfilled));
        };
        let signature = signature.get(self.session).row().clone();
        let call_applicability::MappingAssessment::Mapped { bindings, .. } =
            call_applicability_adapter(obligation.language())
                .map_arguments(&obligation, &signature)
        else {
            return Ok(Some(Unfilled));
        };
        let Some(parameter) = bindings
            .iter()
            .find(|binding| binding.argument_index == argument_index)
            .and_then(|binding| signature.parameters().get(binding.parameter_index))
            .filter(|parameter| !parameter.repeated())
        else {
            return Ok(Some(Unfilled));
        };
        let formal = parameter.slot();

        // The formal's type is written as a type parameter (`f: F`, whose
        // bound sits on the parameter's own identity slot) or as the bounded
        // type itself (`f: impl Fn(A)`).
        let read = self.session.generic_formals_for_owners(&[target])?;
        let Some(rows) = self.accept_session_read(read) else {
            return Ok(None);
        };
        let mut formals = rows
            .iter()
            .map(|row| *row.get(self.session).row())
            .collect::<Vec<_>>();
        formals.sort_unstable_by_key(|formal| formal.ordinal());
        let read = self.session.transfers_to_targets(&[formal])?;
        let Some(rows) = self.accept_session_read(read) else {
            return Ok(None);
        };
        let declared = rows
            .iter()
            .map(|row| row.get(self.session).row())
            .filter(|transfer| {
                transfer.kind() == ResolutionTypeTransferKind::DeclaredType
                    && transfer.rule().target_slot() == formal
            })
            .map(|transfer| {
                (
                    transfer.source_slot(),
                    transfer.rule().indirection_delta(),
                    transfer.rule().reference_indirection_delta(),
                )
            })
            .collect::<Vec<_>>();
        let [(written, 0, 0)] = declared[..] else {
            return Ok(Some(Unfilled));
        };
        let mut owners = vec![written];
        let Some(written_head) = self.selected_type_head_reference(written)? else {
            return Ok(None);
        };
        if let Some(head) = written_head
            && let Some(answer) = self.closure_context_answer(head, answers)
            && answer.completion() == &ResolutionCompletion::Complete
            && let [parameter] = answer.targets()
            && formals
                .iter()
                .any(|formal| formal.parameter() == *parameter)
        {
            let read = self
                .session
                .declaration_types_for_definitions(&[*parameter])?;
            let Some(rows) = self.accept_session_read(read) else {
                return Ok(None);
            };
            owners.extend(
                rows.iter()
                    .map(|row| row.get(self.session).row())
                    .filter(|property| property.role() == DeclarationTypeRole::Identity)
                    .map(|property| property.slot()),
            );
        }
        let shapes = self
            .session
            .typed_source
            .formal_function_shapes(&owners, self.cancellation)?;
        if self.poll_cancelled() {
            return Ok(None);
        }
        let [shape] = shapes.as_slice() else {
            return Ok(Some(Unfilled));
        };
        match self.shape_is_standard_function_trait(shape, obligation.language(), answers)? {
            None => return Ok(None),
            Some(false) => return Ok(Some(Unfilled)),
            Some(true) => {}
        }

        // Arity, then the written type at this binder's position.
        if shape.parameters.len() != context.binder_count {
            return Ok(Some(Unfilled));
        }
        let Some(&written_type) = shape.parameters.get(context.ordinal) else {
            return Ok(Some(Unfilled));
        };
        self.demand_slot(written_type.slot);
        let Some(written_state) = previous_states.get(&written_type.slot) else {
            return Ok(Some(Unfilled));
        };
        let read = self
            .session
            .declared_type_arguments_for_owners(&[written_type.slot])?;
        let Some(rows) = self.accept_session_read(read) else {
            return Ok(None);
        };
        if !rows.is_empty() {
            return Ok(Some(Unfilled));
        }
        let Some(written_head) = self.selected_type_head_reference(written_type.slot)? else {
            return Ok(None);
        };
        // A written type names a declaration through a reference. A primitive
        // is seeded directly and names none.
        let named = match written_head {
            Some(head) => {
                let Some(head_answer) = self.closure_context_answer(head, answers) else {
                    return Ok(Some(Unfilled));
                };
                let ([named], ResolutionCompletion::Complete) =
                    (head_answer.targets(), head_answer.completion())
                else {
                    return Ok(Some(Unfilled));
                };
                Some(*named)
            }
            None => None,
        };

        // A written type that is one of the callee's own generics takes the
        // type the call decides for it; any other must be exactly its own.
        let own_formal = named.and_then(|named| {
            formals
                .iter()
                .position(|formal| formal.parameter() == named)
        });
        let value = if let Some(position) = own_formal {
            let (actual, pattern) = if obligation.type_argument_slots().is_empty() {
                let Some(actuals) = self.infer_generic_actuals_from_values(
                    &obligation,
                    &signature,
                    &formals,
                    projections,
                    answers,
                    previous_states,
                )?
                else {
                    return Ok(None);
                };
                let Some(actual) = actuals.get(position).copied().flatten() else {
                    return Ok(Some(Unfilled));
                };
                (Some(actual.0), Some(actual.1))
            } else {
                (
                    usize::try_from(formals[position].ordinal())
                        .ok()
                        .and_then(|ordinal| obligation.type_argument_slots().get(ordinal).copied()),
                    None,
                )
            };
            let Some(actual) = actual else {
                return Ok(Some(Unfilled));
            };
            self.demand_slot(actual);
            let Some(state) = previous_states.get(&actual) else {
                return Ok(Some(Unfilled));
            };
            let Some(value) = exact_singleton_value(state) else {
                return Ok(Some(Unfilled));
            };
            // Use the same signed layer transfer as call-result instantiation.
            // Underflow or an unrepresentable pointer/reference shape is incomplete.
            if let Some(pattern) = pattern {
                match call_result_instantiation_rule(
                    context.binder,
                    -i64::from(pattern.indirection()),
                    -i64::from(pattern.reference_indirection()),
                )
                .apply(value)
                {
                    TypeTransferApplication::Value(value) => value,
                    TypeTransferApplication::NoValue
                    | TypeTransferApplication::IndirectionOutOfRange => return Ok(Some(Unfilled)),
                }
            } else {
                value
            }
        } else {
            let Some(value) = exact_singleton_value(written_state) else {
                return Ok(Some(Unfilled));
            };
            if named.is_some_and(|named| value.ty().identity() != named) {
                return Ok(Some(Unfilled));
            }
            value
        };
        match self.closure_type_has_no_generics(value.ty().identity())? {
            None => return Ok(None),
            Some(false) => return Ok(Some(Unfilled)),
            Some(true) => {}
        }
        let rule = call_result_instantiation_rule(
            context.binder,
            i64::from(written_type.indirection),
            i64::from(written_type.reference_indirection),
        );
        Ok(Some(match rule.apply(value) {
            TypeTransferApplication::Value(value) => ClosureBinderFill::Filled(value),
            TypeTransferApplication::NoValue | TypeTransferApplication::IndirectionOutOfRange => {
                Unfilled
            }
        }))
    }

    /// Whether the shape's trait head resolves to the standard `Fn`, `FnMut`
    /// or `FnOnce` trait. The head is certified by its selected resolution
    /// through the language's identity evidence, never by how it is spelled,
    /// so a workspace trait named `Fn` (which resolves to its own declaration)
    /// never qualifies. `None` reports cancellation.
    fn shape_is_standard_function_trait(
        &mut self,
        shape: &FormalFunctionShape,
        language: Language,
        answers: &AnswerMap,
    ) -> StoreResult<Option<bool>> {
        let Some(head) = self.selected_type_head_reference(shape.trait_head)? else {
            return Ok(None);
        };
        let Some(head) = head else {
            return Ok(Some(false));
        };
        let Some(answer) = self.closure_context_answer(head, answers) else {
            return Ok(Some(false));
        };
        // A standard trait is unindexed: nothing is selected, and the only
        // evidence is the boundary naming it (and its path prefixes).
        let ResolutionCompletion::Incomplete(reasons) = answer.completion() else {
            return Ok(Some(false));
        };
        let boundaries = reasons
            .iter()
            .filter_map(|reason| match reason {
                ResolutionIncompleteReason::OpenBoundary {
                    semantic,
                    status: crate::analyzer::structural::BoundaryStatus::ExternalDeclaredUnindexed,
                } => Some(*semantic),
                _ => None,
            })
            .collect::<Vec<_>>();
        if !answer.targets().is_empty()
            || boundaries.is_empty()
            || boundaries.len() != reasons.iter().count()
        {
            return Ok(Some(false));
        }
        let Some(support) = crate::analyzer::store::store_language_support_for_hook(
            language,
            "standard_function_trait",
        ) else {
            return Ok(Some(false));
        };
        support.standard_function_trait(&boundaries, self.session)
    }
}

/// The one exact value of a complete state.
fn exact_singleton_value(state: &TypedFrontierState) -> Option<ResolutionSlotValue> {
    if state.completion() != &ResolutionCompletion::Complete {
        return None;
    }
    match state.possible_values() {
        [value] => Some(*value),
        _ => None,
    }
}
