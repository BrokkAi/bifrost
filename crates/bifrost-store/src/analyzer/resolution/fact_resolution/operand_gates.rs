//! Completion-only operand obligations. All materialized types live for one
//! gate evaluation; no gate is a value producer or an identity shortcut.
use super::call_applicability::{CallFormalType, RepeatedParameterAssessment};
use super::*;
use crate::analyzer::resolution::fact_source::language_jvm_array_operand_rules;
use brokk_bifrost_jvm::java::conversion::{
    JavaConversion, JavaConversionTypes, JavaTypeView, JavaTypeViews,
};
use brokk_bifrost_jvm::java::primitives::{JavaPrimitive, primitive_for_name};

impl FactEvaluation<'_, '_> {
    pub(super) fn evaluate_operand_gates(
        &mut self,
        incoming: &[InternedFactRow<SelectedTypedRow<LoweredTypeTransfer>>],
        answers: &AnswerMap,
        previous: &StateMap,
        states: &mut StateMap,
        dirty_slots: &HashSet<SemanticId>,
        slot_reads: &mut HashMap<SemanticId, TypedItemReads>,
    ) -> StoreResult<bool> {
        for selected in incoming {
            if !selected.get(self.session).row().kind().is_operand_gate() {
                continue;
            }
            let gate = selected.get(self.session).row().clone();
            if self.poll_cancelled() {
                return Ok(false);
            }
            let output = gate.rule().target_slot();
            if !dirty_slots.contains(&output) {
                continue;
            }
            let input = gate.source_slot();
            slot_reads.entry(output).or_default().states.insert(input);
            let _reads = TypedSlotReadScope::new(
                answers,
                previous,
                &self.query_obligations,
                [output],
                slot_reads,
            );
            let Some(state) = states.get(&output).cloned() else {
                continue;
            };
            let mut completion = state.completion().combine(gate.rule().completion());
            let operand = previous.get(&input);
            if let Some(operand) = operand {
                completion = completion.combine(operand.completion());
            }
            let language = self
                .session
                .lexical_source
                .semantic_language_of(output, self.cancellation)?;
            let rules = language.and_then(language_jvm_array_operand_rules);
            let source = operand
                .filter(|state| state.completion() == &ResolutionCompletion::Complete)
                .and_then(|state| exact_singleton_runtime_type(state))
                .filter(|ty| ty.indirection() == 0 && ty.reference_indirection() == 0);
            let mut proven = false;
            if let (Some(rules), Some(source)) = (rules, source) {
                if gate.kind() == ResolutionTypeTransferKind::IndexOperand {
                    let Some(descriptors) = self
                        .session
                        .intrinsic_call_type_descriptors(&[source.identity()])?
                    else {
                        return Ok(false);
                    };
                    proven = descriptors.iter().any(|descriptor| {
                        rules.index_type(descriptor.kind(), descriptor.spelling())
                    });
                } else {
                    let owner = singleton_type_ref(&state).filter(|ty| ty.indirection() == 0);
                    if let Some(owner) = owner {
                        let read = self
                            .session
                            .type_components_for_containers(&[owner.identity()])?;
                        let Some(rows) = self.accept_session_read(read) else {
                            return Ok(false);
                        };
                        let components = rows
                            .iter()
                            .map(|row| *row.get(self.session).row())
                            .filter(|row| row.kind() == ResolutionTypeComponentKind::Element)
                            .collect::<Vec<_>>();
                        if let [component] = components.as_slice() {
                            let target_slot = component.component();
                            self.demand_slot(target_slot);
                            if let Some(target) = previous.get(&target_slot) {
                                completion = completion.combine(target.completion());
                                if target.completion() == &ResolutionCompletion::Complete
                                    && let Some(target) = singleton_type_ref(target)
                                    && target.indirection() == 0
                                    && target.reference_indirection() == 0
                                {
                                    // Nominal IDs cannot establish equality of applied
                                    // types. Preserve their structured completion and
                                    // leave arguments unsupported by this adapter open.
                                    let Some(shapes) = self
                                        .projected_type_shapes(&[input, target_slot], previous)?
                                    else {
                                        return Ok(false);
                                    };
                                    let plain_shapes = shapes.len() == 2
                                        && shapes.iter().all(|shape| {
                                            shape.supported()
                                                && shape.completion()
                                                    == &ResolutionCompletion::Complete
                                                && shape.nodes().iter().all(|node| {
                                                    !matches!(
                                                        node.form(),
                                                        FactProjectedTypeNodeForm::Applied(_)
                                                    )
                                                })
                                        });
                                    for shape in &shapes {
                                        completion = completion.combine(shape.completion());
                                    }
                                    if !plain_shapes {
                                        completion = completion.combine(&incomplete(input));
                                        states.insert(
                                            output,
                                            Arc::new(
                                                Arc::unwrap_or_clone(state)
                                                    .with_completion(completion),
                                            ),
                                        );
                                        continue;
                                    }
                                    let roots = operand_shape_roots(&shapes, [input, target_slot]);
                                    let Some(data) = self.operand_conversion_types(
                                        &[source.identity(), target.identity()],
                                        shapes,
                                        previous,
                                    )?
                                    else {
                                        return Ok(false);
                                    };
                                    let mut types = OperandTypes {
                                        evaluation: self,
                                        states: previous,
                                        data,
                                    };
                                    proven = matches!(
                                        rules.element(&mut types, roots[0], roots[1])?,
                                        JavaConversion::Strict | JavaConversion::Loose
                                    );
                                }
                            }
                        }
                    }
                }
            }
            // A complete but invalid/unknown requirement names its exact
            // operand. An incomplete operand preserves its original reasons.
            if !proven
                && operand
                    .is_none_or(|operand| operand.completion() == &ResolutionCompletion::Complete)
            {
                completion = completion.combine(&incomplete(input));
            }
            states.insert(
                output,
                Arc::new(Arc::unwrap_or_clone(state).with_completion(completion)),
            );
        }
        Ok(true)
    }

    /// Prove conversion to the implicit array formal without replacing its
    /// component identity with the actual or publishing a synthetic type.
    #[doc(hidden)]
    pub fn jvm_repeated_sequence_parameter_type(
        &mut self,
        actual_slot: SemanticId,
        formal_slot: SemanticId,
        actual: ResolutionTypeRef,
        component: ResolutionTypeRef,
        states: &StateMap,
    ) -> StoreResult<Option<RepeatedParameterAssessment>> {
        if actual.indirection() != 0 || component.indirection() != 0 {
            return Ok(Some(RepeatedParameterAssessment::Component(component)));
        }
        let Some(shapes) = self.projected_type_shapes(&[actual_slot, formal_slot], states)? else {
            return Ok(None);
        };
        if shapes.len() != 2
            || shapes.iter().any(|shape| {
                !shape.supported()
                    || shape.completion() != &ResolutionCompletion::Complete
                    || shape
                        .nodes()
                        .iter()
                        .any(|node| matches!(node.form(), FactProjectedTypeNodeForm::Applied(_)))
            })
        {
            return Ok(Some(RepeatedParameterAssessment::Component(component)));
        }
        let roots = operand_shape_roots(&shapes, [actual_slot, formal_slot]);
        let Some(data) = self.operand_conversion_types(
            &[actual.identity(), component.identity()],
            shapes,
            states,
        )?
        else {
            return Ok(None);
        };
        let mut types = OperandTypes {
            evaluation: self,
            states,
            data,
        };
        let mut views = JavaTypeViews(&mut types);
        let source = JavaTypeView::Real(roots[0]);
        let target = JavaTypeView::ImplicitArray(roots[1]);
        let assessment =
            if brokk_bifrost_jvm::java::conversion::classify(&mut views, source, target)?
                == JavaConversion::Strict
            {
                RepeatedParameterAssessment::FixedArray {
                    actual,
                    component,
                    kind: if views.same(source, target) {
                        call_applicability::ConversionKind::Exact
                    } else {
                        call_applicability::ConversionKind::Subtype
                    },
                }
            } else {
                RepeatedParameterAssessment::Component(component)
            };
        if self.poll_cancelled() {
            return Ok(None);
        }
        Ok(Some(assessment))
    }

    /// Invocation applicability uses the same selected reference conversion
    /// evidence as operand gates. Primitive operands remain in their own
    /// invocation phases; a loose conversion must not prove a strict call.
    #[doc(hidden)]
    pub fn java_strict_reference_conversion(
        &mut self,
        operand_slots: [SemanticId; 2],
        source: ResolutionTypeRef,
        target: ResolutionTypeRef,
        states: &StateMap,
    ) -> StoreResult<Option<bool>> {
        let Some(shapes) = self.projected_type_shapes(&operand_slots, states)? else {
            return Ok(None);
        };
        if shapes.len() != 2
            || shapes.iter().any(|shape| {
                !shape.supported()
                    || shape.completion() != &ResolutionCompletion::Complete
                    || shape
                        .nodes()
                        .iter()
                        .any(|node| matches!(node.form(), FactProjectedTypeNodeForm::Applied(_)))
            })
        {
            return Ok(Some(false));
        }
        let roots = operand_shape_roots(&shapes, operand_slots);
        let relation = self.java_reference_conversion_with_shapes(
            source.identity(),
            target.identity(),
            roots,
            shapes,
            states,
        )?;
        if self.poll_cancelled() {
            return Ok(None);
        }
        Ok(Some(relation == Some(true)))
    }

    /// Reference-only Java conversion between selected formal identities.
    /// Unknown hierarchy evidence is not a negative or a specificity proof.
    #[doc(hidden)]
    pub fn java_reference_type_is_subtype(
        &mut self,
        source: SemanticId,
        target: SemanticId,
        states: &StateMap,
    ) -> StoreResult<Option<bool>> {
        self.java_reference_conversion_with_shapes(
            source,
            target,
            [source, target],
            Box::new([]),
            states,
        )
    }

    fn java_reference_conversion_with_shapes(
        &mut self,
        source: SemanticId,
        target: SemanticId,
        roots: [SemanticId; 2],
        shapes: Box<[FactProjectedTypeShape]>,
        states: &StateMap,
    ) -> StoreResult<Option<bool>> {
        let identities = [source, target];
        let Some(descriptors) = self.session.intrinsic_call_type_descriptors(&identities)? else {
            return Ok(None);
        };
        if descriptors
            .iter()
            .any(|descriptor| descriptor.kind() == IntrinsicTypeKind::Primitive)
        {
            return Ok(Some(false));
        }
        let Some(data) = self.operand_conversion_types(&[source, target], shapes, states)? else {
            return Ok(None);
        };
        let mut types = OperandTypes {
            evaluation: self,
            states,
            data,
        };
        Ok(
            match brokk_bifrost_jvm::java::conversion::classify(&mut types, roots[0], roots[1])? {
                JavaConversion::Strict => Some(true),
                JavaConversion::Unknown => None,
                JavaConversion::Loose | JavaConversion::Inapplicable => Some(false),
            },
        )
    }

    /// Compare the declared formal views, including their implicit array layer.
    #[doc(hidden)]
    pub fn java_reference_formal_is_subtype(
        &mut self,
        source: CallFormalType,
        target: CallFormalType,
        states: &StateMap,
    ) -> StoreResult<Option<bool>> {
        let identity = |ty| match ty {
            CallFormalType::Real(id) | CallFormalType::ImplicitArray(id) => id,
        };
        if let (CallFormalType::Real(source), CallFormalType::Real(target)) = (source, target) {
            return self.java_reference_type_is_subtype(source, target, states);
        }
        let Some(data) = self.operand_conversion_types(
            &[identity(source), identity(target)],
            Box::new([]),
            states,
        )?
        else {
            return Ok(None);
        };
        let mut types = OperandTypes {
            evaluation: self,
            states,
            data,
        };
        let relation = match brokk_bifrost_jvm::java::conversion::classify(
            &mut JavaTypeViews(&mut types),
            source,
            target,
        )? {
            JavaConversion::Strict => Some(true),
            JavaConversion::Unknown => None,
            JavaConversion::Loose | JavaConversion::Inapplicable => Some(false),
        };
        if self.poll_cancelled() {
            return Ok(None);
        }
        Ok(relation)
    }

    fn operand_conversion_types(
        &mut self,
        roots: &[SemanticId],
        shapes: Box<[FactProjectedTypeShape]>,
        states: &StateMap,
    ) -> StoreResult<Option<OperandTypeData>> {
        let mut data = OperandTypeData::default();
        let mut pending = roots.to_vec();
        pending.extend(
            shapes
                .iter()
                .flat_map(|shape| shape.nodes().iter().map(FactProjectedTypeNode::identity)),
        );
        let mut seen = HashSet::default();
        while let Some(identity) = pending.pop() {
            if self.poll_cancelled() {
                return Ok(None);
            }
            if !seen.insert(identity) {
                continue;
            }
            let Some(descriptors) = self.session.intrinsic_call_type_descriptors(&[identity])?
            else {
                return Ok(None);
            };
            if let Some(descriptor) = descriptors
                .iter()
                .find(|descriptor| descriptor.identity() == identity)
                && descriptor.kind() != IntrinsicTypeKind::Structural
            {
                let name = if descriptor.spelling() == "null" {
                    "<null>"
                } else {
                    descriptor.spelling()
                };
                data.names.insert(identity, name.to_owned());
                if descriptor.kind() == IntrinsicTypeKind::Primitive
                    && let Some(primitive) = primitive_for_name(name)
                {
                    data.primitives.insert(identity, primitive);
                }
                data.ground.insert(identity);
            }
            if let Some(owner) = self
                .session
                .context_identities
                .as_ref()
                .and_then(|ids| ids.external_owner_identity(identity))
            {
                data.names.insert(identity, owner.owner_fqn.to_string());
                data.ground.insert(identity);
            }
            if let std::collections::hash_map::Entry::Vacant(entry) = data.names.entry(identity) {
                let Some(declarations) = self.session.java_declarations(&[identity])? else {
                    return Ok(None);
                };
                if declarations.iter().any(|row| {
                    row.definition == identity
                        && matches!(row.kind, JavaInheritanceDeclarationKind::Type { .. })
                }) {
                    entry.insert(format!("decl:{identity:?}"));
                    data.ground.insert(identity);
                    data.declared.insert(identity);
                }
            }
            let read = self.session.type_components_for_containers(&[identity])?;
            let Some(rows) = self.accept_session_read(read) else {
                return Ok(None);
            };
            if !rows.is_empty() {
                data.ground.remove(&identity);
                let components = rows
                    .iter()
                    .map(|row| *row.get(self.session).row())
                    .collect::<Vec<_>>();
                if let [component] = components.as_slice()
                    && component.constructor() == ResolutionTypeConstructorKind::Sequence
                    && component.kind() == ResolutionTypeComponentKind::Element
                {
                    let slot = component.component();
                    self.demand_slot(slot);
                    let read = self.session.declared_type_arguments_for_owners(&[slot])?;
                    let Some(arguments) = self.accept_session_read(read) else {
                        return Ok(None);
                    };
                    if arguments.is_empty()
                        && let Some(state) = states.get(&slot)
                        && state.completion() == &ResolutionCompletion::Complete
                        && let Some(element) = singleton_type_ref(state)
                        && element.indirection() == 0
                        && element.reference_indirection() == 0
                    {
                        data.elements.insert(identity, element.identity());
                        pending.push(element.identity());
                    }
                }
            }
        }
        let mut parents: HashMap<SemanticId, Vec<SemanticId>> = HashMap::default();
        for (&owner, &element) in &data.elements {
            parents.entry(element).or_default().push(owner);
        }
        let mut ready = data.ground.iter().copied().collect::<VecDeque<_>>();
        while let Some(element) = ready.pop_front() {
            if self.poll_cancelled() {
                return Ok(None);
            }
            if let Some(owners) = parents.get(&element) {
                for &owner in owners {
                    if data.ground.insert(owner) {
                        ready.push_back(owner);
                    }
                }
            }
        }
        // Nominal-only specificity uses identities as leaf handles. Operand
        // slots retain the projected nodes themselves, including their edges.
        for &identity in &seen {
            data.nodes.insert(
                identity,
                FactProjectedTypeNode {
                    slot: identity,
                    identity,
                    indirection: 0,
                    form: FactProjectedTypeNodeForm::Leaf,
                },
            );
        }
        for shape in shapes.into_vec() {
            if !shape.supported || shape.completion != ResolutionCompletion::Complete {
                data.incomplete
                    .extend(shape.nodes.iter().map(FactProjectedTypeNode::slot));
            }
            for node in shape.nodes.into_vec() {
                data.nodes.insert(node.slot(), node);
            }
        }
        Ok(Some(data))
    }
}

// Projected shapes are sorted by output slot, independently of request order.
fn operand_shape_roots(
    shapes: &[FactProjectedTypeShape],
    outputs: [SemanticId; 2],
) -> [SemanticId; 2] {
    outputs.map(|output| {
        shapes
            .iter()
            .find(|shape| shape.output_slot() == output)
            .expect("validated operand shape exists")
            .root_slot()
    })
}

#[derive(Default)]
struct OperandTypeData {
    nodes: HashMap<SemanticId, FactProjectedTypeNode>,
    incomplete: HashSet<SemanticId>,
    names: HashMap<SemanticId, String>,
    primitives: HashMap<SemanticId, JavaPrimitive>,
    elements: HashMap<SemanticId, SemanticId>,
    ground: HashSet<SemanticId>,
    declared: HashSet<SemanticId>,
}
struct OperandTypes<'op, 's, 'ctx> {
    evaluation: &'op mut FactEvaluation<'s, 'ctx>,
    states: &'op StateMap,
    data: OperandTypeData,
}
impl JavaConversionTypes for OperandTypes<'_, '_, '_> {
    type Type = SemanticId;
    type Error = StoreError;
    fn ground(&self, ty: SemanticId) -> bool {
        self.data
            .nodes
            .get(&ty)
            .is_some_and(|node| self.data.ground.contains(&node.identity()))
    }
    fn same(&self, a: SemanticId, b: SemanticId) -> bool {
        let mut pending = vec![(a, b)];
        let mut seen = HashSet::default();
        while let Some((a, b)) = pending.pop() {
            let (Some(left), Some(right)) = (self.data.nodes.get(&a), self.data.nodes.get(&b))
            else {
                return false;
            };
            let same_identity = left.identity() == right.identity()
                || self
                    .data
                    .names
                    .get(&left.identity())
                    .zip(self.data.names.get(&right.identity()))
                    .is_some_and(|(a, b)| a == b);
            // element() and nominal-only specificity still use erased identity
            // coordinates. Either coordinate retains the pre-M3a rule, even
            // when projected nodes also occupy that identity coordinate.
            if left.slot() == left.identity() || right.slot() == right.identity() {
                if !same_identity {
                    return false;
                }
                continue;
            }
            if self.data.incomplete.contains(&a)
                || self.data.incomplete.contains(&b)
                || !seen.insert((a, b))
            {
                return false;
            }
            match (left.form(), right.form()) {
                (FactProjectedTypeNodeForm::Alias(next), _) => pending.push((*next, right.slot())),
                (_, FactProjectedTypeNodeForm::Alias(next)) => pending.push((left.slot(), *next)),
                (FactProjectedTypeNodeForm::Leaf, FactProjectedTypeNodeForm::Leaf) => {
                    if !same_identity {
                        return false;
                    }
                }
                (
                    FactProjectedTypeNodeForm::Applied(a_args),
                    FactProjectedTypeNodeForm::Applied(b_args),
                ) => {
                    if a_args.len() != b_args.len() || !same_identity {
                        return false;
                    }
                    pending.extend(a_args.iter().copied().zip(b_args.iter().copied()));
                }
                (FactProjectedTypeNodeForm::Array(a), FactProjectedTypeNodeForm::Array(b)) => {
                    pending.push((*a, *b))
                }
                _ => return false,
            }
        }
        true
    }
    fn primitive(&self, ty: SemanticId) -> Option<JavaPrimitive> {
        self.data
            .primitives
            .get(&self.data.nodes.get(&ty)?.identity())
            .copied()
    }
    fn element(&self, ty: SemanticId) -> Option<SemanticId> {
        self.data
            .elements
            .get(&self.data.nodes.get(&ty)?.identity())
            .copied()
    }
    fn name(&self, ty: SemanticId) -> Option<&str> {
        self.data
            .names
            .get(&self.data.nodes.get(&ty)?.identity())
            .map(String::as_str)
    }
    fn named(&self, ty: SemanticId) -> bool {
        self.data.nodes.get(&ty).is_some_and(|node| {
            self.data.names.contains_key(&node.identity())
                && !self.data.declared.contains(&node.identity())
        })
    }
    fn nominal_widening(&mut self, a: SemanticId, b: SemanticId) -> StoreResult<Option<bool>> {
        self.evaluation.jvm_closed_type_is_subtype(
            self.data.nodes[&a].identity(),
            self.data.nodes[&b].identity(),
            self.states,
        )
    }
    fn boxed_widening(
        &mut self,
        source: JavaPrimitive,
        target: SemanticId,
    ) -> StoreResult<Option<bool>> {
        let name = brokk_bifrost_jvm::java::conversion::wrapper_name(source);
        let source = self
            .data
            .names
            .iter()
            .find(|(_, n)| n.as_str() == name)
            .map(|(&identity, _)| identity);
        match source {
            Some(source) => self.evaluation.jvm_closed_type_is_subtype(
                source,
                self.data.nodes[&target].identity(),
                self.states,
            ),
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_test_macros::hardwon;

    #[test]
    #[hardwon("#7620: absent nominal hierarchy rows refuted Java array initializer conversions")]
    fn nominal_negatives_require_closed_hierarchy_evidence() {
        // These are selected row fixtures, not a catalog of Java supertypes.
        // In particular, no String/Integer fact follows from their spellings.
        let cases = [
            ("java.lang.String", "java.lang.Object"),
            ("java.lang.String", "java.lang.String"),
            ("java.lang.String", "java.lang.CharSequence"),
            ("java.lang.String", "java.lang.Comparable<java.lang.String>"),
            ("java.lang.String", "java.io.Serializable"),
            ("java.util.ArrayList", "java.util.List"),
            ("java.lang.Integer", "java.lang.Number"),
            ("workspace.Child", "workspace.Base"),
            ("java.lang.String", "java.lang.Integer"),
        ];
        for (source_name, target_name) in cases {
            // Separate selected identities can still have the same spelling.
            let source = SemanticId::for_test(format!("source:{source_name}"));
            let target = SemanticId::for_test(format!("target:{target_name}"));
            let service = PreloadedFactResolutionService::from_lowered_fragments([], []);
            let cancellation = CancellationToken::new();
            let mut session = preloaded_session(&service, &cancellation);
            let mut arena = HierarchyOperationArena::default();
            let mut evaluation = FactEvaluation::new(&mut session, &mut arena, source);
            let states = StateMap::default();
            let mut types = OperandTypes {
                evaluation: &mut evaluation,
                states: &states,
                data: OperandTypeData {
                    nodes: [source, target]
                        .into_iter()
                        .map(|identity| {
                            (
                                identity,
                                FactProjectedTypeNode {
                                    slot: identity,
                                    identity,
                                    indirection: 0,
                                    form: FactProjectedTypeNodeForm::Leaf,
                                },
                            )
                        })
                        .collect(),
                    names: [
                        (source, source_name.to_owned()),
                        (target, target_name.to_owned()),
                    ]
                    .into_iter()
                    .collect(),
                    ground: [source, target].into_iter().collect(),
                    ..OperandTypeData::default()
                },
            };
            let hook = types.nominal_widening(source, target).unwrap();
            assert_eq!(hook, None, "{source_name} -> {target_name}");
            let conversion =
                brokk_bifrost_jvm::java::conversion::classify(&mut types, source, target).unwrap();
            let expected = if source_name == target_name || target_name == "java.lang.Object" {
                JavaConversion::Strict
            } else {
                JavaConversion::Unknown
            };
            assert_eq!(conversion, expected, "{source_name} -> {target_name}");
            println!(
                "unindexed {source_name} -> {target_name}: hook={hook:?}, classify={conversion:?}"
            );
        }

        // A concrete selected path proves a widening; closed inventories with
        // no path prove a negative. Missing any traversed owner's inventory
        // cannot prove that negative, even when the endpoints are indexed.
        for (source_name, target_name, linked) in [
            ("java.lang.String", "java.lang.CharSequence", true),
            ("java.lang.String", "java.io.Serializable", true),
            ("java.util.ArrayList", "java.util.List", true),
            ("java.lang.Integer", "java.lang.Number", true),
            ("workspace.Child", "workspace.Base", true),
            ("java.lang.String", "java.lang.Integer", false),
        ] {
            let source = SemanticId::for_test(source_name);
            let target = SemanticId::for_test(target_name);
            let reference = SemanticId::for_test(b"parent-reference");
            let frontier = SemanticId::for_test(b"parent-frontier");
            let fragment = BindingFragmentId::for_test(b"java-conversion-closed-proof");
            let mut service = PreloadedFactResolutionService::from_lowered_fragments([], []);
            for identity in [source, target] {
                service
                    .typed
                    .source_row_fragments
                    .insert(identity, fragment);
                service.typed.member_scope_by_definition.insert(
                    identity,
                    crate::analyzer::resolution::LoweredMemberScopeProperty::new(
                        identity,
                        BindingNodeId::for_test(identity.to_string()),
                    ),
                );
            }
            let mut states = StateMap::default();
            if linked {
                service
                    .typed
                    .source_row_fragments
                    .insert(reference, fragment);
                service.typed.supertypes_by_definition.insert(
                    source,
                    vec![
                        crate::analyzer::resolution::LoweredSupertypeProperty::from_source(
                            LoweredSourceSupertypeProperty::new(
                                source,
                                reference,
                                frontier,
                                ResolutionSupertypeKind::Superclass,
                                0,
                            ),
                            Language::Java,
                        ),
                    ],
                );
                states.insert(
                    frontier,
                    Arc::new(TypedFrontierState::new(
                        frontier,
                        vec![ResolutionSlotValue::type_object(ResolutionTypeRef::new(
                            target, 0,
                        ))],
                        ResolutionCompletion::Complete,
                    )),
                );
            }
            let cancellation = CancellationToken::new();
            let mut session = preloaded_session(&service, &cancellation);
            let mut arena = HierarchyOperationArena::default();
            let mut evaluation = FactEvaluation::new(&mut session, &mut arena, source);
            let result = evaluation
                .jvm_closed_type_is_subtype(source, target, &states)
                .unwrap();
            assert_eq!(result, Some(linked), "{source_name} -> {target_name}");
            println!("indexed {source_name} -> {target_name}: hook={result:?}");
        }

        let source = SemanticId::for_test(b"indexed-child");
        let middle = SemanticId::for_test(b"unindexed-middle");
        let target = SemanticId::for_test(b"indexed-unrelated-target");
        let reference = SemanticId::for_test(b"missing-middle-reference");
        let frontier = SemanticId::for_test(b"missing-middle-frontier");
        let fragment = BindingFragmentId::for_test(b"missing-middle-inventory");
        let mut service = PreloadedFactResolutionService::from_lowered_fragments([], []);
        for identity in [source, target] {
            service
                .typed
                .source_row_fragments
                .insert(identity, fragment);
            service.typed.member_scope_by_definition.insert(
                identity,
                crate::analyzer::resolution::LoweredMemberScopeProperty::new(
                    identity,
                    BindingNodeId::for_test(identity.to_string()),
                ),
            );
        }
        service
            .typed
            .source_row_fragments
            .insert(reference, fragment);
        service.typed.supertypes_by_definition.insert(
            source,
            vec![
                crate::analyzer::resolution::LoweredSupertypeProperty::from_source(
                    LoweredSourceSupertypeProperty::new(
                        source,
                        reference,
                        frontier,
                        ResolutionSupertypeKind::Superclass,
                        0,
                    ),
                    Language::Java,
                ),
            ],
        );
        let states = [(
            frontier,
            Arc::new(TypedFrontierState::new(
                frontier,
                vec![ResolutionSlotValue::type_object(ResolutionTypeRef::new(
                    middle, 0,
                ))],
                ResolutionCompletion::Complete,
            )),
        )]
        .into_iter()
        .collect();
        let cancellation = CancellationToken::new();
        let mut session = preloaded_session(&service, &cancellation);
        let mut arena = HierarchyOperationArena::default();
        let mut evaluation = FactEvaluation::new(&mut session, &mut arena, source);
        assert_eq!(
            evaluation
                .jvm_closed_type_is_subtype(source, target, &states)
                .unwrap(),
            None
        );
        println!("indexed endpoints with a missing intermediate inventory: None");
    }
    #[test]
    #[hardwon(
        "#7620: exhausted unindexed hierarchy denied protected access instead of retaining uncertainty"
    )]
    fn protected_visibility_obligation_retains_missing_hierarchy_reason() {
        use crate::analyzer::resolution::fact_source::{
            DeclarationAccessRow, FactPageVisitor, SelectedDeclarationAccessSource,
            SelectedTypedFactSource, TypedFactReadOutcome, TypedFactRequest,
        };
        struct Protected;
        impl SelectedDeclarationAccessSource for Protected {
            fn identity(&self) -> SemanticId {
                SemanticId::for_test(b"protected-access-policy")
            }
            fn visit_access_pages(
                &self,
                _: &dyn SelectedTypedFactSource,
                _: TypedFactRequest<DeclarationAccessRequest>,
                _: &CancellationToken,
                _: &mut FactPageVisitor<DeclarationAccessRow>,
            ) -> StoreResult<TypedFactReadOutcome> {
                panic!("exact obligation already loaded")
            }
        }
        let service = PreloadedFactResolutionService::from_lowered_fragments([], []);
        let reference = SemanticId::for_test(b"protected-call-site");
        let target = SemanticId::for_test(b"protected-member");
        let caller = SemanticId::for_test(b"caller-with-missing-hierarchy");
        let owner = SemanticId::for_test(b"protected-declaring-owner");
        let cancellation = CancellationToken::new();
        let mut session = preloaded_session(&service, &cancellation);
        session.declaration_access_source = Some(&Protected);
        let request = DeclarationAccessRequest {
            reference,
            definition: target,
        };
        session.declaration_access.insert(
            request,
            DeclarationAccessRow {
                request,
                decision: DeclarationAccessDecision::Unknown,
                activation_reason: None,
                // This is the producer's real visibility obligation. Without it
                // the generic non-obligated endpoint path would allow access.
                visibility_applies: true,
                subclass_access: Some(SubclassAccessContext {
                    enclosing_templates: vec![caller],
                    declaration_template: owner,
                }),
            },
        );
        let mut arena = HierarchyOperationArena::default();
        let mut evaluation = FactEvaluation::new(&mut session, &mut arena, reference);
        let mut answers = [(
            reference,
            Arc::new(ResolutionAnswer::new(
                vec![target],
                vec![ResolutionWitness::new(
                    reference,
                    target,
                    vec![],
                    ResolutionCompletion::Complete,
                )],
                ResolutionCompletion::Complete,
            )),
        )]
        .into_iter()
        .collect::<AnswerMap>();
        assert!(
            evaluation
                .apply_contextual_declaration_access(
                    &[reference],
                    &mut answers,
                    &StateMap::default(),
                    false,
                )
                .unwrap()
                .is_some()
        );
        let answer = &answers[&reference];
        assert_eq!(
            answer.targets(),
            &[target],
            "navigation witness survives uncertainty"
        );
        assert_eq!(
            answer.completion(),
            &incomplete(reference),
            "visibility obligation must not take the generic grant path"
        );
        assert_eq!(
            answer.witnesses()[0].completion(),
            &incomplete(reference),
            "no complete witness can grant an exact binding"
        );
        println!(
            "protected obligation: incomplete, UnsupportedSemantic(call-site), no complete binding witness; generic grant path not taken"
        );
    }

    #[test]
    #[hardwon(
        "#7196: Kotlin builtin subtype check refuted only proven nominal declarations outside builtin_supertypes"
    )]
    fn kotlin_builtin_subtype_refutes_only_proven_nominal_outside_builtin_supertypes() {
        use crate::analyzer::resolution::fact_source::{
            JavaInheritanceDeclaration, JavaInheritanceDeclarationKind, JvmDeclarationPackage,
        };
        use crate::analyzer::resolution::{
            LoweredIntrinsicSeed, LoweredMemberScopeProperty, LoweredUnderlyingType,
        };

        let seed_kotlin_builtin = |service: &mut PreloadedFactResolutionService,
                                   spelling: &str|
         -> SemanticId {
            let fragment = BindingFragmentId::for_test(format!("fragment:{spelling}"));
            let slot = SemanticId::for_test(format!("seed-slot:{spelling}"));
            let ty = SemanticId::for_test(format!("builtin-ty:{spelling}"));
            let frontier = TypedFrontierState::new(
                slot,
                vec![ResolutionSlotValue::Runtime {
                    ty: ResolutionTypeRef::new(ty, 0),
                    addressable: false,
                    obligation: None,
                }],
                ResolutionCompletion::Complete,
            );
            let seed =
                LoweredIntrinsicSeed::new(IntrinsicTypeKind::LanguageBuiltin, spelling, frontier);
            service.typed.source_row_fragments.insert(slot, fragment);
            service.typed.intrinsic_seed_by_slot.insert(slot, seed);
            service
                .typed
                .intrinsic_slots_by_identity
                .insert(ty, vec![slot]);
            ty
        };

        let install_type_body = |service: &mut PreloadedFactResolutionService,
                                 target: SemanticId| {
            let fragment = BindingFragmentId::for_test(format!("body:{target}"));
            service.typed.source_row_fragments.insert(target, fragment);
            service.typed.member_scope_by_definition.insert(
                target,
                LoweredMemberScopeProperty::new(
                    target,
                    BindingNodeId::for_test(target.to_string()),
                ),
            );
        };

        for builtin_spelling in ["kotlin.Int", "java.lang.String"] {
            // Positive cases: proven workspace nominal declarations outside
            // builtin_supertypes answer Some(false).
            for (label, package, name, is_interface, is_singleton) in [
                (
                    "kotlin-class",
                    JvmDeclarationPackage::Known(Some("sample".to_owned())),
                    "KotlinBox",
                    false,
                    false,
                ),
                (
                    "kotlin-interface",
                    JvmDeclarationPackage::Known(Some("sample".to_owned())),
                    "KotlinTag",
                    true,
                    false,
                ),
                (
                    "nested-class",
                    JvmDeclarationPackage::Known(Some("sample".to_owned())),
                    "Outer.NestedBox",
                    false,
                    false,
                ),
                (
                    "scala-singleton",
                    JvmDeclarationPackage::Known(Some("sample".to_owned())),
                    "ScalaSingleton$",
                    false,
                    true,
                ),
                (
                    "unnamed-package-class",
                    JvmDeclarationPackage::Known(None),
                    "UnnamedBox",
                    false,
                    false,
                ),
                (
                    "empty-string-package-class",
                    JvmDeclarationPackage::Known(Some(String::new())),
                    "int",
                    false,
                    false,
                ),
                (
                    "synthetic-anonymous-body",
                    JvmDeclarationPackage::Known(Some("sample".to_owned())),
                    "",
                    false,
                    false,
                ),
            ] {
                let mut service = PreloadedFactResolutionService::from_lowered_fragments([], []);
                let sub = seed_kotlin_builtin(&mut service, builtin_spelling);
                let sup = SemanticId::for_test(format!("formal:{builtin_spelling}:{label}"));
                install_type_body(&mut service, sup);
                service.java_inheritance_metadata.insert(
                    sup,
                    JavaInheritanceDeclaration {
                        definition: sup,
                        name: name.to_owned(),
                        package,
                        kind: JavaInheritanceDeclarationKind::Type {
                            is_interface,
                            is_singleton,
                        },
                    },
                );
                let cancellation = CancellationToken::new();
                let mut session = preloaded_session(&service, &cancellation);
                let mut arena = HierarchyOperationArena::default();
                let mut evaluation = FactEvaluation::new(&mut session, &mut arena, sub);
                assert_eq!(
                    evaluation
                        .kotlin_type_is_subtype(sub, sup, &StateMap::default())
                        .unwrap(),
                    Some(false),
                    "{builtin_spelling} vs {label} must refute"
                );
                assert!(!evaluation.cancellation_observed);
            }

            // Controls: declarations without a TypeBody member scope (such as
            // typealiases, type parameters, or unindexed default imports),
            // aliases with underlying types, unknown packages, missing
            // declaration metadata, and source-declared supertypes/aliases/open
            // entries in builtin_supertypes must NOT be refuted (answer None).
            let supertype_in_table = if builtin_spelling == "kotlin.Int" {
                [
                    ("kotlin", "Number", false),
                    ("java.lang", "Comparable", false),
                    ("scala", "Int", false),
                ]
            } else {
                [
                    ("java.lang", "CharSequence", false),
                    ("kotlin", "Comparable", false),
                    ("scala.Predef", "String", false),
                ]
            };
            for (pkg, name, is_singleton) in supertype_in_table {
                let mut service = PreloadedFactResolutionService::from_lowered_fragments([], []);
                let sub = seed_kotlin_builtin(&mut service, builtin_spelling);
                let sup = SemanticId::for_test(format!("stdlib:{builtin_spelling}:{pkg}.{name}"));
                install_type_body(&mut service, sup);
                service.java_inheritance_metadata.insert(
                    sup,
                    JavaInheritanceDeclaration {
                        definition: sup,
                        name: name.to_owned(),
                        package: JvmDeclarationPackage::Known(Some(pkg.to_owned())),
                        kind: JavaInheritanceDeclarationKind::Type {
                            is_interface: true,
                            is_singleton,
                        },
                    },
                );
                let cancellation = CancellationToken::new();
                let mut session = preloaded_session(&service, &cancellation);
                let mut arena = HierarchyOperationArena::default();
                let mut evaluation = FactEvaluation::new(&mut session, &mut arena, sub);
                assert_eq!(
                    evaluation
                        .kotlin_type_is_subtype(sub, sup, &StateMap::default())
                        .unwrap(),
                    None,
                    "{builtin_spelling} vs source-declared {pkg}.{name} must stay open, not refute"
                );
            }

            // Typealias / type parameter control: JavaInheritanceDeclaration::Type
            // present WITHOUT a TypeBody member scope must not refute.
            {
                let mut service = PreloadedFactResolutionService::from_lowered_fragments([], []);
                let sub = seed_kotlin_builtin(&mut service, builtin_spelling);
                let alias = SemanticId::for_test(format!("typealias:{builtin_spelling}"));
                service.java_inheritance_metadata.insert(
                    alias,
                    JavaInheritanceDeclaration {
                        definition: alias,
                        name: "NumberAlias".to_owned(),
                        package: JvmDeclarationPackage::Known(Some("sample".to_owned())),
                        kind: JavaInheritanceDeclarationKind::Type {
                            is_interface: false,
                            is_singleton: false,
                        },
                    },
                );
                let cancellation = CancellationToken::new();
                let mut session = preloaded_session(&service, &cancellation);
                let mut arena = HierarchyOperationArena::default();
                let mut evaluation = FactEvaluation::new(&mut session, &mut arena, sub);
                assert_eq!(
                    evaluation
                        .kotlin_type_is_subtype(sub, alias, &StateMap::default())
                        .unwrap(),
                    None,
                    "{builtin_spelling} vs typealias without TypeBody must not refute"
                );
            }

            // Underlying-type alias control: even with a TypeBody row, an alias
            // carrying LoweredUnderlyingType must not refute.
            {
                let mut service = PreloadedFactResolutionService::from_lowered_fragments([], []);
                let sub = seed_kotlin_builtin(&mut service, builtin_spelling);
                let alias = SemanticId::for_test(format!("underlying:{builtin_spelling}"));
                let slot = SemanticId::for_test(format!("underlying-slot:{builtin_spelling}"));
                install_type_body(&mut service, alias);
                service
                    .typed
                    .underlying_types_by_definition
                    .insert(alias, LoweredUnderlyingType::new(alias, slot));
                service.java_inheritance_metadata.insert(
                    alias,
                    JavaInheritanceDeclaration {
                        definition: alias,
                        name: "DefinedAlias".to_owned(),
                        package: JvmDeclarationPackage::Known(Some("sample".to_owned())),
                        kind: JavaInheritanceDeclarationKind::Type {
                            is_interface: false,
                            is_singleton: false,
                        },
                    },
                );
                let cancellation = CancellationToken::new();
                let mut session = preloaded_session(&service, &cancellation);
                let mut arena = HierarchyOperationArena::default();
                let mut evaluation = FactEvaluation::new(&mut session, &mut arena, sub);
                assert_eq!(
                    evaluation
                        .kotlin_type_is_subtype(sub, alias, &StateMap::default())
                        .unwrap(),
                    None,
                    "{builtin_spelling} vs definition with underlying type must not refute"
                );
            }

            // Unknown package and missing metadata controls must not refute.
            for with_unknown_pkg in [false, true] {
                let mut service = PreloadedFactResolutionService::from_lowered_fragments([], []);
                let sub = seed_kotlin_builtin(&mut service, builtin_spelling);
                let sup = SemanticId::for_test(format!(
                    "unknown-meta:{builtin_spelling}:{with_unknown_pkg}"
                ));
                install_type_body(&mut service, sup);
                if with_unknown_pkg {
                    service.java_inheritance_metadata.insert(
                        sup,
                        JavaInheritanceDeclaration {
                            definition: sup,
                            name: "Box".to_owned(),
                            package: JvmDeclarationPackage::Unknown,
                            kind: JavaInheritanceDeclarationKind::Type {
                                is_interface: false,
                                is_singleton: false,
                            },
                        },
                    );
                }
                let cancellation = CancellationToken::new();
                let mut session = preloaded_session(&service, &cancellation);
                let mut arena = HierarchyOperationArena::default();
                let mut evaluation = FactEvaluation::new(&mut session, &mut arena, sub);
                assert_eq!(
                    evaluation
                        .kotlin_type_is_subtype(sub, sup, &StateMap::default())
                        .unwrap(),
                    None,
                );
            }

            // Cancelled read control: refutes nothing and records cancellation.
            {
                let mut service = PreloadedFactResolutionService::from_lowered_fragments([], []);
                let sub = seed_kotlin_builtin(&mut service, builtin_spelling);
                let sup = SemanticId::for_test(format!("cancelled:{builtin_spelling}"));
                install_type_body(&mut service, sup);
                service.java_inheritance_metadata.insert(
                    sup,
                    JavaInheritanceDeclaration {
                        definition: sup,
                        name: "KotlinBox".to_owned(),
                        package: JvmDeclarationPackage::Known(Some("sample".to_owned())),
                        kind: JavaInheritanceDeclarationKind::Type {
                            is_interface: false,
                            is_singleton: false,
                        },
                    },
                );
                let cancellation = CancellationToken::new();
                cancellation.cancel();
                let mut session = preloaded_session(&service, &cancellation);
                let mut arena = HierarchyOperationArena::default();
                let mut evaluation = FactEvaluation::new(&mut session, &mut arena, sub);
                assert_eq!(
                    evaluation
                        .kotlin_type_is_subtype(sub, sup, &StateMap::default())
                        .unwrap(),
                    None,
                    "a cancelled read must refute nothing"
                );
                assert!(evaluation.cancellation_observed);
            }
        }

        // Scala singleton `scala.Unit$` in builtin.open (`scala.Unit`) must not refute.
        {
            let mut service = PreloadedFactResolutionService::from_lowered_fragments([], []);
            let sub = seed_kotlin_builtin(&mut service, "kotlin.Unit");
            let sup = SemanticId::for_test("stdlib:scala.Unit$");
            install_type_body(&mut service, sup);
            service.java_inheritance_metadata.insert(
                sup,
                JavaInheritanceDeclaration {
                    definition: sup,
                    name: "Unit$".to_owned(),
                    package: JvmDeclarationPackage::Known(Some("scala".to_owned())),
                    kind: JavaInheritanceDeclarationKind::Type {
                        is_interface: false,
                        is_singleton: true,
                    },
                },
            );
            let cancellation = CancellationToken::new();
            let mut session = preloaded_session(&service, &cancellation);
            let mut arena = HierarchyOperationArena::default();
            let mut evaluation = FactEvaluation::new(&mut session, &mut arena, sub);
            assert_eq!(
                evaluation
                    .kotlin_type_is_subtype(sub, sup, &StateMap::default())
                    .unwrap(),
                None,
                "kotlin.Unit vs scala.Unit$ must stay open"
            );
        }
    }
}
