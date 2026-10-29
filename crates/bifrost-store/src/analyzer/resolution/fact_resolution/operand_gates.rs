//! Completion-only operand obligations. All materialized types live for one
//! gate evaluation; no gate is a value producer or an identity shortcut.
use super::*;
use crate::analyzer::resolution::fact_source::language_jvm_array_operand_rules;
use brokk_bifrost_jvm::java::conversion::{JavaConversion, JavaConversionTypes};
use brokk_bifrost_jvm::java::primitives::{JavaPrimitive, primitive_for_name};

impl FactEvaluation<'_, '_> {
    pub(super) fn evaluate_operand_gates(
        &mut self,
        incoming: &[InternedFactRow<SelectedTypedRow<LoweredTypeTransfer>>],
        previous: &StateMap,
        states: &mut StateMap,
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
            let input = gate.source_slot();
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
                                    let Some(data) = self.operand_conversion_types(
                                        &[source.identity(), target.identity()],
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
                                        rules.element(
                                            &mut types,
                                            source.identity(),
                                            target.identity()
                                        )?,
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

    /// The repeated declaration publishes its component, while an actual
    /// array has a Sequence/Element row. Equal grounded components prove that
    /// the actual array itself represents the implicit fixed-arity formal.
    #[doc(hidden)]
    pub fn jvm_repeated_sequence_parameter_type(
        &mut self,
        actual_slot: SemanticId,
        formal_slot: SemanticId,
        actual: ResolutionTypeRef,
        component: ResolutionTypeRef,
        states: &StateMap,
    ) -> StoreResult<Option<ResolutionTypeRef>> {
        if actual.indirection() != 0 || component.indirection() != 0 {
            return Ok(Some(component));
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
            return Ok(Some(component));
        }
        let Some(data) =
            self.operand_conversion_types(&[actual.identity(), component.identity()], states)?
        else {
            return Ok(None);
        };
        let types = OperandTypes {
            evaluation: self,
            states,
            data,
        };
        let fixed_arity = types.element(actual.identity()).is_some_and(|element| {
            types.ground(actual.identity())
                && types.ground(component.identity())
                && types.same(element, component.identity())
        });
        Ok(Some(if fixed_arity { actual } else { component }))
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
        let relation =
            self.java_reference_type_is_subtype(source.identity(), target.identity(), states)?;
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
        let Some(data) = self.operand_conversion_types(&[source, target], states)? else {
            return Ok(None);
        };
        let mut types = OperandTypes {
            evaluation: self,
            states,
            data,
        };
        Ok(
            match brokk_bifrost_jvm::java::conversion::classify(&mut types, source, target)? {
                JavaConversion::Strict => Some(true),
                JavaConversion::Unknown => None,
                JavaConversion::Loose | JavaConversion::Inapplicable => Some(false),
            },
        )
    }

    fn operand_conversion_types(
        &mut self,
        roots: &[SemanticId],
        states: &StateMap,
    ) -> StoreResult<Option<OperandTypeData>> {
        let mut data = OperandTypeData::default();
        let mut pending = roots.to_vec();
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
        Ok(Some(data))
    }
}

#[derive(Default)]
struct OperandTypeData {
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
        self.data.ground.contains(&ty)
    }
    fn same(&self, a: SemanticId, b: SemanticId) -> bool {
        a == b
            || self
                .data
                .names
                .get(&a)
                .zip(self.data.names.get(&b))
                .is_some_and(|(a, b)| a == b)
    }
    fn primitive(&self, ty: SemanticId) -> Option<JavaPrimitive> {
        self.data.primitives.get(&ty).copied()
    }
    fn element(&self, ty: SemanticId) -> Option<SemanticId> {
        self.data.elements.get(&ty).copied()
    }
    fn name(&self, ty: SemanticId) -> Option<&str> {
        self.data.names.get(&ty).map(String::as_str)
    }
    fn named(&self, ty: SemanticId) -> bool {
        self.data.names.contains_key(&ty) && !self.data.declared.contains(&ty)
    }
    fn nominal_widening(&mut self, a: SemanticId, b: SemanticId) -> StoreResult<Option<bool>> {
        self.evaluation
            .jvm_closed_type_is_subtype(a, b, self.states)
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
            Some(source) => self
                .evaluation
                .jvm_closed_type_is_subtype(source, target, self.states),
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
                service
                    .typed
                    .member_scope_by_definition
                    .insert(identity, BindingNodeId::for_test(identity.to_string()));
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
                        LoweredSourceSupertypeProperty::new(
                            source,
                            reference,
                            frontier,
                            ResolutionSupertypeKind::Superclass,
                            0,
                        )
                        .into(),
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
            service
                .typed
                .member_scope_by_definition
                .insert(identity, BindingNodeId::for_test(identity.to_string()));
        }
        service
            .typed
            .source_row_fragments
            .insert(reference, fragment);
        service.typed.supertypes_by_definition.insert(
            source,
            vec![
                LoweredSourceSupertypeProperty::new(
                    source,
                    reference,
                    frontier,
                    ResolutionSupertypeKind::Superclass,
                    0,
                )
                .into(),
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
        .collect();
        assert!(
            evaluation
                .apply_contextual_declaration_access(&mut answers, &StateMap::default())
                .unwrap()
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
}
