//! Java method inheritance precedes invocation applicability. All state here
//! belongs to one selected query; declarations remain indexed source rows.

use super::super::fact_source::{
    JavaInheritanceDeclaration, JavaInheritanceDeclarationKind,
    language_can_close_interface_object_frontier, language_implicit_root_member_names,
};
use super::*;
use crate::analyzer::usages::call_conversion::JavaPrimitive;
use brokk_bifrost_core::analyzer::structural::resolution::DeclaredVisibility;

/// The lookup identities of the methods `java.lang.Object` declares, as the
/// shared-name digests the lowering interns for a callable lookup. A qualified
/// route names its callee only by that identity, so an absent member is
/// compared with the Object method names through their digests.
static JAVA_OBJECT_METHOD_LOOKUP_DIGESTS: std::sync::LazyLock<HashSet<[u8; 32]>> =
    std::sync::LazyLock::new(|| {
        language_implicit_root_member_names(Language::Java)
            .iter()
            .map(|name| {
                super::super::local_identity::ResolutionLookupSemanticRecipe::new(
                    Language::Java,
                    ResolutionNamespace::Callable,
                    name,
                )
                .name_digest()
            })
            .collect()
    });

impl FactReadSession<'_> {
    pub(super) fn java_declarations(
        &mut self,
        definitions: &[SemanticId],
    ) -> StoreResult<Option<Vec<JavaInheritanceDeclaration>>> {
        let missing = definitions
            .iter()
            .copied()
            .filter(|definition| !self.java_inheritance_declarations.contains_key(definition))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        if !missing.is_empty() {
            let Some(rows) = self
                .typed_source
                .java_inheritance_declarations(&missing, self.cancellation)?
            else {
                return Ok(None);
            };
            let mut found = HashMap::default();
            for row in rows {
                assert!(missing.binary_search(&row.definition).is_ok());
                assert!(found.insert(row.definition, row).is_none());
            }
            if self.cancellation.is_cancelled() {
                return Ok(None);
            }
            for definition in missing {
                self.java_inheritance_declarations
                    .insert(definition, found.remove(&definition));
            }
        }
        Ok(Some(
            definitions
                .iter()
                .filter_map(|definition| self.java_inheritance_declarations[definition].clone())
                .collect(),
        ))
    }
}

impl FactEvaluation<'_, '_> {
    pub(super) fn java_call_candidate_type_frontier_reasons(
        &mut self,
        obligation: &LoweredCallApplicabilityObligation,
        signature: &LoweredCallableSignatureProperty,
        states: &StateMap,
    ) -> StoreResult<Option<Option<BTreeSet<SemanticId>>>> {
        if obligation.explicit_type_argument_count() != 0
            || signature.completion() != &ResolutionCompletion::Complete
            || signature.type_parameter_count() != 0
            || signature
                .parameters()
                .iter()
                .any(|parameter| parameter.repeated())
            || signature.parameters().len() != obligation.argument_slots().len()
        {
            return Ok(Some(None));
        }
        let mut reasons = BTreeSet::new();
        for (&argument, parameter) in obligation
            .argument_slots()
            .iter()
            .zip(signature.parameters())
        {
            if self.poll_cancelled() {
                return Ok(None);
            }
            for slot in [argument, parameter.slot()] {
                let Some(state) = states.get(&slot) else {
                    return Ok(Some(None));
                };
                if state
                    .possible_values()
                    .iter()
                    .any(|value| !matches!(value, ResolutionSlotValue::Runtime { .. }))
                    || (state.completion() == &ResolutionCompletion::Complete
                        && state.possible_values().is_empty())
                {
                    return Ok(Some(None));
                }
                if let ResolutionCompletion::Incomplete(incomplete) = state.completion() {
                    for reason in incomplete.iter() {
                        if self.poll_cancelled() {
                            return Ok(None);
                        }
                        let ResolutionIncompleteReason::UnsupportedSemantic(reason) = reason else {
                            return Ok(Some(None));
                        };
                        reasons.insert(*reason);
                    }
                }
            }
        }
        Ok(Some(Some(reasons)))
    }

    /// The traversal reasons of this call that only an unindexed
    /// `java.lang.Object` can answer, when no candidate or called name can be
    /// an Object method.
    ///
    /// An implicit Object superclass edge (a class with no `extends`) adds only
    /// the Object methods to a lookup, so for any other name its traversal
    /// reason does not keep the candidate set open. The edge is identified by
    /// its supertype row, not by an owner path: a bare call walks the
    /// hierarchy of every enclosing class and records no owner path at all.
    /// The called name is the name of the candidates; a call with no candidate
    /// names no declaration, so its qualified route names the callee through
    /// its lookup identity instead. An interface with no superinterface
    /// implicitly declares the Object methods (JLS 9.2), which closes the
    /// reason on the interface declaration the same way.
    pub(super) fn java_call_implicit_object_gap_reasons(
        &mut self,
        obligation: &LoweredCallApplicabilityObligation,
        answer: &ResolutionAnswer,
        completion: &ResolutionCompletion,
        previous_states: &StateMap,
    ) -> StoreResult<Option<BTreeSet<SemanticId>>> {
        let language = obligation.language();
        let mut reasons = BTreeSet::new();
        if !self.session.typed_source.selection_has_jvm_semantics() {
            return Ok(Some(reasons));
        }
        let mut owners = BTreeSet::new();
        let mut member_owners = BTreeSet::new();
        if answer.targets().is_empty() {
            if language != Language::Java {
                return Ok(Some(reasons));
            }
            let Some(receivers) =
                self.java_absent_member_receiver_owners(obligation, previous_states)?
            else {
                return Ok(None);
            };
            if receivers.is_empty() {
                return Ok(Some(reasons));
            }
            member_owners.extend(receivers.iter().copied());
            owners = receivers;
        }
        for &target in answer.targets() {
            match self.member_owner_by_target.get(&target) {
                Some(Some(owner)) => {
                    let Some(root) = owner.owner_path.first().copied() else {
                        return Ok(Some(reasons));
                    };
                    owners.insert(root);
                    member_owners.insert(owner.owner());
                }
                // A member that Java's lexical lookup of a bare call reached
                // records no owner path. It has no receiver type to test for
                // the interface rule, and the edge rule below needs none.
                None if language == Language::Java => {}
                Some(None) | None => return Ok(Some(reasons)),
            }
        }
        let mut requested = answer.targets().iter().copied().collect::<BTreeSet<_>>();
        requested.extend(owners.iter().copied());
        requested.extend(member_owners.iter().copied());
        let Some(declarations) = self
            .session
            .java_declarations(&requested.into_iter().collect::<Vec<_>>())?
        else {
            self.cancellation_observed = true;
            return Ok(None);
        };
        let declarations = declarations
            .into_iter()
            .map(|row| (row.definition, row))
            .collect::<HashMap<_, _>>();
        let mut call_name: Option<&str> = None;
        for &target in answer.targets() {
            if self.poll_cancelled() {
                return Ok(None);
            }
            let Some(method) = declarations.get(&target) else {
                return Ok(Some(reasons));
            };
            // An implicit java.lang.Object edge cannot add a same-name
            // candidate when none of the source methods use an Object method
            // name. Static source methods are covered too: the Object method
            // inventory is name-based, and static/instance kind cannot make a
            // differently named method applicable.
            if !matches!(&method.kind, JavaInheritanceDeclarationKind::Method { .. })
                || language_implicit_root_member_names(Language::Java)
                    .contains(&method.name.as_str())
                || call_name.is_some_and(|name| name != method.name.as_str())
            {
                return Ok(Some(reasons));
            }
            call_name.get_or_insert(method.name.as_str());
        }

        let mut interface_object_gaps = BTreeSet::new();
        if language_can_close_interface_object_frontier(language) {
            for &owner in &member_owners {
                if self.poll_cancelled() {
                    return Ok(None);
                }
                // A bound or inherited owner still has a route beyond the
                // receiver itself, so its hierarchy frontier remains open.
                if !owners.contains(&owner) {
                    continue;
                }
                let Some(declaration) = declarations.get(&owner) else {
                    continue;
                };
                if !matches!(
                    &declaration.kind,
                    JavaInheritanceDeclarationKind::Type {
                        is_interface: true,
                        ..
                    }
                ) {
                    continue;
                }
                let read = self.session.supertypes_for_definitions(&[owner])?;
                let Some(supertypes) = self.accept_session_read(read) else {
                    return Ok(None);
                };
                if supertypes.is_empty() {
                    interface_object_gaps.insert(owner);
                }
            }
        }

        let ResolutionCompletion::Incomplete(incomplete) = completion else {
            return Ok(Some(reasons));
        };
        let candidates = incomplete
            .iter()
            .filter_map(|reason| match reason {
                ResolutionIncompleteReason::UnsupportedSemantic(reason) => Some(*reason),
                _ => None,
            })
            .collect::<Vec<_>>();
        // A traversal reason is about the supertype edge at its source site.
        // The edge is the implicit Object superclass of some class when its
        // supertype row says so, whichever class's hierarchy the lookup walked.
        let mut edge_reasons = Vec::new();
        for chunk in candidates.chunks(MAX_TYPED_FACT_REQUESTS_PER_BATCH) {
            if self.poll_cancelled() {
                return Ok(None);
            }
            let read = self.session.gap_reason_provenance_for_reasons(chunk)?;
            let Some(provenance) = self.accept_session_read(read) else {
                return Ok(None);
            };
            for provenance in provenance {
                if self.poll_cancelled() {
                    return Ok(None);
                }
                let provenance = provenance.get(self.session);
                if provenance.origin()
                    != LoweringGapOrigin::Extracted(
                        ResolutionGapKind::UnsupportedHierarchyTraversal,
                    )
                {
                    continue;
                }
                let source_site = super::super::fact_lowering::site_semantic(
                    provenance.fragment(),
                    provenance.source_site(),
                );
                if interface_object_gaps.contains(&source_site) {
                    reasons.insert(provenance.reason());
                } else {
                    edge_reasons.push((source_site, provenance.reason()));
                }
            }
        }
        let edge_references = edge_reasons
            .iter()
            .map(|&(reference, _)| reference)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let mut implicit_object_references = HashSet::default();
        for chunk in edge_references.chunks(MAX_TYPED_FACT_REQUESTS_PER_BATCH) {
            if self.poll_cancelled() {
                return Ok(None);
            }
            let read = self.session.supertypes_for_references(chunk)?;
            let Some(supertypes) = self.accept_session_read(read) else {
                return Ok(None);
            };
            implicit_object_references.extend(
                supertypes
                    .iter()
                    .map(|row| row.get(self.session).row())
                    .filter(|row| row.kind() == ResolutionSupertypeKind::ImplicitSuperclass)
                    .map(|row| row.reference()),
            );
        }
        reasons.extend(
            edge_reasons
                .into_iter()
                .filter(|(reference, _)| implicit_object_references.contains(reference))
                .map(|(_, reason)| reason),
        );
        Ok(Some(reasons))
    }

    /// The static types of the receiver of a qualified Java call that found no
    /// member, when the receiver is exact and the called name is not a method of
    /// `java.lang.Object`. Empty means no claim: an unqualified call, an open
    /// member surface, a receiver that is not one complete value, or a name
    /// that an implicit Object edge could still supply. `None` reports
    /// cancellation.
    fn java_absent_member_receiver_owners(
        &mut self,
        obligation: &LoweredCallApplicabilityObligation,
        previous_states: &StateMap,
    ) -> StoreResult<Option<BTreeSet<SemanticId>>> {
        let read = self
            .session
            .routes_for_references(&[obligation.callee_reference()])?;
        let Some(routes) = self.accept_session_read(read) else {
            return Ok(None);
        };
        let mut owners = BTreeSet::new();
        for route in routes {
            if self.poll_cancelled() {
                return Ok(None);
            }
            let (namespace, open_member_surface, qualifier_slot, lookup) = {
                let route = route.get(self.session).row();
                (
                    route.namespace(),
                    route.open_member_surface(),
                    route.qualifier_slot(),
                    route.lookup(),
                )
            };
            let Some(qualifier) = previous_states.get(&qualifier_slot) else {
                return Ok(Some(BTreeSet::new()));
            };
            if namespace != ResolutionNamespace::Callable
                || open_member_surface
                || qualifier.completion() != &ResolutionCompletion::Complete
                || qualifier.possible_values().is_empty()
                || qualifier
                    .possible_values()
                    .iter()
                    .any(|value| value.ty().indirection() != 0)
            {
                return Ok(Some(BTreeSet::new()));
            }
            let digest = self
                .session
                .lexical_source
                .shared_name_digest_for_identity(lookup, self.cancellation)?;
            if self.poll_cancelled() {
                return Ok(None);
            }
            if digest.is_none_or(|digest| JAVA_OBJECT_METHOD_LOOKUP_DIGESTS.contains(&digest)) {
                return Ok(Some(BTreeSet::new()));
            }
            owners.extend(
                qualifier
                    .possible_values()
                    .iter()
                    .map(|value| value.ty().identity()),
            );
        }
        Ok(Some(owners))
    }

    pub(super) fn java_method_origin_owners(
        &mut self,
        selection: &QualifiedOriginSelection,
        rust_owners: &BTreeSet<SemanticId>,
    ) -> StoreResult<Option<BTreeSet<SemanticId>>> {
        if !self.session.typed_source.selection_has_java_semantics() {
            return Ok(Some(BTreeSet::new()));
        }
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

    pub(crate) fn filter_java_inherited_methods(
        &mut self,
        answer: ResolutionAnswer,
        signatures: &HashMap<
            SemanticId,
            InternedFactRow<SelectedTypedRow<LoweredCallableSignatureProperty>>,
        >,
        previous_states: &StateMap,
    ) -> StoreResult<Option<ResolutionAnswer>> {
        let java = answer.targets().iter().any(|target| {
            self.member_owner_by_target
                .get(target)
                .and_then(Option::as_ref)
                .and_then(|owner| owner.owner_path.first())
                .and_then(|root| self.session.java_inheritance_declarations.get(root))
                .and_then(Option::as_ref)
                .is_some_and(|row| matches!(row.kind, JavaInheritanceDeclarationKind::Type { .. }))
        });
        if !java {
            return Ok(Some(answer));
        }
        let mut requested = BTreeSet::new();
        for &target in answer.targets() {
            requested.insert(target);
            if let Some(Some(owner)) = self.member_owner_by_target.get(&target) {
                requested.extend(owner.owner_path.iter().copied());
            }
        }
        let Some(rows) = self
            .session
            .java_declarations(&requested.into_iter().collect::<Vec<_>>())?
        else {
            self.cancellation_observed = true;
            return Ok(None);
        };
        let declarations = rows
            .into_iter()
            .map(|row| (row.definition, row))
            .collect::<HashMap<_, _>>();
        let mut removed = HashSet::default();
        let mut unresolved = false;
        for &target in answer.targets() {
            if self.poll_cancelled() {
                return Ok(None);
            }
            let Some(Some(owner)) = self.member_owner_by_target.get(&target) else {
                unresolved = true;
                continue;
            };
            if owner.hierarchy_depth == 0 {
                continue;
            }
            let Some(method) = declarations.get(&target) else {
                unresolved = true;
                continue;
            };
            let JavaInheritanceDeclarationKind::Method {
                is_static,
                visibility,
                ..
            } = method.kind
            else {
                unresolved = true;
                continue;
            };
            if visibility == DeclaredVisibility::Private {
                removed.insert(target);
                continue;
            }
            let Some(declaration) = declarations.get(&owner.owner) else {
                unresolved = true;
                continue;
            };
            if is_static
                && matches!(
                    declaration.kind,
                    JavaInheritanceDeclarationKind::Type {
                        is_interface: true,
                        ..
                    }
                )
            {
                removed.insert(target);
                continue;
            }
            if visibility == DeclaredVisibility::PackagePrivate {
                for step in &owner.owner_path {
                    match declarations.get(step) {
                        Some(declaration) if method.package != declaration.package => {
                            removed.insert(target);
                            break;
                        }
                        // None names the known unnamed package on a present
                        // source declaration, not unavailable metadata.
                        Some(_) => {}
                        None => unresolved = true,
                    }
                }
            }
        }
        let candidates = answer
            .targets()
            .iter()
            .copied()
            .filter(|target| !removed.contains(target))
            .collect::<Vec<_>>();
        for &base in &candidates {
            let Some(Some(base_owner)) = self.member_owner_by_target.get(&base).cloned() else {
                continue;
            };
            if base_owner.hierarchy_depth == 0 {
                continue;
            }
            for &derived in &candidates {
                if self.poll_cancelled() {
                    return Ok(None);
                }
                if base == derived {
                    continue;
                }
                let Some(Some(derived_owner)) = self.member_owner_by_target.get(&derived).cloned()
                else {
                    continue;
                };
                let Some(nearer) = self.java_owner_inherits(derived_owner.owner, base_owner.owner)
                else {
                    return Ok(None);
                };
                let class_over_interface = matches!(
                    declarations.get(&base_owner.owner).map(|row| &row.kind),
                    Some(JavaInheritanceDeclarationKind::Type {
                        is_interface: true,
                        ..
                    })
                ) && matches!(
                    declarations.get(&derived_owner.owner).map(|row| &row.kind),
                    Some(JavaInheritanceDeclarationKind::Type {
                        is_interface: false,
                        ..
                    })
                );
                if !nearer && !class_over_interface {
                    continue;
                }
                let (Some(base_signature), Some(derived_signature)) =
                    (signatures.get(&base), signatures.get(&derived))
                else {
                    unresolved = true;
                    continue;
                };
                let base_signature = base_signature.get(self.session).row().clone();
                let derived_signature = derived_signature.get(self.session).row().clone();
                match self.java_same_method_signature(
                    &base_signature,
                    &derived_signature,
                    previous_states,
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
        if self.cancellation_observed {
            return Ok(None);
        }
        let (targets, witnesses, mut completion) = answer.into_parts();
        if unresolved {
            completion = completion.combine(&incomplete(canonical_service_reason(
                self.session,
                &*self.hierarchy,
                b"java-method-inheritance-unproven",
                &[CanonicalIdentityPart::identity(self.root)],
            )?));
        }
        let targets = targets
            .into_vec()
            .into_iter()
            .filter(|target| !removed.contains(target))
            .collect::<Vec<_>>();
        let witnesses = witnesses
            .into_vec()
            .into_iter()
            .filter(|witness| !removed.contains(&witness.target()))
            .collect::<Vec<_>>();
        Ok(Some(ResolutionAnswer::new(targets, witnesses, completion)))
    }

    // A recorded candidate path is just one path through an interface DAG.
    // Dominance asks whether the declaring owners are related, independently
    // of which shortest path discovered the base declaration first.
    fn java_owner_inherits(&mut self, derived: SemanticId, base: SemanticId) -> Option<bool> {
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
                .expect("Java callable collection sealed the ancestor closure");
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

    fn java_same_method_signature(
        &mut self,
        base: &LoweredCallableSignatureProperty,
        derived: &LoweredCallableSignatureProperty,
        previous_states: &StateMap,
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
                if !self.java_parameter_lookups_equivalent(parameter_slots, previous_states)? {
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

    /// Equal ordered lookups can denote the same type while a shared external
    /// hierarchy remains open. Require unchanged identity transfers, selected
    /// access for known candidates, and the same package access domain. Other
    /// gaps (including visibility and activation) cannot supply this proof.
    fn java_parameter_lookups_equivalent(
        &mut self,
        slots: [SemanticId; 2],
        states: &StateMap,
    ) -> StoreResult<bool> {
        let mut lookups = Vec::with_capacity(2);
        for slot in slots {
            if self.poll_cancelled() {
                return Ok(false);
            }
            let read = self.session.transfers_to_targets(&[slot])?;
            let Some(transfers) = self.accept_session_read(read) else {
                return Ok(false);
            };
            let [transfer] = transfers.as_slice() else {
                return Ok(false);
            };
            let transfer = transfer.get(self.session).row();
            if transfer.kind() != ResolutionTypeTransferKind::DeclaredType
                || transfer.rule().completion() != &ResolutionCompletion::Complete
                || transfer.rule().indirection_delta() != 0
                || transfer.rule().reference_indirection_delta() != 0
                || !matches!(
                    transfer.rule().value_transform(),
                    TypeTransferValueTransform::ToRuntime { .. }
                )
            {
                return Ok(false);
            }
            let source = transfer.source_slot();
            let read = self.session.projections_for_outputs(&[source])?;
            let Some(projections) = self.accept_session_read(read) else {
                return Ok(false);
            };
            let [projection] = projections.as_slice() else {
                return Ok(false);
            };
            let projection = projection.get(self.session).row();
            if projection.kind() != BindingProjectionKind::TargetTypeIdentity {
                return Ok(false);
            }
            let reference = projection.reference();
            let Some(answer) = self.lexical_answers.get(&reference).cloned() else {
                return Ok(false);
            };
            if answer.lookup_decision().is_none() {
                return Ok(false);
            }
            let Some(state) = states.get(&slot) else {
                return Ok(false);
            };
            let ([target], [value]) = (answer.targets(), state.possible_values()) else {
                return Ok(false);
            };
            if !matches!(value, ResolutionSlotValue::Runtime { .. })
                || value.ty() != ResolutionTypeRef::new(*target, 0)
                || completions_equal_with_poll(answer.completion(), state.completion(), &mut || {
                    self.poll_cancelled()
                }) != Some(true)
                || self
                    .session
                    .declaration_access
                    .get(&DeclarationAccessRequest {
                        reference,
                        definition: *target,
                    })
                    .is_none_or(|row| row.decision != DeclarationAccessDecision::Allowed)
            {
                return Ok(false);
            }
            lookups.push((reference, answer));
        }
        let [(left_reference, left), (right_reference, right)] = lookups.as_slice() else {
            unreachable!("two parameter lookups were collected");
        };
        if left.lookup_decisions_equal_with_poll(right, &mut || self.poll_cancelled()) != Some(true)
        {
            return Ok(false);
        }
        let Some(contexts) = self
            .session
            .typed_source
            .java_access_endpoints(&[*left_reference, *right_reference], self.cancellation)?
        else {
            self.cancellation_observed = true;
            return Ok(false);
        };
        let left_context = contexts.iter().find(|row| row.semantic == *left_reference);
        let right_context = contexts.iter().find(|row| row.semantic == *right_reference);
        let (Some(left_context), Some(right_context)) = (left_context, right_context) else {
            return Ok(false);
        };
        if left_context.package.is_none() || left_context.package != right_context.package {
            return Ok(false);
        }
        let ResolutionCompletion::Incomplete(reasons) = left.completion() else {
            return Ok(false);
        };
        let mut semantics = Vec::new();
        for reason in reasons.iter() {
            if self.poll_cancelled() {
                return Ok(false);
            }
            let ResolutionIncompleteReason::UnsupportedSemantic(semantic) = reason else {
                return Ok(false);
            };
            semantics.push(*semantic);
        }
        let read = self.session.gap_reason_provenance_for_reasons(&semantics)?;
        let Some(provenance) = self.accept_session_read(read) else {
            return Ok(false);
        };
        if provenance.len() != semantics.len() {
            return Ok(false);
        }
        for row in provenance {
            if self.poll_cancelled() {
                return Ok(false);
            }
            if !matches!(
                row.get(self.session).origin(),
                LoweringGapOrigin::Extracted(
                    ResolutionGapKind::UnsupportedHierarchyTraversal
                        | ResolutionGapKind::UnsupportedPlacementBoundary
                )
            ) {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

impl FactEvaluation<'_, '_> {
    /// Identity and primitive widening permit a fixed-arity strict invocation.
    /// A primitive-to-reference argument needs boxing and cannot compete in
    /// that phase. Unknown conversions remain candidates until
    /// their own applicability/specificity proof is available.
    pub(crate) fn filter_java_boxing_after_strict_invocation(
        &mut self,
        answer: ResolutionAnswer,
        obligation: &LoweredCallApplicabilityObligation,
        signatures: &HashMap<
            SemanticId,
            InternedFactRow<SelectedTypedRow<LoweredCallableSignatureProperty>>,
        >,
        states: &StateMap,
        argument_receiver_gap_reason: Option<SemanticId>,
    ) -> StoreResult<Option<ResolutionAnswer>> {
        if answer.targets().len() < 2 || obligation.explicit_type_argument_count() != 0 {
            return Ok(Some(answer));
        }
        // Candidate method rows are query-local inputs to this native
        // applicability operation. They are not necessarily cached by the
        // earlier inheritance refinement (which only needs owner rows).
        let targets = answer.targets().to_vec();
        let Some(_) = self.session.java_declarations(&targets)? else {
            self.cancellation_observed = true;
            return Ok(None);
        };
        let java_methods = answer
            .targets()
            .iter()
            .copied()
            .filter(|target| {
                self.session
                    .java_inheritance_declarations
                    .get(target)
                    .and_then(Option::as_ref)
                    .is_some_and(|row| {
                        matches!(row.kind, JavaInheritanceDeclarationKind::Method { .. })
                    })
            })
            .collect::<BTreeSet<_>>();
        if java_methods.is_empty() {
            return Ok(Some(answer));
        }
        let mut arguments = Vec::new();
        for slot in obligation.argument_slots() {
            self.demand_slot(*slot);
            let Some(ty) = states.get(slot).and_then(|state| {
                java_invocation_argument_type(state, argument_receiver_gap_reason)
            }) else {
                return Ok(Some(answer));
            };
            arguments.push(ty);
        }
        let mut candidates = Vec::new();
        for target in java_methods {
            if self.poll_cancelled() {
                return Ok(None);
            }
            let Some(signature) = signatures.get(&target) else {
                continue;
            };
            let signature = signature.get(self.session).row().clone();
            if signature.type_parameter_count() != 0
                || signature.parameters().len() != arguments.len()
                || signature
                    .parameters()
                    .iter()
                    .any(|parameter| parameter.repeated())
            {
                continue;
            }
            let mut parameters = Vec::new();
            for parameter in signature.parameters() {
                self.demand_slot(parameter.slot());
                parameters.push(states.get(&parameter.slot()).and_then(|state| {
                    java_invocation_argument_type(state, argument_receiver_gap_reason)
                }));
            }
            candidates.push((
                target,
                parameters,
                signature
                    .parameters()
                    .iter()
                    .map(|parameter| parameter.slot())
                    .collect::<Vec<_>>(),
            ));
        }
        let type_ids = arguments
            .iter()
            .chain(
                candidates
                    .iter()
                    .flat_map(|(_, parameters, _)| parameters.iter().flatten()),
            )
            .map(|ty| ty.identity())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let Some(intrinsics) = self.session.intrinsic_type_descriptors(&type_ids)? else {
            return Ok(None);
        };
        let mut primitives = HashMap::default();
        for intrinsic in intrinsics {
            if self.poll_cancelled() {
                return Ok(None);
            }
            if intrinsic.kind() == IntrinsicTypeKind::Primitive
                && let Some(primitive) =
                    crate::analyzer::java::primitive_for_name(intrinsic.spelling())
            {
                primitives.insert(intrinsic.identity(), primitive);
            }
        }
        let strict = candidates.iter().any(|(_, parameters, _)| {
            parameters
                .iter()
                .zip(&arguments)
                .all(|(parameter, argument)| {
                    parameter.is_some_and(|parameter| {
                        parameter == *argument
                            || (parameter.indirection() == 0
                                && argument.indirection() == 0
                                && primitives
                                    .get(&argument.identity())
                                    .zip(primitives.get(&parameter.identity()))
                                    .is_some_and(|(&source, &target)| {
                                        crate::analyzer::java::primitive_converts(source, target)
                                    }))
                    })
                })
        });
        if !strict || primitives.is_empty() {
            return Ok(Some(answer));
        }
        let parameters = candidates
            .iter()
            .flat_map(|(_, parameters, _)| parameters.iter().flatten())
            .map(|ty| ty.identity())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let Some(declarations) = self.session.java_declarations(&parameters)? else {
            self.cancellation_observed = true;
            return Ok(None);
        };
        let reference_types = declarations
            .into_iter()
            .filter(|row| matches!(row.kind, JavaInheritanceDeclarationKind::Type { .. }))
            .map(|row| row.definition)
            .collect::<BTreeSet<_>>();
        let slots = candidates
            .iter()
            .flat_map(|(_, _, slots)| slots.iter().copied())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let Some(named_reference_slots) = self.java_named_reference_parameter_slots(&slots)? else {
            return Ok(None);
        };
        let excluded = candidates
            .into_iter()
            .filter(|(_, parameters, slots)| {
                arguments.iter().zip(parameters.iter().zip(slots)).any(
                    |(argument, (parameter, slot))| {
                        argument.indirection() == 0
                            && primitives.contains_key(&argument.identity())
                            && (named_reference_slots.contains(slot)
                                || parameter.is_some_and(|parameter| {
                                    parameter.indirection() == 0
                                        && reference_types.contains(&parameter.identity())
                                }))
                    },
                )
            })
            .map(|(target, _, _)| target)
            .collect::<BTreeSet<_>>();
        if excluded.is_empty() {
            return Ok(Some(answer));
        }
        if obligation.callee_reference() == self.root {
            for &target in &excluded {
                assert!(
                    self.callable_candidate_applicability
                        .insert(
                            target,
                            FactCallableCandidateApplicability {
                                target,
                                verdict: ApplicabilityVerdict::Inapplicable,
                                reason: Some(CallableRejectionReason::RequiresBoxing),
                            },
                        )
                        .is_none(),
                    "one native Java candidate has one final applicability reason"
                );
            }
        }
        let (targets, witnesses, completion) = answer.into_parts();
        let targets = targets
            .iter()
            .copied()
            .filter(|target| !excluded.contains(target))
            .collect::<Vec<_>>();
        assert!(
            !targets.is_empty(),
            "the proven strict candidate cannot require boxing"
        );
        let witnesses = witnesses
            .into_vec()
            .into_iter()
            .filter(|witness| !excluded.contains(&witness.target()))
            .collect::<Vec<_>>();
        Ok(Some(ResolutionAnswer::new(targets, witnesses, completion)))
    }

    /// Java primitive widening can make several fixed-arity overloads
    /// applicable, but the JLS chooses the candidate with the most specific
    /// primitive formals. This operation removes only candidates dominated by
    /// an applicable sibling whose formal types widen to theirs. Exact
    /// argument and formal primitive descriptors are required; any gap leaves
    /// the candidate set open for the later applicability classifier.
    pub(crate) fn filter_java_primitive_less_specific(
        &mut self,
        answer: ResolutionAnswer,
        obligation: &LoweredCallApplicabilityObligation,
        signatures: &HashMap<
            SemanticId,
            InternedFactRow<SelectedTypedRow<LoweredCallableSignatureProperty>>,
        >,
        states: &StateMap,
        argument_receiver_gap_reason: Option<SemanticId>,
    ) -> StoreResult<Option<ResolutionAnswer>> {
        if answer.targets().len() < 2 || obligation.explicit_type_argument_count() != 0 {
            return Ok(Some(answer));
        }
        if !answer.targets().iter().all(|target| {
            self.session
                .java_inheritance_declarations
                .get(target)
                .and_then(Option::as_ref)
                .is_some_and(|row| {
                    matches!(row.kind, JavaInheritanceDeclarationKind::Method { .. })
                })
        }) {
            return Ok(Some(answer));
        }

        let mut arguments = Vec::with_capacity(obligation.argument_slots().len());
        for &slot in obligation.argument_slots() {
            self.demand_slot(slot);
            let Some(ty) = states
                .get(&slot)
                .and_then(|state| {
                    java_invocation_argument_type(state, argument_receiver_gap_reason)
                })
                .filter(|ty| ty.indirection() == 0)
            else {
                return Ok(Some(answer));
            };
            arguments.push(ty.identity());
        }

        let mut formal_identities = Vec::new();
        let mut candidate_formals = Vec::with_capacity(answer.targets().len());
        for &target in answer.targets() {
            if self.poll_cancelled() {
                return Ok(None);
            }
            let Some(signature) = signatures.get(&target) else {
                return Ok(Some(answer));
            };
            let signature = signature.get(self.session).row().clone();
            if signature.parameters().len() != arguments.len() {
                continue;
            }
            if signature.completion() != &ResolutionCompletion::Complete
                || signature.type_parameter_count() != 0
                || signature
                    .parameters()
                    .iter()
                    .any(|parameter| parameter.repeated())
            {
                return Ok(Some(answer));
            }
            let mut formals = Vec::with_capacity(signature.parameters().len());
            for parameter in signature.parameters() {
                self.demand_slot(parameter.slot());
                let Some(ty) = states
                    .get(&parameter.slot())
                    .and_then(|state| {
                        java_invocation_argument_type(state, argument_receiver_gap_reason)
                    })
                    .filter(|ty| ty.indirection() == 0)
                else {
                    return Ok(Some(answer));
                };
                formal_identities.push(ty.identity());
                formals.push(ty.identity());
            }
            candidate_formals.push((target, formals));
        }
        if candidate_formals.is_empty() {
            return Ok(Some(answer));
        }

        let mut identities = arguments.clone();
        identities.extend(formal_identities);
        identities.sort_unstable();
        identities.dedup();
        let Some(intrinsics) = self.session.intrinsic_type_descriptors(&identities)? else {
            return Ok(None);
        };
        let mut primitives = HashMap::default();
        for intrinsic in intrinsics {
            if self.poll_cancelled() {
                return Ok(None);
            }
            if intrinsic.kind() == IntrinsicTypeKind::Primitive
                && let Some(primitive) =
                    crate::analyzer::java::primitive_for_name(intrinsic.spelling())
            {
                primitives.insert(intrinsic.identity(), primitive);
            }
        }
        if arguments
            .iter()
            .chain(candidate_formals.iter().flat_map(|(_, formals)| formals))
            .any(|identity| !primitives.contains_key(identity))
        {
            return Ok(Some(answer));
        }
        let argument_primitives = arguments
            .iter()
            .map(|identity| primitives[identity])
            .collect::<Vec<_>>();

        let candidates = candidate_formals
            .into_iter()
            .map(|(target, formals)| {
                let formals = formals
                    .into_iter()
                    .map(|identity| primitives[&identity])
                    .collect::<Vec<JavaPrimitive>>();
                let applicable =
                    argument_primitives
                        .iter()
                        .zip(&formals)
                        .all(|(&argument, &formal)| {
                            argument == formal
                                || crate::analyzer::java::primitive_converts(argument, formal)
                        });
                (target, formals, applicable)
            })
            .collect::<Vec<_>>();
        if !candidates.iter().any(|(_, _, applicable)| *applicable) {
            if obligation.callee_reference() == self.root {
                for (target, _, _) in candidates {
                    assert!(
                        self.callable_candidate_applicability
                            .insert(
                                target,
                                FactCallableCandidateApplicability {
                                    target,
                                    verdict: ApplicabilityVerdict::Inapplicable,
                                    reason: Some(CallableRejectionReason::PrimitiveTypeMismatch),
                                },
                            )
                            .is_none(),
                        "one native Java candidate has one final applicability reason"
                    );
                }
            }
            return Ok(Some(answer));
        }

        let dominates = |left: &[JavaPrimitive], right: &[JavaPrimitive]| {
            let mut strictly_more_specific = false;
            for (&left, &right) in left.iter().zip(right) {
                if left == right {
                    continue;
                }
                if !crate::analyzer::java::primitive_converts(left, right) {
                    return false;
                }
                strictly_more_specific = true;
            }
            strictly_more_specific
        };
        let most_specific = candidates
            .iter()
            .filter(|(_, _, applicable)| *applicable)
            .filter(|(_, formals, _)| {
                !candidates
                    .iter()
                    .any(|(_, other_formals, other_applicable)| {
                        *other_applicable && dominates(other_formals, formals)
                    })
            })
            .map(|(target, _, _)| *target)
            .collect::<BTreeSet<_>>();
        assert!(
            !most_specific.is_empty(),
            "an applicable finite primitive overload set has a maximal candidate"
        );
        if obligation.callee_reference() == self.root {
            for (target, _, applicable) in &candidates {
                let (verdict, reason) = if !applicable {
                    (
                        ApplicabilityVerdict::Inapplicable,
                        Some(CallableRejectionReason::PrimitiveTypeMismatch),
                    )
                } else if most_specific.contains(target) {
                    (ApplicabilityVerdict::Applicable, None)
                } else {
                    (
                        ApplicabilityVerdict::Inapplicable,
                        Some(CallableRejectionReason::LessSpecificPrimitiveOverload),
                    )
                };
                assert!(
                    self.callable_candidate_applicability
                        .insert(
                            *target,
                            FactCallableCandidateApplicability {
                                target: *target,
                                verdict,
                                reason,
                            },
                        )
                        .is_none(),
                    "one native Java candidate has one final applicability reason"
                );
            }
        }
        let excluded = candidates
            .iter()
            .filter_map(|(target, _, applicable)| {
                if !applicable {
                    Some((*target, CallableRejectionReason::PrimitiveTypeMismatch))
                } else if !most_specific.contains(target) {
                    Some((
                        *target,
                        CallableRejectionReason::LessSpecificPrimitiveOverload,
                    ))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        if excluded.is_empty() {
            return Ok(Some(answer));
        }
        let excluded = excluded
            .into_iter()
            .map(|(target, _)| target)
            .collect::<BTreeSet<_>>();
        let (targets, witnesses, completion) = answer.into_parts();
        let targets = targets
            .iter()
            .copied()
            .filter(|target| !excluded.contains(target))
            .collect::<Vec<_>>();
        let witnesses = witnesses
            .into_vec()
            .into_iter()
            .filter(|witness| !excluded.contains(&witness.target()))
            .collect::<Vec<_>>();
        Ok(Some(ResolutionAnswer::new(targets, witnesses, completion)))
    }

    /// JLS 15.12.2: a candidate is applicable only if each argument type
    /// converts to its formal. For two Java source class or interface types a
    /// widening reference conversion exists exactly when the formal is a
    /// supertype of the argument, so a formal outside the argument's complete
    /// supertype closure proves the candidate inapplicable. The proof needs
    /// exact complete argument and formal states and an argument closure with
    /// every authored edge resolved; an implicit `java.lang.Object` edge adds
    /// no source type (an unindexed Object cannot equal a source class). Any
    /// other gap keeps the candidate. The filter never removes every
    /// candidate and leaves completion to the call's own obligation.
    pub(crate) fn filter_java_reference_inapplicable(
        &mut self,
        answer: ResolutionAnswer,
        obligation: &LoweredCallApplicabilityObligation,
        signatures: &HashMap<
            SemanticId,
            InternedFactRow<SelectedTypedRow<LoweredCallableSignatureProperty>>,
        >,
        states: &StateMap,
        argument_receiver_gap_reason: Option<SemanticId>,
    ) -> StoreResult<Option<ResolutionAnswer>> {
        if answer.targets().len() < 2 || obligation.explicit_type_argument_count() != 0 {
            return Ok(Some(answer));
        }
        let mut arguments = Vec::with_capacity(obligation.argument_slots().len());
        for slot in obligation.argument_slots() {
            self.demand_slot(*slot);
            let Some(ty) = states
                .get(slot)
                .and_then(|state| {
                    java_invocation_argument_type(state, argument_receiver_gap_reason)
                })
                .filter(|ty| ty.indirection() == 0)
            else {
                return Ok(Some(answer));
            };
            arguments.push(ty.identity());
        }
        let mut candidates = Vec::with_capacity(answer.targets().len());
        for &target in answer.targets() {
            if self.poll_cancelled() {
                return Ok(None);
            }
            let is_java_method = self
                .session
                .java_inheritance_declarations
                .get(&target)
                .and_then(Option::as_ref)
                .is_some_and(|row| {
                    matches!(row.kind, JavaInheritanceDeclarationKind::Method { .. })
                });
            if !is_java_method {
                return Ok(Some(answer));
            }
            let Some(signature) = signatures.get(&target) else {
                continue;
            };
            let signature = signature.get(self.session).row().clone();
            if signature.completion() != &ResolutionCompletion::Complete
                || signature.type_parameter_count() != 0
                || signature.parameters().len() != arguments.len()
                || signature
                    .parameters()
                    .iter()
                    .any(|parameter| parameter.repeated())
            {
                continue;
            }
            let mut formals = Vec::with_capacity(arguments.len());
            for parameter in signature.parameters() {
                self.demand_slot(parameter.slot());
                formals.push(
                    states
                        .get(&parameter.slot())
                        .and_then(|state| {
                            java_invocation_argument_type(state, argument_receiver_gap_reason)
                        })
                        .filter(|ty| ty.indirection() == 0)
                        .map(|ty| ty.identity()),
                );
            }
            candidates.push((target, formals));
        }
        let mut identities = arguments.clone();
        identities.extend(
            candidates
                .iter()
                .flat_map(|(_, formals)| formals.iter().flatten().copied()),
        );
        identities.sort_unstable();
        identities.dedup();
        let Some(declarations) = self.session.java_declarations(&identities)? else {
            self.cancellation_observed = true;
            return Ok(None);
        };
        let source_types = declarations
            .into_iter()
            .filter(|row| matches!(row.kind, JavaInheritanceDeclarationKind::Type { .. }))
            .map(|row| row.definition)
            .collect::<HashSet<_>>();
        let mut closures = HashMap::<SemanticId, Option<HashSet<SemanticId>>>::default();
        let mut excluded = BTreeSet::new();
        for (target, formals) in &candidates {
            for (&argument, formal) in arguments.iter().zip(formals) {
                if self.poll_cancelled() {
                    return Ok(None);
                }
                let Some(formal) = *formal else {
                    continue;
                };
                if formal == argument
                    || !source_types.contains(&argument)
                    || !source_types.contains(&formal)
                {
                    continue;
                }
                let closure = match closures.entry(argument) {
                    std::collections::hash_map::Entry::Occupied(entry) => entry.into_mut(),
                    std::collections::hash_map::Entry::Vacant(entry) => {
                        let Some(closure) = self.java_supertype_closure(argument, states)? else {
                            return Ok(None);
                        };
                        entry.insert(closure)
                    }
                };
                if closure
                    .as_ref()
                    .is_some_and(|closure| !closure.contains(&formal))
                {
                    excluded.insert(*target);
                    break;
                }
            }
        }
        if excluded.is_empty() || excluded.len() == answer.targets().len() {
            return Ok(Some(answer));
        }
        let (targets, witnesses, completion) = answer.into_parts();
        let targets = targets
            .iter()
            .copied()
            .filter(|target| !excluded.contains(target))
            .collect::<Vec<_>>();
        let witnesses = witnesses
            .into_vec()
            .into_iter()
            .filter(|witness| !excluded.contains(&witness.target()))
            .collect::<Vec<_>>();
        Ok(Some(ResolutionAnswer::new(targets, witnesses, completion)))
    }

    /// Every type reachable from `root` through resolved supertype edges,
    /// including `root`. The outer `None` reports cancellation; the inner
    /// `None` reports an unresolved authored edge or a frontier not yet
    /// evaluated (it is demanded for the next round).
    pub(super) fn java_supertype_closure(
        &mut self,
        root: SemanticId,
        states: &StateMap,
    ) -> StoreResult<Option<Option<HashSet<SemanticId>>>> {
        let mut closure = HashSet::default();
        let mut pending = vec![root];
        let mut known = true;
        while let Some(current) = pending.pop() {
            if self.poll_cancelled() {
                return Ok(None);
            }
            if !closure.insert(current) {
                continue;
            }
            let read = self.session.supertypes_for_definitions(&[current])?;
            let Some(rows) = self.accept_session_read(read) else {
                return Ok(None);
            };
            for row in rows {
                let (kind, frontier) = {
                    let row = row.get(self.session).row();
                    (row.kind(), row.frontier())
                };
                if kind == ResolutionSupertypeKind::SelfType {
                    continue;
                }
                self.demand_slot(frontier);
                let resolved = states.get(&frontier).and_then(|state| {
                    match (state.completion(), state.possible_values()) {
                        (ResolutionCompletion::Complete, [ResolutionSlotValue::TypeObject(ty)])
                            if ty.indirection() == 0 =>
                        {
                            Some(ty.identity())
                        }
                        _ => None,
                    }
                });
                match resolved {
                    Some(supertype) => pending.push(supertype),
                    None if kind == ResolutionSupertypeKind::ImplicitSuperclass => {}
                    None => known = false,
                }
            }
        }
        Ok(Some(known.then_some(closure)))
    }

    /// Java named type syntax denotes a reference type even when its exact
    /// class binding is open. Read the declaration's structured transfer and
    /// identity projection; never infer this property from a signature string
    /// or from the currently observed incomplete set of class candidates.
    fn java_named_reference_parameter_slots(
        &mut self,
        slots: &[SemanticId],
    ) -> StoreResult<Option<BTreeSet<SemanticId>>> {
        let read = self.session.transfers_to_targets(slots)?;
        let Some(transfers) = self.accept_session_read(read) else {
            return Ok(None);
        };
        let mut inputs = HashMap::<SemanticId, Vec<SemanticId>>::default();
        for transfer in transfers {
            if self.poll_cancelled() {
                return Ok(None);
            }
            let row = transfer.get(self.session).row();
            if row.kind() == ResolutionTypeTransferKind::DeclaredType
                && matches!(
                    row.rule().value_transform(),
                    TypeTransferValueTransform::ToRuntime { .. }
                )
                && row.rule().completion() == &ResolutionCompletion::Complete
            {
                inputs
                    .entry(row.rule().target_slot())
                    .or_default()
                    .push(row.source_slot());
            }
        }
        let sources = inputs
            .values()
            .filter_map(|sources| match sources.as_slice() {
                [source] => Some(*source),
                _ => None,
            })
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let read = self.session.projections_for_outputs(&sources)?;
        let Some(projections) = self.accept_session_read(read) else {
            return Ok(None);
        };
        let mut named = BTreeSet::new();
        for projection in projections {
            if self.poll_cancelled() {
                return Ok(None);
            }
            let row = projection.get(self.session).row();
            if row.kind() == BindingProjectionKind::TargetTypeIdentity {
                named.insert(row.output_slot());
            }
        }
        let mut result = BTreeSet::new();
        for (slot, sources) in inputs {
            if self.poll_cancelled() {
                return Ok(None);
            }
            if let [source] = sources.as_slice()
                && named.contains(source)
            {
                result.insert(slot);
            }
        }
        Ok(Some(result))
    }
}

/// The static-call producer gap also reaches argument frontiers because the
/// call expression is one typed graph. Once the native member-owner facts
/// prove this call uses static methods, discard only that exact receiver gap
/// while reading the source argument's known type. Call applicability keeps
/// the original completion, so this local view cannot make the call complete.
fn java_invocation_argument_type(
    state: &TypedFrontierState,
    ignored_receiver_gap: Option<SemanticId>,
) -> Option<ResolutionTypeRef> {
    let completion = ignored_receiver_gap.map_or_else(
        || state.completion().clone(),
        |reason| completion_without_unsupported_semantic(state.completion(), reason),
    );
    if completion != ResolutionCompletion::Complete {
        return None;
    }
    match state.possible_values() {
        [ResolutionSlotValue::Runtime { ty, .. }] => Some(*ty),
        _ => None,
    }
}
