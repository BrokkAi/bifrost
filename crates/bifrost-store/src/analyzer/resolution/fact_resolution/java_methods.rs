//! Java method inheritance precedes invocation applicability. All state here
//! belongs to one selected query; declarations remain indexed source rows.

use super::super::fact_source::{
    JavaInheritanceDeclaration, JavaInheritanceDeclarationKind,
    language_can_close_interface_object_frontier, language_implicit_root_member_names,
};
use super::*;
use brokk_bifrost_core::analyzer::structural::callable::ArgumentConversion;
use brokk_bifrost_core::analyzer::structural::resolution::DeclaredVisibility;
use brokk_bifrost_jvm::java::primitives::JavaPrimitive;

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
    /// Operand types affect applicability, not a fixed member inventory.
    /// Keep operational failures open even when all semantic operand gaps
    /// can be left on the nested evaluation that produced them.
    pub(super) fn jvm_call_candidate_operand_frontier(
        &mut self,
        obligation: &LoweredCallApplicabilityObligation,
        signature: &LoweredCallableSignatureProperty,
        states: &StateMap,
    ) -> StoreResult<Option<Option<BTreeSet<ResolutionIncompleteReason>>>> {
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
                if let ResolutionCompletion::Incomplete(incomplete) = state.completion() {
                    for reason in incomplete.iter() {
                        if self.poll_cancelled() {
                            return Ok(None);
                        }
                        match reason {
                            ResolutionIncompleteReason::UnsupportedSemantic(_)
                            | ResolutionIncompleteReason::OpenBoundary { .. }
                            | ResolutionIncompleteReason::InconsistentPrecedence(_) => {
                                reasons.insert(*reason);
                            }
                            _ => return Ok(Some(None)),
                        }
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
    pub(super) fn java_member_implicit_object_gap_reasons(
        &mut self,
        language: Language,
        reference: SemanticId,
        answer: &ResolutionAnswer,
        completion: &ResolutionCompletion,
        previous_states: &StateMap,
    ) -> StoreResult<Option<BTreeSet<SemanticId>>> {
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
                self.java_absent_member_receiver_owners(reference, previous_states)?
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
                edge_reasons.push((source_site, provenance.reason()));
            }
        }
        // A lexical search can exhaust an inner interface before selecting an
        // enclosing class member. Its implicit Object frontier still belongs to
        // this same name lookup, even though no selected method is owned by it.
        // A source reference must have an exhaustive unique hierarchy binding
        // before the leaf-interface proof can discharge its traversal marker.
        let mut interface_references = HashMap::default();
        if language == Language::Java {
            for &(reference, reason) in &edge_reasons {
                if !self.hierarchy.reference_ready(reference) {
                    continue;
                }
                let Some((targets, completion)) =
                    self.cached_hierarchy_reference_parts(reference, &BTreeSet::from([reason]))?
                else {
                    return Ok(None);
                };
                if completion == ResolutionCompletion::Complete && targets.len() == 1 {
                    interface_references.insert(reference, targets[0]);
                }
            }
        }
        let mut interface_object_gaps = BTreeSet::new();
        if language_can_close_interface_object_frontier(language) {
            let mut candidates = member_owners
                .iter()
                .copied()
                .filter(|owner| owners.contains(owner))
                .collect::<BTreeSet<_>>();
            if language == Language::Java {
                candidates.extend(edge_reasons.iter().map(|&(site, _)| site));
                candidates.extend(interface_references.values().copied());
            }
            let Some(rows) = self
                .session
                .java_declarations(&candidates.into_iter().collect::<Vec<_>>())?
            else {
                self.cancellation_observed = true;
                return Ok(None);
            };
            let interfaces = rows
                .into_iter()
                .filter_map(|row| {
                    matches!(
                        row.kind,
                        JavaInheritanceDeclarationKind::Type {
                            is_interface: true,
                            ..
                        }
                    )
                    .then_some(row.definition)
                })
                .collect::<Vec<_>>();
            if !interfaces.is_empty() {
                let read = self.session.supertypes_for_definitions(&interfaces)?;
                let Some(supertypes) = self.accept_session_read(read) else {
                    return Ok(None);
                };
                let authored = supertypes
                    .iter()
                    .map(|row| row.get(self.session).row().definition())
                    .collect::<HashSet<_>>();
                interface_object_gaps.extend(
                    interfaces
                        .into_iter()
                        .filter(|owner| !authored.contains(owner)),
                );
            }
        }
        let proven_interface_references = interface_references
            .into_iter()
            .filter_map(|(reference, target)| {
                interface_object_gaps.contains(&target).then_some(reference)
            })
            .collect::<Vec<_>>();
        interface_object_gaps.extend(proven_interface_references);
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
                .filter(|(reference, _)| {
                    implicit_object_references.contains(reference)
                        || interface_object_gaps.contains(reference)
                })
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
        reference: SemanticId,
        previous_states: &StateMap,
    ) -> StoreResult<Option<BTreeSet<SemanticId>>> {
        let read = self.session.routes_for_references(&[reference])?;
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
        self.indexed_jvm_type_origin_owners(selection, rust_owners)
    }

    #[doc(hidden)]
    pub fn filter_java_inherited_methods(
        &mut self,
        answer: ResolutionAnswer,
        reference: SemanticId,
        signatures: &HashMap<
            SemanticId,
            InternedFactRow<SelectedTypedRow<LoweredCallableSignatureProperty>>,
        >,
        previous_states: &StateMap,
    ) -> StoreResult<Option<ResolutionAnswer>> {
        // Replay also explores shadowed enclosing scopes. Only a bridge in a
        // surviving witness can attribute the call's selected receiver search.
        for &target in answer.targets() {
            let Some(origins) = self
                .hierarchy
                .java_lexical_member_owners
                .get(&(reference, target))
            else {
                continue;
            };
            let mut selected: Option<Option<FactMemberOwner>> = None;
            for origin in origins {
                let survives = answer.witnesses().iter().any(|witness| {
                    witness.target() == target
                        && (origin.steps.is_empty()
                            || witness
                                .steps()
                                .windows(origin.steps.len())
                                .any(|steps| steps == origin.steps.as_ref()))
                });
                if !survives {
                    continue;
                }
                match &mut selected {
                    None => selected = Some(Some(origin.owner.clone())),
                    Some(owner) if owner.as_ref() != Some(&origin.owner) => *owner = None,
                    Some(_) => {}
                }
            }
            if let Some(owner) = selected {
                self.member_owner_by_target.insert(target, owner);
            }
        }
        // Bare references have no receiver route. Qualified lookups own their
        // attribution; reconstructing it from a declaration would replace the
        // receiver search with the declaring type.
        let unqualified = self
            .reference_site_metadata(reference)
            .is_some_and(|metadata| metadata.unqualified());
        let missing = answer
            .targets()
            .iter()
            .copied()
            .filter(|target| unqualified && !self.member_owner_by_target.contains_key(target))
            .collect::<Vec<_>>();
        if !self.ensure_hierarchy_member_owner_metadata(&missing)? {
            return Ok(None);
        }
        for target in missing {
            let Some(ExactMemberOwnerMetadata::Unique(row)) =
                self.hierarchy.member_owner_metadata.get(&target)
            else {
                continue;
            };
            let row = row.get(self.session).row();
            let (owner, kind) = (row.owner_definition(), row.kind());
            if kind == ResolutionMemberKind::Method {
                self.record_member_owner(target, kind, Box::new([owner]), false);
            }
        }
        // Constructors and non-member callables do not participate in method
        // inheritance. Lexical methods now have the same attribution as routes.
        if !answer.targets().iter().any(|target| {
            self.member_owner_by_target
                .get(target)
                .is_some_and(Option::is_some)
        }) {
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
            if let Some((_, rules)) = self.implicit_interface_member_rules(owner) {
                debug_assert_eq!(rules.visibility, DeclaredVisibility::Public);
                debug_assert!(rules.is_abstract);
                // JLS 9.2 declares this member directly on the interface.
                // Its public, abstract instance modifiers come from the
                // selected language rule; no Object owner metadata is needed.
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
            if is_static {
                match declarations.get(&owner.owner).map(|row| &row.kind) {
                    Some(JavaInheritanceDeclarationKind::Type {
                        is_interface: true, ..
                    }) => {
                        removed.insert(target);
                        continue;
                    }
                    Some(JavaInheritanceDeclarationKind::Type {
                        is_interface: false,
                        ..
                    }) => {}
                    _ => unresolved = true,
                }
            }
            if visibility == DeclaredVisibility::PackagePrivate {
                for step in &owner.owner_path {
                    match declarations.get(step) {
                        Some(declaration)
                            if method.package.same_known_package(&declaration.package)
                                == Some(false) =>
                        {
                            removed.insert(target);
                            break;
                        }
                        Some(declaration)
                            if method.package.same_known_package(&declaration.package)
                                == Some(true) => {}
                        Some(_) => unresolved = true,
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
        // Java owns static hiding and class-over-interface precedence. The
        // shared loop supplies the proved owner relation and compares signatures.
        let static_methods = candidates
            .iter()
            .filter_map(|&target| {
                let owner = self.member_owner_by_target.get(&target)?.as_ref()?;
                (self.method_access_for_override(
                    owner,
                    declarations.get(&target).map(|row| &row.kind),
                ) == Some(ResolutionMemberAccess::Type))
                .then_some(target)
            })
            .collect::<HashSet<_>>();
        let declaration_owners = candidates
            .iter()
            .filter_map(|target| {
                let owner = self.member_owner_by_target.get(target)?.as_ref()?;
                Some((*target, self.method_declaration_owner(owner)))
            })
            .collect::<HashMap<_, _>>();
        let additional_dominance = |base: SemanticId,
                                    derived: SemanticId,
                                    _base_owner: &FactMemberOwner,
                                    _derived_owner: &FactMemberOwner,
                                    nearer: bool| {
            let static_family = static_methods.contains(&base) || static_methods.contains(&derived);
            if static_family && nearer {
                return Some(true);
            }
            let owner_kind = |target| match declarations
                .get(&declaration_owners[&target])
                .map(|row| &row.kind)
            {
                Some(JavaInheritanceDeclarationKind::Type { is_interface, .. }) => {
                    Some(*is_interface)
                }
                _ => None,
            };
            match (owner_kind(base), owner_kind(derived)) {
                (Some(false), _) | (_, Some(true)) => Some(false),
                (Some(base_interface), Some(derived_interface)) => {
                    Some(base_interface && !derived_interface)
                }
                _ => None,
            }
        };
        let owners = candidates
            .iter()
            .filter_map(|target| {
                self.member_owner_by_target
                    .get(target)
                    .map(|owner| (*target, owner.clone()))
            })
            .collect();
        let Some((overridden, unknown)) = self.overridden_methods(
            &candidates,
            &owners,
            signatures,
            previous_states,
            additional_dominance,
            Language::Java,
        )?
        else {
            return Ok(None);
        };
        removed.extend(overridden);
        unresolved |= unknown;
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

    /// Equal ordered lookups can denote the same type while a shared external
    /// hierarchy remains open. Require unchanged identity transfers, selected
    /// access for known candidates, and the same package access domain. Other
    /// gaps (including visibility and activation) cannot supply this proof.
    pub(super) fn java_parameter_lookups_equivalent(
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
    #[doc(hidden)]
    /// Identity and primitive widening permit a fixed-arity strict invocation.
    /// A primitive-to-reference argument needs boxing and cannot compete in
    /// that phase. Unknown conversions remain candidates until
    /// their own applicability/specificity proof is available.
    #[doc(hidden)]
    pub fn filter_java_boxing_after_strict_invocation(
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
                    brokk_bifrost_jvm::java::primitives::primitive_for_name(intrinsic.spelling())
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
                                        brokk_bifrost_jvm::java::primitives::primitive_converts(
                                            source, target,
                                        )
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
        // The first primitive argument whose formal is a reference type needs
        // boxing, which strict invocation does not permit.
        let boxed = candidates
            .into_iter()
            .filter_map(|(target, parameters, slots)| {
                let ordinal = arguments
                    .iter()
                    .zip(parameters.iter().zip(&slots))
                    .position(|(argument, (parameter, slot))| {
                        argument.indirection() == 0
                            && primitives.contains_key(&argument.identity())
                            && (named_reference_slots.contains(slot)
                                || parameter.is_some_and(|parameter| {
                                    parameter.indirection() == 0
                                        && reference_types.contains(&parameter.identity())
                                }))
                    })?;
                Some((target, ordinal))
            })
            .collect::<Vec<_>>();
        if boxed.is_empty() {
            return Ok(Some(answer));
        }
        if obligation.callee_reference() == self.root {
            for &(target, ordinal) in &boxed {
                let record = FactCallableCandidateApplicability::assessed(
                    target,
                    ApplicabilityVerdict::Inapplicable,
                    Some(CallableRejectionReason::RequiresBoxing),
                    answer.witnesses(),
                )
                .in_phase(Some(InvocationPhase::Strict))
                .with_failing_argument(Some(failing_argument(ordinal, ArgumentConversion::Boxing)));
                assert!(
                    self.callable_candidate_applicability
                        .insert(target, record)
                        .is_none(),
                    "one native Java candidate has one final applicability reason"
                );
            }
        }
        let excluded = boxed
            .into_iter()
            .map(|(target, _)| target)
            .collect::<BTreeSet<_>>();
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

    #[doc(hidden)]
    /// The first argument of a strict-phase primitive mismatch that the shared
    /// assessment found, read from the exact argument and formal types it
    /// recorded. `Some(None)` when the mismatched pair is not two Java
    /// primitives; the outer `None` reports cancellation.
    #[doc(hidden)]
    pub fn java_primitive_mismatch_argument(
        &mut self,
        conversions: &[super::call_applicability::ConversionEvidence],
    ) -> StoreResult<Option<Option<FailingArgument>>> {
        let identities = conversions
            .iter()
            .flat_map(|conversion| [conversion.source_type, conversion.target_type])
            .flatten()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
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
                    brokk_bifrost_jvm::java::primitives::primitive_for_name(intrinsic.spelling())
            {
                primitives.insert(intrinsic.identity(), primitive);
            }
        }
        let mut ordered = conversions
            .iter()
            .filter(|conversion| conversion.argument_ordinal != u32::MAX)
            .collect::<Vec<_>>();
        ordered.sort_unstable_by_key(|conversion| conversion.argument_ordinal);
        for conversion in ordered {
            let (Some(source), Some(target)) = (conversion.source_type, conversion.target_type)
            else {
                return Ok(Some(None));
            };
            if source == target {
                continue;
            }
            let (Some(&source), Some(&target)) = (primitives.get(&source), primitives.get(&target))
            else {
                return Ok(Some(None));
            };
            if brokk_bifrost_jvm::java::primitives::primitive_converts(source, target) {
                continue;
            }
            let failure = java_primitive_failure(&[source], &[target])
                .expect("a primitive pair outside strict conversion fails");
            return Ok(Some(Some(FailingArgument {
                ordinal: conversion.argument_ordinal,
                conversion: failure.conversion,
            })));
        }
        Ok(Some(None))
    }

    #[doc(hidden)]
    /// Java primitive widening can make several fixed-arity overloads
    /// applicable, but the JLS chooses the candidate with the most specific
    /// primitive formals. This operation removes only candidates dominated by
    /// an applicable sibling whose formal types widen to theirs. Exact
    /// argument and formal primitive descriptors are required; any gap leaves
    /// the candidate set open for the later applicability classifier.
    #[doc(hidden)]
    pub fn filter_java_primitive_less_specific(
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
                    brokk_bifrost_jvm::java::primitives::primitive_for_name(intrinsic.spelling())
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

        // Strict invocation (JLS 15.12.2.2) admits identity and widening
        // primitive conversions; the first argument outside them fails it.
        let candidates = candidate_formals
            .into_iter()
            .map(|(target, formals)| {
                let formals = formals
                    .into_iter()
                    .map(|identity| primitives[&identity])
                    .collect::<Vec<JavaPrimitive>>();
                let failure = java_primitive_failure(&argument_primitives, &formals);
                (target, formals, failure)
            })
            .collect::<Vec<_>>();
        if candidates.iter().all(|(_, _, failure)| failure.is_some()) {
            if obligation.callee_reference() == self.root {
                for &(target, _, failure) in &candidates {
                    let record = FactCallableCandidateApplicability::assessed(
                        target,
                        ApplicabilityVerdict::Inapplicable,
                        Some(CallableRejectionReason::PrimitiveTypeMismatch),
                        answer.witnesses(),
                    )
                    .in_phase(Some(InvocationPhase::Strict))
                    .with_failing_argument(failure);
                    assert!(
                        self.callable_candidate_applicability
                            .insert(target, record)
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
                if !brokk_bifrost_jvm::java::primitives::primitive_converts(left, right) {
                    return false;
                }
                strictly_more_specific = true;
            }
            strictly_more_specific
        };
        // JLS 15.12.2.5: among the strictly applicable candidates, one whose
        // formals another applicable candidate's formals widen to is less
        // specific. It still accepts the call; it cannot be chosen.
        let most_specific = candidates
            .iter()
            .filter(|(_, _, failure)| failure.is_none())
            .filter(|(_, formals, _)| {
                !candidates.iter().any(|(_, other_formals, other_failure)| {
                    other_failure.is_none() && dominates(other_formals, formals)
                })
            })
            .map(|(target, _, _)| *target)
            .collect::<BTreeSet<_>>();
        assert!(
            !most_specific.is_empty(),
            "an applicable finite primitive overload set has a maximal candidate"
        );
        if obligation.callee_reference() == self.root {
            for &(target, _, failure) in &candidates {
                let (verdict, reason) = if failure.is_some() {
                    (
                        ApplicabilityVerdict::Inapplicable,
                        Some(CallableRejectionReason::PrimitiveTypeMismatch),
                    )
                } else if most_specific.contains(&target) {
                    (ApplicabilityVerdict::Applicable, None)
                } else {
                    (ApplicabilityVerdict::LessSpecific, None)
                };
                let record = FactCallableCandidateApplicability::assessed(
                    target,
                    verdict,
                    reason,
                    answer.witnesses(),
                )
                .in_phase(Some(InvocationPhase::Strict))
                .with_failing_argument(failure);
                assert!(
                    self.callable_candidate_applicability
                        .insert(target, record)
                        .is_none(),
                    "one native Java candidate has one final applicability reason"
                );
            }
        }
        let excluded = candidates
            .iter()
            .filter(|(target, _, _)| !most_specific.contains(target))
            .map(|(target, _, _)| *target)
            .collect::<BTreeSet<_>>();
        if excluded.is_empty() {
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

    #[doc(hidden)]
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
    #[doc(hidden)]
    pub fn filter_java_reference_inapplicable(
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
        let mut excluded = BTreeMap::new();
        for (target, formals) in &candidates {
            for (ordinal, (&argument, formal)) in arguments.iter().zip(formals).enumerate() {
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
                    excluded.insert(*target, ordinal);
                    break;
                }
            }
        }
        if excluded.is_empty() || excluded.len() == answer.targets().len() {
            return Ok(Some(answer));
        }
        if obligation.callee_reference() == self.root {
            for (&target, &ordinal) in &excluded {
                let record = FactCallableCandidateApplicability::assessed(
                    target,
                    ApplicabilityVerdict::Inapplicable,
                    Some(CallableRejectionReason::ArgumentTypeMismatch),
                    answer.witnesses(),
                )
                .in_phase(Some(InvocationPhase::Strict))
                .with_failing_argument(Some(failing_argument(
                    ordinal,
                    ArgumentConversion::NoWideningReference,
                )));
                assert!(
                    self.callable_candidate_applicability
                        .insert(target, record)
                        .is_none(),
                    "one native Java candidate has one final applicability reason"
                );
            }
        }
        let (targets, witnesses, completion) = answer.into_parts();
        let targets = targets
            .iter()
            .copied()
            .filter(|target| !excluded.contains_key(target))
            .collect::<Vec<_>>();
        let witnesses = witnesses
            .into_vec()
            .into_iter()
            .filter(|witness| !excluded.contains_key(&witness.target()))
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
                        (
                            ResolutionCompletion::Complete,
                            [ResolutionSlotValue::TypeObject(ty, _)],
                        ) if ty.indirection() == 0 => Some(ty.identity()),
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

fn failing_argument(ordinal: usize, conversion: ArgumentConversion) -> FailingArgument {
    FailingArgument {
        ordinal: u32::try_from(ordinal).expect("a call's argument ordinal fits u32"),
        conversion,
    }
}

/// The first argument that no strict invocation conversion carries to its
/// primitive formal, or `None` when every argument converts.
fn java_primitive_failure(
    arguments: &[JavaPrimitive],
    formals: &[JavaPrimitive],
) -> Option<FailingArgument> {
    assert_eq!(
        arguments.len(),
        formals.len(),
        "a fixed-arity candidate has one formal per argument"
    );
    let ordinal = arguments
        .iter()
        .zip(formals)
        .position(|(&argument, &formal)| {
            !brokk_bifrost_jvm::java::primitives::primitive_converts(argument, formal)
        })?;
    let conversion = if brokk_bifrost_jvm::java::primitives::primitive_narrows(
        arguments[ordinal],
        formals[ordinal],
    ) {
        ArgumentConversion::NarrowingPrimitive
    } else {
        ArgumentConversion::NoPrimitiveConversion
    };
    Some(failing_argument(ordinal, conversion))
}
