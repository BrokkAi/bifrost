//! Go receiver eligibility uses exact source metadata and each lookup path's
//! runtime value. All memoized rows die with the selected query.

use super::super::fact_source::GoMemberDeclarationKind;
use super::*;

// Fixed-point re-entry may ask for the same package membership before a
// receiver slot closes. Retain only immutable input rows, with both identity
// and total-row caps, and drop them with this selected operation's read session.
#[derive(Default)]
pub(super) struct GoPackageMemberInputsMemo {
    authority: Option<SeedReadAuthority>,
    sources: HashMap<SemanticId, Option<Vec<SemanticId>>>,
    placements: HashMap<SemanticId, bool>,
    retained_rows: usize,
}

impl FactReadSession<'_> {
    fn prepare_go_package_inputs(&mut self) {
        // Like the context binder, keep inputs only for this request's current
        // selected scope and stage. A source without authority is never reused.
        let authority = self.lexical_source.selection_authority();
        if authority.is_none() || self.go_package_member_sources.authority != authority {
            self.go_package_member_sources = GoPackageMemberInputsMemo {
                authority,
                ..Default::default()
            };
        }
    }

    fn go_package_member_sources(
        &mut self,
        definitions: &[SemanticId],
    ) -> StoreResult<Option<Vec<Option<Vec<SemanticId>>>>> {
        self.prepare_go_package_inputs();
        if self.cancellation.is_cancelled() {
            return Ok(None);
        }
        let missing = definitions
            .iter()
            .copied()
            .filter(|definition| {
                !self
                    .go_package_member_sources
                    .sources
                    .contains_key(definition)
            })
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let mut fresh = HashMap::default();
        if !missing.is_empty() {
            let Some(rows) = self
                .typed_source
                .go_package_member_sources(&missing, self.cancellation)?
            else {
                return Ok(None);
            };
            assert_eq!(rows.len(), missing.len());
            for (definition, sources) in missing.into_iter().zip(rows) {
                let row_count = sources.as_ref().map_or(0, Vec::len);
                let memo = &mut self.go_package_member_sources;
                if memo.sources.len() < 1024 && memo.retained_rows + row_count <= 8192 {
                    memo.retained_rows += row_count;
                    memo.sources.insert(definition, sources);
                } else {
                    fresh.insert(definition, sources);
                }
            }
        }
        Ok((!self.cancellation.is_cancelled()).then(|| {
            definitions
                .iter()
                .map(|definition| {
                    self.go_package_member_sources
                        .sources
                        .get(definition)
                        .or_else(|| fresh.get(definition))
                        .expect("every requested membership was read")
                        .clone()
                })
                .collect()
        }))
    }

    fn go_source_placement_is_complete(
        &mut self,
        sources: &[SemanticId],
    ) -> StoreResult<Option<bool>> {
        self.prepare_go_package_inputs();
        if self.cancellation.is_cancelled() {
            return Ok(None);
        }
        let missing = sources
            .iter()
            .copied()
            .filter(|source| {
                !self
                    .go_package_member_sources
                    .placements
                    .contains_key(source)
            })
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let mut fresh = HashMap::default();
        if !missing.is_empty() {
            let Some(proofs) = self
                .typed_source
                .go_source_placement_proofs(&missing, self.cancellation)?
            else {
                return Ok(None);
            };
            assert_eq!(proofs.len(), missing.len());
            for (source, placed) in missing.into_iter().zip(proofs) {
                if self.go_package_member_sources.placements.len() < 8192 {
                    self.go_package_member_sources
                        .placements
                        .insert(source, placed);
                } else {
                    fresh.insert(source, placed);
                }
            }
        }
        Ok((!self.cancellation.is_cancelled()).then(|| {
            sources.iter().all(|source| {
                *self
                    .go_package_member_sources
                    .placements
                    .get(source)
                    .or_else(|| fresh.get(source))
                    .expect("every requested placement was read")
            })
        }))
    }

    pub(super) fn ensure_go_member_declarations(
        &mut self,
        definitions: &[SemanticId],
    ) -> StoreResult<bool> {
        let missing = definitions
            .iter()
            .copied()
            .filter(|definition| !self.go_member_declarations.contains_key(definition))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        if missing.is_empty() {
            return Ok(true);
        }
        let Some(rows) = self
            .typed_source
            .go_member_declarations(&missing, self.cancellation)?
        else {
            return Ok(false);
        };
        let mut found = HashMap::default();
        for row in rows {
            if self.cancellation.is_cancelled() {
                return Ok(false);
            }
            assert!(missing.binary_search(&row.definition).is_ok());
            assert!(found.insert(row.definition, row).is_none());
        }
        for definition in missing {
            if self.cancellation.is_cancelled() {
                return Ok(false);
            }
            self.go_member_declarations
                .insert(definition, found.remove(&definition));
        }
        Ok(true)
    }

    pub(super) fn go_receiver_eligible(
        &self,
        target: SemanticId,
        value: ResolutionSlotValue,
    ) -> bool {
        // The method set of *I is empty when I is an interface, even for
        // addressable runtime operands. No implicit dereference applies here.
        if matches!(
            self.go_member_declarations.get(&value.ty().identity()),
            Some(Some(declaration)) if matches!(declaration.kind, GoMemberDeclarationKind::Interface { .. })
        ) {
            return value.ty().indirection() == 0;
        }
        // Addressable values permit the implicit address operation. A pointer
        // value already has the receiver required by the method, including
        // when reached through an embedded pointer in a non-addressable root.
        // Unknown metadata retains the existing applicability incompleteness.
        self.go_method_receiver(target) != Some(true)
            || match value {
                ResolutionSlotValue::TypeObject(ty, _) => ty.indirection() == 1,
                ResolutionSlotValue::Runtime {
                    ty, addressable, ..
                } => ty.indirection() == 1 || addressable,
            }
    }

    fn go_method_receiver(&self, target: SemanticId) -> Option<bool> {
        self.go_member_declarations
            .get(&target)
            .and_then(Option::as_ref)
            .and_then(|declaration| match declaration.kind {
                GoMemberDeclarationKind::Method { pointer_receiver } => pointer_receiver,
                GoMemberDeclarationKind::Struct { .. }
                | GoMemberDeclarationKind::Interface { .. }
                | GoMemberDeclarationKind::Defined => None,
            })
    }

    pub(super) fn receiver_indirection_supported(
        &self,
        target: SemanticId,
        value: ResolutionSlotValue,
    ) -> bool {
        value.ty().indirection() == 0
            || matches!(value, ResolutionSlotValue::Runtime { ty, .. }
                if ty.has_only_reference_indirection())
            || (value.ty().indirection() == 1 && self.go_method_receiver(target).is_some())
    }
}

impl FactEvaluation<'_, '_> {
    /// A known method receiver admits a value receiver, or a pointer receiver
    /// through a pointer value or an addressable operand. Without those facts,
    /// preserve the declaration's applicability marker on the target binding.
    #[doc(hidden)]
    pub fn go_receiver_binding_completion(
        &mut self,
        candidate: SemanticId,
        call: &LoweredCallApplicabilityObligation,
        signature: &LoweredCallableSignatureProperty,
    ) -> StoreResult<Option<ResolutionCompletion>> {
        let Some(reasons) = self.call_applicability_reasons([signature.completion()])? else {
            return Ok(None);
        };
        if reasons.is_empty() {
            return Ok(Some(ResolutionCompletion::Complete));
        }
        let read = self
            .session
            .deferred_member_owners_for_definitions(&[candidate])?;
        let Some(owners) = self.accept_session_read(read) else {
            return Ok(None);
        };
        assert!(
            owners.len() <= 1,
            "one method has one deferred receiver owner"
        );
        if owners.is_empty() {
            // An invocation gap on a function literal is not a method-set
            // requirement. Its signature still constrains call-result typing.
            return Ok(Some(ResolutionCompletion::Complete));
        }
        // Member lookup records the actual selected receiver after promotion,
        // including pointer embeddings of a non-addressable outer value.
        if let Some(evidence) = self
            .receiver_target_evidence
            .get(&(call.callee_reference(), candidate))
            && !evidence.category_open
            && !evidence.values.is_empty()
        {
            let mut values = Vec::with_capacity(evidence.values.len());
            for &value in &evidence.values {
                if poll_cancelled(self.cancellation, &mut self.work) {
                    self.cancellation_observed = true;
                    return Ok(None);
                }
                values.push(value);
            }
            let mut definitions = vec![candidate];
            definitions.extend(values.iter().map(|value| value.ty().identity()));
            if !self.session.ensure_go_member_declarations(&definitions)? {
                self.cancellation_observed = true;
                return Ok(None);
            }
            if self.session.go_method_receiver(candidate).is_some()
                && values.iter().all(|&value| {
                    self.session
                        .receiver_indirection_supported(candidate, value)
                        && self.session.go_receiver_eligible(candidate, value)
                })
            {
                return Ok(Some(ResolutionCompletion::Complete));
            }
        }
        Ok(Some(ResolutionCompletion::incomplete(
            reasons
                .into_iter()
                .map(ResolutionIncompleteReason::UnsupportedSemantic),
        )))
    }

    /// A Go interface method declaration is a statically selected name, but
    /// invoking it can dispatch to implementations that are not in this
    /// binding. Preserve that boundary only on the implementation family;
    /// it cannot change which interface declaration the source name denotes.
    pub(super) fn retain_go_interface_dispatch_boundary(
        &mut self,
        answer: ResolutionAnswer,
        obligation: &LoweredCallApplicabilityObligation,
        states: &StateMap,
    ) -> StoreResult<Option<ResolutionAnswer>> {
        if obligation.callee_reference() == self.root {
            // Recompute the selected root's family evidence on each refinement.
            self.call_target_boundary = ResolutionCompletion::Complete;
        }
        if !self.session.lexical_source.supports_go_universe() || answer.targets().len() != 1 {
            return Ok(Some(answer));
        }
        let Some(receiver_slot) = obligation.receiver_slot() else {
            return Ok(Some(answer));
        };
        let Some(receiver) = states.get(&receiver_slot) else {
            return Ok(Some(answer));
        };
        let [value] = receiver.possible_values() else {
            return Ok(Some(answer));
        };
        let owner = value.ty().identity();
        if !self.session.ensure_go_member_declarations(&[owner])? {
            self.cancellation_observed = true;
            return Ok(None);
        }
        if !matches!(
            self.session
                .go_member_declarations
                .get(&owner)
                .and_then(Option::as_ref)
                .map(|declaration| &declaration.kind),
            Some(GoMemberDeclarationKind::Interface { .. })
        ) {
            return Ok(Some(answer));
        }

        let reason = canonical_service_reason(
            self.session,
            &*self.hierarchy,
            b"go-interface-call-dynamic-dispatch",
            &[
                CanonicalIdentityPart::identity(obligation.callee_reference()),
                CanonicalIdentityPart::identity(owner),
            ],
        )?;
        if obligation.callee_reference() == self.root {
            self.call_target_boundary = incomplete(reason);
        }
        Ok(Some(answer))
    }
}

/// One shortest embedding path, retained only during this selected query.
struct GoPromotionPath {
    value: ResolutionSlotValue,
    declared_type: ResolutionTypeRef,
    owners: Vec<SemanticId>,
    fields: Vec<SemanticId>,
    completion: ResolutionCompletion,
}

struct GoInterfaceMethodOrigin {
    method: super::super::fact_source::GoInterfaceMethod,
    owners: Vec<SemanticId>,
    completion: ResolutionCompletion,
}

struct GoInterfaceMethodLookup {
    methods: Vec<GoInterfaceMethodOrigin>,
    owner_inventory_complete: bool,
    absence: ResolutionCompletion,
}

pub(super) struct GoSelectedMember {
    pub(super) target: SemanticId,
    pub(super) kind: ResolutionMemberKind,
    pub(super) value: ResolutionSlotValue,
    pub(super) owners: Box<[SemanticId]>,
    pub(super) fields: Vec<SemanticId>,
    pub(super) completion: ResolutionCompletion,
}

pub(super) enum GoMemberSearchPreparation {
    Missing,
    Pending,
    Ready(GoMemberSearch),
    AwaitingHierarchy(BTreeSet<SemanticId>),
}

pub(super) struct GoMemberSearch {
    pub(super) members: Vec<GoSelectedMember>,
    pub(super) rejected: Vec<GoRejectedMember>,
    pub(super) completion: ResolutionCompletion,
}

pub(super) struct GoRejectedMember {
    pub(super) target: SemanticId,
    pub(super) kind: ResolutionMemberKind,
    pub(super) owners: Box<[SemanticId]>,
}

impl FactEvaluation<'_, '_> {
    /// Explicit interface declarations own their method names. Signature
    /// compatibility is a separate validity obligation: Go's type checker
    /// collects explicit methods first and checks overlapping signatures later.
    /// Keep that obligation incomplete when the selected types cannot prove it.
    pub(super) fn filter_go_interface_methods(
        &mut self,
        answer: ResolutionAnswer,
        signatures: &HashMap<
            SemanticId,
            InternedFactRow<SelectedTypedRow<LoweredCallableSignatureProperty>>,
        >,
        states: &StateMap,
    ) -> StoreResult<Option<ResolutionAnswer>> {
        if answer.targets().len() < 2 {
            return Ok(Some(answer));
        }
        let direct = answer
            .targets()
            .iter()
            .copied()
            .filter(|target| {
                self.member_owner_by_target
                    .get(target)
                    .and_then(Option::as_ref)
                    .is_some_and(|owner| {
                        owner.hierarchy_depth == 0
                            && matches!(
                    self.session.go_member_declarations.get(&owner.receiver),
                    Some(Some(row)) if matches!(row.kind, GoMemberDeclarationKind::Interface { .. }))
                    })
            })
            .collect::<Vec<_>>();
        if direct.is_empty() {
            return Ok(Some(answer));
        }
        let mut removed = HashSet::default();
        let mut unresolved = false;
        for &base in answer.targets() {
            let Some(Some(base_owner)) = self.member_owner_by_target.get(&base).cloned() else {
                continue;
            };
            if base_owner.hierarchy_depth == 0 {
                continue;
            }
            for &derived in &direct {
                if self.poll_cancelled() {
                    return Ok(None);
                }
                let Some(Some(derived_owner)) = self.member_owner_by_target.get(&derived) else {
                    continue;
                };
                if derived_owner.receiver != base_owner.receiver {
                    continue;
                }
                // Selecting the written declaration does not certify that
                // the interface's overlapping method signatures are valid.
                removed.insert(base);
                let (Some(base_signature), Some(derived_signature)) =
                    (signatures.get(&base), signatures.get(&derived))
                else {
                    unresolved = true;
                    continue;
                };
                let base_signature = base_signature.get(self.session).row().clone();
                let derived_signature = derived_signature.get(self.session).row().clone();
                if self.go_compare_signature_types(&base_signature, &derived_signature, states)?
                    == GoMethodSatisfaction::Satisfies
                {
                    break;
                }
                unresolved = true;
            }
        }
        let (targets, witnesses, mut completion) = answer.into_parts();
        if unresolved {
            completion = completion.combine(&incomplete(canonical_service_reason(
                self.session,
                &*self.hierarchy,
                b"go-interface-method-signature-unproven",
                &[CanonicalIdentityPart::identity(self.root)],
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

    pub(super) fn go_interface_origin_owners(
        &mut self,
        selection: &QualifiedOriginSelection,
    ) -> StoreResult<Option<BTreeSet<SemanticId>>> {
        let owners = selection
            .origins
            .iter()
            .filter(|origin| {
                origin.shape.namespace == ResolutionNamespace::Callable
                    && origin.shape.receiver_indirection == 0
            })
            .map(|origin| origin.owner)
            .collect::<Vec<_>>();
        if !self.session.ensure_go_member_declarations(&owners)? {
            self.cancellation_observed = true;
            return Ok(None);
        }
        Ok(Some(
            owners
                .into_iter()
                .filter(|owner| {
                    matches!(self.session.go_member_declarations.get(owner),
                Some(Some(row)) if matches!(row.kind, GoMemberDeclarationKind::Interface { .. }))
                })
                .collect(),
        ))
    }

    /// A selected Go named type admits member search even when no method has
    /// the requested spelling. Value selectors and calls share one shadowing
    /// space.
    pub(super) fn go_receiver_callable_lookups(
        &mut self,
        routes: &[&SourceSelectedQualifiedRoute],
        states: &StateMap,
    ) -> StoreResult<Option<HashMap<SemanticId, SemanticId>>> {
        let mut receivers = BTreeSet::new();
        for route in routes {
            if self.poll_cancelled() {
                return Ok(None);
            }
            if matches!(
                route.row().namespace(),
                ResolutionNamespace::Value | ResolutionNamespace::Callable
            ) && let Some(state) = states.get(&route.row().qualifier_slot())
            {
                for value in state.possible_values() {
                    if self.poll_cancelled() {
                        return Ok(None);
                    }
                    receivers.insert(value.ty().identity());
                }
            }
        }
        if !self
            .session
            .ensure_go_member_declarations(&receivers.into_iter().collect::<Vec<_>>())?
        {
            self.cancellation_observed = true;
            return Ok(None);
        }
        let mut requested = BTreeSet::new();
        let mut lookups = HashMap::default();
        for route in routes {
            if self.poll_cancelled() {
                return Ok(None);
            }
            if !matches!(
                route.row().namespace(),
                ResolutionNamespace::Value | ResolutionNamespace::Callable
            ) {
                continue;
            }
            let Some(state) = states.get(&route.row().qualifier_slot()) else {
                continue;
            };
            let go_receiver = state.possible_values().iter().any(|value| {
                match self
                    .session
                    .go_member_declarations
                    .get(&value.ty().identity())
                    .and_then(Option::as_ref)
                    .map(|declaration| &declaration.kind)
                {
                    Some(GoMemberDeclarationKind::Struct { .. }) => true,
                    Some(GoMemberDeclarationKind::Interface { .. }) => {
                        route.row().namespace() == ResolutionNamespace::Callable
                            && state.completion() == &ResolutionCompletion::Complete
                    }
                    Some(GoMemberDeclarationKind::Defined) => {
                        state.completion() == &ResolutionCompletion::Complete
                    }
                    Some(GoMemberDeclarationKind::Method { .. }) | None => false,
                }
            });
            if !go_receiver {
                continue;
            }
            let lookup = route.row().lookup();
            if route.row().namespace() == ResolutionNamespace::Callable {
                lookups.insert(lookup, lookup);
            } else if let Some(&callable) = self.session.go_callable_lookups.get(&lookup) {
                lookups.insert(lookup, callable);
            } else {
                requested.insert((route.fragment(), lookup));
            }
        }
        let requested = requested.into_iter().collect::<Vec<_>>();
        for chunk in requested.chunks(MAX_SOURCE_ROWS_PER_BATCH) {
            if !self.session.charge_scope_steps(chunk.len()) {
                self.cancellation_observed = true;
                return Ok(None);
            }
            let Some(rows) = self
                .session
                .typed_source
                .go_callable_lookups(chunk, self.cancellation)?
            else {
                self.cancellation_observed = true;
                return Ok(None);
            };
            for (lookup, callable) in rows {
                if self.poll_cancelled() {
                    return Ok(None);
                }
                assert!(chunk.iter().any(|(_, requested)| *requested == lookup));
                self.session.go_callable_lookups.insert(lookup, callable);
                lookups.insert(lookup, callable);
            }
        }
        Ok(Some(lookups))
    }

    pub(super) fn go_package_inventory_covers_placement_frontier(
        &mut self,
        completion: &ResolutionCompletion,
    ) -> StoreResult<Option<bool>> {
        let ResolutionCompletion::Incomplete(reasons) = completion else {
            return Ok(Some(false));
        };
        let mut evidence = BTreeMap::<SemanticId, (bool, bool)>::new();
        for reason in reasons.iter() {
            if self.poll_cancelled() {
                return Ok(None);
            }
            let ResolutionIncompleteReason::UnsupportedSemantic(reason) = reason else {
                return Ok(Some(false));
            };
            evidence.insert(*reason, (false, true));
        }
        if evidence.is_empty() {
            return Ok(Some(false));
        }
        let candidates = evidence.keys().copied().collect::<Vec<_>>();
        for chunk in candidates.chunks(MAX_TYPED_FACT_REQUESTS_PER_BATCH) {
            let read = self.session.gap_reason_provenance_for_reasons(chunk)?;
            let Some(rows) = self.accept_session_read(read) else {
                return Ok(None);
            };
            for row in rows {
                if self.poll_cancelled() {
                    return Ok(None);
                }
                let row = *row.get(self.session);
                let provenance_is_package_placement = row.origin()
                    == LoweringGapOrigin::Extracted(
                        ResolutionGapKind::UnsupportedPlacementBoundary,
                    )
                    && match self.go_placement_reason_is_proven(row)? {
                        Some(proven) => proven,
                        None => return Ok(None),
                    };
                let reason = evidence
                    .get_mut(&row.reason())
                    .expect("gap provenance belongs to the requested reason batch");
                reason.0 = true;
                reason.1 &= provenance_is_package_placement;
            }
        }
        Ok(Some(evidence.values().all(|(seen, package_placement)| {
            *seen && *package_placement
        })))
    }

    /// Search fields and methods at the same depth before testing callability.
    /// Missing means the receiver has no selected Go type metadata. Cancellation
    /// is also reflected in the evaluation, as at the other selected readers.
    /// Unclosed interface roots are prerequisites, not an unavailable method set.
    pub(super) fn go_receiver_members(
        &mut self,
        reference: SemanticId,
        lookup: SemanticId,
        receiver: ResolutionSlotValue,
        rows: &[LoweredDeferredMemberOwner],
        states: &StateMap,
    ) -> StoreResult<GoMemberSearchPreparation> {
        let root = receiver.ty().identity();
        if !self.session.ensure_go_member_declarations(&[root])? {
            self.cancellation_observed = true;
            return Ok(GoMemberSearchPreparation::Missing);
        }
        match self
            .session
            .go_member_declarations
            .get(&root)
            .and_then(Option::as_ref)
            .map(|declaration| &declaration.kind)
        {
            Some(
                GoMemberDeclarationKind::Struct { .. }
                | GoMemberDeclarationKind::Interface { .. }
                | GoMemberDeclarationKind::Defined,
            ) => {}
            // Defined is known Go metadata, even when it contributes no fields.
            // Only unavailable metadata falls back to name-first lookup.
            None => return Ok(GoMemberSearchPreparation::Missing),
            Some(GoMemberDeclarationKind::Method { .. }) => {
                return Ok(GoMemberSearchPreparation::Missing);
            }
        }
        let mut level = vec![GoPromotionPath {
            value: receiver,
            declared_type: receiver.ty(),
            owners: vec![root],
            fields: Vec::new(),
            completion: ResolutionCompletion::Complete,
        }];
        let mut completion = ResolutionCompletion::Complete;
        while !level.is_empty() {
            let owners = level
                .iter()
                .map(|path| path.value.ty().identity())
                .collect::<Vec<_>>();
            if !self.session.ensure_go_member_declarations(&owners)? {
                self.cancellation_observed = true;
                return Ok(GoMemberSearchPreparation::Missing);
            }
            // The promotion walk already owns this depth's declarations. Close
            // its interface roots together before flattening any method set.
            let roots = owners.iter().copied().filter(|owner| {
                matches!(self.session.go_member_declarations.get(owner),
                    Some(Some(declaration)) if matches!(declaration.kind, GoMemberDeclarationKind::Interface { .. }))
                    && !self.hierarchy.closure_contains(HierarchyOwnerKey {
                        owner: *owner,
                        policy: self.hierarchy_policy,
                    })
            }).collect::<BTreeSet<_>>();
            if !roots.is_empty() {
                return Ok(GoMemberSearchPreparation::AwaitingHierarchy(roots));
            }
            let mut selected = Vec::new();
            let mut expansions = Vec::new();
            let mut unavailable = false;
            for mut path in level {
                if self.poll_cancelled() || !self.session.charge_scope_steps(1) {
                    self.cancellation_observed = true;
                    return Ok(GoMemberSearchPreparation::Missing);
                }
                let owner = path.value.ty().identity();
                let mut fields = Vec::new();
                let mut interface_methods = Vec::new();
                let mut surfaces = vec![owner];
                let mut seen = HashSet::default();
                while let Some(surface) = surfaces.pop() {
                    // This path already charged its owner. Only an underlying
                    // definition adds another surface expansion.
                    if self.poll_cancelled()
                        || (surface != owner && !self.session.charge_scope_steps(1))
                    {
                        self.cancellation_observed = true;
                        return Ok(GoMemberSearchPreparation::Missing);
                    }
                    if !seen.insert(surface) {
                        continue;
                    }
                    if !self.session.ensure_go_member_declarations(&[surface])? {
                        self.cancellation_observed = true;
                        return Ok(GoMemberSearchPreparation::Missing);
                    }
                    let metadata = self
                        .session
                        .go_member_declarations
                        .get(&surface)
                        .cloned()
                        .flatten();
                    match metadata.map(|declaration| declaration.kind) {
                        Some(GoMemberDeclarationKind::Struct { fields: declared }) => {
                            fields.extend(declared)
                        }
                        Some(GoMemberDeclarationKind::Interface { .. }) => {
                            let roots = BTreeSet::from([surface]);
                            if !self.hierarchy_owner_roots_closed(&roots) {
                                return Ok(GoMemberSearchPreparation::AwaitingHierarchy(roots));
                            }
                            if matches!(path.value, ResolutionSlotValue::TypeObject(_, _)) {
                                path.value = ResolutionSlotValue::type_object(path.declared_type);
                            }
                            let Some(methods) =
                                self.go_interface_methods_for_lookup(surface, lookup, path.value)?
                            else {
                                return Ok(GoMemberSearchPreparation::Missing);
                            };
                            unavailable |= !methods.owner_inventory_complete;
                            completion = completion.combine(&methods.absence);
                            if surface != owner {
                                let ty =
                                    ResolutionTypeRef::new(surface, path.value.ty().indirection());
                                path.value = match path.value {
                                    ResolutionSlotValue::TypeObject(_, _) => {
                                        ResolutionSlotValue::type_object(ty)
                                    }
                                    ResolutionSlotValue::Runtime { addressable, .. } => {
                                        ResolutionSlotValue::runtime(ty, addressable)
                                    }
                                };
                            }
                            interface_methods.extend(methods.methods);
                        }
                        Some(GoMemberDeclarationKind::Defined) => {
                            let Some(underlying) =
                                self.go_underlying_type_objects(surface, states)?
                            else {
                                return Ok(GoMemberSearchPreparation::Missing);
                            };
                            if underlying.pending {
                                return Ok(GoMemberSearchPreparation::Pending);
                            }
                            completion = completion.combine(&underlying.completion);
                            path.completion = path.completion.combine(&underlying.completion);
                            surfaces.extend(underlying.objects.into_iter().map(|ty| ty.identity()));
                        }
                        // Complete underlying type objects may be intrinsic
                        // scalars or structural function/container types. They
                        // contribute no named fields or interface methods.
                        None => {}
                        Some(GoMemberDeclarationKind::Method { .. }) => {
                            unavailable = true;
                        }
                    }
                }
                if crate::analyzer::semantic::languages::language_knowledge(Language::Go)
                    .is_some_and(|support| support.call_may_apply_value())
                    && path.fields.is_empty()
                    && matches!(receiver, ResolutionSlotValue::Runtime { .. })
                {
                    let mut direct_fields = fields
                        .iter()
                        .filter(|field| field.callable_lookup == lookup);
                    if let Some(field) = direct_fields.next()
                        && direct_fields.next().is_none()
                        && let (Some(target), Some(_value_type)) = (field.field, field.value_type)
                    {
                        // The receiver identity selected this exact struct,
                        // whose direct field shadows every promoted member.
                        // Its ordinary binding projection carries the field's
                        // declared type; unresolved methods on other owners
                        // cannot make that receiver route incomplete.
                        return Ok(GoMemberSearchPreparation::Ready(GoMemberSearch {
                            members: vec![GoSelectedMember {
                                target,
                                kind: ResolutionMemberKind::Field,
                                value: path.value,
                                owners: path.owners.into_boxed_slice(),
                                fields: path.fields,
                                completion: path.completion.clone(),
                            }],
                            rejected: Vec::new(),
                            completion: path.completion,
                        }));
                    }
                }
                // Method ownership belongs to the selected package, not to
                // the file that declares the receiver type. The same keyed
                // source proof admits a sibling's method even when its type
                // frontier has no file context. Package membership comes from
                // the existing source rows, including generic receivers.
                // With no method candidates, there is no package proof to ask
                // for. Keep such requests empty, including profile-free literal
                // field and remote-absence lookups.
                let owner_requests = rows
                    .iter()
                    .filter(|row| row.kind() == ResolutionMemberKind::Method)
                    .take(1)
                    .map(|_| owner)
                    .collect::<Vec<_>>();
                let Some(mut packages) = self.session.go_package_member_sources(&owner_requests)?
                else {
                    self.cancellation_observed = true;
                    return Ok(GoMemberSearchPreparation::Missing);
                };
                assert_eq!(packages.len(), owner_requests.len());
                let owner_sources = packages.pop().flatten();
                let method_rows = rows
                    .iter()
                    .filter(|row| {
                        row.kind() == ResolutionMemberKind::Method
                            && owner_sources.as_ref().is_none_or(|sources| {
                                sources
                                    .iter()
                                    .any(|source| source.ordinal() == row.definition().ordinal())
                            })
                    })
                    .collect::<Vec<_>>();
                let candidates = method_rows
                    .iter()
                    .map(|row| (row.definition(), row.owner_frontier()))
                    .collect::<Vec<_>>();
                let Some(proofs) = self.session.typed_source.deferred_member_owner_proofs(
                    &[owner],
                    &candidates,
                    self.session.cancellation,
                )?
                else {
                    self.cancellation_observed = true;
                    return Ok(GoMemberSearchPreparation::Missing);
                };
                assert_eq!(
                    proofs.len(),
                    candidates.len(),
                    "one ownership proof per method"
                );
                // Named receiver ownership does not close participation of
                // saved siblings. Prove each package member's placement using
                // the same selected role reader as placement-gap discharge.
                let definitions = candidates
                    .iter()
                    .zip(&proofs)
                    .filter(|(_, proof)| {
                        **proof == super::super::fact_source::DeferredMemberOwnerProof::Matches
                    })
                    .map(|(candidate, _)| candidate.0)
                    .collect::<Vec<_>>();
                let Some(packages) = self.session.go_package_member_sources(&definitions)? else {
                    self.cancellation_observed = true;
                    return Ok(GoMemberSearchPreparation::Missing);
                };
                assert_eq!(packages.len(), definitions.len());
                let mut complete_method_packages = HashSet::default();
                for (definition, sources) in definitions.iter().zip(packages) {
                    let Some(sources) = sources else {
                        continue;
                    };
                    let Some(placed) = self.session.go_source_placement_is_complete(&sources)?
                    else {
                        self.cancellation_observed = true;
                        return Ok(GoMemberSearchPreparation::Missing);
                    };
                    if !sources.is_empty() && placed {
                        complete_method_packages.insert(*definition);
                    }
                }
                // Distinct paths intentionally produce distinct candidates,
                // including paths that end at the very same declaration.
                for (row, proof) in method_rows.into_iter().zip(proofs) {
                    if self.poll_cancelled() || !self.session.charge_scope_steps(1) {
                        self.cancellation_observed = true;
                        return Ok(GoMemberSearchPreparation::Missing);
                    }
                    use super::super::fact_source::DeferredMemberOwnerProof;
                    let owner_completion = match proof {
                        DeferredMemberOwnerProof::Matches
                            if complete_method_packages.contains(&row.definition()) =>
                        {
                            ResolutionCompletion::Complete
                        }
                        DeferredMemberOwnerProof::DoesNotMatch => continue,
                        DeferredMemberOwnerProof::Matches | DeferredMemberOwnerProof::Unknown => {
                            if !self.charge_owner_expansion(row.owner_frontier()) {
                                self.cancellation_observed = true;
                                return Ok(GoMemberSearchPreparation::Missing);
                            }
                            self.demand_slot(row.owner_frontier());
                            let Some(state) = states.get(&row.owner_frontier()) else {
                                return Ok(GoMemberSearchPreparation::Pending);
                            };
                            let owner_matches = state.possible_values().iter().any(|value| {
                                matches!(value, ResolutionSlotValue::TypeObject(ty, _)
                                    if ty.indirection() <= 1 && ty.identity() == owner)
                            });
                            if !owner_matches {
                                completion = completion.combine(state.completion());
                                continue;
                            }
                            state.completion().clone()
                        }
                    };
                    completion = completion.combine(&owner_completion);
                    selected.push(GoSelectedMember {
                        target: row.definition(),
                        kind: row.kind(),
                        value: path.value,
                        owners: path.owners.clone().into_boxed_slice(),
                        fields: path.fields.clone(),
                        completion: path.completion.combine(&owner_completion),
                    });
                }
                for origin in &interface_methods {
                    let method = &origin.method;
                    if method.callable_lookup != lookup {
                        continue;
                    }
                    if let Some(target) = method.definition {
                        selected.push(GoSelectedMember {
                            target,
                            kind: ResolutionMemberKind::Method,
                            value: path.value,
                            owners: path.owners[..path.owners.len() - 1]
                                .iter()
                                .copied()
                                .chain(origin.owners.iter().copied())
                                .collect(),
                            fields: path.fields.clone(),
                            completion: path.completion.combine(&origin.completion),
                        });
                    } else {
                        unavailable = true;
                    }
                }
                for field in &fields {
                    if self.poll_cancelled() || !self.session.charge_scope_steps(1) {
                        self.cancellation_observed = true;
                        return Ok(GoMemberSearchPreparation::Missing);
                    }
                    if field.callable_lookup == lookup {
                        if let Some(target) = field.field {
                            selected.push(GoSelectedMember {
                                target,
                                kind: ResolutionMemberKind::Field,
                                value: path.value,
                                owners: path.owners.clone().into_boxed_slice(),
                                fields: path.fields.clone(),
                                completion: path.completion.clone(),
                            });
                        } else {
                            unavailable = true;
                        }
                    }
                }
                expansions.push((path, fields));
            }
            if unavailable {
                completion = completion.combine(&ResolutionCompletion::incomplete([
                    ResolutionIncompleteReason::UnsupportedSemantic(canonical_service_reason(
                        self.session,
                        &*self.hierarchy,
                        b"go-promotion-frontier-unavailable",
                        &[
                            CanonicalIdentityPart::identity(reference),
                            CanonicalIdentityPart::identity(lookup),
                        ],
                    )?),
                ]));
            }
            if matches!(receiver, ResolutionSlotValue::TypeObject(_, _))
                && selected
                    .iter()
                    .any(|member| member.kind != ResolutionMemberKind::Method)
            {
                return Ok(GoMemberSearchPreparation::Ready(GoMemberSearch {
                    members: Vec::new(),
                    rejected: Vec::new(),
                    completion,
                }));
            }
            // Preserve the hierarchy's declaring owners before applying the
            // existing interface precedence and signature validity rules.
            if selected.len() > 1
                && selected.iter().all(|member| {
                    matches!(member.owners.first().and_then(|root|
                        self.session.go_member_declarations.get(root)),
                        Some(Some(row)) if matches!(row.kind, GoMemberDeclarationKind::Interface { .. }))
                })
            {
                let definitions = selected.iter().map(|member| member.target).collect::<Vec<_>>();
                for member in &selected {
                    self.record_member_owner(member.target, member.kind, member.owners.clone(), false);
                }
                let read = self.session.signatures_for_definitions(&definitions)?;
                let Some(signatures) = self.accept_session_read(read) else {
                    return Ok(GoMemberSearchPreparation::Missing);
                };
                let signatures = signatures.into_iter().map(|row| (row.get(self.session).row().definition(), row)).collect();
                let Some(answer) = self.filter_go_interface_methods(
                    ResolutionAnswer::new(definitions, Vec::new(), completion),
                    &signatures, states,
                )? else {
                    return Ok(GoMemberSearchPreparation::Missing);
                };
                selected.retain(|member| answer.targets().contains(&member.target));
                completion = answer.completion().clone();
            }
            for member in &selected {
                completion = completion.combine(&member.completion);
            }
            if selected.len() > 1 {
                let precedence = ResolutionCompletion::incomplete([
                    ResolutionIncompleteReason::InconsistentPrecedence(reference),
                ]);
                completion = completion.combine(&precedence);
                return Ok(GoMemberSearchPreparation::Ready(GoMemberSearch {
                    // Preserve every promotion witness while precedence stays
                    // ambiguous. Consumers may report candidates but cannot
                    // select a unique callable target.
                    members: selected,
                    rejected: Vec::new(),
                    completion,
                }));
            }
            if let Some(member) = selected.pop() {
                if member.kind == ResolutionMemberKind::Method
                    && !self
                        .session
                        .ensure_go_member_declarations(&[member.target])?
                {
                    self.cancellation_observed = true;
                    return Ok(GoMemberSearchPreparation::Missing);
                }
                // A field still shadows deeper methods, but selecting a field
                // on a type does not form a Go method expression.
                if matches!(receiver, ResolutionSlotValue::TypeObject(_, _))
                    && member.kind != ResolutionMemberKind::Method
                {
                    return Ok(GoMemberSearchPreparation::Ready(GoMemberSearch {
                        members: Vec::new(),
                        rejected: Vec::new(),
                        completion,
                    }));
                }
                if member.kind == ResolutionMemberKind::Method
                    && !self
                        .session
                        .receiver_indirection_supported(member.target, member.value)
                {
                    completion = completion.combine(&ResolutionCompletion::incomplete([
                        ResolutionIncompleteReason::UnsupportedSemantic(canonical_service_reason(
                            self.session,
                            &*self.hierarchy,
                            b"go-pointer-method-requires-addressable-receiver",
                            &[
                                CanonicalIdentityPart::identity(reference),
                                CanonicalIdentityPart::identity(member.target),
                            ],
                        )?),
                    ]));
                    return Ok(GoMemberSearchPreparation::Ready(GoMemberSearch {
                        members: Vec::new(),
                        rejected: Vec::new(),
                        completion,
                    }));
                }
                if member.kind == ResolutionMemberKind::Method
                    && !self
                        .session
                        .go_receiver_eligible(member.target, member.value)
                {
                    completion = completion.combine(&ResolutionCompletion::incomplete([
                        ResolutionIncompleteReason::UnsupportedSemantic(canonical_service_reason(
                            self.session,
                            &*self.hierarchy,
                            b"go-pointer-method-requires-addressable-receiver",
                            &[
                                CanonicalIdentityPart::identity(reference),
                                CanonicalIdentityPart::identity(member.target),
                            ],
                        )?),
                    ]));
                    return Ok(GoMemberSearchPreparation::Ready(GoMemberSearch {
                        members: Vec::new(),
                        rejected: vec![GoRejectedMember {
                            target: member.target,
                            kind: member.kind,
                            owners: member.owners,
                        }],
                        completion,
                    }));
                }
                return Ok(GoMemberSearchPreparation::Ready(GoMemberSearch {
                    members: vec![member],
                    rejected: Vec::new(),
                    completion,
                }));
            }
            if unavailable {
                break;
            }
            let mut next = Vec::new();
            for (path, fields) in expansions {
                for field in fields {
                    if !field.embedded {
                        continue;
                    }
                    if self.poll_cancelled() || !self.session.charge_scope_steps(1) {
                        self.cancellation_observed = true;
                        return Ok(GoMemberSearchPreparation::Missing);
                    }
                    let (Some(field_id), Some(slot)) = (field.field, field.value_type) else {
                        unavailable = true;
                        continue;
                    };
                    if !self.charge_owner_expansion(path.value.ty().identity()) {
                        self.cancellation_observed = true;
                        return Ok(GoMemberSearchPreparation::Missing);
                    }
                    self.demand_slot(slot);
                    let Some(state) = states.get(&slot) else {
                        // This snapshot predates the slot demand above. The
                        // fixed-point pass will revisit the frontier after
                        // materializing the embedded field's type state.
                        return Ok(GoMemberSearchPreparation::Pending);
                    };
                    // This slot models the embedded field's value flow, while
                    // selector promotion needs only its declared type. Keep
                    // every unrelated incompleteness but do not let that
                    // field's own memory blocker prevent type-based lookup.
                    let state_completion =
                        completion_without_unsupported_semantic(state.completion(), field_id);
                    completion = completion.combine(&state_completion);
                    if state.possible_values().is_empty() {
                        let Some(inventory_closes_frontier) =
                            self.go_package_inventory_covers_placement_frontier(&state_completion)?
                        else {
                            return Ok(GoMemberSearchPreparation::Missing);
                        };
                        unavailable |= !inventory_closes_frontier;
                    }
                    for value in state.possible_values() {
                        if self.poll_cancelled() || !self.session.charge_scope_steps(1) {
                            self.cancellation_observed = true;
                            return Ok(GoMemberSearchPreparation::Missing);
                        }
                        // A known cycle cannot add a shorter selector path.
                        // Prune this path without hiding its sibling branches.
                        if path.owners.contains(&value.ty().identity()) {
                            continue;
                        }
                        let mut owners = path.owners.clone();
                        owners.push(value.ty().identity());
                        let mut fields = path.fields.clone();
                        fields.push(field_id);
                        next.push(GoPromotionPath {
                            declared_type: value.ty(),
                            value: match path.value {
                                ResolutionSlotValue::TypeObject(parent, _) => {
                                    ResolutionSlotValue::type_object(ResolutionTypeRef::new(
                                        value.ty().identity(),
                                        parent.indirection().max(value.ty().indirection()),
                                    ))
                                }
                                ResolutionSlotValue::Runtime { .. } => {
                                    ResolutionSlotValue::runtime(
                                        value.ty(),
                                        path.value.addressable() == Some(true)
                                            || path.value.ty().indirection() == 1,
                                    )
                                }
                            },
                            owners,
                            fields,
                            completion: path.completion.combine(&state_completion),
                        });
                    }
                }
            }
            if unavailable {
                completion = completion.combine(&ResolutionCompletion::incomplete([
                    ResolutionIncompleteReason::UnsupportedSemantic(canonical_service_reason(
                        self.session,
                        &*self.hierarchy,
                        b"go-promotion-frontier-unavailable",
                        &[
                            CanonicalIdentityPart::identity(reference),
                            CanonicalIdentityPart::identity(lookup),
                        ],
                    )?),
                ]));
                break;
            }
            level = next;
        }
        Ok(GoMemberSearchPreparation::Ready(GoMemberSearch {
            members: Vec::new(),
            rejected: Vec::new(),
            completion,
        }))
    }
}

/// Satisfaction is query evidence, never a persisted concrete/interface pair.
#[derive(Debug, Clone, PartialEq, Eq)]
#[doc(hidden)]
pub enum GoMethodSatisfaction {
    Satisfies,
    DoesNotSatisfy,
    Inconclusive(&'static str),
}

#[derive(Debug, Clone)]
pub(crate) struct GoInterfaceSatisfaction {
    pub(crate) owner: SemanticId,
    pub(crate) methods: Vec<SemanticId>,
    pub(crate) outcome: GoMethodSatisfaction,
}

const GO_SIGNATURE_UNKNOWN: &str = "unsupported structural type in the required signature";

impl FactResolutionOperation<'_> {
    pub(crate) fn go_method_satisfaction(
        &mut self,
        target: SemanticId,
        lookup: SemanticId,
        interfaces: &[SemanticId],
        mut method_identity: impl FnMut(SemanticId) -> StoreResult<Option<(String, i64)>>,
    ) -> StoreResult<Vec<GoInterfaceSatisfaction>> {
        let mut provider = self
            .demand_provider
            .take()
            .expect("Go method family requires its installed demand provider");
        // A declaration is the seed for this type query. Its binding is known;
        // the ordinary fixed point owns all receiver/signature slot demands.
        let mut evaluation = FactEvaluation::from_lexical_answer(
            &mut self.session,
            &mut self.hierarchy,
            target,
            ResolutionAnswer::new([target], [], ResolutionCompletion::Complete),
        )
        .with_candidate_paths(&mut self.candidate_paths);
        evaluation.forward_candidate_artifacts = Some(&mut self.forward_candidate_artifacts);
        let mut closed_interfaces = Vec::new();
        let mut unclosed_interfaces = Vec::new();
        for &owner in interfaces {
            if evaluation
                .close_hierarchy_owner_roots(&BTreeSet::from([owner]), provider.as_mut())?
            {
                closed_interfaces.push(owner);
            } else {
                unclosed_interfaces.push(GoInterfaceSatisfaction {
                    owner,
                    methods: Vec::new(),
                    outcome: GoMethodSatisfaction::Inconclusive(
                        "interface method-set endpoint closure is incomplete or cancelled",
                    ),
                });
            }
        }
        let mut result = Vec::new();
        // Inventory discovery adds roots; each subsequent round closes their
        // endpoints through the same demand provider used by reverse confirmation.
        // Only a stable, closed round is inspected for signature comparison.
        let provider = std::cell::RefCell::new(provider);
        let answer = evaluation.run_with_rounds_and_inspection(
            |evaluation, answers, states| {
                evaluation.evaluate_round_with_dependencies(
                    answers,
                    states,
                    provider.borrow_mut().as_mut(),
                )
            },
            |evaluation, states| {
                result = evaluation.go_check_method_interfaces(
                    target,
                    lookup,
                    &closed_interfaces,
                    states,
                    &mut method_identity,
                    provider.borrow_mut().as_mut(),
                )?;
                Ok(())
            },
        );
        self.demand_provider = Some(provider.into_inner());
        answer?;
        if evaluation.cancellation_observed
            || evaluation.cancellation.is_cancelled()
            || evaluation.session.resolution_stopped()
        {
            return Ok(interfaces
                .iter()
                .map(|&owner| GoInterfaceSatisfaction {
                    owner,
                    methods: result
                        .iter()
                        .find(|interface| interface.owner == owner)
                        .map(|interface| interface.methods.clone())
                        .unwrap_or_default(),
                    outcome: GoMethodSatisfaction::Inconclusive(
                        "method-family endpoint closure was cancelled or exhausted its budget",
                    ),
                })
                .collect());
        }
        result.extend(unclosed_interfaces);
        Ok(result)
    }
}

impl FactEvaluation<'_, '_> {
    // Flatten a selected interface's method set, using the shared hierarchy
    // closure and edge authority. This also serves struct-embedded interfaces.
    fn go_interface_method_set(
        &mut self,
        root: SemanticId,
    ) -> StoreResult<Option<(Vec<GoInterfaceMethodOrigin>, bool)>> {
        let Some((paths, complete)) = self.go_interface_owner_paths(root)? else {
            return Ok(None);
        };
        Ok(self
            .go_interface_declared_methods(&paths)
            .map(|methods| (methods, complete)))
    }

    fn go_interface_declared_methods(
        &mut self,
        paths: &[Vec<SemanticId>],
    ) -> Option<Vec<GoInterfaceMethodOrigin>> {
        let mut methods = Vec::new();
        for owners in paths {
            if self.poll_cancelled() {
                return None;
            }
            let owner = *owners.last().expect("interface route has its owner");
            if let Some(Some(row)) = self.session.go_member_declarations.get(&owner)
                && let GoMemberDeclarationKind::Interface { methods: declared } = &row.kind
            {
                methods.extend(
                    declared
                        .iter()
                        .cloned()
                        .map(|method| GoInterfaceMethodOrigin {
                            method,
                            owners: owners.clone(),
                            completion: ResolutionCompletion::Complete,
                        }),
                );
            }
        }
        methods.sort_unstable_by_key(|origin| {
            (origin.method.callable_lookup, origin.method.definition)
        });
        methods.dedup_by(|a, b| a.method == b.method);
        Some(methods)
    }

    fn go_interface_methods_for_lookup(
        &mut self,
        root: SemanticId,
        lookup: SemanticId,
        receiver: ResolutionSlotValue,
    ) -> StoreResult<Option<GoInterfaceMethodLookup>> {
        let Some((paths, owner_inventory_complete)) = self.go_interface_owner_paths(root)? else {
            return Ok(None);
        };
        let Some(mut methods) = self.go_interface_declared_methods(&paths) else {
            return Ok(None);
        };
        methods.retain(|origin| origin.method.callable_lookup == lookup);
        let declared = methods
            .iter()
            .filter_map(|origin| origin.method.definition)
            .collect::<HashSet<_>>();
        let shape = self.hierarchy_shape(
            lookup,
            ResolutionNamespace::Callable,
            QualifierCategory::of(receiver),
            i64::from(receiver.ty().indirection()),
        );
        let keys = paths
            .iter()
            .map(|owners| HierarchyNodeKey {
                shape,
                owner: *owners.last().expect("interface route has its owner"),
            })
            .collect::<Vec<_>>();
        if !self.ensure_hierarchy_local_nodes(&keys)? {
            return Ok(None);
        }
        let mut absence = ResolutionCompletion::Complete;
        for (owners, key) in paths.into_iter().zip(keys) {
            if self.poll_cancelled() {
                return Ok(None);
            }
            let node = &self.hierarchy.local_nodes[&key];
            let evidence = {
                let cancellation = self.cancellation;
                let work = &mut self.work;
                self.hierarchy
                    .evidence
                    .flatten(&node.evidence, u32::MAX, &mut || {
                        poll_cancelled(cancellation, work)
                    })
            };
            let Some(evidence) = evidence else {
                self.cancellation_observed = true;
                return Ok(None);
            };
            // declared metadata proves a positive selection; hierarchy-only
            // recovery and absence inherit the node's inventory evidence.
            absence = absence.combine(&evidence);
            methods.extend(
                node.direct_definitions
                    .iter()
                    .filter(|definition| !declared.contains(definition))
                    .map(|&definition| GoInterfaceMethodOrigin {
                        method: super::super::fact_source::GoInterfaceMethod {
                            callable_lookup: lookup,
                            definition: Some(definition),
                        },
                        owners: owners.clone(),
                        completion: evidence.clone(),
                    }),
            );
        }
        methods.sort_unstable_by_key(|origin| {
            (origin.method.callable_lookup, origin.method.definition)
        });
        methods.dedup_by(|a, b| a.method == b.method);
        if !methods.is_empty() {
            absence = ResolutionCompletion::Complete;
        }
        Ok(Some(GoInterfaceMethodLookup {
            methods,
            owner_inventory_complete,
            absence,
        }))
    }

    fn go_interface_owner_paths(
        &mut self,
        root: SemanticId,
    ) -> StoreResult<Option<(Vec<Vec<SemanticId>>, bool)>> {
        if !self.hierarchy_owner_roots_closed(&BTreeSet::from([root])) {
            return Ok(None);
        }
        let mut pending = vec![vec![root]];
        let mut seen = HashSet::default();
        let mut paths = Vec::new();
        let mut complete = true;
        while let Some(owners) = pending.pop() {
            let owner = *owners.last().expect("interface route has its owner");
            if self.poll_cancelled() || !self.session.charge_scope_steps(1) {
                return Ok(None);
            }
            if !seen.insert(owner) {
                continue;
            }
            if !self.session.ensure_go_member_declarations(&[owner])? {
                return Ok(None);
            }
            complete &= matches!(
                self.session.go_member_declarations.get(&owner),
                Some(Some(row)) if matches!(row.kind, GoMemberDeclarationKind::Interface { .. })
            );
            let node = self
                .hierarchy
                .edge_nodes
                .get(&HierarchyOwnerKey {
                    owner,
                    policy: self.hierarchy_policy,
                })
                .expect("shared hierarchy closure publishes each owner");
            complete &= node.indexed
                && node.hierarchy_inventory_complete
                && matches!(node.evidence, HierarchyEvidence::Complete);
            for edge in &node.edges {
                complete &= matches!(edge.residual_evidence, HierarchyEvidence::Complete);
                pending.extend(edge.targets.iter().map(|target| {
                    let mut path = owners.clone();
                    path.push(*target);
                    path
                }));
            }
            paths.push(owners);
        }
        Ok(Some((paths, complete)))
    }

    fn go_signature_satisfaction(
        &mut self,
        candidate: SemanticId,
        required: SemanticId,
        states: &StateMap,
        method_identity: &mut impl FnMut(SemanticId) -> StoreResult<Option<(String, i64)>>,
    ) -> StoreResult<GoMethodSatisfaction> {
        use GoMethodSatisfaction::*;
        let Some((required_name, required_package)) = method_identity(required)? else {
            return Ok(Inconclusive("required method identity is unavailable"));
        };
        let Some((candidate_name, candidate_package)) = method_identity(candidate)? else {
            return Ok(Inconclusive("candidate method identity is unavailable"));
        };
        if candidate_name != required_name
            || (!brokk_bifrost_go::declarations::go_identifier_is_exported(&required_name)
                && required_package != candidate_package)
        {
            return Ok(DoesNotSatisfy);
        }
        let read = self
            .session
            .signatures_for_definitions(&[candidate, required])?;
        let Some(rows) = self.accept_session_read(read) else {
            return Ok(Inconclusive("method signature read was cancelled"));
        };
        let signatures = rows
            .into_iter()
            .map(|row| {
                let signature = row.get(self.session).row().clone();
                (signature.definition(), signature)
            })
            .collect::<HashMap<_, _>>();
        let (Some(candidate_signature), Some(required_signature)) =
            (signatures.get(&candidate), signatures.get(&required))
        else {
            return Ok(Inconclusive("method signature is unavailable"));
        };
        self.go_compare_signature_types(candidate_signature, required_signature, states)
    }

    fn go_compare_signature_types(
        &mut self,
        candidate_signature: &LoweredCallableSignatureProperty,
        required_signature: &LoweredCallableSignatureProperty,
        states: &StateMap,
    ) -> StoreResult<GoMethodSatisfaction> {
        use GoMethodSatisfaction::*;
        if candidate_signature.parameters().len() != required_signature.parameters().len()
            || candidate_signature.result_types().len() != required_signature.result_types().len()
            || candidate_signature
                .parameters()
                .iter()
                .zip(required_signature.parameters())
                .any(|(a, b)| a.repeated() != b.repeated())
        {
            return Ok(DoesNotSatisfy);
        }
        let candidate_complete = self.go_signature_type_inventory_complete(candidate_signature)?;
        let required_complete = self.go_signature_type_inventory_complete(required_signature)?;
        let mut unknown = candidate_complete != Some(true)
            || required_complete != Some(true)
            || candidate_signature.type_parameter_count() != 0
            || required_signature.type_parameter_count() != 0;
        // The lowerer propagates a method's receiver-applicability marker to
        // its written result slots. That exact marker cannot change signature
        // identity after the inventory check classified it as receiver-only.
        let slot_complete = |state: &TypedFrontierState,
                             signature: &LoweredCallableSignatureProperty,
                             inventory: Option<bool>| {
            state.completion() == &ResolutionCompletion::Complete
                || (inventory == Some(true)
                    && match (state.completion(), signature.completion()) {
                        (
                            ResolutionCompletion::Incomplete(slot_reasons),
                            ResolutionCompletion::Incomplete(signature_reasons),
                        ) => slot_reasons
                            .iter()
                            .all(|reason| signature_reasons.contains(reason)),
                        _ => false,
                    })
        };
        let pairs = candidate_signature
            .parameters()
            .iter()
            .zip(required_signature.parameters())
            .map(|(a, b)| (a.slot(), b.slot()))
            .chain(
                candidate_signature
                    .result_types()
                    .iter()
                    .zip(required_signature.result_types())
                    .map(|(a, b)| (a.slot(), b.slot())),
            );
        for (left, right) in pairs {
            if self.poll_cancelled() {
                return Ok(Inconclusive("signature comparison was cancelled"));
            }
            self.demand_slot(left);
            self.demand_slot(right);
            match states.get(&left).zip(states.get(&right)) {
                Some((a, b))
                    if slot_complete(a, candidate_signature, candidate_complete)
                        && slot_complete(b, required_signature, required_complete) =>
                {
                    match (a.possible_values(), b.possible_values()) {
                        ([a], [b]) if a.ty() == b.ty() => {}
                        ([a], [b]) => {
                            // Anonymous structural identities identify occurrences,
                            // not nominal types. Their inequality cannot disprove
                            // signature equality without comparing the structure.
                            let identities = [a.ty().identity(), b.ty().identity()];
                            let read = self
                                .session
                                .declaration_types_for_definitions(&identities)?;
                            let Some(declarations) = self.accept_session_read(read) else {
                                return Ok(Inconclusive(GO_SIGNATURE_UNKNOWN));
                            };
                            let mut slots = identities.to_vec();
                            slots.extend(declarations.iter().filter_map(|declaration| {
                                let declaration = declaration.get(self.session).row();
                                (declaration.role() == DeclarationTypeRole::Identity)
                                    .then_some(declaration.slot())
                            }));
                            let read = self.session.intrinsics_for_slots(&slots)?;
                            let Some(seeds) = self.accept_session_read(read) else {
                                return Ok(Inconclusive(GO_SIGNATURE_UNKNOWN));
                            };
                            if seeds.iter().any(|seed| {
                                seed.get(self.session).row().kind() == IntrinsicTypeKind::Structural
                            }) {
                                unknown = true;
                            } else {
                                return Ok(DoesNotSatisfy);
                            }
                        }
                        _ => unknown = true,
                    }
                }
                _ => unknown = true,
            }
        }
        Ok(if unknown {
            Inconclusive(GO_SIGNATURE_UNKNOWN)
        } else {
            Satisfies
        })
    }

    fn go_check_method_interfaces(
        &mut self,
        target: SemanticId,
        lookup: SemanticId,
        interfaces: &[SemanticId],
        states: &StateMap,
        method_identity: &mut impl FnMut(SemanticId) -> StoreResult<Option<(String, i64)>>,
        provider: &mut dyn DemandRootProvider,
    ) -> StoreResult<Vec<GoInterfaceSatisfaction>> {
        use GoMethodSatisfaction::*;
        let read = self
            .session
            .deferred_member_owners_for_definitions(&[target])?;
        let Some(rows) = self.accept_session_read(read) else {
            return Ok(Vec::new());
        };
        let rows = rows
            .into_iter()
            .map(|row| *row.get(self.session).row())
            .collect::<Vec<_>>();
        if rows.is_empty() {
            // An interface declaration has a direct owner rather than a
            // deferred receiver frontier. It is coupled to its own contract.
            let read = self.session.member_owners_for_definitions(&[target])?;
            let Some(rows) = self.accept_session_read(read) else {
                return Ok(Vec::new());
            };
            return Ok(rows
                .into_iter()
                .filter_map(|row| {
                    let owner = row.get(self.session).row().owner_definition();
                    interfaces
                        .contains(&owner)
                        .then_some(GoInterfaceSatisfaction {
                            owner,
                            methods: vec![target],
                            outcome: Satisfies,
                        })
                })
                .collect());
        }
        let mut receivers = Vec::new();
        for row in rows {
            self.demand_slot(row.owner_frontier());
            if let Some(state) = states.get(&row.owner_frontier())
                && state.completion() == &ResolutionCompletion::Complete
                && let [value] = state.possible_values()
            {
                // Value-receiver methods belong to both T and *T. Pointer
                // methods belong only to *T; neither lookup is addressable.
                receivers.push(ResolutionSlotValue::type_object(value.ty()));
                if value.ty().indirection() == 0 {
                    receivers.push(ResolutionSlotValue::type_object(ResolutionTypeRef::new(
                        value.ty().identity(),
                        1,
                    )));
                }
            }
        }
        let mut result = Vec::new();
        for &owner in interfaces {
            if !self.close_hierarchy_owner_roots(&BTreeSet::from([owner]), provider)? {
                return Ok(result);
            }
            let Some((required_methods, complete)) = self.go_interface_method_set(owner)? else {
                return Ok(result);
            };
            let matches = required_methods
                .iter()
                .filter(|origin| origin.method.callable_lookup == lookup)
                .filter_map(|origin| origin.method.definition)
                .collect::<Vec<_>>();
            if matches.is_empty() && complete {
                continue;
            }
            let mut outcome = Inconclusive("receiver or interface method set is unavailable");
            for receiver in &receivers {
                let mut unknown = !complete;
                let mut unknown_reason =
                    (!complete).then_some("interface method-set inventory is incomplete");
                let mut mismatch = false;
                let mut selects_target = false;
                for origin in &required_methods {
                    let required_method = &origin.method;
                    let Some(required) = required_method.definition else {
                        unknown = true;
                        continue;
                    };
                    let read = self.session.deferred_member_owners_for_lookup_names(&[
                        DeferredMemberOwnerLookupName::new(required_method.callable_lookup),
                    ])?;
                    let Some(rows) = self.accept_session_read(read) else {
                        return Ok(result);
                    };
                    let rows = rows
                        .into_iter()
                        .map(|row| *row.get(self.session).row())
                        .collect::<Vec<_>>();
                    for row in &rows {
                        self.demand_slot(row.owner_frontier());
                    }
                    let definitions = rows.iter().map(|row| row.definition()).collect::<Vec<_>>();
                    if !self.session.ensure_go_member_declarations(&definitions)? {
                        return Ok(result);
                    }
                    let search = loop {
                        match self.go_receiver_members(
                            target,
                            required_method.callable_lookup,
                            *receiver,
                            &rows,
                            states,
                        )? {
                            GoMemberSearchPreparation::Ready(search) => break Some(search),
                            GoMemberSearchPreparation::Missing
                            | GoMemberSearchPreparation::Pending => break None,
                            GoMemberSearchPreparation::AwaitingHierarchy(roots) => {
                                if !self.close_hierarchy_owner_roots(&roots, provider)? {
                                    break None;
                                }
                            }
                        }
                    };
                    let Some(search) = search else {
                        unknown = true;
                        continue;
                    };
                    let [member] = search.members.as_slice() else {
                        if search.completion == ResolutionCompletion::Complete
                            || !search.rejected.is_empty()
                        {
                            mismatch = true;
                        } else {
                            unknown = true;
                        }
                        continue;
                    };
                    if member.kind != ResolutionMemberKind::Method {
                        mismatch = true;
                        continue;
                    }
                    if member.target == target && required_method.callable_lookup == lookup {
                        selects_target = true;
                    }
                    match self.go_signature_satisfaction(
                        member.target,
                        required,
                        states,
                        method_identity,
                    )? {
                        DoesNotSatisfy => mismatch = true,
                        Inconclusive(reason) => {
                            unknown = true;
                            unknown_reason = Some(reason);
                        }
                        Satisfies => {
                            if search.completion != ResolutionCompletion::Complete {
                                unknown = true;
                                unknown_reason =
                                    Some("method-family endpoint closure is incomplete");
                            }
                        }
                    }
                }
                let checked = if mismatch || (!unknown && !selects_target) {
                    DoesNotSatisfy
                } else if unknown {
                    Inconclusive(
                        unknown_reason.unwrap_or("method-family endpoint closure is incomplete"),
                    )
                } else {
                    Satisfies
                };
                if checked == Satisfies {
                    outcome = checked;
                    break;
                }
                if outcome == DoesNotSatisfy
                    || matches!(checked, Inconclusive(_))
                    || matches!(
                        outcome,
                        Inconclusive("receiver or interface method set is unavailable")
                    )
                {
                    outcome = checked;
                }
            }
            result.push(GoInterfaceSatisfaction {
                owner,
                methods: matches,
                outcome,
            });
        }
        Ok(result)
    }
}
