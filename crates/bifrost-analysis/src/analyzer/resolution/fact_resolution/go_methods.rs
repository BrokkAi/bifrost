//! Go receiver eligibility uses exact source metadata and each lookup path's
//! runtime value. All memoized rows die with the selected query.

use super::super::fact_source::GoMemberDeclarationKind;
use super::*;

impl FactReadSession<'_> {
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
                ResolutionSlotValue::TypeObject(ty) => ty.indirection() == 1,
                ResolutionSlotValue::Runtime { ty, addressable } => {
                    ty.indirection() == 1 || addressable
                }
            }
    }

    fn go_method_receiver(&self, target: SemanticId) -> Option<bool> {
        self.go_member_declarations
            .get(&target)
            .and_then(Option::as_ref)
            .and_then(|declaration| match declaration.kind {
                GoMemberDeclarationKind::Method { pointer_receiver } => pointer_receiver,
                GoMemberDeclarationKind::Struct { .. }
                | GoMemberDeclarationKind::Interface { .. } => None,
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
    /// A negative owner proof needs every promotion edge, including paths that
    /// lose selector precedence. An unavailable edge makes the whole proof
    /// unknown; it must not turn an unrelated owner's incompleteness into a miss.
    pub(super) fn complete_go_member_owners(
        &mut self,
        routes: &[&SourceSelectedQualifiedRoute],
        states: &StateMap,
    ) -> StoreResult<Option<BTreeSet<SemanticId>>> {
        let mut pending = Vec::new();
        for route in routes {
            let Some(state) = states.get(&route.row().qualifier_slot()) else {
                return Ok(None);
            };
            if state.completion() != &ResolutionCompletion::Complete
                || state.possible_values().is_empty()
            {
                return Ok(None);
            }
            for value in state.possible_values() {
                let owner = value.ty().identity();
                if !matches!(self.session.go_member_declarations.get(&owner),
                    Some(Some(declaration)) if matches!(declaration.kind,
                        GoMemberDeclarationKind::Struct { .. } | GoMemberDeclarationKind::Interface { .. }))
                {
                    // The existing receiver hook already read Go root metadata.
                    // Do not add a read or work charge for another language.
                    return Ok(None);
                }
                pending.push(owner);
            }
        }
        let mut owners = BTreeSet::new();
        while let Some(owner) = pending.pop() {
            if self.poll_cancelled() || !self.session.charge_scope_steps(1) {
                self.cancellation_observed = true;
                return Ok(None);
            }
            if !owners.insert(owner) {
                continue;
            }
            if !self.session.ensure_go_member_declarations(&[owner])? {
                self.cancellation_observed = true;
                return Ok(None);
            }
            let Some(Some(declaration)) = self.session.go_member_declarations.get(&owner) else {
                // Other languages, aliases and unavailable Go source facts keep
                // the existing name-based owner demand without a new SQL read.
                return Ok(None);
            };
            match &declaration.kind {
                GoMemberDeclarationKind::Struct { fields } => {
                    for field in fields.iter().filter(|field| field.embedded) {
                        let (Some(field_id), Some(slot)) = (field.field, field.value_type) else {
                            return Ok(None);
                        };
                        let Some(state) = states.get(&slot) else {
                            return Ok(None);
                        };
                        // Same declared-type completion rule as selector promotion.
                        if completion_without_unsupported_semantic(state.completion(), field_id)
                            != ResolutionCompletion::Complete
                            || state.possible_values().is_empty()
                        {
                            return Ok(None);
                        }
                        pending.extend(
                            state
                                .possible_values()
                                .iter()
                                .map(|value| value.ty().identity()),
                        );
                    }
                }
                GoMemberDeclarationKind::Interface { .. } => {
                    // Do not open hierarchy relations before scheduler closure.
                    // A later pass can use the already sealed method-set graph.
                    if !self.hierarchy.closure_contains(owner) {
                        return Ok(None);
                    }
                    let node = self
                        .hierarchy
                        .edge_nodes
                        .get(&owner)
                        .expect("a sealed hierarchy owner has an edge node");
                    if !node.indexed
                        || !node.hierarchy_inventory_complete
                        || !matches!(node.evidence, HierarchyEvidence::Complete)
                    {
                        return Ok(None);
                    }
                    for edge in &node.edges {
                        if !matches!(edge.residual_evidence, HierarchyEvidence::Complete) {
                            return Ok(None);
                        }
                        pending.extend(edge.targets.iter().copied());
                    }
                }
                GoMemberDeclarationKind::Method { .. } => return Ok(None),
            }
        }
        Ok(Some(owners))
    }

    /// A Go interface method declaration is a statically selected name, but
    /// invoking it can dispatch to implementations that are not in this
    /// binding. Preserve that open receiver boundary on the call answer.
    pub(super) fn retain_go_interface_dispatch_boundary(
        &mut self,
        answer: ResolutionAnswer,
        obligation: &LoweredCallApplicabilityObligation,
        states: &StateMap,
    ) -> StoreResult<Option<ResolutionAnswer>> {
        if !self.session.lexical_source.supports_go_universe() || answer.targets().len() != 1 {
            return Ok(Some(answer));
        }
        if self
            .session
            .go_receiver_slot_type_overlay
            .as_ref()
            .is_some_and(|overlay| {
                overlay.query_binding == (obligation.callee_reference(), answer.targets()[0])
            })
        {
            // This point site's keyed receiver chain names the exact interface
            // declaration that the shared lookup selected. Dynamic
            // implementations cannot change which declaration the name at this
            // source site denotes.
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
        let completion = answer.completion().combine(&incomplete(reason));
        Ok(Some(answer_with_completion(answer, completion)))
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

pub(super) struct GoSelectedMember {
    pub(super) target: SemanticId,
    pub(super) kind: ResolutionMemberKind,
    pub(super) value: ResolutionSlotValue,
    pub(super) owners: Box<[SemanticId]>,
    pub(super) fields: Vec<SemanticId>,
    pub(super) completion: ResolutionCompletion,
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

    /// A selected Go struct admits member search even when no method has the
    /// requested spelling. Value selectors and calls share one shadowing space.
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
            let go_struct = state.possible_values().iter().any(|value| {
                matches!(self.session.go_member_declarations.get(&value.ty().identity()),
                        Some(Some(declaration)) if matches!(declaration.kind, GoMemberDeclarationKind::Struct { .. }))
            });
            if !go_struct {
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
                let row = row.get(self.session);
                let provenance_is_package_placement = row.origin()
                    == LoweringGapOrigin::Extracted(
                        ResolutionGapKind::UnsupportedPlacementBoundary,
                    )
                    && self
                        .session
                        .lexical_source
                        .go_package_inventory_complete_for_fragment(row.fragment());
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
    /// None means the receiver has no selected Go struct metadata. Cancellation
    /// is also reflected in the evaluation, as at the other selected readers.
    pub(super) fn go_struct_members(
        &mut self,
        reference: SemanticId,
        lookup: SemanticId,
        receiver: ResolutionSlotValue,
        rows: &[LoweredDeferredMemberOwner],
        states: &StateMap,
    ) -> StoreResult<Option<GoMemberSearch>> {
        let root = receiver.ty().identity();
        if !self.session.ensure_go_member_declarations(&[root])? {
            self.cancellation_observed = true;
            return Ok(None);
        }
        if !matches!(self.session.go_member_declarations.get(&root),
            Some(Some(declaration)) if matches!(declaration.kind, GoMemberDeclarationKind::Struct { .. }))
        {
            return Ok(None);
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
                return Ok(None);
            }
            let mut selected = Vec::new();
            let mut expansions = Vec::new();
            let mut unavailable = false;
            for mut path in level {
                if self.poll_cancelled() || !self.session.charge_scope_steps(1) {
                    self.cancellation_observed = true;
                    return Ok(None);
                }
                let owner = path.value.ty().identity();
                let metadata = self
                    .session
                    .go_member_declarations
                    .get(&owner)
                    .cloned()
                    .flatten();
                let (fields, interface_methods) = match metadata.map(|declaration| declaration.kind)
                {
                    Some(GoMemberDeclarationKind::Struct { fields }) => (fields, Vec::new()),
                    // A struct may embed an interface value. The interface
                    // has no fields to expand, but its declared methods are
                    // still candidates for promoted selector lookup below.
                    Some(GoMemberDeclarationKind::Interface { .. }) => {
                        // A pointer struct receiver promotes an embedded
                        // interface value's methods, not those of *I. Keep the
                        // field's declared indirection; *I has no method set.
                        if matches!(path.value, ResolutionSlotValue::TypeObject(_)) {
                            path.value = ResolutionSlotValue::type_object(path.declared_type);
                        }
                        let Some((methods, complete)) = self.go_interface_method_set(owner)? else {
                            return Ok(None);
                        };
                        unavailable |= !complete;
                        (Vec::new(), methods)
                    }
                    _ => {
                        unavailable = true;
                        continue;
                    }
                };
                if crate::analyzer::languages::language_support(Language::Go)
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
                        return Ok(Some(GoMemberSearch {
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
                // Distinct paths intentionally produce distinct candidates,
                // including paths that end at the very same declaration.
                for row in rows {
                    if self.poll_cancelled() || !self.session.charge_scope_steps(1) {
                        self.cancellation_observed = true;
                        return Ok(None);
                    }
                    // Go struct metadata owns field selection. The lowered
                    // owner frontier is only needed to associate method rows
                    // with this receiver; an unrelated field row's frontier
                    // must not make the structured field walk incomplete.
                    if row.kind() != ResolutionMemberKind::Method {
                        continue;
                    }
                    let Some(state) = states.get(&row.owner_frontier()) else {
                        unavailable = true;
                        continue;
                    };
                    let owner_matches = state.possible_values().iter().any(|value| {
                        matches!(value, ResolutionSlotValue::TypeObject(ty)
                                if ty.indirection() <= 1 && ty.identity() == owner)
                    });
                    if !owner_matches {
                        if state.completion() != &ResolutionCompletion::Complete {
                            completion = completion.combine(state.completion());
                        }
                        continue;
                    }
                    completion = completion.combine(state.completion());
                    selected.push(GoSelectedMember {
                        target: row.definition(),
                        kind: row.kind(),
                        value: path.value,
                        owners: path.owners.clone().into_boxed_slice(),
                        fields: path.fields.clone(),
                        completion: path.completion.combine(state.completion()),
                    });
                }
                for method in &interface_methods {
                    if method.callable_lookup != lookup {
                        continue;
                    }
                    if let Some(target) = method.definition {
                        selected.push(GoSelectedMember {
                            target,
                            kind: ResolutionMemberKind::Method,
                            value: path.value,
                            owners: path.owners.clone().into_boxed_slice(),
                            fields: path.fields.clone(),
                            completion: path.completion.clone(),
                        });
                    } else {
                        unavailable = true;
                    }
                }
                for field in &fields {
                    if self.poll_cancelled() || !self.session.charge_scope_steps(1) {
                        self.cancellation_observed = true;
                        return Ok(None);
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
            if matches!(receiver, ResolutionSlotValue::TypeObject(_))
                && selected
                    .iter()
                    .any(|member| member.kind != ResolutionMemberKind::Method)
            {
                return Ok(Some(GoMemberSearch {
                    members: Vec::new(),
                    rejected: Vec::new(),
                    completion,
                }));
            }
            if selected.len() > 1 {
                let precedence = ResolutionCompletion::incomplete([
                    ResolutionIncompleteReason::InconsistentPrecedence(reference),
                ]);
                completion = completion.combine(&precedence);
                return Ok(Some(GoMemberSearch {
                    // Preserve every promotion witness while precedence stays
                    // ambiguous. Consumers may report candidates but cannot
                    // select a unique callable target.
                    members: selected,
                    rejected: Vec::new(),
                    completion,
                }));
            }
            if let Some(member) = selected.pop() {
                // A field still shadows deeper methods, but selecting a field
                // on a type does not form a Go method expression.
                if matches!(receiver, ResolutionSlotValue::TypeObject(_))
                    && member.kind != ResolutionMemberKind::Method
                {
                    return Ok(Some(GoMemberSearch {
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
                    return Ok(Some(GoMemberSearch {
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
                    return Ok(Some(GoMemberSearch {
                        members: Vec::new(),
                        rejected: vec![GoRejectedMember {
                            target: member.target,
                            kind: member.kind,
                            owners: member.owners,
                        }],
                        completion,
                    }));
                }
                return Ok(Some(GoMemberSearch {
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
                        return Ok(None);
                    }
                    let (Some(field_id), Some(slot)) = (field.field, field.value_type) else {
                        unavailable = true;
                        continue;
                    };
                    if !self.charge_owner_expansion(path.value.ty().identity()) {
                        self.cancellation_observed = true;
                        return Ok(None);
                    }
                    self.demand_slot(slot);
                    let Some(state) = states.get(&slot) else {
                        // This snapshot predates the slot demand above. The
                        // fixed-point pass will revisit the frontier after
                        // materializing the embedded field's type state.
                        continue;
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
                            return Ok(None);
                        };
                        unavailable |= !inventory_closes_frontier;
                    }
                    for value in state.possible_values() {
                        if self.poll_cancelled() || !self.session.charge_scope_steps(1) {
                            self.cancellation_observed = true;
                            return Ok(None);
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
                                ResolutionSlotValue::TypeObject(parent) => {
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
        Ok(Some(GoMemberSearch {
            members: Vec::new(),
            rejected: Vec::new(),
            completion,
        }))
    }
}

/// Satisfaction is query evidence, never a persisted concrete/interface pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum GoMethodSatisfaction {
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
        );
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
        let answer = evaluation.run_with_rounds_and_inspection(
            |evaluation, answers, states| {
                evaluation.evaluate_round_with_dependencies(answers, states, provider.as_mut())
            },
            |evaluation, states| {
                result = evaluation.go_check_method_interfaces(
                    target,
                    lookup,
                    &closed_interfaces,
                    states,
                    &mut method_identity,
                )?;
                Ok(())
            },
        );
        self.demand_provider = Some(provider);
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
    ) -> StoreResult<Option<(Vec<super::super::fact_source::GoInterfaceMethod>, bool)>> {
        if !self.ensure_hierarchy_owner_closure(&BTreeSet::from([root]))? {
            return Ok(None);
        }
        let mut pending = vec![root];
        let mut seen = HashSet::default();
        let mut methods = Vec::new();
        let mut complete = true;
        while let Some(owner) = pending.pop() {
            if self.poll_cancelled() || !self.session.charge_scope_steps(1) {
                return Ok(None);
            }
            if !seen.insert(owner) {
                continue;
            }
            if !self.session.ensure_go_member_declarations(&[owner])? {
                return Ok(None);
            }
            match self.session.go_member_declarations.get(&owner) {
                Some(Some(row)) => match &row.kind {
                    GoMemberDeclarationKind::Interface { methods: declared } => {
                        methods.extend(declared.iter().cloned());
                    }
                    _ => complete = false,
                },
                _ => complete = false,
            }
            let node = self
                .hierarchy
                .edge_nodes
                .get(&owner)
                .expect("shared hierarchy closure publishes each owner");
            complete &= node.indexed
                && node.hierarchy_inventory_complete
                && matches!(node.evidence, HierarchyEvidence::Complete);
            for edge in &node.edges {
                complete &= matches!(edge.residual_evidence, HierarchyEvidence::Complete);
                pending.extend(edge.targets.iter().copied());
            }
        }
        methods.sort_unstable_by_key(|method| (method.callable_lookup, method.definition));
        methods.dedup();
        Ok(Some((methods, complete)))
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
                        ([_], [_]) => return Ok(DoesNotSatisfy),
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
                receivers.push(ResolutionSlotValue::TypeObject(value.ty()));
                if value.ty().indirection() == 0 {
                    receivers.push(ResolutionSlotValue::TypeObject(ResolutionTypeRef::new(
                        value.ty().identity(),
                        1,
                    )));
                }
            }
        }
        let mut result = Vec::new();
        for &owner in interfaces {
            let Some((required_methods, complete)) = self.go_interface_method_set(owner)? else {
                return Ok(result);
            };
            let matches = required_methods
                .iter()
                .filter(|method| method.callable_lookup == lookup)
                .filter_map(|method| method.definition)
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
                for required_method in &required_methods {
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
                    let Some(search) = self.go_struct_members(
                        target,
                        required_method.callable_lookup,
                        *receiver,
                        &rows,
                        states,
                    )?
                    else {
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
