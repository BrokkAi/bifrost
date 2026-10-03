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
            Some(Some(declaration)) if declaration.kind == GoMemberDeclarationKind::Interface
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
                GoMemberDeclarationKind::Struct { .. } | GoMemberDeclarationKind::Interface => None,
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

/// One shortest embedding path, retained only during this selected query.
struct GoPromotionPath {
    value: ResolutionSlotValue,
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
    pub(super) completion: ResolutionCompletion,
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
                    Some(Some(row)) if row.kind == GoMemberDeclarationKind::Interface)
                    })
            })
            .collect::<Vec<_>>();
        if direct.is_empty() {
            return Ok(Some(answer));
        }
        let read = self
            .session
            .declaration_types_for_definitions(answer.targets())?;
        let Some(rows) = self.accept_session_read(read) else {
            return Ok(None);
        };
        let mut returns = HashMap::<SemanticId, Vec<SemanticId>>::default();
        for property in rows {
            if self.poll_cancelled() {
                return Ok(None);
            }
            let row = property.get(self.session).row();
            if row.role() == DeclarationTypeRole::Return {
                returns
                    .entry(row.definition())
                    .or_default()
                    .push(row.slot());
            }
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
                let comparable = base_signature.completion() == &ResolutionCompletion::Complete
                    && derived_signature.completion() == &ResolutionCompletion::Complete
                    && base_signature.type_parameter_count() == 0
                    && derived_signature.type_parameter_count() == 0;
                let base_returns = returns.get(&base).map_or(&[][..], Vec::as_slice);
                let derived_returns = returns.get(&derived).map_or(&[][..], Vec::as_slice);
                let same_shape = base_signature.parameters().len()
                    == derived_signature.parameters().len()
                    && base_returns.len() == derived_returns.len()
                    && base_signature
                        .parameters()
                        .iter()
                        .zip(derived_signature.parameters())
                        .all(|(a, b)| a.repeated() == b.repeated());
                if !comparable || !same_shape {
                    unresolved = true;
                    continue;
                }
                let pairs = base_signature
                    .parameters()
                    .iter()
                    .zip(derived_signature.parameters())
                    .map(|(a, b)| (a.slot(), b.slot()))
                    .chain(
                        base_returns
                            .iter()
                            .copied()
                            .zip(derived_returns.iter().copied()),
                    );
                let mut equal = true;
                for (left, right) in pairs {
                    if self.poll_cancelled() {
                        return Ok(None);
                    }
                    self.demand_slot(left);
                    self.demand_slot(right);
                    let exact = states.get(&left).zip(states.get(&right)).is_some_and(|(left,right)| {
                        left.completion() == &ResolutionCompletion::Complete
                            && right.completion() == &ResolutionCompletion::Complete
                            && matches!((left.possible_values(), right.possible_values()), ([a], [b]) if a.ty() == b.ty())
                    });
                    equal &= exact;
                }
                if equal {
                    break;
                }
                unresolved = true;
            }
        }
        let (targets, witnesses, mut completion) = answer.into_parts();
        if unresolved {
            completion = completion.combine(&incomplete(service_reason(
                &*self.hierarchy,
                b"go-interface-method-signature-unproven",
                &[self.root.as_bytes().as_slice()],
            )));
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
                Some(Some(row)) if row.kind == GoMemberDeclarationKind::Interface)
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
            for path in level {
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
                let Some(super::super::fact_source::GoMemberDeclaration {
                    kind: GoMemberDeclarationKind::Struct { fields },
                    ..
                }) = metadata
                else {
                    unavailable = true;
                    continue;
                };
                // Distinct paths intentionally produce distinct candidates,
                // including paths that end at the very same declaration.
                for row in rows {
                    if self.poll_cancelled() || !self.session.charge_scope_steps(1) {
                        self.cancellation_observed = true;
                        return Ok(None);
                    }
                    let Some(state) = states.get(&row.owner_frontier()) else {
                        unavailable = true;
                        continue;
                    };
                    completion = completion.combine(state.completion());
                    if row.kind() != ResolutionMemberKind::Method
                        || !state.possible_values().iter().any(|value| {
                            matches!(value, ResolutionSlotValue::TypeObject(ty)
                                if ty.indirection() <= 1 && ty.identity() == owner)
                        })
                    {
                        continue;
                    }
                    selected.push(GoSelectedMember {
                        target: row.definition(),
                        kind: row.kind(),
                        value: path.value,
                        owners: path.owners.clone().into_boxed_slice(),
                        fields: path.fields.clone(),
                        completion: path.completion.combine(state.completion()),
                    });
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
                    ResolutionIncompleteReason::UnsupportedSemantic(service_reason(
                        &*self.hierarchy,
                        b"go-promotion-frontier-unavailable",
                        &[
                            reference.as_bytes().as_slice(),
                            lookup.as_bytes().as_slice(),
                        ],
                    )),
                ]));
            }
            if selected.len() > 1 {
                completion = completion.combine(&ResolutionCompletion::incomplete([
                    ResolutionIncompleteReason::InconsistentPrecedence(reference),
                ]));
                return Ok(Some(GoMemberSearch {
                    members: Vec::new(),
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
                        completion,
                    }));
                }
                if member.kind == ResolutionMemberKind::Method
                    && (!self
                        .session
                        .receiver_indirection_supported(member.target, member.value)
                        || !self
                            .session
                            .go_receiver_eligible(member.target, member.value))
                {
                    completion = completion.combine(&ResolutionCompletion::incomplete([
                        ResolutionIncompleteReason::UnsupportedSemantic(service_reason(
                            &*self.hierarchy,
                            b"go-pointer-method-requires-addressable-receiver",
                            &[
                                reference.as_bytes().as_slice(),
                                member.target.as_bytes().as_slice(),
                            ],
                        )),
                    ]));
                    return Ok(Some(GoMemberSearch {
                        members: Vec::new(),
                        completion,
                    }));
                }
                return Ok(Some(GoMemberSearch {
                    members: vec![member],
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
                    self.demand_slot(slot);
                    let Some(state) = states.get(&slot) else {
                        unavailable = true;
                        continue;
                    };
                    completion = completion.combine(state.completion());
                    if state.possible_values().is_empty() {
                        unavailable = true;
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
                            completion: path.completion.combine(state.completion()),
                        });
                    }
                }
            }
            if unavailable {
                completion = completion.combine(&ResolutionCompletion::incomplete([
                    ResolutionIncompleteReason::UnsupportedSemantic(service_reason(
                        &*self.hierarchy,
                        b"go-promotion-frontier-unavailable",
                        &[
                            reference.as_bytes().as_slice(),
                            lookup.as_bytes().as_slice(),
                        ],
                    )),
                ]));
                break;
            }
            level = next;
        }
        Ok(Some(GoMemberSearch {
            members: Vec::new(),
            completion,
        }))
    }
}
