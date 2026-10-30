//! Go receiver eligibility uses exact source metadata and each lookup path's
//! runtime value. All memoized rows die with the selected query.

use super::super::fact_source::GoMemberDeclarationKind;
use super::*;
use crate::analyzer::store::resolution_operation::go_receiver_anchor::{
    GoMemberRejectionCause, GoStaticMemberCandidate, GoStaticMemberRejection, GoStaticMembership,
    GoStaticTypeMember, go_member_membership,
};

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
        let mut source_missing = Vec::new();
        for &definition in &missing {
            let external = self.context_identities.as_ref().and_then(|identities| {
                (identities.external_owner_language(definition)
                    == Some(crate::analyzer::resolution::ExternalOwnerLanguage::Go))
                .then(|| identities.external_owner_identity(definition))
                .flatten()
            });
            let Some(owner) = external else {
                source_missing.push(definition);
                continue;
            };
            let Some(model) = self.typed_source.go_model_owner_declarations(
                definition,
                &owner,
                self.cancellation,
            )?
            else {
                return Ok(false);
            };
            self.go_member_declarations.insert(
                definition,
                model.as_ref().map(|model| model.declaration.clone()),
            );
            if let Some(model) = &model {
                for method in &model.methods {
                    self.go_member_declarations.insert(
                        method.definition,
                        Some(super::super::fact_source::GoMemberDeclaration {
                            definition: method.definition,
                            kind: GoMemberDeclarationKind::Method {
                                pointer_receiver: method
                                    .declaration
                                    .receiver
                                    .map(|receiver| receiver.pointer),
                            },
                        }),
                    );
                    self.go_model_members.insert(method.definition, definition);
                }
            }
            self.go_model_owners.insert(definition, model);
        }
        let missing = source_missing;
        if missing.is_empty() {
            return Ok(!self.cancellation.is_cancelled());
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
    fn mark_go_model_receiver(&mut self, reference: SemanticId, owner: SemanticId) {
        self.receiver_target_evidence
            .entry((reference, owner))
            .or_default()
            .model_member_selection
            .get_or_insert_with(|| {
                Box::new(super::super::FactModelMemberSelection {
                    native_target_count: 0,
                    candidates: Vec::new(),
                    completion: ResolutionCompletion::Complete,
                })
            });
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn record_go_model_receiver_candidate(
        &mut self,
        reference: SemanticId,
        target: SemanticId,
        owners: &[SemanticId],
        receiver: ResolutionSlotValue,
        completion: &ResolutionCompletion,
        rejected: bool,
        receiver_category_closed: bool,
        selection_completion: &ResolutionCompletion,
    ) -> StoreResult<()> {
        let Some(&owner) = self.session.go_model_members.get(&target) else {
            return Ok(());
        };
        let metadata = self.session.go_model_owners[&owner]
            .as_ref()
            .expect("a reached model member has owner metadata");
        let member = metadata
            .methods
            .iter()
            .find(|member| member.definition == target)
            .expect("reached model method is declared");
        assert_eq!(
            owners.last(),
            Some(&owner),
            "model selection ends at its declaring owner"
        );
        let identity = self
            .session
            .context_identities
            .as_ref()
            .expect("model owner has selected identities")
            .external_owner_identity(owner)
            .expect("model declaration has owner coordinates");
        let candidate = super::super::FactModelMember {
            target,
            member: member.member.clone(),
            declaration: member.declaration.clone(),
            owner: identity,
            owners: owners.into(),
            owner_coordinates: owners
                .iter()
                .map(|owner| {
                    self.session
                        .context_identities
                        .as_ref()
                        .expect("selected identities")
                        .external_owner_identity(*owner)
                })
                .collect(),
            receiver_owner: self
                .session
                .context_identities
                .as_ref()
                .expect("selected identities")
                .external_owner_identity(receiver.ty().identity()),
            receiver_proven: receiver_category_closed
                && match receiver {
                    ResolutionSlotValue::TypeObject(_, obligation)
                    | ResolutionSlotValue::Runtime { obligation, .. } => obligation.is_none(),
                },
            selected: false,
            selection_complete: selection_completion == &ResolutionCompletion::Complete,
            incomplete_reasons: match completion {
                ResolutionCompletion::Complete => Vec::new(),
                ResolutionCompletion::Incomplete(reasons) => {
                    let services = self
                        .hierarchy
                        .service_reasons
                        .lock()
                        .expect("service reasons are not poisoned");
                    reasons
                        .iter()
                        .filter_map(|reason| match reason {
                            ResolutionIncompleteReason::UnsupportedSemantic(reason) => services
                                .get(reason)
                                .map(|(kind, _)| kind.clone())
                                .or_else(|| {
                                    self.session
                                        .context_identities
                                        .as_ref()
                                        .and_then(|identities| identities.named_reason(*reason))
                                        .map(|(kind, _)| kind.to_owned())
                                }),
                            _ => None,
                        })
                        .collect()
                }
            },
            receiver,
            interface: matches!(
                metadata.declaration.kind,
                GoMemberDeclarationKind::Interface { .. }
            ),
            route_exact: self.go_member_owner_path_is_depth_exact(owners),
            // Conservative until model field places exist (#7556). Even a
            // source-field promotion cannot prepare the outer receiver here.
            receiver_route_proven: owners.len() == 1,
            completion: completion.clone(),
            rejected,
        };
        let output = self
            .receiver_target_evidence
            .entry((reference, target))
            .or_default()
            .model_member_selection
            .get_or_insert_with(|| {
                Box::new(super::super::FactModelMemberSelection {
                    native_target_count: 0,
                    candidates: Vec::new(),
                    completion: ResolutionCompletion::Complete,
                })
            });
        output.completion = output.completion.combine(completion);
        if !output.candidates.contains(&candidate) {
            output.candidates.push(candidate);
        }
        Ok(())
    }

    pub(super) fn go_member_owner_path_is_depth_exact(&self, owners: &[SemanticId]) -> bool {
        use crate::analyzer::semantic_model::overlay::ModelMembersState;
        if self.session.go_model_owners.is_empty() {
            return true;
        }
        owners.iter().all(|owner| {
            self.session
                .go_model_owners
                .get(owner)
                .is_none_or(|metadata| {
                    metadata
                        .as_ref()
                        .is_some_and(|metadata| metadata.members_state == ModelMembersState::Exact)
                })
        })
    }

    fn go_model_owner_completion(
        &mut self,
        owner: SemanticId,
    ) -> StoreResult<ResolutionCompletion> {
        use crate::analyzer::semantic_model::overlay::ModelMembersState;
        let Some(metadata) = self.session.go_model_owners.get(&owner) else {
            return Ok(ResolutionCompletion::Complete);
        };
        let (mut completion, reason) = match metadata {
            Some(metadata) => (
                metadata.completion.clone(),
                (metadata.members_state != ModelMembersState::Exact)
                    .then_some(b"go-model-members-not-depth-exact".as_slice()),
            ),
            None => (
                ResolutionCompletion::Complete,
                Some(b"go-model-owner-declarations-unavailable".as_slice()),
            ),
        };
        if let Some(reason) = reason {
            completion = completion.combine(&incomplete(canonical_service_reason(
                self.session,
                &*self.hierarchy,
                reason,
                &[CanonicalIdentityPart::identity(owner)],
            )?));
        }
        Ok(completion)
    }

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
        if let Some(&owner) = self.session.go_model_members.get(&candidate) {
            let mut completion = self.go_model_owner_completion(owner)?;
            let receiver = self
                .receiver_target_evidence
                .get(&(call.callee_reference(), candidate));
            let proven = receiver.is_some_and(|receiver| {
                !receiver.category_open
                    && !receiver.values.is_empty()
                    && self.session.go_method_receiver(candidate).is_some()
                    && receiver.values.iter().all(|&value| {
                        self.session
                            .receiver_indirection_supported(candidate, value)
                            && self.session.go_receiver_eligible(candidate, value)
                    })
            });
            if !proven {
                completion = completion.combine(&incomplete(canonical_service_reason(
                    self.session,
                    &*self.hierarchy,
                    b"go-model-receiver-applicability-unproven",
                    &[CanonicalIdentityPart::identity(candidate)],
                )?));
            }
            // Declared signature applicability is independent of receiver proof.
            return Ok(Some(completion.combine(signature.completion())));
        }
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

struct GoInterfaceOwnerPaths {
    paths: Vec<Vec<SemanticId>>,
    complete: bool,
    completion: ResolutionCompletion,
    source_roots: BTreeSet<SemanticId>,
}

struct GoInterfaceMethodLookup {
    model_receiver: bool,
    source_roots: BTreeSet<SemanticId>,
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
    pub(super) search_completion: ResolutionCompletion,
    pub(super) receiver_is_interface: bool,
}

pub(super) struct GoRejectedMember {
    pub(super) cause: GoMemberRejectionCause,
    pub(super) target: SemanticId,
    pub(super) kind: ResolutionMemberKind,
    pub(super) owners: Box<[SemanticId]>,
}

pub(super) enum GoSatisfactionMember<'a> {
    Method(&'a GoSelectedMember),
    Excluded,
    Open(&'static str),
}

impl GoMemberSearch {
    pub(super) fn method_for_satisfaction(&self) -> GoSatisfactionMember<'_> {
        match go_member_membership(
            self.members.iter().map(|member| member.kind),
            self.rejected.iter().map(|rejection| rejection.cause),
            &self.search_completion,
        ) {
            GoStaticMembership::Present => GoSatisfactionMember::Method(&self.members[0]),
            GoStaticMembership::Excluded => GoSatisfactionMember::Excluded,
            GoStaticMembership::Open => {
                GoSatisfactionMember::Open("method-family endpoint closure is incomplete")
            }
        }
    }
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
                // A recognized model owner with unavailable metadata must still
                // reach the named incomplete result, never source absence.
                if self
                    .session
                    .go_model_owners
                    .contains_key(&value.ty().identity())
                {
                    return true;
                }
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
        let mut receiver_is_interface = false;
        if !self.session.ensure_go_member_declarations(&[root])? {
            self.cancellation_observed = true;
            return Ok(GoMemberSearchPreparation::Missing);
        }
        if self
            .session
            .go_model_owners
            .get(&root)
            .is_some_and(Option::is_none)
        {
            let completion = self.go_model_owner_completion(root)?;
            return Ok(GoMemberSearchPreparation::Ready(GoMemberSearch {
                members: Vec::new(),
                rejected: Vec::new(),
                search_completion: completion.clone(),
                receiver_is_interface,
                completion,
            }));
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
            for &owner in &owners {
                if self.session.go_model_owners.contains_key(&owner) {
                    self.mark_go_model_receiver(reference, owner);
                }
            }
            // The promotion walk already owns this depth's declarations. Close
            // its interface roots together before flattening any method set.
            let roots = owners.iter().copied().filter(|owner| {
                matches!(self.session.go_member_declarations.get(owner),
                    Some(Some(declaration)) if matches!(declaration.kind, GoMemberDeclarationKind::Interface { .. }))
                    && !self.session.go_model_owners.contains_key(owner)
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
                let model_completion = self.go_model_owner_completion(owner)?;
                path.completion = path.completion.combine(&model_completion);
                completion = completion.combine(&model_completion);
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
                    if surface != owner {
                        let surface_completion = self.go_model_owner_completion(surface)?;
                        completion = completion.combine(&surface_completion);
                        path.completion = path.completion.combine(&surface_completion);
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
                            receiver_is_interface |= path.fields.is_empty();
                            if matches!(path.value, ResolutionSlotValue::TypeObject(_, _)) {
                                path.value = ResolutionSlotValue::type_object(path.declared_type);
                            }
                            let Some(methods) =
                                self.go_interface_methods_for_lookup(surface, lookup, path.value)?
                            else {
                                return Ok(GoMemberSearchPreparation::Missing);
                            };
                            if !methods.source_roots.is_empty() {
                                return Ok(GoMemberSearchPreparation::AwaitingHierarchy(
                                    methods.source_roots,
                                ));
                            }
                            if methods.model_receiver {
                                self.mark_go_model_receiver(reference, surface);
                            }
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
                            if let Some(Some(model)) = self.session.go_model_owners.get(&surface) {
                                if !model
                                    .methods
                                    .iter()
                                    .any(|method| method.callable_lookup == lookup)
                                {
                                    let gap = incomplete(canonical_service_reason(
                                        self.session,
                                        &*self.hierarchy,
                                        b"go-model-defined-underlying-shape-unavailable",
                                        &[CanonicalIdentityPart::identity(surface)],
                                    )?);
                                    completion = completion.combine(&gap);
                                    path.completion = path.completion.combine(&gap);
                                }
                                // Own direct methods need no underlying shape.
                                continue;
                            }
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
                        None => {
                            // An underlying predeclared interface can have no
                            // source declaration row. Preserve its type category
                            // for consumers that cannot close interface absence.
                            if path.fields.is_empty()
                                && let Some(entry) =
                                    self.session.go_universe_type_for_identity(surface)?
                                && matches!(entry.spelling, "error" | "any" | "comparable")
                            {
                                receiver_is_interface = true;
                            }
                        }
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
                            search_completion: path.completion.clone(),
                            receiver_is_interface,
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
                if let Some(Some(model)) = self.session.go_model_owners.get(&owner) {
                    // Interface declarations, including their model parents,
                    // were collected by the one owner-path worklist above.
                    for method in model.methods.iter().filter(|_| {
                        !matches!(
                            model.declaration.kind,
                            GoMemberDeclarationKind::Interface { .. }
                        )
                    }) {
                        if method.callable_lookup != lookup {
                            continue;
                        }
                        if self.cancellation.is_cancelled() || !self.session.charge_scope_steps(1) {
                            self.cancellation_observed = true;
                            return Ok(GoMemberSearchPreparation::Missing);
                        }
                        let mut member_completion = path.completion.clone();
                        if method.declaration.receiver.is_none()
                            && !matches!(
                                model.declaration.kind,
                                GoMemberDeclarationKind::Interface { .. }
                            )
                        {
                            member_completion =
                                member_completion.combine(&incomplete(canonical_service_reason(
                                    self.session,
                                    &*self.hierarchy,
                                    b"go-model-method-receiver-unavailable",
                                    &[CanonicalIdentityPart::identity(method.definition)],
                                )?));
                        }
                        selected.push(GoSelectedMember {
                            target: method.definition,
                            kind: ResolutionMemberKind::Method,
                            value: path.value,
                            owners: path.owners.clone().into_boxed_slice(),
                            fields: path.fields.clone(),
                            completion: member_completion,
                        });
                    }
                } else {
                    let owner_requests = rows
                        .iter()
                        .filter(|row| row.kind() == ResolutionMemberKind::Method)
                        .take(1)
                        .map(|_| owner)
                        .collect::<Vec<_>>();
                    let Some(mut packages) =
                        self.session.go_package_member_sources(&owner_requests)?
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
                                    sources.iter().any(|source| {
                                        source.ordinal() == row.definition().ordinal()
                                    })
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
                    let Some(packages) = self.session.go_package_member_sources(&definitions)?
                    else {
                        self.cancellation_observed = true;
                        return Ok(GoMemberSearchPreparation::Missing);
                    };
                    assert_eq!(packages.len(), definitions.len());
                    let mut complete_method_packages = HashSet::default();
                    for (definition, sources) in definitions.iter().zip(packages) {
                        let Some(sources) = sources else {
                            continue;
                        };
                        let Some(placed) =
                            self.session.go_source_placement_is_complete(&sources)?
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
                            DeferredMemberOwnerProof::Matches
                            | DeferredMemberOwnerProof::Unknown => {
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
                    search_completion: completion.clone(),
                    receiver_is_interface,
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
                    search_completion: completion.clone(),
                    receiver_is_interface,
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
                        search_completion: completion.clone(),
                        receiver_is_interface,
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
                        search_completion: completion.clone(),
                        receiver_is_interface,
                        completion,
                    }));
                }
                if member.kind == ResolutionMemberKind::Method
                    && !self
                        .session
                        .go_receiver_eligible(member.target, member.value)
                {
                    // Static membership distinguishes a language exclusion from
                    // an open promotion frontier. Keep inherited gaps separate;
                    // ordinary selector consumers retain completion unchanged.
                    let search_completion = completion.clone();
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
                        search_completion,
                        receiver_is_interface,
                        rejected: vec![GoRejectedMember {
                            cause: GoMemberRejectionCause::ReceiverNotAddressable,
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
                    search_completion: completion.clone(),
                    receiver_is_interface,
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
                    let Some(slot) = field.value_type else {
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
                    let state_completion = match field.field {
                        Some(field_id) => {
                            completion_without_unsupported_semantic(state.completion(), field_id)
                        }
                        None => state.completion().clone(),
                    };
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
                        fields.extend(field.field);
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
                                    crate::analyzer::store::store_language_support_for_hook(
                                        Language::Go,
                                        "member_value",
                                    )
                                    .expect("Go member traversal has language support")
                                    .member_value(Some(path.value), *value)
                                    .expect("a known Go field receiver projects its value")
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
            search_completion: completion.clone(),
            receiver_is_interface,
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

// Receiver-only applicability markers do not change the written signature.
// Share this rule with static member projection; no caller strips gap labels.
fn go_signature_slot_complete(
    state: &TypedFrontierState,
    signature: &LoweredCallableSignatureProperty,
    inventory: Option<bool>,
) -> bool {
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
}

const GO_SIGNATURE_UNKNOWN: &str = "unsupported structural type in the required signature";

impl FactResolutionOperation<'_> {
    pub(crate) fn go_static_type_member(
        &mut self,
        receiver: ResolutionTypeRef,
        lookup: SemanticId,
        receiver_addressable: bool,
    ) -> StoreResult<GoStaticTypeMember> {
        let request =
            DemandMemberSelectionRequest::for_go_type(receiver, lookup, receiver_addressable);
        let provider = self
            .demand_provider
            .take()
            .expect("Go static membership requires its installed demand provider");
        let unresolved = canonical_service_reason(
            &self.session,
            &self.hierarchy,
            b"go-static-member-unresolved",
            &[
                CanonicalIdentityPart::identity(request.reference),
                CanonicalIdentityPart::identity(lookup),
                CanonicalIdentityPart::identity(receiver.identity()),
            ],
        )?;
        let gap =
            ResolutionCompletion::incomplete([ResolutionIncompleteReason::UnsupportedSemantic(
                unresolved,
            )]);
        let mut result = GoStaticTypeMember {
            candidates: Vec::new(),
            rejected: Vec::new(),
            completion: gap.clone(),
            search_completion: gap,
            intrinsic_types: Vec::new(),
            receiver_is_interface: false,
        };
        let mut evaluation = FactEvaluation::from_lexical_answer(
            &mut self.session,
            &mut self.hierarchy,
            receiver.identity(),
            ResolutionAnswer::new([receiver.identity()], [], ResolutionCompletion::Complete),
        )
        .with_candidate_paths(&mut self.candidate_paths);
        evaluation.forward_candidate_artifacts = Some(&mut self.forward_candidate_artifacts);
        evaluation.hierarchy_policy = evaluation.hierarchy.register_policy(request.policy);
        evaluation.selected_route_language = Language::Go;
        let provider = std::cell::RefCell::new(provider);
        let answer = evaluation.run_with_rounds_and_inspection(
            |evaluation, answers, states| evaluation.evaluate_round_with_dependencies(
                answers, states, provider.borrow_mut().as_mut(),
            ),
            |evaluation, states| {
                // Never retain a previous round's positive or negative answer
                // when this round needs new source closure or slot demands.
                result.candidates.clear();
                result.rejected.clear();
                result.search_completion = ResolutionCompletion::incomplete([
                    ResolutionIncompleteReason::UnsupportedSemantic(unresolved),
                ]);
                result.completion = result.search_completion.clone();
                let read = evaluation.session.deferred_member_owners_for_lookup_names(&[
                    DeferredMemberOwnerLookupName::new(request.lookup),
                ])?;
                let Some(rows) = evaluation.accept_session_read(read) else { return Ok(()); };
                let rows = rows.into_iter().map(|row| *row.get(evaluation.session).row()).collect::<Vec<_>>();
                if !evaluation.session.ensure_go_member_declarations(&[receiver.identity()])? { return Ok(()); }
                result.receiver_is_interface = matches!(evaluation.session.go_member_declarations.get(&receiver.identity()),
                    Some(Some(declaration)) if matches!(declaration.kind, GoMemberDeclarationKind::Interface { .. }));
                let search = loop {
                    match evaluation.go_receiver_members(request.reference, request.lookup, request.values[0], &rows, states)? {
                        GoMemberSearchPreparation::Ready(search) => break search,
                        GoMemberSearchPreparation::Missing | GoMemberSearchPreparation::Pending => return Ok(()),
                        GoMemberSearchPreparation::AwaitingHierarchy(roots) => {
                            if !evaluation.close_hierarchy_owner_roots(&roots, provider.borrow_mut().as_mut())? { return Ok(()); }
                        }
                    }
                };
                result.completion = search.completion;
                result.search_completion = search.search_completion;
                result.receiver_is_interface = search.receiver_is_interface;
                // Models are authored evidence, not closed source inventories.
                if evaluation.session.go_model_owners.contains_key(&receiver.identity())
                    || search.members.iter().any(|member| member.owners.iter().any(|owner| evaluation.session.go_model_owners.contains_key(owner)))
                    || search.rejected.iter().any(|member| member.owners.iter().any(|owner| evaluation.session.go_model_owners.contains_key(owner)))
                {
                    result.search_completion = result.search_completion.combine(&ResolutionCompletion::incomplete([
                        ResolutionIncompleteReason::UnsupportedSemantic(canonical_service_reason(
                            evaluation.session,
                            &*evaluation.hierarchy,
                            b"go-static-member-model-authored",
                            &[
                                CanonicalIdentityPart::identity(request.reference),
                                CanonicalIdentityPart::identity(lookup),
                                CanonicalIdentityPart::identity(receiver.identity()),
                            ],
                        )?),
                    ]));
                }
                result.rejected = search.rejected.into_iter().map(|member| GoStaticMemberRejection {
                    target: member.target, kind: member.kind, owners: member.owners, cause: member.cause,
                }).collect();
                for member in search.members {
                    let read = evaluation.session.signatures_for_definitions(&[member.target])?;
                    let Some(signatures) = evaluation.accept_session_read(read) else {
                        result.search_completion = result.search_completion.combine(&ResolutionCompletion::incomplete([
                            ResolutionIncompleteReason::UnsupportedSemantic(canonical_service_reason(
                                evaluation.session,
                                &*evaluation.hierarchy,
                                b"go-static-member-signature-unavailable",
                                &[
                                    CanonicalIdentityPart::identity(request.reference),
                                    CanonicalIdentityPart::identity(lookup),
                                    CanonicalIdentityPart::identity(member.target),
                                ],
                            )?),
                        ]));
                        return Ok(());
                    };
                    let signature = signatures.first().map(|row| row.get(evaluation.session).row().clone());
                    let mut signature_types = Vec::new();
                    let mut signature_types_complete = false;
                    if let Some(signature) = &signature {
                        let inventory = evaluation.go_signature_type_inventory_complete(signature)?;
                        signature_types_complete = inventory == Some(true) && signature.type_parameter_count() == 0;
                        for slot in signature.parameters().iter().map(|parameter| parameter.slot())
                            .chain(signature.result_types().iter().map(|result| result.slot()))
                        {
                            evaluation.demand_slot(slot);
                            if let Some(state) = states.get(&slot) {
                                signature_types_complete &= state.possible_values().len() == 1
                                    && go_signature_slot_complete(state, signature, inventory);
                                signature_types.push(state.as_ref().clone());
                            } else { signature_types_complete = false; }
                        }
                    }
                    result.candidates.push(GoStaticMemberCandidate {
                        definition: member.target, kind: member.kind,
                        promotion_depth: member.fields.len(), signature, signature_types, signature_types_complete,
                    });
                }
                Ok(())
            },
        );
        self.demand_provider = Some(provider.into_inner());
        answer?;
        let cancellation_observed = evaluation.cancellation_observed;
        drop(evaluation);
        let identities = result
            .candidates
            .iter()
            .flat_map(|candidate| &candidate.signature_types)
            .flat_map(|state| {
                state
                    .possible_values()
                    .iter()
                    .map(|value| value.ty().identity())
            })
            .collect::<Vec<_>>();
        let descriptors = self.read_intrinsic_type_descriptors(&identities)?;
        if let Some(descriptors) = descriptors {
            result.intrinsic_types = descriptors.into_vec();
        } else {
            result.search_completion =
                result
                    .search_completion
                    .combine(&ResolutionCompletion::incomplete([
                        ResolutionIncompleteReason::UnsupportedSemantic(unresolved),
                    ]));
        }
        // Preserve the session's first terminal outcome: a budget stop must
        // not become cancellation when a later read observes the stop.
        let stop_reason = match self
            .session
            .resolution_session
            .map(|session| session.finish(()))
        {
            Some(BoundedResolution::Exceeded { .. }) => Some(
                ResolutionIncompleteReason::ReceiverBudgetExhausted(request.reference),
            ),
            Some(BoundedResolution::Cancelled { .. }) => {
                Some(ResolutionIncompleteReason::Cancelled)
            }
            Some(BoundedResolution::Complete { .. }) | None => (cancellation_observed
                || self.session.cancellation.is_cancelled())
            .then_some(ResolutionIncompleteReason::Cancelled),
        };
        if let Some(reason) = stop_reason {
            result.search_completion = result
                .search_completion
                .combine(&ResolutionCompletion::incomplete([reason]));
        }
        Ok(result)
    }

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
        provider: &mut dyn DemandRootProvider,
    ) -> StoreResult<Option<(Vec<GoInterfaceMethodOrigin>, bool)>> {
        loop {
            let Some(paths) = self.go_interface_owner_paths(root)? else {
                return Ok(None);
            };
            if !paths.source_roots.is_empty() {
                if !self.close_hierarchy_owner_roots(&paths.source_roots, provider)? {
                    return Ok(None);
                }
                continue;
            }
            return Ok(self
                .go_interface_declared_methods(&paths.paths)?
                .map(|methods| (methods, paths.complete)));
        }
    }

    fn go_interface_declared_methods(
        &mut self,
        paths: &[Vec<SemanticId>],
    ) -> StoreResult<Option<Vec<GoInterfaceMethodOrigin>>> {
        let mut methods = Vec::new();
        for owners in paths {
            if self.poll_cancelled() {
                return Ok(None);
            }
            let owner = *owners.last().expect("interface route has its owner");
            let mut completion = ResolutionCompletion::Complete;
            for &ancestor in owners {
                completion = completion.combine(&self.go_model_owner_completion(ancestor)?);
            }
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
                            completion: completion.clone(),
                        }),
                );
            }
        }
        methods.sort_unstable_by_key(|origin| {
            (origin.method.callable_lookup, origin.method.definition)
        });
        methods.dedup_by(|a, b| a.method == b.method);
        Ok(Some(methods))
    }

    fn go_interface_methods_for_lookup(
        &mut self,
        root: SemanticId,
        lookup: SemanticId,
        receiver: ResolutionSlotValue,
    ) -> StoreResult<Option<GoInterfaceMethodLookup>> {
        let Some(paths) = self.go_interface_owner_paths(root)? else {
            return Ok(None);
        };
        let owner_inventory_complete = paths.complete;
        let model_receiver = paths
            .paths
            .iter()
            .flatten()
            .any(|owner| self.session.go_model_owners.contains_key(owner));
        if !paths.source_roots.is_empty() {
            return Ok(Some(GoInterfaceMethodLookup {
                model_receiver,
                source_roots: paths.source_roots,
                methods: Vec::new(),
                owner_inventory_complete: false,
                absence: paths.completion,
            }));
        }
        let model_completion = paths.completion;
        let paths = paths.paths;
        let Some(mut methods) = self.go_interface_declared_methods(&paths)? else {
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
        let source_paths = paths
            .iter()
            .filter(|owners| {
                let owner = *owners.last().expect("interface route has its owner");
                !self.session.go_model_owners.contains_key(&owner)
            })
            .collect::<Vec<_>>();
        let keys = source_paths
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
        for (owners, key) in source_paths.into_iter().zip(keys) {
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
        // A positive source declaration can discharge source absence, but
        // never a model inventory gap or a malformed embedded interface.
        absence = absence.combine(&model_completion);
        for method in &mut methods {
            method.completion = method.completion.combine(&model_completion);
        }
        Ok(Some(GoInterfaceMethodLookup {
            model_receiver,
            source_roots: BTreeSet::new(),
            methods,
            owner_inventory_complete,
            absence,
        }))
    }

    fn go_interface_owner_paths(
        &mut self,
        root: SemanticId,
    ) -> StoreResult<Option<GoInterfaceOwnerPaths>> {
        let mut pending = vec![vec![root]];
        let mut seen = HashSet::default();
        let mut paths = Vec::new();
        let mut complete = true;
        let mut completion = ResolutionCompletion::Complete;
        let mut source_roots = BTreeSet::new();
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
            let interface = matches!(
                self.session.go_member_declarations.get(&owner),
                Some(Some(row)) if matches!(row.kind, GoMemberDeclarationKind::Interface { .. })
            );
            complete &= interface;
            let is_model = self
                .session
                .context_identities
                .as_ref()
                .is_some_and(|identities| {
                    identities.external_owner_language(owner)
                        == Some(super::super::ExternalOwnerLanguage::Go)
                        && identities.external_owner_identity(owner).is_some()
                });
            if is_model {
                // Source closure may seal an indexed=false boundary terminal
                // for this identity. Its empty edges are not model inventory:
                // only this worklist expands the selected model declarations.
                completion = completion.combine(&self.go_model_owner_completion(owner)?);
                // Model method inventories never close the implementation
                // family, including when all authored methods are available.
                complete = false;
                let embedded = self
                    .session
                    .go_model_owners
                    .get(&owner)
                    .and_then(Option::as_ref)
                    .map(|model| model.embedded.clone())
                    .unwrap_or_default();
                for ty in embedded {
                    if self.poll_cancelled() || !self.session.charge_scope_steps(1) {
                        return Ok(None);
                    }
                    let target = ty.identity();
                    if !self.session.ensure_go_member_declarations(&[target])? {
                        return Ok(None);
                    }
                    let target_interface = matches!(self.session.go_member_declarations.get(&target),
                        Some(Some(row)) if matches!(row.kind, GoMemberDeclarationKind::Interface { .. }));
                    let reason = if !interface || !target_interface || ty.indirection() != 0 {
                        Some(b"go-model-embedded-interface-unavailable".as_slice())
                    } else if owners.contains(&target) {
                        Some(b"go-model-interface-cycle".as_slice())
                    } else {
                        None
                    };
                    if let Some(reason) = reason {
                        completion = completion.combine(&incomplete(canonical_service_reason(
                            self.session,
                            &*self.hierarchy,
                            reason,
                            &[
                                CanonicalIdentityPart::identity(owner),
                                CanonicalIdentityPart::identity(target),
                            ],
                        )?));
                        continue;
                    }
                    let mut path = owners.clone();
                    path.push(target);
                    pending.push(path);
                }
                paths.push(owners);
                continue;
            }
            if !self.hierarchy_owner_roots_closed(&BTreeSet::from([owner])) {
                source_roots.insert(owner);
                continue;
            }
            let node = self
                .hierarchy
                .edge_nodes
                .get(&HierarchyOwnerKey {
                    owner,
                    policy: self.hierarchy_policy,
                })
                .expect("shared hierarchy closure publishes each source owner");
            complete &= node.indexed
                && node.hierarchy_inventory_complete
                && matches!(node.evidence, HierarchyEvidence::Complete);
            for edge in &node.edges {
                if self.cancellation.is_cancelled() || !self.session.charge_scope_steps(1) {
                    return Ok(None);
                }
                complete &= matches!(edge.residual_evidence, HierarchyEvidence::Complete);
                for &target in &edge.targets {
                    if owners.contains(&target) {
                        complete = false;
                        continue;
                    }
                    let mut path = owners.clone();
                    path.push(target);
                    pending.push(path);
                }
            }
            paths.push(owners);
        }
        Ok(Some(GoInterfaceOwnerPaths {
            paths,
            complete,
            completion,
            source_roots,
        }))
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
                    if go_signature_slot_complete(a, candidate_signature, candidate_complete)
                        && go_signature_slot_complete(b, required_signature, required_complete) =>
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
            let Some((required_methods, complete)) =
                self.go_interface_method_set(owner, provider)?
            else {
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
                    let member = match search.method_for_satisfaction() {
                        GoSatisfactionMember::Method(member) => member,
                        GoSatisfactionMember::Excluded => {
                            mismatch = true;
                            continue;
                        }
                        GoSatisfactionMember::Open(reason) => {
                            unknown = true;
                            unknown_reason = Some(reason);
                            continue;
                        }
                    };
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
